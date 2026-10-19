/**
 * One budget shared by every worker of a scan. Model calls are reserved in
 * `admit()` so parallel workers cannot overshoot the call ceiling; tokens are
 * charged when usage arrives, so the token ceiling can be exceeded by at most
 * the requests already in flight.
 *
 * The AI phases run one after another on this budget, so without limits the
 * hunt phase can spend it all before any finding is independently reviewed.
 * {@link phaseCeilings} therefore gives each phase a ceiling that keeps a
 * reserve for the phases after it: as much as the pending reviews (and the
 * chain run) are expected to need, capped at a share of the budget, plus a
 * small reserve that lets running workers finish with one wrap-up request.
 */

import type { ScanUsage } from '../../shared/contracts.ts'
import type { ScanBudget } from '../../shared/settings.ts'
import type { LlmTokenUsage } from '../dsh/ports.ts'
import { type BudgetGate, chargedCacheReadTokens } from '../agents/runtime/budget.ts'

export type BudgetStop = 'calls' | 'tokens' | 'time' | 'cancelled'

/** Usage levels at which a phase's ordinary requests stop (wrap-up requests may go on to the scan's limits). */
export interface BudgetCeiling {
  readonly llmCalls: number
  readonly tokens: number
  readonly elapsedMs: number
}

/** Model requests one review is expected to need, for sizing the review reserve. */
export const CALLS_PER_REVIEW = 6
/** Model requests one hunt task is expected to need, for sizing the plan from the budget. */
export const CALLS_PER_HUNT = 12
/** Model requests the chain run is expected to need. */
export const CALLS_PER_CHAIN = 12
/** Largest share of each budget dimension kept for the review phase. */
export const REVIEW_SHARE = { quick: 0, deep: 0.3, research: 0.35 } as const
/** Largest share kept for the chain run (Research). */
const CHAIN_SHARE = 0.05
/** Wrap-up requests kept per parallel worker, and the largest share of the budget they may take. */
const WRAP_CALLS_PER_WORKER = 2
const WRAP_SHARE = 0.05
/** Share of the time budget kept so running workers can wrap up before the deadline. */
const WRAP_TIME_SHARE = 0.03

export class ScanBudgetGate implements BudgetGate {
  private llmCalls: number
  private inputTokens: number
  private outputTokens: number
  private toolCalls: number
  /** Elapsed running time accumulated before this run segment started. */
  private readonly baseElapsedMs: number
  private readonly segmentStart: number

  constructor(
    private readonly limits: ScanBudget,
    start: ScanUsage,
    private readonly signal: AbortSignal,
    private readonly now: () => number = Date.now,
  ) {
    this.llmCalls = start.llmCalls
    this.inputTokens = start.inputTokens
    this.outputTokens = start.outputTokens
    this.toolCalls = start.toolCalls
    this.baseElapsedMs = start.elapsedMs
    this.segmentStart = now()
  }

  /** Why no more model work should start, under `ceiling` when given (never above the scan's limits). */
  exhausted(ceiling?: BudgetCeiling): BudgetStop | undefined {
    if (this.signal.aborted) return 'cancelled'
    const maxMs = this.limits.maxMinutes * 60_000
    const calls = Math.min(this.limits.maxLlmCalls, ceiling?.llmCalls ?? Number.POSITIVE_INFINITY)
    const tokens = Math.min(this.limits.maxTokens, ceiling?.tokens ?? Number.POSITIVE_INFINITY)
    const ms = Math.min(maxMs, ceiling?.elapsedMs ?? Number.POSITIVE_INFINITY)
    if (this.llmCalls >= calls) return 'calls'
    if (this.inputTokens + this.outputTokens >= tokens) return 'tokens'
    if (this.elapsedMs() >= ms) return 'time'
    return undefined
  }

  /** Admits up to the scan's limits; a wrap-up request gets no more than any other here. */
  admit(): { readonly ok: true } | { readonly ok: false; readonly reason: BudgetStop } {
    const reason = this.exhausted()
    if (reason) return { ok: false, reason }
    this.llmCalls++
    return { ok: true }
  }

  /**
   * A gate for one phase: ordinary requests stop at `ceiling()` (evaluated
   * on every request, so the reserve can follow the work found so far);
   * wrap-up requests may use what is left up to the scan's limits.
   */
  phase(ceiling: () => BudgetCeiling): PhaseBudget {
    return new PhaseBudget(this, ceiling)
  }

  record(usage: LlmTokenUsage): void {
    // Input is stored as the budget charge: uncached and cache-write tokens
    // at full rate, cache reads at CACHE_READ_CHARGE_RATE (see runtime/budget).
    this.inputTokens +=
      safe(usage.inputTokens) + chargedCacheReadTokens(safe(usage.cacheReadTokens)) + safe(usage.cacheWriteTokens)
    this.outputTokens += safe(usage.outputTokens)
  }

  addToolCalls(count: number): void {
    this.toolCalls += safe(count)
  }

  /** Running time left before the time budget is used up (negative once it is). */
  remainingMs(): number {
    return this.limits.maxMinutes * 60_000 - this.elapsedMs()
  }

  elapsedMs(): number {
    return this.baseElapsedMs + Math.max(0, this.now() - this.segmentStart)
  }

  usage(): ScanUsage {
    return {
      llmCalls: this.llmCalls,
      inputTokens: this.inputTokens,
      outputTokens: this.outputTokens,
      toolCalls: this.toolCalls,
      elapsedMs: this.elapsedMs(),
    }
  }

  /** Fraction of the tightest budget dimension already used, 0..1. */
  pressure(): number {
    return Math.min(
      1,
      Math.max(
        this.llmCalls / this.limits.maxLlmCalls,
        (this.inputTokens + this.outputTokens) / this.limits.maxTokens,
        this.elapsedMs() / (this.limits.maxMinutes * 60_000),
      ),
    )
  }
}

/** One phase's view of the scan budget (see {@link ScanBudgetGate.phase}). */
export class PhaseBudget implements BudgetGate {
  constructor(
    private readonly gate: ScanBudgetGate,
    private readonly ceiling: () => BudgetCeiling,
  ) {}

  /** Why the phase should start no more work: its ceiling or the scan's limits are reached. */
  exhausted(): BudgetStop | undefined {
    return this.gate.exhausted(this.ceiling())
  }

  /** Whether the scan's own limits (not only this phase's ceiling) are reached. */
  scanExhausted(): BudgetStop | undefined {
    return this.gate.exhausted()
  }

  admit(request?: { readonly wrapUp?: boolean }) {
    if (request?.wrapUp !== true) {
      const reason = this.exhausted()
      if (reason) return { ok: false as const, reason }
    }
    return this.gate.admit()
  }

  record(usage: LlmTokenUsage): void {
    this.gate.record(usage)
  }
}

/** What {@link phaseCeilings} sizes the reserves from. */
export interface ReserveInput {
  readonly limits: ScanBudget
  readonly mode: 'quick' | 'deep' | 'research'
  /** Reviews that would run after hunting if the budget allows (0 without a review phase). */
  readonly reviews: number
  /** Whether a chain run follows the review phase. */
  readonly chain: boolean
  /** Parallel workers, each of which may need a wrap-up request. */
  readonly workers: number
  /** Observed budget tokens per model request; 0 or less uses the budget's own ratio. */
  readonly tokensPerCall: number
}

/**
 * Ceilings for the hunt (and planner), review and chain phases. The review
 * reserve is what the pending reviews need ({@link CALLS_PER_REVIEW} each),
 * at most {@link REVIEW_SHARE} of the budget; the chain reserve is at most
 * 5%; the wrap-up reserve is two requests per worker, at most 5% (and 3% of
 * the time). Tokens and time are reserved in proportion to the calls.
 */
export function phaseCeilings(input: ReserveInput): {
  readonly hunt: BudgetCeiling
  readonly review: BudgetCeiling
  readonly chain: BudgetCeiling
} {
  const { limits } = input
  const maxCalls = Math.max(0, limits.maxLlmCalls)
  const maxMs = limits.maxMinutes * 60_000
  const share = REVIEW_SHARE[input.mode]
  const wrap = Math.min(Math.max(1, input.workers) * WRAP_CALLS_PER_WORKER, Math.floor(maxCalls * WRAP_SHARE))
  const chain = input.chain ? Math.min(CALLS_PER_CHAIN, Math.floor(maxCalls * CHAIN_SHARE)) : 0
  const review = Math.min(Math.max(0, input.reviews) * CALLS_PER_REVIEW, Math.floor(maxCalls * share))
  const perCall = input.tokensPerCall > 0 ? input.tokensPerCall : limits.maxTokens / Math.max(1, maxCalls)
  // Never reserve more tokens than the share the calls stand for allows (a costly early phase skews the average).
  const tokensFor = (calls: number) =>
    Math.min(Math.round(calls * perCall), Math.round(limits.maxTokens * (calls / Math.max(1, maxCalls)) * 1.5))
  const timeFor = (calls: number) => Math.round(maxMs * (calls / Math.max(1, maxCalls)))
  const wrapMs = wrap > 0 ? Math.round(maxMs * WRAP_TIME_SHARE) : 0
  const ceiling = (reserved: number, timeReserved: number): BudgetCeiling => ({
    llmCalls: maxCalls - reserved,
    tokens: limits.maxTokens - tokensFor(reserved),
    elapsedMs: maxMs - timeReserved,
  })
  return {
    hunt: ceiling(review + chain + wrap, timeFor(review + chain) + wrapMs),
    review: ceiling(chain + wrap, timeFor(chain) + wrapMs),
    chain: ceiling(wrap, wrapMs),
  }
}

/**
 * Hunt tasks the hunt ceiling can still pay for at {@link CALLS_PER_HUNT}
 * requests each, given the usage so far.
 */
export function affordableHuntTasks(ceiling: BudgetCeiling, usage: ScanUsage, tokensPerCall: number): number {
  const calls = Math.floor(Math.max(0, ceiling.llmCalls - usage.llmCalls) / CALLS_PER_HUNT)
  if (tokensPerCall <= 0) return calls
  const tokens = Math.floor(
    Math.max(0, ceiling.tokens - usage.inputTokens - usage.outputTokens) / (CALLS_PER_HUNT * tokensPerCall),
  )
  return Math.min(calls, tokens)
}

function safe(value: number | undefined): number {
  return typeof value === 'number' && Number.isFinite(value) && value > 0 ? Math.round(value) : 0
}
