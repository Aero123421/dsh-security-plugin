/**
 * One budget shared by every worker of a scan. Model calls are reserved in
 * `admit()` so parallel workers cannot overshoot the call ceiling; tokens are
 * charged when usage arrives, so the token ceiling can be exceeded by at most
 * the requests already in flight.
 */

import type { ScanUsage } from '../../shared/contracts.ts'
import type { ScanBudget } from '../../shared/settings.ts'
import type { LlmTokenUsage } from '../dsh/ports.ts'
import { type BudgetGate, chargedCacheReadTokens } from '../agents/runtime/budget.ts'

export type BudgetStop = 'calls' | 'tokens' | 'time' | 'cancelled'

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

  /** Why no more model work should start, if any. */
  exhausted(): BudgetStop | undefined {
    if (this.signal.aborted) return 'cancelled'
    if (this.llmCalls >= this.limits.maxLlmCalls) return 'calls'
    if (this.inputTokens + this.outputTokens >= this.limits.maxTokens) return 'tokens'
    if (this.elapsedMs() >= this.limits.maxMinutes * 60_000) return 'time'
    return undefined
  }

  admit(): { readonly ok: true } | { readonly ok: false; readonly reason: BudgetStop } {
    const reason = this.exhausted()
    if (reason) return { ok: false, reason }
    this.llmCalls++
    return { ok: true }
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

function safe(value: number | undefined): number {
  return typeof value === 'number' && Number.isFinite(value) && value > 0 ? Math.round(value) : 0
}
