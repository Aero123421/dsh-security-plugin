/**
 * The generic tool-calling loop for short-lived, read-only security workers.
 *
 * Workers run directly on DSH's provider-neutral LLM registry (`ctx.llm.stream`)
 * rather than as DSH chat sessions, so they never appear in or inherit from the
 * user's chats. One `stream()` call is one provider attempt; this loop owns
 * retries, context compaction, nudging, budgets, and cancellation, and always
 * terminates (at most `(maxTurns + 1) × 4` model requests: the extra turn is
 * the single grace or wrap-up request described below).
 *
 * The same tools are offered on every request, so the request prefix (and the
 * provider's prompt cache) stays stable. Late in a run the loop warns the
 * model, and on the final turn it accepts only a submission: other tool calls
 * get an error result. A final turn without an accepted submission gets one
 * grace request. When the budget refuses a worker that already did some work,
 * the worker asks the gate for one wrap-up request in which it may only
 * submit. Submissions on these last-chance requests are validated with
 * `final: true`, so terminal tools keep what they can verify instead of
 * sending everything back.
 *
 * Hostile or confused models are bounded per reply as well: at most
 * {@link MAX_TOOL_CALLS_PER_TURN} tool calls run per model reply (the rest get
 * an error result), the worker yields to the event loop after every tool
 * execution, and a request whose first stream chunk takes longer than
 * `firstChunkTimeoutMs`, or that then goes `idleTimeoutMs` without a chunk, is
 * abandoned and retried as a `TIMEOUT`.
 */

import { randomUUID } from 'node:crypto'
import type {
  LlmAssistantMessage,
  LlmContentBlock,
  LlmFailure,
  LlmFinishReason,
  LlmGenerateOptions,
  LlmPort,
  LlmRequestMessage,
  LlmStreamChunk,
  LlmTokenUsage,
  LlmToolCallBlock,
  LlmToolResultMessage,
  LlmToolSchema,
  LlmUserInput,
} from '../../dsh/ports.ts'
import { type BudgetGate, type BudgetRefusal, chargedCacheReadTokens } from './budget.ts'
import { classifyFailure } from './failure.ts'
import { salvageArgs } from './lenient.ts'
import {
  assertValidTool,
  coerceToolArgs,
  type TerminalContext,
  type ToolResult,
  toolSchema,
  type WorkerTool,
} from './tool.ts'

/** Which model a worker talks to. */
export interface ModelRoute {
  readonly provider: string
  readonly model: string
  /** Passed through as `reasoningEffort`. */
  readonly reasoningEffort?: string
  /** Passed through as `maxTokens`. */
  readonly maxOutputTokens?: number
}

/** Everything one worker run needs. */
export interface WorkerSpec<T> {
  readonly id: string
  /** Stable routing identity for this conversation; defaults to a fresh UUID per worker run. */
  readonly sessionId?: string
  readonly role: string
  /** The LLM registry (`ctx.llm`); only `stream` is used. */
  readonly llm: Pick<LlmPort, 'stream'>
  readonly route: ModelRoute
  /** Sent as `options.system` on every request. */
  readonly system: string
  /** First user message. */
  readonly task: string
  /** At least one terminal tool; names must be unique. */
  readonly tools: readonly WorkerTool<unknown, T>[]
  /** Maximum model turns. Retries do not count as turns but do go through the budget gate. */
  readonly maxTurns: number
  readonly budget: BudgetGate
  readonly signal: AbortSignal
  /** Default 24 000; longer tool results are truncated with a marker. */
  readonly maxToolResultChars?: number
  /**
   * Sent only when set. A provider that rejects the parameter (an `INVALID_REQUEST`
   * naming `temperature`) is retried at once without it for the rest of the run.
   */
  readonly temperature?: number
  /** Progress listener. Thrown errors (and rejected promises) are swallowed. */
  readonly onEvent?: (event: WorkerEvent) => void
  /** Abortable sleep used for retry backoff; injectable for tests. Defaults to a timer. */
  readonly sleep?: (ms: number, signal: AbortSignal) => Promise<void>
  /**
   * Abandon a request when its stream, once started, sends no chunk for this
   * long; the attempt fails as a retryable `TIMEOUT`. Default
   * {@link DEFAULT_IDLE_TIMEOUT_MS}.
   */
  readonly idleTimeoutMs?: number
  /**
   * How long to wait for a request's first chunk. Providers can hold a queued
   * request for minutes under load, sending only keep-alive comments the
   * adapters do not surface. Default {@link DEFAULT_FIRST_CHUNK_TIMEOUT_MS};
   * never shorter than `idleTimeoutMs`.
   */
  readonly firstChunkTimeoutMs?: number
  /**
   * The model's context window in tokens, when known. Before a request that
   * would come close to it, the oldest tool results are elided.
   */
  readonly contextWindow?: number
}

/** Progress notifications emitted while a worker runs. */
export type WorkerEvent =
  | { type: 'request'; turn: number; attempt: number }
  | { type: 'response'; turn: number; usage: LlmTokenUsage; finish: string }
  | { type: 'tool'; turn: number; name: string; ok: boolean; ms: number }
  | { type: 'retry'; turn: number; code: string; delayMs: number }
  | { type: 'nudge'; turn: number; reason: string }
  /** The budget refused the next request; the worker asks for one submit-only request. */
  | { type: 'wrap-up'; turn: number; reason: BudgetRefusal }
  /** The provider rejected a request option; the worker continues without it. */
  | { type: 'option-dropped'; turn: number; option: 'temperature' }
  /** Older tool results were elided; `proactive` when done before a request instead of after an overflow. */
  | { type: 'compact'; turn: number; elided: number; proactive: boolean }

/** How a worker ended. */
export type WorkerStatus =
  | 'submitted'
  | 'no_submission'
  | 'budget_exhausted'
  | 'cancelled'
  | 'failed'
  | 'blocked_by_provider'

/** Outcome of {@link runWorker}. */
export interface WorkerResult<T> {
  readonly status: WorkerStatus
  /** Present iff `status === 'submitted'`. */
  readonly output?: T
  /** Name of the accepted terminal tool. */
  readonly terminalTool?: string
  /** Model turns started (retries excluded; the grace or wrap-up request counts as a turn). */
  readonly turns: number
  /** Tool calls handled: executed, rejected, or accepted as the submission. */
  readonly toolCalls: number
  /**
   * Summed usage over every request. `inputTokens` is the budget charge:
   * reported uncached input and cache writes at full rate, cache reads at
   * `CACHE_READ_CHARGE_RATE`. Raw per-request usage stays in the transcript.
   */
  readonly usage: { readonly inputTokens: number; readonly outputTokens: number; readonly llmCalls: number }
  /** Any non-terminal stream chunk received across attempts (error finish alone is a rejection). */
  readonly receivedAnyStreamChunk: boolean
  readonly transcript: readonly TranscriptEntry[]
  /** The provider (or internal) failure behind `failed` / `blocked_by_provider`. */
  readonly error?: { readonly code: string; readonly message: string }
  /**
   * Why a non-submitted worker stopped: a budget reason (`calls`, `tokens`, `time`,
   * `cancelled`), `max-turns`, `nudges-exhausted`, `aborted`, `retries-exhausted`,
   * `context-overflow`, `blocked`, or `fatal`.
   */
  readonly stopReason?: string
  /** Items a last-chance submission dropped because they failed validation. */
  readonly droppedItems?: number
}

/**
 * Log of a worker run, safe to `JSON.stringify`. Messages are recorded as they
 * were appended (nudge and final-turn notes as separate user entries, tool
 * results before any context compaction).
 */
export type TranscriptEntry =
  | { kind: 'system'; text: string }
  | { kind: 'message'; at: string; message: LlmRequestMessage }
  | { kind: 'usage'; at: string; turn: number; usage: LlmTokenUsage; finish: string }
  | { kind: 'error'; at: string; turn: number; code: string; message: string }

/** Default cap for one tool result's text. */
export const DEFAULT_MAX_TOOL_RESULT_CHARS = 24_000
/** Provider attempts per turn, the compaction retry included. */
export const MAX_ATTEMPTS_PER_TURN = 4
/**
 * Consecutive plain-text replies tolerated (each answered with a nudge)
 * before `no_submission`. Any tool call resets the count.
 */
export const MAX_NUDGES = 2
/** Tool calls run per model reply; further calls in the same reply get an error result instead. */
export const MAX_TOOL_CALLS_PER_TURN = 48
/** Default for {@link WorkerSpec.idleTimeoutMs}: two minutes without a stream chunk. */
export const DEFAULT_IDLE_TIMEOUT_MS = 120_000
/** Default for {@link WorkerSpec.firstChunkTimeoutMs}: ten minutes until the first chunk. */
export const DEFAULT_FIRST_CHUNK_TIMEOUT_MS = 600_000
/** Share of `maxTurns` after which the model is told how many turns are left. */
export const TURN_WARNING_FRACTION = 0.75

const BACKOFF_BASE_MS = 1_000
const BACKOFF_MAX_MS = 30_000
const BACKOFF_JITTER = 0.2
const RETRY_AFTER_CAP_MS = 60_000
const MAX_ISSUE_TEXT = 2_048
const MAX_ERROR_MESSAGE = 500
/** Without a known context window, an overflow elides tool results older than the latest two turns. */
const KEEP_RECENT_TURNS = 2
/** Compact before a request estimated above this share of the context window... */
const PROACTIVE_COMPACT_AT = 0.85
/** ...down to this share. */
const COMPACT_TARGET = 0.6
/** Characters per token assumed until a response reports usage. */
const DEFAULT_CHARS_PER_TOKEN = 3
const TEMPERATURE_REJECTED = /temperature/i

/**
 * Delay before retrying after failed attempt number `attempt` (1-based).
 * A valid provider retry-after wins (capped at 60 s); otherwise exponential
 * backoff from 1 s, doubling, capped at 30 s, with ±20% jitter.
 */
export function backoffDelayMs(
  attempt: number,
  providerRetryAfterMs?: number,
  random: () => number = Math.random,
): number {
  if (typeof providerRetryAfterMs === 'number' && Number.isFinite(providerRetryAfterMs) && providerRetryAfterMs >= 0) {
    return Math.min(Math.round(providerRetryAfterMs), RETRY_AFTER_CAP_MS)
  }
  const base = Math.min(BACKOFF_BASE_MS * 2 ** Math.max(0, attempt - 1), BACKOFF_MAX_MS)
  const jitter = 1 + (random() * 2 - 1) * BACKOFF_JITTER
  return Math.max(0, Math.round(base * jitter))
}

/**
 * Run one worker to completion. Never throws for model, tool, budget, or
 * listener failures; those end in a {@link WorkerStatus}.
 * @throws TypeError when the spec itself is invalid (no terminal tool, duplicate
 *   or malformed tool names, non-positive `maxTurns`).
 */
export async function runWorker<T>(spec: WorkerSpec<T>): Promise<WorkerResult<T>> {
  validateSpec(spec)
  return new WorkerRun(spec).run()
}

function validateSpec<T>(spec: WorkerSpec<T>): void {
  if (!Number.isInteger(spec.maxTurns) || spec.maxTurns < 1) {
    throw new TypeError(`Worker ${spec.id}: maxTurns must be a positive integer`)
  }
  if (
    spec.maxToolResultChars !== undefined &&
    (!Number.isInteger(spec.maxToolResultChars) || spec.maxToolResultChars < 1)
  ) {
    throw new TypeError(`Worker ${spec.id}: maxToolResultChars must be a positive integer`)
  }
  for (const [name, value] of [
    ['idleTimeoutMs', spec.idleTimeoutMs],
    ['firstChunkTimeoutMs', spec.firstChunkTimeoutMs],
  ] as const) {
    if (value !== undefined && (!Number.isFinite(value) || value <= 0)) {
      throw new TypeError(`Worker ${spec.id}: ${name} must be a positive number`)
    }
  }
  const names = new Set<string>()
  for (const tool of spec.tools) {
    assertValidTool(tool)
    if (names.has(tool.name)) throw new TypeError(`Worker ${spec.id}: duplicate tool ${tool.name}`)
    names.add(tool.name)
  }
  if (!spec.tools.some(tool => tool.terminal)) {
    throw new TypeError(`Worker ${spec.id}: at least one terminal tool is required`)
  }
}

// ---------------------------------------------------------------------------
// One run
// ---------------------------------------------------------------------------

type Mutable<T> = { -readonly [K in keyof T]: T[K] }

interface StopFields<T> {
  readonly output?: T
  readonly terminalTool?: string
  readonly error?: { readonly code: string; readonly message: string }
  readonly stopReason?: string
}

/** A completed model response. */
interface Reply {
  readonly kind: 'reply'
  readonly blocks: readonly LlmContentBlock[]
  readonly finish: string
  readonly replayState: unknown
  /** Names of tool calls dropped because the reply hit the output token limit. */
  readonly droppedCalls: readonly string[]
}

type RequestOutcome<T> =
  | Reply
  | { readonly kind: 'refused'; readonly reason: Exclude<BudgetRefusal, 'cancelled'> }
  | { readonly kind: 'stop'; readonly result: WorkerResult<T> }

/** What one handled reply means for the loop. */
type TurnOutcome<T> =
  | { readonly kind: 'done'; readonly result: WorkerResult<T> }
  | { readonly kind: 'continue' }
  /** A last-chance turn ended without an accepted submission. */
  | { readonly kind: 'missed' }

type AttemptOutcome = { readonly receivedAnyStreamChunk: boolean } & (
  | {
      readonly ok: true
      readonly blocks: LlmContentBlock[]
      readonly usage: LlmTokenUsage | undefined
      readonly finish: string
      readonly replayState: unknown
      readonly droppedCalls: readonly string[]
    }
  | {
      readonly ok: false
      readonly usage: LlmTokenUsage | undefined
      readonly finish: string
      readonly failure: LlmFailure
    }
)

type Verdict<T> =
  | { readonly ok: true; readonly output: T; readonly dropped: number }
  | { readonly ok: false; readonly result: ToolResult }

class WorkerRun<T> {
  private readonly messages: LlmRequestMessage[] = []
  private readonly transcript: TranscriptEntry[] = []
  private readonly tools: readonly WorkerTool<unknown, T>[]
  private readonly toolsByName: ReadonlyMap<string, WorkerTool<unknown, T>>
  private readonly schemas: LlmToolSchema[]
  private readonly schemaChars: number
  private readonly terminalTools: readonly WorkerTool<unknown, T>[]
  private readonly maxChars: number
  private readonly sessionId: string
  private readonly elided = new WeakSet<LlmRequestMessage>()
  private turns = 0
  private toolCalls = 0
  /** Non-terminal tool calls actually run. */
  private executedTools = 0
  /** Plain-text replies in a row. */
  private consecutiveText = 0
  private inputTokens = 0
  private outputTokens = 0
  private llmCalls = 0
  private receivedAnyStreamChunk = false
  private temperature: number | undefined
  /** Set once the budget refused and the worker switched to its single submit-only request. */
  private wrapUp: Exclude<BudgetRefusal, 'cancelled'> | undefined
  private charsPerToken = DEFAULT_CHARS_PER_TOKEN

  constructor(private readonly spec: WorkerSpec<T>) {
    this.sessionId = spec.sessionId ?? randomUUID()
    this.tools = spec.tools
    this.toolsByName = new Map(spec.tools.map(tool => [tool.name, tool]))
    this.schemas = spec.tools.map(toolSchema)
    this.schemaChars = JSON.stringify(this.schemas).length
    this.terminalTools = spec.tools.filter(tool => tool.terminal)
    this.maxChars = spec.maxToolResultChars ?? DEFAULT_MAX_TOOL_RESULT_CHARS
    this.temperature = spec.temperature
  }

  async run(): Promise<WorkerResult<T>> {
    const { spec } = this
    this.transcript.push({ kind: 'system', text: spec.system })
    this.pushMessage({ role: 'user', content: [{ type: 'text', text: spec.task }] })
    const names = this.terminalNames(' or ')
    const warnAt = spec.maxTurns >= 4 ? Math.ceil(spec.maxTurns * TURN_WARNING_FRACTION) : 0
    let lastTurn = spec.maxTurns
    let grace = false

    for (let turn = 1; turn <= lastTurn; turn++) {
      if (spec.signal.aborted) return this.stop('cancelled', { stopReason: 'aborted' })
      if (turn === lastTurn && !this.wrapUp) {
        this.addUserNote(
          grace
            ? `Your final turn ended without an accepted ${names} call. This is one extra request: call ${names} now with what you have verified so far; other tools will not run.`
            : `This is your final turn: call ${names} now with what you have verified so far. Other tools will not run on this turn.`,
        )
      } else if (turn === warnAt && turn < lastTurn) {
        const left = lastTurn - turn + 1
        this.addUserNote(
          `You have used ${turn - 1} of ${spec.maxTurns} turns. Finish the checks that matter most and call ${names} within the next ${left} turns.`,
        )
      }
      let reply = await this.request(turn)
      if (reply.kind === 'refused') {
        if (this.wrapUp || turn === 1) return this.stop('budget_exhausted', { stopReason: reply.reason })
        // Refused after some work: one last request to save it.
        this.wrapUp = reply.reason
        lastTurn = turn
        this.emit({ type: 'wrap-up', turn, reason: reply.reason })
        this.addUserNote(
          `The scan's ${budgetName(reply.reason)} budget for this work is used up. Call ${names} now with what you have verified so far; other tools will not run, and this is your last request.`,
        )
        reply = await this.request(turn)
        if (reply.kind === 'refused') return this.stop('budget_exhausted', { stopReason: reply.reason })
      }
      if (reply.kind === 'stop') return reply.result
      const outcome = await this.handleReply(turn, reply, turn === lastTurn)
      if (outcome.kind === 'done') return outcome.result
      if (outcome.kind === 'missed') {
        if (this.wrapUp) return this.stop('budget_exhausted', { stopReason: this.wrapUp })
        if (!grace) {
          grace = true
          lastTurn = turn + 1
        }
      }
    }
    return this.stop('no_submission', { stopReason: 'max-turns' })
  }

  // -- Model requests ------------------------------------------------------

  /** Performs one turn's request, retrying and compacting as needed. */
  private async request(turn: number): Promise<RequestOutcome<T>> {
    const { spec } = this
    let compacted = false
    for (let attempt = 1; attempt <= MAX_ATTEMPTS_PER_TURN; attempt++) {
      if (spec.signal.aborted) return { kind: 'stop', result: this.stop('cancelled', { stopReason: 'aborted' }) }
      const refused = this.admit()
      if (refused) return refused
      if (attempt === 1) this.turns = turn
      this.emit({ type: 'request', turn, attempt })
      this.llmCalls++
      if (!compacted && this.proactiveCompact(turn)) compacted = true

      const chars = this.requestChars()
      const options = this.options()
      const idleMs = spec.idleTimeoutMs ?? DEFAULT_IDLE_TIMEOUT_MS
      const outcome = await consumeStream(
        spec.llm,
        options,
        spec.signal,
        Math.max(idleMs, spec.firstChunkTimeoutMs ?? DEFAULT_FIRST_CHUNK_TIMEOUT_MS),
        idleMs,
      )
      this.receivedAnyStreamChunk ||= outcome.receivedAnyStreamChunk
      const usage: LlmTokenUsage = outcome.usage ? { ...outcome.usage } : { inputTokens: 0, outputTokens: 0 }
      this.recordUsage(usage, chars)
      this.transcript.push({ kind: 'usage', at: now(), turn, usage, finish: outcome.finish })
      this.emit({ type: 'response', turn, usage, finish: outcome.finish })
      if (outcome.ok) {
        return {
          kind: 'reply',
          blocks: outcome.blocks,
          finish: outcome.finish,
          replayState: outcome.replayState,
          droppedCalls: outcome.droppedCalls,
        }
      }

      const { failure } = outcome
      const error = { code: failure.code, message: clip(String(failure.message), MAX_ERROR_MESSAGE) }
      this.transcript.push({ kind: 'error', at: now(), turn, ...error })
      const cls = spec.signal.aborted ? 'aborted' : classifyFailure(failure)
      switch (cls) {
        case 'aborted':
          return { kind: 'stop', result: this.stop('cancelled', { stopReason: 'aborted' }) }
        case 'blocked_by_provider':
          return { kind: 'stop', result: this.stop('blocked_by_provider', { error, stopReason: 'blocked' }) }
        case 'context_overflow':
          if (compacted || attempt >= MAX_ATTEMPTS_PER_TURN || !this.compact(turn, false)) {
            return { kind: 'stop', result: this.stop('failed', { error, stopReason: 'context-overflow' }) }
          }
          compacted = true
          continue
        case 'retryable': {
          if (attempt >= MAX_ATTEMPTS_PER_TURN) {
            return { kind: 'stop', result: this.stop('failed', { error, stopReason: 'retries-exhausted' }) }
          }
          const delayMs = backoffDelayMs(attempt, failure.providerRetryAfterMs)
          this.emit({ type: 'retry', turn, code: failure.code, delayMs })
          if (!(await this.sleep(delayMs))) {
            return { kind: 'stop', result: this.stop('cancelled', { stopReason: 'aborted' }) }
          }
          continue
        }
        default:
          // Some routes reject sampling parameters outright; the request is still worth sending without it.
          if (
            options.temperature !== undefined &&
            TEMPERATURE_REJECTED.test(String(failure.message)) &&
            attempt < MAX_ATTEMPTS_PER_TURN
          ) {
            this.temperature = undefined
            this.emit({ type: 'option-dropped', turn, option: 'temperature' })
            continue
          }
          return { kind: 'stop', result: this.stop('failed', { error, stopReason: 'fatal' }) }
      }
    }
    // Unreachable: the last attempt always returns above.
    return { kind: 'stop', result: this.stop('failed', { stopReason: 'retries-exhausted' }) }
  }

  private options(): LlmGenerateOptions {
    const { route, system, signal } = this.spec
    const options: LlmGenerateOptions = {
      provider: route.provider,
      model: route.model,
      sessionId: this.sessionId,
      messages: this.messages.slice(),
      system,
      tools: this.schemas,
      signal,
    }
    if (route.reasoningEffort !== undefined) options.reasoningEffort = route.reasoningEffort
    if (route.maxOutputTokens !== undefined) options.maxTokens = route.maxOutputTokens
    if (this.temperature !== undefined) options.temperature = this.temperature
    return options
  }

  /** A refusal or stop result when the budget refuses the next request. */
  private admit(): RequestOutcome<T> | undefined {
    let admission: ReturnType<BudgetGate['admit']>
    try {
      admission = this.spec.budget.admit(this.wrapUp ? { wrapUp: true } : undefined)
    } catch (error) {
      const result = this.stop('failed', {
        error: { code: 'INTERNAL', message: errorText(error) },
        stopReason: 'fatal',
      })
      return { kind: 'stop', result }
    }
    if (admission.ok) return undefined
    if (admission.reason === 'cancelled') {
      return { kind: 'stop', result: this.stop('cancelled', { stopReason: 'cancelled' }) }
    }
    return { kind: 'refused', reason: admission.reason }
  }

  private recordUsage(usage: LlmTokenUsage, requestChars: number): void {
    const prompt = count(usage.inputTokens) + count(usage.cacheReadTokens) + count(usage.cacheWriteTokens)
    if (prompt > 0 && requestChars > 0) {
      this.charsPerToken = Math.min(8, Math.max(1, requestChars / prompt))
    }
    this.inputTokens +=
      count(usage.inputTokens) + chargedCacheReadTokens(count(usage.cacheReadTokens)) + count(usage.cacheWriteTokens)
    this.outputTokens += count(usage.outputTokens)
    try {
      this.spec.budget.record(usage)
    } catch {
      // A broken gate must not break the worker; admission still applies.
    }
  }

  /** Resolves false when cancelled before or during the sleep. */
  private async sleep(ms: number): Promise<boolean> {
    const { signal } = this.spec
    try {
      await (this.spec.sleep ?? abortableSleep)(ms, signal)
    } catch {
      return false
    }
    return !signal.aborted
  }

  // -- Context size --------------------------------------------------------

  /** Rough size of the next request in characters: system prompt, tool schemas, and messages. */
  private requestChars(): number {
    let chars = this.spec.system.length + this.schemaChars
    for (const message of this.messages) chars += contentChars(message.content)
    return chars
  }

  /** Compacts before a request that would come close to a known context window. */
  private proactiveCompact(turn: number): boolean {
    const window = this.spec.contextWindow
    if (window === undefined || !Number.isFinite(window) || window <= 0) return false
    const output = this.spec.route.maxOutputTokens ?? 0
    const limit = Math.max(window * 0.5, window * PROACTIVE_COMPACT_AT - output)
    if (this.requestChars() / this.charsPerToken <= limit) return false
    return this.compact(turn, true)
  }

  /**
   * Elides tool results, oldest first, never those answering the latest
   * reply. With a known context window it stops once the request is
   * estimated below {@link COMPACT_TARGET} of it; otherwise it keeps the
   * results of the latest {@link KEEP_RECENT_TURNS} replies. Each marker names
   * the call whose output it replaces. Returns false when nothing changed,
   * i.e. retrying could not help.
   */
  private compact(turn: number, proactive: boolean): boolean {
    const assistants: number[] = []
    const calls = new Map<string, LlmToolCallBlock>()
    this.messages.forEach((message, index) => {
      if (message.role !== 'assistant') return
      assistants.push(index)
      for (const block of message.content) if (isToolCall(block)) calls.set(block.id, block)
    })
    const window = this.spec.contextWindow
    const sized = window !== undefined && Number.isFinite(window) && window > 0
    const protectFrom = sized ? (assistants.at(-1) ?? 0) : (assistants.at(-KEEP_RECENT_TURNS) ?? 0)
    const target = sized ? window * COMPACT_TARGET : 0
    let elided = 0
    for (let index = 0; index < protectFrom; index++) {
      if (sized && this.requestChars() / this.charsPerToken <= target) break
      const message = this.messages[index]
      if (message?.role !== 'tool' || this.elided.has(message)) continue
      const call = calls.get(message.toolCallId)
      const replacement: LlmToolResultMessage = {
        ...message,
        content: [{ type: 'text', text: elisionMarker(call, contentChars(message.content)) }],
      }
      this.elided.add(replacement)
      this.messages[index] = replacement
      elided++
    }
    if (elided > 0) this.emit({ type: 'compact', turn, elided, proactive })
    return elided > 0
  }

  // -- Replies and tools ---------------------------------------------------

  /** Handles a completed reply. `lastChance` marks a final, grace, or wrap-up turn. */
  private async handleReply(turn: number, reply: Reply, lastChance: boolean): Promise<TurnOutcome<T>> {
    const { spec } = this
    if (reply.blocks.length > 0) {
      const source: Mutable<LlmAssistantMessage['source']> = {
        kind: 'model',
        provider: spec.route.provider,
        model: spec.route.model,
      }
      if (reply.replayState !== undefined) source.replayState = reply.replayState
      this.pushMessage({ id: randomUUID(), role: 'assistant', content: reply.blocks, source })
    }

    const names = this.terminalNames(' or ')
    if (reply.droppedCalls.length > 0) {
      // Like DSH's BlockAssembler: a reply cut off by the output limit never runs (or replays) its tool calls.
      this.consecutiveText = 0
      this.emit({ type: 'nudge', turn, reason: 'max-tokens' })
      this.addUserNote(
        `Your previous reply hit the output token limit, so its tool calls were cut off and not run: ${summarizeNames(reply.droppedCalls)}. ` +
          'Call them again with shorter arguments: fewer calls or items per reply, more concise text, and brief reasoning.',
      )
      return lastChance ? { kind: 'missed' } : { kind: 'continue' }
    }

    const calls = reply.blocks.filter(isToolCall)
    if (calls.length === 0) {
      this.consecutiveText++
      if (this.consecutiveText > MAX_NUDGES) {
        return { kind: 'done', result: this.stop('no_submission', { stopReason: 'nudges-exhausted' }) }
      }
      if (lastChance) return { kind: 'missed' }
      const truncated = reply.finish === 'max-tokens'
      this.emit({ type: 'nudge', turn, reason: truncated ? 'max-tokens' : 'no-tool-call' })
      const nudge = `Plain text is not read. Continue with a tool call, or call ${names} when you are done.`
      this.addUserNote(
        truncated
          ? `Your previous reply hit the output token limit before it called a tool. Reply with a tool call right away and keep your reasoning short. ${nudge}`
          : nudge,
      )
      return { kind: 'continue' }
    }
    this.consecutiveText = 0

    // At most MAX_TOOL_CALLS_PER_TURN calls run (terminal evaluations included); every call still gets a result.
    let remaining = MAX_TOOL_CALLS_PER_TURN
    const overLimit = (call: LlmToolCallBlock): ToolResult => {
      this.emit({ type: 'tool', turn, name: call.name, ok: false, ms: 0 })
      return errorResult(
        `Not run: this reply contained ${calls.length} tool calls and only the first ${MAX_TOOL_CALLS_PER_TURN} are run per reply. ` +
          `Call at most ${MAX_TOOL_CALLS_PER_TURN} tools per reply, batch related lookups (for example one broader search_code pattern), ` +
          'and call this tool again if you still need it.',
      )
    }
    const context: TerminalContext = { final: lastChance, toolCalls: this.executedTools }
    // Terminal calls first: the first valid one ends the worker and the rest are ignored.
    const rejected = new Map<number, ToolResult>()
    for (const [index, call] of calls.entries()) {
      const tool = this.toolsByName.get(call.name)
      if (!tool?.terminal) continue
      if (remaining <= 0) {
        rejected.set(index, overLimit(call))
        continue
      }
      remaining--
      const started = performance.now()
      const verdict = await this.evaluateTerminal(tool, call, context)
      this.emit({ type: 'tool', turn, name: call.name, ok: verdict.ok, ms: elapsed(started) })
      if (verdict.ok) {
        this.toolCalls++
        const result = this.stop('submitted', { output: verdict.output, terminalTool: tool.name })
        return { kind: 'done', result: verdict.dropped > 0 ? { ...result, droppedItems: verdict.dropped } : result }
      }
      rejected.set(index, verdict.result)
      await yieldToEventLoop()
    }

    for (const [index, call] of calls.entries()) {
      if (spec.signal.aborted) return { kind: 'done', result: this.stop('cancelled', { stopReason: 'aborted' }) }
      let result = rejected.get(index)
      if (!result && lastChance) {
        this.emit({ type: 'tool', turn, name: call.name, ok: false, ms: 0 })
        result = errorResult(
          `Not run: this is your last request, so only ${names} is accepted. Call ${names} now with what you have verified so far.`,
        )
      }
      if (!result && remaining > 0) {
        remaining--
        result = await this.execute(turn, call)
        // A tool may have run synchronously for a while (regex search): let timers, I/O and other workers run.
        await yieldToEventLoop()
      }
      result ??= overLimit(call)
      this.toolCalls++
      this.pushMessage(toolResultMessage(call.id, truncateText(result.text, this.maxChars), result.isError === true))
    }
    if (spec.signal.aborted) return { kind: 'done', result: this.stop('cancelled', { stopReason: 'aborted' }) }
    return lastChance ? { kind: 'missed' } : { kind: 'continue' }
  }

  private async evaluateTerminal(
    tool: WorkerTool<unknown, T>,
    call: LlmToolCallBlock,
    context: TerminalContext,
  ): Promise<Verdict<T>> {
    const args = await this.parseArgs(tool, call, context.final)
    if (!args.ok) return { ok: false, result: args.result }
    const terminal = tool.terminal
    if (!terminal) return { ok: false, result: errorResult(`Tool ${tool.name} cannot submit.`) }
    try {
      const message = terminal.validate?.(args.value, context)
      if (typeof message === 'string' && message !== '') return { ok: false, result: errorResult(message) }
      return { ok: true, output: terminal.toOutput(args.value, context), dropped: args.dropped }
    } catch (error) {
      return { ok: false, result: errorResult(`Tool failed: ${errorText(error)}`) }
    }
  }

  private async execute(turn: number, call: LlmToolCallBlock): Promise<ToolResult> {
    const started = performance.now()
    const result = await this.executeUntimed(turn, call)
    this.emit({ type: 'tool', turn, name: call.name, ok: result.isError !== true, ms: elapsed(started) })
    return result
  }

  private async executeUntimed(turn: number, call: LlmToolCallBlock): Promise<ToolResult> {
    const tool = this.toolsByName.get(call.name)
    if (!tool) {
      const names = this.tools.map(t => t.name).join(', ')
      return errorResult(`Unknown tool ${JSON.stringify(clip(String(call.name), 80))}. Available tools: ${names}.`)
    }
    const args = await this.parseArgs(tool, call, false)
    if (!args.ok) return args.result
    if (!tool.execute) return errorResult(`Tool failed: ${tool.name} is not executable`)
    this.executedTools++
    try {
      const { signal, id } = this.spec
      const result: unknown = await raceAbort(tool.execute(args.value, { signal, workerId: id, turn }), signal)
      if (!isToolResult(result)) return errorResult(`Tool failed: ${tool.name} returned an invalid result`)
      return { text: result.text, isError: result.isError === true }
    } catch (error) {
      return errorResult(`Tool failed: ${errorText(error)}`)
    }
  }

  /**
   * JSON-decodes, repairs (see `lenient.ts`) and schema-validates a call's
   * arguments. With `salvage`, list items that still fail are dropped instead
   * of rejecting the call.
   */
  private async parseArgs(
    tool: WorkerTool<unknown, T>,
    call: LlmToolCallBlock,
    salvage: boolean,
  ): Promise<
    | { readonly ok: true; readonly value: unknown; readonly dropped: number }
    | { readonly ok: false; readonly result: ToolResult }
  > {
    const decoded = decodeArguments(call.arguments)
    if (!decoded.ok) {
      return {
        ok: false,
        result: errorResult(
          `Invalid JSON arguments for ${tool.name}: ${decoded.error}. Send one JSON object matching the tool's schema.`,
        ),
      }
    }
    try {
      const repaired = coerceToolArgs(tool, decoded.value)
      const parsed = await tool.input.safeParseAsync(repaired)
      if (parsed.success) return { ok: true, value: parsed.data, dropped: 0 }
      if (salvage) {
        const kept = await salvageArgs(tool.input, repaired)
        if (kept.ok) return { ok: true, value: kept.value, dropped: kept.dropped }
      }
      return { ok: false, result: errorResult(clip(formatIssues(tool.name, parsed.error.issues), MAX_ISSUE_TEXT)) }
    } catch (error) {
      return { ok: false, result: errorResult(`Tool failed: ${errorText(error)}`) }
    }
  }

  // -- Bookkeeping ---------------------------------------------------------

  private pushMessage(message: LlmRequestMessage): void {
    this.messages.push(message)
    this.transcript.push({ kind: 'message', at: now(), message })
  }

  /**
   * Appends a user note. Consecutive user turns are merged into one request
   * message because some providers reject successive user messages.
   */
  private addUserNote(text: string): void {
    const block = { type: 'text', text }
    const last = this.messages.at(-1)
    if (last?.role === 'user') {
      this.messages[this.messages.length - 1] = { role: 'user', content: [...last.content, block] }
    } else {
      this.messages.push({ role: 'user', content: [block] })
    }
    const note: LlmUserInput = { role: 'user', content: [block] }
    this.transcript.push({ kind: 'message', at: now(), message: note })
  }

  private terminalNames(separator: string): string {
    return this.terminalTools.map(tool => tool.name).join(separator)
  }

  private emit(event: WorkerEvent): void {
    const listener = this.spec.onEvent
    if (!listener) return
    try {
      const returned: unknown = listener(event)
      if (returned instanceof Promise) returned.catch(() => {})
    } catch {
      // Listeners must never break the worker.
    }
  }

  private stop(status: WorkerStatus, fields: StopFields<T> = {}): WorkerResult<T> {
    const result: Mutable<WorkerResult<T>> = {
      status,
      turns: this.turns,
      toolCalls: this.toolCalls,
      usage: { inputTokens: this.inputTokens, outputTokens: this.outputTokens, llmCalls: this.llmCalls },
      transcript: this.transcript.slice(),
      receivedAnyStreamChunk: this.receivedAnyStreamChunk,
    }
    if (status === 'submitted') {
      result.output = fields.output
      if (fields.terminalTool !== undefined) result.terminalTool = fields.terminalTool
    }
    if (fields.error) result.error = fields.error
    if (fields.stopReason !== undefined) result.stopReason = fields.stopReason
    return result
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** What {@link nextChunk} resolves with when no chunk came in time, or the request was aborted. */
const IDLE = Symbol('idle')
const ABORTED = Symbol('aborted')

/**
 * Drains one provider attempt. Never throws.
 *
 * The request gets its own signal, linked to `signal`. When the first chunk
 * takes longer than `firstChunkMs`, a later chunk longer than `idleMs`, or
 * `signal` aborts while the provider ignores it, the request is aborted and
 * the stream abandoned without waiting for it to settle. A reply that ends
 * with `max-tokens` keeps its text and reasoning but loses its tool calls
 * (their arguments may be cut off), and its replay state is pruned to match,
 * exactly as DSH's BlockAssembler does.
 */
async function consumeStream(
  llm: Pick<LlmPort, 'stream'>,
  options: LlmGenerateOptions,
  signal: AbortSignal,
  firstChunkMs: number,
  idleMs: number,
): Promise<AttemptOutcome> {
  // Same open-block tolerance as DSH BlockAssembler; first close wins.
  const blocks = new Map<number, LlmContentBlock>()
  const partials = new Map<number, { type: string; text: string; id: string; name: string; args: string }>()
  let receivedAnyStreamChunk = false
  let receivedChunk = false
  const partial = (index: number, type: string) => {
    let value = partials.get(index)
    if (!value) {
      value = { type, text: '', id: `call-${index}`, name: '', args: '' }
      partials.set(index, value)
    }
    return value
  }
  let usage: LlmTokenUsage | undefined
  let reason: LlmFinishReason | undefined
  let replayState: unknown
  const request = new AbortController()
  const forward = (): void => request.abort(signal.reason)
  if (signal.aborted) forward()
  else signal.addEventListener('abort', forward, { once: true })
  let iterator: AsyncIterator<LlmStreamChunk> | undefined
  let abandoned: typeof IDLE | typeof ABORTED | undefined
  try {
    iterator = llm.stream({ ...options, signal: request.signal })[Symbol.asyncIterator]()
    for (;;) {
      const next = await nextChunk(iterator, receivedChunk ? idleMs : firstChunkMs, request.signal)
      if (next === IDLE || next === ABORTED) {
        abandoned = next
        break
      }
      if (next.done) break
      receivedChunk = true
      const chunk = next.value
      // Error finish chunks are also emitted for immediate HTTP rejections.
      if (chunk.type !== 'finish') receivedAnyStreamChunk = true
      if (chunk.type === 'block-start') {
        partial(chunk.index, chunk.blockType)
      } else if (chunk.type === 'text-delta' || chunk.type === 'reasoning-delta') {
        if (!blocks.has(chunk.index))
          partial(chunk.index, chunk.type === 'text-delta' ? 'text' : 'reasoning').text += chunk.text
      } else if (chunk.type === 'tool-call-delta') {
        if (!blocks.has(chunk.index)) {
          const value = partial(chunk.index, 'tool-call')
          value.id = chunk.id
          if (chunk.name) value.name = chunk.name
          value.args += chunk.argumentsDelta
        }
      } else if (chunk.type === 'block-end') {
        partial(chunk.index, chunk.block.type)
        if (!blocks.has(chunk.index)) blocks.set(chunk.index, chunk.block)
      } else if (chunk.type === 'usage') {
        usage = chunk.usage
      } else if (chunk.type === 'finish') {
        reason = chunk.reason
        replayState = chunk.replayState
        // Like `break` in `for await`: let the provider clean up.
        abandon(iterator)
        break
      }
    }
  } catch (error) {
    // A throw after the terminal finish (e.g. from iterator cleanup) does not undo the response.
    if (!reason) {
      const providerError = error as { code?: unknown; status?: number }
      const code = signal.aborted
        ? 'ABORTED'
        : typeof providerError?.code === 'string'
          ? providerError.code
          : 'INTERNAL'
      return {
        ok: false,
        receivedAnyStreamChunk,
        usage,
        finish: 'error',
        failure: {
          code,
          message: errorText(error),
          ...(providerError?.status ? { status: providerError.status } : {}),
        },
      }
    }
  } finally {
    signal.removeEventListener('abort', forward)
    if (abandoned) {
      request.abort(abandoned === IDLE ? new Error('idle timeout') : signal.reason)
      abandon(iterator)
    }
  }
  if (abandoned === IDLE) {
    const seconds = Math.max(1, Math.round((receivedChunk ? idleMs : firstChunkMs) / 1000))
    return {
      ok: false,
      receivedAnyStreamChunk,
      usage,
      finish: 'error',
      failure: {
        code: 'TIMEOUT',
        message: receivedChunk
          ? `The model sent no data for ${seconds} s; the request was abandoned`
          : `The model did not start responding within ${seconds} s; the request was abandoned`,
      },
    }
  }
  if (abandoned === ABORTED) {
    return {
      ok: false,
      receivedAnyStreamChunk,
      usage,
      finish: 'aborted',
      failure: { code: 'ABORTED', message: 'The request was aborted' },
    }
  }
  for (const [index, value] of partials) {
    if (blocks.has(index)) continue
    if (value.type === 'text' || value.type === 'reasoning') blocks.set(index, { type: value.type, text: value.text })
    else if (value.type === 'tool-call')
      blocks.set(index, { type: 'tool-call', id: value.id, name: value.name, arguments: value.args })
  }
  // A clean EOF is stop only with an assembled block. Empty EOF remains retryable;
  // adapter-reported STREAM_CLOSED/errors above are never converted into success.
  if (!reason && blocks.size > 0) reason = { kind: 'stop' }
  if (!reason) {
    return {
      ok: false,
      receivedAnyStreamChunk,
      usage,
      finish: 'error',
      failure: { code: 'INTERNAL', message: 'The model stream ended without a finish chunk' },
    }
  }
  const failure = failureOf(reason)
  if (failure) return { ok: false, receivedAnyStreamChunk, usage, finish: reason.kind, failure }
  const all = [...blocks.entries()].sort((a, b) => a[0] - b[0]).map(([, block]) => block)
  if (reason.kind !== 'max-tokens') {
    return { ok: true, receivedAnyStreamChunk, blocks: all, usage, finish: reason.kind, replayState, droppedCalls: [] }
  }
  const kept = all.map(block => block.type !== 'tool-call')
  const droppedCalls = all.filter(block => block.type === 'tool-call').map(block => toolName(block))
  return {
    ok: true,
    receivedAnyStreamChunk,
    blocks: all.filter((_, position) => kept[position]),
    usage,
    finish: reason.kind,
    replayState: droppedCalls.length === 0 ? replayState : pruneReplay(replayState, kept),
    droppedCalls,
  }
}

/**
 * Replay state with per-block entries pruned in step with dropped blocks, as
 * DSH's BlockAssembler does: an envelope whose entries do not align with the
 * blocks is dropped; one without per-block entries is kept as it is.
 */
function pruneReplay(replayState: unknown, kept: readonly boolean[]): unknown {
  if (typeof replayState !== 'object' || replayState === null) return replayState
  const entries = (replayState as { blocks?: unknown }).blocks
  if (entries === undefined) return replayState
  if (!Array.isArray(entries) || entries.length !== kept.length) return undefined
  return { ...replayState, blocks: entries.filter((_, position) => kept[position]) }
}

function toolName(block: LlmContentBlock): string {
  const name = (block as { name?: unknown }).name
  return typeof name === 'string' && name !== '' ? clip(name, 60) : 'a tool call'
}

/** `read_file ×3, submit_findings` */
function summarizeNames(names: readonly string[]): string {
  const counts = new Map<string, number>()
  for (const name of names) counts.set(name, (counts.get(name) ?? 0) + 1)
  return [...counts.entries()].map(([name, n]) => (n > 1 ? `${name} ×${n}` : name)).join(', ')
}

/** The next chunk, or {@link IDLE} after `idleMs` without one, or {@link ABORTED} once `signal` aborts. */
function nextChunk(
  iterator: AsyncIterator<LlmStreamChunk>,
  idleMs: number,
  signal: AbortSignal,
): Promise<IteratorResult<LlmStreamChunk> | typeof IDLE | typeof ABORTED> {
  if (signal.aborted) return Promise.resolve(ABORTED)
  return new Promise((resolve, reject) => {
    const settle = (): void => {
      clearTimeout(timer)
      signal.removeEventListener('abort', onAbort)
    }
    const onAbort = (): void => {
      settle()
      resolve(ABORTED)
    }
    const timer = setTimeout(() => {
      settle()
      resolve(IDLE)
    }, idleMs)
    signal.addEventListener('abort', onAbort, { once: true })
    let pending: Promise<IteratorResult<LlmStreamChunk>>
    try {
      pending = iterator.next()
    } catch (error) {
      settle()
      reject(error)
      return
    }
    pending.then(
      value => {
        settle()
        resolve(value)
      },
      (error: unknown) => {
        settle()
        reject(error)
      },
    )
  })
}

/** Ask an abandoned stream to close without waiting: a stalled generator would never answer. */
function abandon(iterator: AsyncIterator<LlmStreamChunk> | undefined): void {
  try {
    const closing = iterator?.return?.()
    if (closing) Promise.resolve(closing).catch(() => {})
  } catch {
    // Nothing more to do for a stream that cannot close.
  }
}

/** Let timers, I/O callbacks and other workers run before continuing. */
function yieldToEventLoop(): Promise<void> {
  return new Promise(resolve => setImmediate(resolve))
}

function failureOf(reason: LlmFinishReason): LlmFailure | undefined {
  const failure = 'failure' in reason ? reason.failure : undefined
  if (reason.kind === 'aborted') {
    return { code: 'ABORTED', message: failure?.message ?? 'The request was aborted' }
  }
  if (failure) return failure
  if (reason.kind === 'error') return { code: 'INTERNAL', message: 'The model request failed without details' }
  return undefined
}

/** Abortable `setTimeout`; the timer is always cleared on abort. */
function abortableSleep(ms: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal.aborted) {
      reject(signal.reason)
      return
    }
    const onAbort = (): void => {
      clearTimeout(timer)
      reject(signal.reason)
    }
    const timer = setTimeout(() => {
      signal.removeEventListener('abort', onAbort)
      resolve()
    }, ms)
    signal.addEventListener('abort', onAbort, { once: true })
  })
}

/**
 * Settles with `promise`, or rejects as soon as `signal` aborts so a tool that
 * ignores its signal cannot hold the worker. The listener is always removed.
 */
function raceAbort<V>(promise: Promise<V>, signal: AbortSignal): Promise<V> {
  if (signal.aborted) {
    promise.catch(() => {})
    return Promise.reject(new Error('aborted'))
  }
  return new Promise<V>((resolve, reject) => {
    const onAbort = (): void => reject(new Error('aborted'))
    signal.addEventListener('abort', onAbort, { once: true })
    promise.then(
      value => {
        signal.removeEventListener('abort', onAbort)
        resolve(value)
      },
      (error: unknown) => {
        signal.removeEventListener('abort', onAbort)
        reject(error)
      },
    )
  })
}

function isToolCall(block: LlmContentBlock): block is LlmToolCallBlock {
  if (block.type !== 'tool-call') return false
  const candidate = block as Partial<LlmToolCallBlock>
  return typeof candidate.id === 'string' && typeof candidate.name === 'string'
}

function isToolResult(value: unknown): value is ToolResult {
  return typeof value === 'object' && value !== null && typeof (value as { text?: unknown }).text === 'string'
}

/** Decodes raw tool arguments; empty input means `{}` and double-encoded JSON is unwrapped. */
function decodeArguments(
  raw: unknown,
): { readonly ok: true; readonly value: unknown } | { readonly ok: false; readonly error: string } {
  if (raw === undefined || raw === null) return { ok: true, value: {} }
  if (typeof raw !== 'string') return { ok: true, value: raw }
  const text = raw.trim()
  if (text === '') return { ok: true, value: {} }
  try {
    let value: unknown = JSON.parse(text)
    if (typeof value === 'string' && /^\s*[{[]/.test(value)) {
      try {
        value = JSON.parse(value)
      } catch {
        // Keep the string; schema validation reports it.
      }
    }
    return { ok: true, value }
  } catch (error) {
    return { ok: false, error: clip(errorText(error), 200) }
  }
}

function formatIssues(
  toolName: string,
  issues: readonly { readonly path: PropertyKey[]; readonly message: string }[],
): string {
  const lines = issues.map(issue => `- ${formatPath(issue.path)}: ${issue.message}`)
  const text = `Invalid arguments for ${toolName}:\n${lines.join('\n')}\nFix the arguments and call the tool again.`
  return clip(text, MAX_ISSUE_TEXT)
}

function formatPath(path: readonly PropertyKey[]): string {
  if (path.length === 0) return '(root)'
  let out = ''
  for (const key of path) {
    if (typeof key === 'number') out += `[${key}]`
    else out += out === '' ? String(key) : `.${String(key)}`
  }
  return out
}

function toolResultMessage(callId: string, text: string, isError: boolean): LlmToolResultMessage {
  return {
    id: randomUUID(),
    role: 'tool',
    source: { kind: 'tool', callId },
    toolCallId: callId,
    content: [{ type: 'text', text }],
    isError,
  }
}

function errorResult(text: string): ToolResult {
  return { text, isError: true }
}

/** Replacement text for an elided tool result, naming the call it answered. */
function elisionMarker(call: LlmToolCallBlock | undefined, chars: number): string {
  const what = call
    ? `output of ${clip(call.name, 60)} ${clip(singleLine(String(call.arguments ?? '')), 160)}`
    : 'earlier tool output'
  return `[${what} elided to fit the context window (${chars} chars); call the tool again if you still need it]`
}

function singleLine(text: string): string {
  return text.replace(/\s+/g, ' ').trim()
}

function budgetName(reason: Exclude<BudgetRefusal, 'cancelled'>): string {
  return reason === 'calls' ? 'model-request' : reason === 'tokens' ? 'token' : 'time'
}

/** Truncates to `max` characters (never splitting a surrogate pair) and appends a marker. */
export function truncateText(text: string, max: number): string {
  if (text.length <= max) return text
  let cut = max
  const code = text.charCodeAt(cut - 1)
  if (code >= 0xd800 && code <= 0xdbff) cut--
  return `${text.slice(0, cut)}\n[truncated: ${text.length - cut} more chars]`
}

function clip(text: string, max: number): string {
  return text.length <= max ? text : `${text.slice(0, max - 1)}…`
}

/** Characters a message's content contributes to a request: text, reasoning, and tool-call arguments. */
function contentChars(content: readonly LlmContentBlock[]): number {
  let total = 0
  for (const block of content) {
    const { text, arguments: args } = block as { text?: unknown; arguments?: unknown }
    if (typeof text === 'string') total += text.length
    if (typeof args === 'string') total += args.length
  }
  return total
}

function errorText(error: unknown): string {
  const message = error instanceof Error ? error.message : String(error)
  return clip(message.split('\n')[0] ?? '', MAX_ERROR_MESSAGE)
}

function count(value: number | undefined): number {
  return typeof value === 'number' && Number.isFinite(value) && value > 0 ? value : 0
}

function elapsed(started: number): number {
  return Math.max(0, Math.round(performance.now() - started))
}

function now(): string {
  return new Date().toISOString()
}
