/**
 * The generic tool-calling loop for short-lived, read-only security workers.
 *
 * Workers run directly on DSH's provider-neutral LLM registry (`ctx.llm.stream`)
 * rather than as DSH chat sessions, so they never appear in or inherit from the
 * user's chats. One `stream()` call is one provider attempt; this loop owns
 * retries, context compaction, nudging, budgets, and cancellation, and always
 * terminates (at most `maxTurns × 4` model requests).
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
  LlmTokenUsage,
  LlmToolCallBlock,
  LlmToolResultMessage,
  LlmToolSchema,
  LlmUserInput,
} from '../../dsh/ports.ts'
import type { BudgetGate } from './budget.ts'
import { classifyFailure } from './failure.ts'
import { assertValidTool, type ToolResult, toolSchema, type WorkerTool } from './tool.ts'

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
  /** Sent only when set. */
  readonly temperature?: number
  /** Progress listener. Thrown errors (and rejected promises) are swallowed. */
  readonly onEvent?: (event: WorkerEvent) => void
  /** Abortable sleep used for retry backoff; injectable for tests. Defaults to a timer. */
  readonly sleep?: (ms: number, signal: AbortSignal) => Promise<void>
}

/** Progress notifications emitted while a worker runs. */
export type WorkerEvent =
  | { type: 'request'; turn: number; attempt: number }
  | { type: 'response'; turn: number; usage: LlmTokenUsage; finish: string }
  | { type: 'tool'; turn: number; name: string; ok: boolean; ms: number }
  | { type: 'retry'; turn: number; code: string; delayMs: number }
  | { type: 'nudge'; turn: number; reason: string }

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
  /** Model turns started (retries excluded). */
  readonly turns: number
  /** Tool calls handled: executed, rejected, or accepted as the submission. */
  readonly toolCalls: number
  /**
   * Summed usage over every request. `inputTokens` counts all prompt tokens,
   * i.e. reported `inputTokens + cacheReadTokens + cacheWriteTokens`.
   */
  readonly usage: { readonly inputTokens: number; readonly outputTokens: number; readonly llmCalls: number }
  readonly transcript: readonly TranscriptEntry[]
  /** The provider (or internal) failure behind `failed` / `blocked_by_provider`. */
  readonly error?: { readonly code: string; readonly message: string }
  /**
   * Why a non-submitted worker stopped: a budget reason (`calls`, `tokens`, `time`,
   * `cancelled`), `max-turns`, `nudges-exhausted`, `aborted`, `retries-exhausted`,
   * `context-overflow`, `blocked`, or `fatal`.
   */
  readonly stopReason?: string
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
/** Plain-text replies tolerated (each answered with a nudge) before `no_submission`. */
export const MAX_NUDGES = 2

const BACKOFF_BASE_MS = 1_000
const BACKOFF_MAX_MS = 30_000
const BACKOFF_JITTER = 0.2
const RETRY_AFTER_CAP_MS = 60_000
const MAX_ISSUE_TEXT = 2_048
const MAX_ERROR_MESSAGE = 500
const KEEP_RECENT_TOOL_RESULTS = 2

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
}

type AttemptOutcome =
  | {
      readonly ok: true
      readonly blocks: LlmContentBlock[]
      readonly usage: LlmTokenUsage | undefined
      readonly finish: string
      readonly replayState: unknown
    }
  | {
      readonly ok: false
      readonly usage: LlmTokenUsage | undefined
      readonly finish: string
      readonly failure: LlmFailure
    }

type Verdict<T> = { readonly ok: true; readonly output: T } | { readonly ok: false; readonly result: ToolResult }

class WorkerRun<T> {
  private readonly messages: LlmRequestMessage[] = []
  private readonly transcript: TranscriptEntry[] = []
  private readonly toolsByName = new Map<string, WorkerTool<unknown, T>>()
  private readonly allTools: readonly WorkerTool<unknown, T>[]
  private readonly terminalTools: readonly WorkerTool<unknown, T>[]
  private readonly maxChars: number
  private readonly elided = new WeakSet<LlmRequestMessage>()
  private turns = 0
  private toolCalls = 0
  private nudges = 0
  private inputTokens = 0
  private outputTokens = 0
  private llmCalls = 0

  constructor(private readonly spec: WorkerSpec<T>) {
    this.allTools = spec.tools
    this.terminalTools = spec.tools.filter(tool => tool.terminal)
    for (const tool of spec.tools) this.toolsByName.set(tool.name, tool)
    this.maxChars = spec.maxToolResultChars ?? DEFAULT_MAX_TOOL_RESULT_CHARS
  }

  async run(): Promise<WorkerResult<T>> {
    const { spec } = this
    this.transcript.push({ kind: 'system', text: spec.system })
    this.pushMessage({ role: 'user', content: [{ type: 'text', text: spec.task }] })

    for (let turn = 1; turn <= spec.maxTurns; turn++) {
      if (spec.signal.aborted) return this.stop('cancelled', { stopReason: 'aborted' })
      const final = turn === spec.maxTurns
      if (final) {
        this.addUserNote(
          `This is your final turn: submit now with ${this.terminalNames(' or ')} using what you have verified so far.`,
        )
      }
      const offered = final ? this.terminalTools : this.allTools
      const reply = await this.request(turn, offered.map(toolSchema))
      if (reply.kind === 'stop') return reply.result
      const ended = await this.handleReply(turn, reply, offered, final)
      if (ended) return ended
    }
    return this.stop('no_submission', { stopReason: 'max-turns' })
  }

  // -- Model requests ------------------------------------------------------

  /** Performs one turn's request, retrying and compacting as needed. */
  private async request(
    turn: number,
    tools: LlmToolSchema[],
  ): Promise<Reply | { readonly kind: 'stop'; readonly result: WorkerResult<T> }> {
    const { spec } = this
    let compacted = false
    for (let attempt = 1; attempt <= MAX_ATTEMPTS_PER_TURN; attempt++) {
      if (spec.signal.aborted) return { kind: 'stop', result: this.stop('cancelled', { stopReason: 'aborted' }) }
      const refused = this.admit()
      if (refused) return { kind: 'stop', result: refused }
      if (attempt === 1) this.turns = turn
      this.emit({ type: 'request', turn, attempt })
      this.llmCalls++

      const outcome = await consumeStream(spec.llm, this.options(tools), spec.signal)
      const usage: LlmTokenUsage = outcome.usage ? { ...outcome.usage } : { inputTokens: 0, outputTokens: 0 }
      this.recordUsage(usage)
      this.transcript.push({ kind: 'usage', at: now(), turn, usage, finish: outcome.finish })
      this.emit({ type: 'response', turn, usage, finish: outcome.finish })
      if (outcome.ok) {
        return { kind: 'reply', blocks: outcome.blocks, finish: outcome.finish, replayState: outcome.replayState }
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
          if (compacted || attempt >= MAX_ATTEMPTS_PER_TURN || !this.compact()) {
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
          return { kind: 'stop', result: this.stop('failed', { error, stopReason: 'fatal' }) }
      }
    }
    // Unreachable: the last attempt always returns above.
    return { kind: 'stop', result: this.stop('failed', { stopReason: 'retries-exhausted' }) }
  }

  private options(tools: LlmToolSchema[]): LlmGenerateOptions {
    const { route, system, signal, temperature } = this.spec
    const options: LlmGenerateOptions = {
      provider: route.provider,
      model: route.model,
      messages: this.messages.slice(),
      system,
      tools,
      signal,
    }
    if (route.reasoningEffort !== undefined) options.reasoningEffort = route.reasoningEffort
    if (route.maxOutputTokens !== undefined) options.maxTokens = route.maxOutputTokens
    if (temperature !== undefined) options.temperature = temperature
    return options
  }

  /** Returns a stop result when the budget refuses the next request. */
  private admit(): WorkerResult<T> | undefined {
    let admission: ReturnType<BudgetGate['admit']>
    try {
      admission = this.spec.budget.admit()
    } catch (error) {
      return this.stop('failed', { error: { code: 'INTERNAL', message: errorText(error) }, stopReason: 'fatal' })
    }
    if (admission.ok) return undefined
    if (admission.reason === 'cancelled') return this.stop('cancelled', { stopReason: 'cancelled' })
    return this.stop('budget_exhausted', { stopReason: admission.reason })
  }

  private recordUsage(usage: LlmTokenUsage): void {
    this.inputTokens += count(usage.inputTokens) + count(usage.cacheReadTokens) + count(usage.cacheWriteTokens)
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

  /**
   * Elides every tool result except the latest two. Returns false when nothing
   * changed, i.e. retrying could not help.
   */
  private compact(): boolean {
    const toolIndexes: number[] = []
    this.messages.forEach((message, index) => {
      if (message.role === 'tool') toolIndexes.push(index)
    })
    let changed = false
    for (const index of toolIndexes.slice(0, Math.max(0, toolIndexes.length - KEEP_RECENT_TOOL_RESULTS))) {
      const message = this.messages[index]
      if (message?.role !== 'tool' || this.elided.has(message)) continue
      const chars = textLength(message.content)
      const replacement: LlmToolResultMessage = {
        ...message,
        content: [{ type: 'text', text: `[earlier tool output elided to fit the context window: ${chars} chars]` }],
      }
      this.elided.add(replacement)
      this.messages[index] = replacement
      changed = true
    }
    return changed
  }

  // -- Replies and tools ---------------------------------------------------

  /** Handles a completed reply. Returns a result when the worker ends. */
  private async handleReply(
    turn: number,
    reply: Reply,
    offered: readonly WorkerTool<unknown, T>[],
    final: boolean,
  ): Promise<WorkerResult<T> | undefined> {
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

    const truncated = reply.finish === 'max-tokens'
    const calls = reply.blocks.filter(isToolCall)
    if (calls.length === 0) {
      if (final) return this.stop('no_submission', { stopReason: 'max-turns' })
      if (this.nudges >= MAX_NUDGES) return this.stop('no_submission', { stopReason: 'nudges-exhausted' })
      this.nudges++
      this.emit({ type: 'nudge', turn, reason: truncated ? 'max-tokens' : 'no-tool-call' })
      const nudge = `You must finish by calling one of: ${this.terminalNames(', ')}. Do not reply with plain text.`
      this.addUserNote(truncated ? `${nudge} Your previous reply hit the output token limit; keep it short.` : nudge)
      return undefined
    }

    const available = new Map(offered.map(tool => [tool.name, tool]))
    // Terminal calls first: the first valid one ends the worker and the rest are ignored.
    const rejected = new Map<number, ToolResult>()
    for (const [index, call] of calls.entries()) {
      const tool = available.get(call.name)
      if (!tool?.terminal) continue
      const started = performance.now()
      const verdict = await this.evaluateTerminal(tool, call, truncated)
      this.emit({ type: 'tool', turn, name: call.name, ok: verdict.ok, ms: elapsed(started) })
      if (verdict.ok) {
        this.toolCalls++
        return this.stop('submitted', { output: verdict.output, terminalTool: tool.name })
      }
      rejected.set(index, verdict.result)
    }

    for (const [index, call] of calls.entries()) {
      if (spec.signal.aborted) return this.stop('cancelled', { stopReason: 'aborted' })
      const result = rejected.get(index) ?? (await this.execute(turn, call, available, truncated))
      this.toolCalls++
      this.pushMessage(toolResultMessage(call.id, truncateText(result.text, this.maxChars), result.isError === true))
    }
    if (spec.signal.aborted) return this.stop('cancelled', { stopReason: 'aborted' })
    return final ? this.stop('no_submission', { stopReason: 'max-turns' }) : undefined
  }

  private async evaluateTerminal(
    tool: WorkerTool<unknown, T>,
    call: LlmToolCallBlock,
    truncated: boolean,
  ): Promise<Verdict<T>> {
    const args = await this.parseArgs(tool, call, truncated)
    if (!args.ok) return { ok: false, result: args.result }
    const terminal = tool.terminal
    if (!terminal) return { ok: false, result: errorResult(`Tool ${tool.name} cannot submit.`) }
    try {
      const message = terminal.validate?.(args.value)
      if (typeof message === 'string' && message !== '') return { ok: false, result: errorResult(message) }
      return { ok: true, output: terminal.toOutput(args.value) }
    } catch (error) {
      return { ok: false, result: errorResult(`Tool failed: ${errorText(error)}`) }
    }
  }

  private async execute(
    turn: number,
    call: LlmToolCallBlock,
    available: ReadonlyMap<string, WorkerTool<unknown, T>>,
    truncated: boolean,
  ): Promise<ToolResult> {
    const started = performance.now()
    const result = await this.executeUntimed(turn, call, available, truncated)
    this.emit({ type: 'tool', turn, name: call.name, ok: result.isError !== true, ms: elapsed(started) })
    return result
  }

  private async executeUntimed(
    turn: number,
    call: LlmToolCallBlock,
    available: ReadonlyMap<string, WorkerTool<unknown, T>>,
    truncated: boolean,
  ): Promise<ToolResult> {
    const tool = available.get(call.name)
    if (!tool) {
      const names = [...available.keys()].join(', ')
      return errorResult(`Unknown tool ${JSON.stringify(clip(String(call.name), 80))}. Available tools: ${names}.`)
    }
    const args = await this.parseArgs(tool, call, truncated)
    if (!args.ok) return args.result
    if (!tool.execute) return errorResult(`Tool failed: ${tool.name} is not executable`)
    try {
      const { signal, id } = this.spec
      const result: unknown = await raceAbort(tool.execute(args.value, { signal, workerId: id, turn }), signal)
      if (!isToolResult(result)) return errorResult(`Tool failed: ${tool.name} returned an invalid result`)
      return { text: result.text, isError: result.isError === true }
    } catch (error) {
      return errorResult(`Tool failed: ${errorText(error)}`)
    }
  }

  /** JSON-decodes and schema-validates a call's arguments. */
  private async parseArgs(
    tool: WorkerTool<unknown, T>,
    call: LlmToolCallBlock,
    truncated: boolean,
  ): Promise<{ readonly ok: true; readonly value: unknown } | { readonly ok: false; readonly result: ToolResult }> {
    const decoded = decodeArguments(call.arguments)
    if (!decoded.ok) {
      if (truncated) {
        return {
          ok: false,
          result: errorResult(
            `Your reply hit the output token limit, so the arguments of ${tool.name} were cut off (${decoded.error}). ` +
              'Call it again with a shorter submission: fewer items and more concise text.',
          ),
        }
      }
      return {
        ok: false,
        result: errorResult(
          `Invalid JSON arguments for ${tool.name}: ${decoded.error}. Send one JSON object matching the tool's schema.`,
        ),
      }
    }
    try {
      const parsed = await tool.input.safeParseAsync(decoded.value)
      if (parsed.success) return { ok: true, value: parsed.data }
      const issues = formatIssues(tool.name, parsed.error.issues)
      const hint = truncated ? 'Your reply hit the output token limit; send a shorter submission.\n' : ''
      return { ok: false, result: errorResult(clip(hint + issues, MAX_ISSUE_TEXT)) }
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

/** Drains one provider attempt. Never throws. */
async function consumeStream(
  llm: Pick<LlmPort, 'stream'>,
  options: LlmGenerateOptions,
  signal: AbortSignal,
): Promise<AttemptOutcome> {
  const blocks = new Map<number, LlmContentBlock>()
  let usage: LlmTokenUsage | undefined
  let reason: LlmFinishReason | undefined
  let replayState: unknown
  try {
    for await (const chunk of llm.stream(options)) {
      if (chunk.type === 'block-end') {
        blocks.set(chunk.index, chunk.block)
      } else if (chunk.type === 'usage') {
        usage = chunk.usage
      } else if (chunk.type === 'finish') {
        reason = chunk.reason
        replayState = chunk.replayState
        break
      }
    }
  } catch (error) {
    // A throw after the terminal finish (e.g. from iterator cleanup) does not undo the response.
    if (!reason) {
      const code = signal.aborted ? 'ABORTED' : 'INTERNAL'
      return { ok: false, usage, finish: 'error', failure: { code, message: errorText(error) } }
    }
  }
  if (!reason) {
    return {
      ok: false,
      usage,
      finish: 'error',
      failure: { code: 'INTERNAL', message: 'The model stream ended without a finish chunk' },
    }
  }
  const failure = failureOf(reason)
  if (failure) return { ok: false, usage, finish: reason.kind, failure }
  const ordered = [...blocks.entries()].sort((a, b) => a[0] - b[0]).map(([, block]) => block)
  return { ok: true, blocks: ordered, usage, finish: reason.kind, replayState }
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

function textLength(content: readonly LlmContentBlock[]): number {
  let total = 0
  for (const block of content) {
    const text = (block as { text?: unknown }).text
    if (block.type === 'text' && typeof text === 'string') total += text.length
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
