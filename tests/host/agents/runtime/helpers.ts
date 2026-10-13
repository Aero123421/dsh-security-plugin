import { z } from 'zod'
import type {
  LlmFailure,
  LlmGenerateOptions,
  LlmPort,
  LlmStreamChunk,
  LlmTokenUsage,
} from '../../../../src/host/dsh/ports.ts'
import { type BudgetGate, unlimitedBudget } from '../../../../src/host/agents/runtime/budget.ts'
import { defineTool, type WorkerTool } from '../../../../src/host/agents/runtime/tool.ts'
import type { WorkerEvent, WorkerSpec } from '../../../../src/host/agents/runtime/worker.ts'

/** One scripted provider attempt: chunks to yield, or a function producing them. */
export type Script =
  | readonly LlmStreamChunk[]
  | ((options: LlmGenerateOptions) => readonly LlmStreamChunk[] | AsyncIterable<LlmStreamChunk>)

/** A fake `ctx.llm` that plays one script per `stream()` call and records every request. */
export class FakeLlm implements Pick<LlmPort, 'stream'> {
  readonly calls: LlmGenerateOptions[] = []

  constructor(private readonly scripts: readonly Script[]) {}

  stream(options: LlmGenerateOptions): AsyncIterable<LlmStreamChunk> {
    this.calls.push(options)
    const script = this.scripts[this.calls.length - 1]
    if (!script) return iterate(errorFinish('TEST_UNEXPECTED_CALL', `unexpected call #${this.calls.length}`))
    const produced = typeof script === 'function' ? script(options) : script
    return Symbol.asyncIterator in produced ? (produced as AsyncIterable<LlmStreamChunk>) : iterate(produced)
  }

  /** Messages sent with call `n` (0-based). */
  messages(n: number): LlmGenerateOptions['messages'] {
    const call = this.calls[n]
    if (!call) throw new Error(`no call #${n}`)
    return call.messages
  }
}

async function* iterate(chunks: readonly LlmStreamChunk[]): AsyncGenerator<LlmStreamChunk> {
  for (const chunk of chunks) yield chunk
}

export function textBlock(index: number, text: string): LlmStreamChunk[] {
  return [
    { type: 'block-start', index, blockType: 'text' },
    { type: 'text-delta', index, text },
    { type: 'block-end', index, block: { type: 'text', text } },
  ]
}

export function reasoningBlock(index: number, text: string): LlmStreamChunk[] {
  return [
    { type: 'block-start', index, blockType: 'reasoning' },
    { type: 'reasoning-delta', index, text },
    { type: 'block-end', index, block: { type: 'reasoning', text } },
  ]
}

/** A tool-call block; non-string args are JSON-encoded. */
export function callBlock(index: number, id: string, name: string, args: unknown): LlmStreamChunk[] {
  const raw = typeof args === 'string' ? args : JSON.stringify(args)
  return [
    { type: 'block-start', index, blockType: 'tool-call' },
    { type: 'tool-call-delta', index, id, name, argumentsDelta: raw },
    { type: 'block-end', index, block: { type: 'tool-call', id, name, arguments: raw } },
  ]
}

export const USAGE: LlmTokenUsage = { inputTokens: 100, outputTokens: 20 }

/** A successful response made of the given blocks. */
export function reply(
  blocks: readonly LlmStreamChunk[][],
  options: { finish?: 'stop' | 'tool-calls' | 'max-tokens'; usage?: LlmTokenUsage | null; replayState?: unknown } = {},
): LlmStreamChunk[] {
  const chunks: LlmStreamChunk[] = blocks.flat()
  if (options.usage !== null) chunks.push({ type: 'usage', usage: options.usage ?? USAGE })
  const hasCall = chunks.some(chunk => chunk.type === 'block-end' && chunk.block.type === 'tool-call')
  const finish: LlmStreamChunk = {
    type: 'finish',
    reason: { kind: options.finish ?? (hasCall ? 'tool-calls' : 'stop') },
  }
  if (options.replayState !== undefined) finish.replayState = options.replayState
  chunks.push(finish)
  return chunks
}

/** Shorthand: a response with one tool call. */
export function callReply(id: string, name: string, args: unknown): LlmStreamChunk[] {
  return reply([callBlock(0, id, name, args)])
}

export function errorFinish(
  code: string,
  message = `${code} failure`,
  extra: Partial<LlmFailure> = {},
): LlmStreamChunk[] {
  return [{ type: 'finish', reason: { kind: 'error', failure: { code, message, ...extra } } }]
}

export interface Report {
  readonly summary: string
  readonly findings: readonly string[]
}

export const readFile = defineTool({
  name: 'read_file',
  description: 'Read a file from the snapshot.',
  input: z.object({
    path: z.string().describe('Repository-relative path'),
    maxLines: z.number().int().min(1).optional(),
  }),
  execute: async ({ path }) => ({ text: `contents of ${path}` }),
})

export const submitReport = defineTool({
  name: 'submit_report',
  description: 'Submit the final report.',
  input: z.object({ summary: z.string().min(1), findings: z.array(z.string()) }),
  terminal: {
    toOutput: (args): Report => ({ summary: args.summary, findings: args.findings }),
  },
})

/** Records budget calls and refuses after `maxCalls` admissions. */
export function countingBudget(
  maxCalls = Number.POSITIVE_INFINITY,
  reason: 'calls' | 'tokens' | 'time' | 'cancelled' = 'calls',
): BudgetGate & { admitted: number; recorded: LlmTokenUsage[] } {
  const gate = {
    admitted: 0,
    recorded: [] as LlmTokenUsage[],
    admit: () => {
      if (gate.admitted >= maxCalls) return { ok: false as const, reason }
      gate.admitted++
      return { ok: true as const }
    },
    record: (usage: LlmTokenUsage) => {
      gate.recorded.push(usage)
    },
  }
  return gate
}

/** A spec with sensible defaults; `sleep` resolves immediately and records delays. */
export function makeSpec(
  llm: FakeLlm,
  overrides: Partial<WorkerSpec<Report>> = {},
): { spec: WorkerSpec<Report>; events: WorkerEvent[]; sleeps: number[] } {
  const events: WorkerEvent[] = []
  const sleeps: number[] = []
  const tools: WorkerTool<unknown, Report>[] = [readFile, submitReport]
  const spec: WorkerSpec<Report> = {
    id: 'w1',
    role: 'hunter',
    llm,
    route: { provider: 'deepseek', model: 'deepseek-reasoner' },
    system: 'You are a security reviewer.',
    task: 'Review src/app.ts',
    tools,
    maxTurns: 8,
    budget: unlimitedBudget(),
    signal: new AbortController().signal,
    onEvent: event => {
      events.push(event)
    },
    sleep: async ms => {
      sleeps.push(ms)
    },
    ...overrides,
  }
  return { spec, events, sleeps }
}

export const SUBMISSION = { summary: 'All good', findings: ['f1'] }
