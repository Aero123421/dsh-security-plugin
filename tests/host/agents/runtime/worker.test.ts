import { afterEach, describe, expect, it, vi } from 'vitest'
import { z } from 'zod'
import type { LlmStreamChunk, LlmToolResultMessage } from '../../../../src/host/dsh/ports.ts'
import { defineTool, type TerminalContext, type WorkerTool } from '../../../../src/host/agents/runtime/tool.ts'
import {
  backoffDelayMs,
  DEFAULT_FIRST_CHUNK_TIMEOUT_MS,
  DEFAULT_IDLE_TIMEOUT_MS,
  MAX_TOOL_CALLS_PER_TURN,
  runWorker,
  truncateText,
} from '../../../../src/host/agents/runtime/worker.ts'
import {
  callBlock,
  callReply,
  countingBudget,
  errorFinish,
  FakeLlm,
  makeSpec,
  readFile,
  reasoningBlock,
  type Report,
  reply,
  SUBMISSION,
  submitReport,
  textBlock,
} from './helpers.ts'

function toolMessages(messages: readonly unknown[]): LlmToolResultMessage[] {
  return messages.filter((m): m is LlmToolResultMessage => (m as { role?: string }).role === 'tool')
}

function lastToolText(llm: FakeLlm, call: number): string {
  const tools = toolMessages(llm.messages(call))
  const last = tools.at(-1)
  const block = last?.content[0] as { text?: string } | undefined
  return block?.text ?? ''
}

/** Text of the last block of the last message sent with call `n` (a user note when the worker added one). */
function lastNote(llm: FakeLlm, call: number): string {
  const block = llm.messages(call).at(-1)?.content.at(-1) as { text?: string } | undefined
  return block?.text ?? ''
}

afterEach(() => {
  vi.useRealTimers()
})

describe('runWorker: happy path', () => {
  it('executes two tool calls then submits', async () => {
    const executed: string[] = []
    const reader = defineTool({
      name: 'read_file',
      description: 'Read a file.',
      input: z.object({ path: z.string() }),
      execute: async ({ path }, ctx) => {
        executed.push(`${path}@${ctx.turn}:${ctx.workerId}`)
        return { text: `contents of ${path}` }
      },
    })
    const llm = new FakeLlm([
      reply([textBlock(0, 'Let me look.'), callBlock(1, 'c1', 'read_file', { path: 'a.ts' })]),
      callReply('c2', 'read_file', { path: 'b.ts' }),
      callReply('c3', 'submit_report', SUBMISSION),
    ])
    const { spec, events } = makeSpec(llm, { tools: [reader, submitReport] })
    const result = await runWorker(spec)

    expect(result.status).toBe('submitted')
    expect(result.output).toEqual(SUBMISSION)
    expect(result.terminalTool).toBe('submit_report')
    expect(result.turns).toBe(3)
    expect(result.toolCalls).toBe(3)
    expect(result.usage).toEqual({ inputTokens: 300, outputTokens: 60, llmCalls: 3 })
    expect(result.error).toBeUndefined()
    expect(executed).toEqual(['a.ts@1:w1', 'b.ts@2:w1'])

    // First request: a single request-only user input; system prompt in options.
    const first = llm.calls[0]!
    expect(first.messages).toEqual([{ role: 'user', content: [{ type: 'text', text: 'Review src/app.ts' }] }])
    expect(first.system).toBe('You are a security reviewer.')
    expect(first.provider).toBe('deepseek')
    expect(first.model).toBe('deepseek-reasoner')
    // Each request gets its own signal (for the idle timeout), linked to the worker's.
    expect(first.signal).toBeInstanceOf(AbortSignal)
    expect(first.signal).not.toBe(spec.signal)
    expect(first.tools?.map(t => t.name)).toEqual(['read_file', 'submit_report'])
    expect(first.tools?.[0]?.parameters).toMatchObject({ type: 'object', required: ['path'] })
    expect(first.tools?.[0]?.parameters).not.toHaveProperty('$schema')
    expect('temperature' in first).toBe(false)
    expect('maxTokens' in first).toBe(false)
    expect('reasoningEffort' in first).toBe(false)

    // Third request carries the full well-formed history.
    const third = llm.messages(2)
    expect(third.map(m => m.role)).toEqual(['user', 'assistant', 'tool', 'assistant', 'tool'])
    const tool1 = third[2] as LlmToolResultMessage
    expect(tool1).toMatchObject({
      role: 'tool',
      toolCallId: 'c1',
      source: { kind: 'tool', callId: 'c1' },
      content: [{ type: 'text', text: 'contents of a.ts' }],
      isError: false,
    })
    expect(tool1.id).toMatch(/^[0-9a-f-]{36}$/)

    expect(events.filter(e => e.type === 'request')).toHaveLength(3)
    expect(events.filter(e => e.type === 'tool')).toEqual([
      expect.objectContaining({ name: 'read_file', ok: true, turn: 1 }),
      expect.objectContaining({ name: 'read_file', ok: true, turn: 2 }),
      expect.objectContaining({ name: 'submit_report', ok: true, turn: 3 }),
    ])
  })

  it('keeps one generated session identity across turns and retries, distinct from other workers', async () => {
    const llm = new FakeLlm([
      errorFinish('RATE_LIMIT'),
      callReply('c1', 'read_file', { path: 'a.ts' }),
      callReply('c2', 'submit_report', SUBMISSION),
      callReply('c3', 'read_file', { path: 'b.ts' }),
      callReply('c4', 'submit_report', SUBMISSION),
    ])
    expect((await runWorker(makeSpec(llm).spec)).status).toBe('submitted')
    expect((await runWorker(makeSpec(llm).spec)).status).toBe('submitted')
    const first = llm.calls[0]?.sessionId
    const second = llm.calls[3]?.sessionId
    expect(first).toMatch(/^[0-9a-f-]{36}$/)
    expect(second).toMatch(/^[0-9a-f-]{36}$/)
    expect(second).not.toBe(first)
    expect(llm.calls.map(call => call.sessionId)).toEqual([first, first, first, second, second])
  })

  it('preserves an explicitly supplied session identity', async () => {
    const llm = new FakeLlm([
      callReply('c1', 'read_file', { path: 'a.ts' }),
      callReply('c2', 'submit_report', SUBMISSION),
    ])
    await runWorker(makeSpec(llm, { sessionId: 'stable-task-id' }).spec)
    expect(llm.calls.map(call => call.sessionId)).toEqual(['stable-task-id', 'stable-task-id'])
  })

  it('passes route options through and sends temperature only when set', async () => {
    const llm = new FakeLlm([callReply('c1', 'submit_report', SUBMISSION)])
    const { spec } = makeSpec(llm, {
      route: { provider: 'p', model: 'm', reasoningEffort: 'high', maxOutputTokens: 4096 },
      temperature: 0.2,
    })
    await runWorker(spec)
    expect(llm.calls[0]).toMatchObject({
      provider: 'p',
      model: 'm',
      reasoningEffort: 'high',
      maxTokens: 4096,
      temperature: 0.2,
    })
  })

  it('preserves reasoning blocks, block order, and replayState in the next request', async () => {
    const replay = { response: { id: 'resp-1' }, blocks: [{ sig: 'r' }, null, null] }
    const llm = new FakeLlm([
      reply(
        [
          // Emitted out of order: assembled by index.
          callBlock(2, 'c1', 'read_file', { path: 'a.ts' }),
          reasoningBlock(0, 'thinking about a.ts'),
          textBlock(1, 'Reading.'),
        ],
        { replayState: replay },
      ),
      callReply('c2', 'submit_report', SUBMISSION),
    ])
    const { spec } = makeSpec(llm, { route: { provider: 'deepseek', model: 'deepseek-v4' } })
    const result = await runWorker(spec)
    expect(result.status).toBe('submitted')

    const assistant = llm.messages(1)[1]
    expect(assistant).toMatchObject({
      role: 'assistant',
      source: { kind: 'model', provider: 'deepseek', model: 'deepseek-v4', replayState: replay },
      content: [
        { type: 'reasoning', text: 'thinking about a.ts' },
        { type: 'text', text: 'Reading.' },
        { type: 'tool-call', id: 'c1', name: 'read_file', arguments: '{"path":"a.ts"}' },
      ],
    })
    expect((assistant as { id: string }).id).toMatch(/^[0-9a-f-]{36}$/)
  })

  it('omits replayState from the source when the finish carries none', async () => {
    const llm = new FakeLlm([callReply('c1', 'read_file', { path: 'a' }), callReply('c2', 'submit_report', SUBMISSION)])
    await runWorker(makeSpec(llm).spec)
    const assistant = llm.messages(1)[1] as { source: Record<string, unknown> }
    expect('replayState' in assistant.source).toBe(false)
  })
})

describe('runWorker: argument errors', () => {
  it('recovers from invalid JSON arguments', async () => {
    const llm = new FakeLlm([
      callReply('c1', 'read_file', '{"path": "a.ts"'),
      callReply('c2', 'read_file', { path: 'a.ts' }),
      callReply('c3', 'submit_report', SUBMISSION),
    ])
    const result = await runWorker(makeSpec(llm).spec)
    expect(result.status).toBe('submitted')
    const [error] = toolMessages(llm.messages(1))
    expect(error).toMatchObject({ toolCallId: 'c1', isError: true })
    expect(lastToolText(llm, 1)).toMatch(/^Invalid JSON arguments for read_file: .+/)
  })

  it('treats empty arguments as an empty object', async () => {
    const ping = defineTool({
      name: 'ping',
      description: 'Ping.',
      input: z.object({}),
      execute: async () => ({ text: 'pong' }),
    })
    const llm = new FakeLlm([callReply('c1', 'ping', ''), callReply('c2', 'submit_report', SUBMISSION)])
    await runWorker(makeSpec(llm, { tools: [ping, submitReport] }).spec)
    expect(lastToolText(llm, 1)).toBe('pong')
  })

  it('reports zod issues with paths and lets the model correct itself', async () => {
    const llm = new FakeLlm([
      callReply('c1', 'submit_report', { summary: '', findings: ['ok', 3] }),
      callReply('c2', 'submit_report', SUBMISSION),
    ])
    const { spec, events } = makeSpec(llm)
    const result = await runWorker(spec)
    expect(result.status).toBe('submitted')
    expect(result.turns).toBe(2)
    expect(result.toolCalls).toBe(2)
    const text = lastToolText(llm, 1)
    expect(text).toContain('Invalid arguments for submit_report:')
    expect(text).toContain('- summary:')
    expect(text).toContain('- findings[1]:')
    expect(toolMessages(llm.messages(1))[0]?.isError).toBe(true)
    expect(events.filter(e => e.type === 'tool').map(e => (e as { ok: boolean }).ok)).toEqual([false, true])
  })

  it('caps the issue list at 2 KB', async () => {
    const wide = defineTool({
      name: 'wide',
      description: 'Many fields.',
      input: z.object(Object.fromEntries(Array.from({ length: 200 }, (_, i) => [`field_number_${i}`, z.string()]))),
      execute: async () => ({ text: 'ok' }),
    })
    const llm = new FakeLlm([callReply('c1', 'wide', {}), callReply('c2', 'submit_report', SUBMISSION)])
    await runWorker(makeSpec(llm, { tools: [wide, submitReport] }).spec)
    expect(lastToolText(llm, 1).length).toBeLessThanOrEqual(2048)
  })

  it('answers an unknown tool with the available tool names', async () => {
    const llm = new FakeLlm([callReply('c1', 'rm_rf', { path: '/' }), callReply('c2', 'submit_report', SUBMISSION)])
    const result = await runWorker(makeSpec(llm).spec)
    expect(result.status).toBe('submitted')
    const text = lastToolText(llm, 1)
    expect(text).toContain('Unknown tool "rm_rf"')
    expect(text).toContain('read_file, submit_report')
    expect(toolMessages(llm.messages(1))[0]).toMatchObject({ toolCallId: 'c1', isError: true })
  })

  it('turns a throwing tool into an error result without a stack', async () => {
    const boom = defineTool({
      name: 'boom',
      description: 'Always fails.',
      input: z.object({}),
      execute: async () => {
        throw new Error('disk on fire\n    at secret (/home/user/x.ts:1:1)')
      },
    })
    const llm = new FakeLlm([callReply('c1', 'boom', {}), callReply('c2', 'submit_report', SUBMISSION)])
    const { spec, events } = makeSpec(llm, { tools: [boom, submitReport] })
    const result = await runWorker(spec)
    expect(result.status).toBe('submitted')
    expect(lastToolText(llm, 1)).toBe('Tool failed: disk on fire')
    expect(toolMessages(llm.messages(1))[0]?.isError).toBe(true)
    expect(events).toContainEqual(expect.objectContaining({ type: 'tool', name: 'boom', ok: false }))
  })

  it('forwards isError from a tool result', async () => {
    const soft = defineTool({
      name: 'soft',
      description: 'Soft failure.',
      input: z.object({}),
      execute: async () => ({ text: 'not found', isError: true }),
    })
    const llm = new FakeLlm([callReply('c1', 'soft', {}), callReply('c2', 'submit_report', SUBMISSION)])
    await runWorker(makeSpec(llm, { tools: [soft, submitReport] }).spec)
    expect(toolMessages(llm.messages(1))[0]).toMatchObject({ isError: true, content: [{ text: 'not found' }] })
  })
})

describe('runWorker: terminal tools', () => {
  const validated = defineTool({
    name: 'submit_report',
    description: 'Submit.',
    input: z.object({ summary: z.string(), findings: z.array(z.string()) }),
    terminal: {
      validate: args => (args.findings.length === 0 ? 'Include at least one finding or explain why none.' : undefined),
      toOutput: (args): Report => args,
    },
  })

  it('sends a validate rejection back and accepts the corrected submission', async () => {
    const llm = new FakeLlm([
      callReply('c1', 'submit_report', { summary: 's', findings: [] }),
      callReply('c2', 'submit_report', SUBMISSION),
    ])
    const result = await runWorker(makeSpec(llm, { tools: [readFile, validated] }).spec)
    expect(result.status).toBe('submitted')
    expect(result.output).toEqual(SUBMISSION)
    expect(result.turns).toBe(2)
    expect(lastToolText(llm, 1)).toBe('Include at least one finding or explain why none.')
    expect(toolMessages(llm.messages(1))[0]).toMatchObject({ toolCallId: 'c1', isError: true })
  })

  it('a validate rejection counts against maxTurns; a rejected final turn gets one grace request', async () => {
    const llm = new FakeLlm([
      callReply('c1', 'submit_report', { summary: 's', findings: [] }),
      callReply('c2', 'submit_report', { summary: 's', findings: [] }),
      callReply('c3', 'submit_report', { summary: 's', findings: [] }),
    ])
    const result = await runWorker(makeSpec(llm, { tools: [readFile, validated], maxTurns: 2 }).spec)
    expect(result.status).toBe('no_submission')
    expect(result.stopReason).toBe('max-turns')
    expect(result.turns).toBe(3)
    expect(llm.calls).toHaveLength(3)
    expect(lastNote(llm, 2)).toContain('Your final turn ended without an accepted submit_report call.')
  })

  it('submits on a valid terminal call and ignores sibling calls', async () => {
    const execute = vi.fn(async () => ({ text: 'x' }))
    const reader = defineTool({
      name: 'read_file',
      description: 'Read.',
      input: z.object({ path: z.string() }),
      execute,
    })
    const llm = new FakeLlm([
      reply([callBlock(0, 'c1', 'read_file', { path: 'a' }), callBlock(1, 'c2', 'submit_report', SUBMISSION)]),
    ])
    const result = await runWorker(makeSpec(llm, { tools: [reader, submitReport] }).spec)
    expect(result.status).toBe('submitted')
    expect(execute).not.toHaveBeenCalled()
    expect(llm.calls).toHaveLength(1)
  })

  it('uses the first valid of several terminal calls', async () => {
    const llm = new FakeLlm([
      reply([
        callBlock(0, 'c1', 'submit_report', { summary: '' }),
        callBlock(1, 'c2', 'submit_report', { summary: 'second', findings: [] }),
        callBlock(2, 'c3', 'submit_report', { summary: 'third', findings: [] }),
      ]),
    ])
    const result = await runWorker(makeSpec(llm).spec)
    expect(result.status).toBe('submitted')
    expect(result.output?.summary).toBe('second')
  })

  it('executes siblings and answers every call when all terminal calls are invalid', async () => {
    const llm = new FakeLlm([
      reply([callBlock(0, 'c1', 'read_file', { path: 'a' }), callBlock(1, 'c2', 'submit_report', { summary: '' })]),
      callReply('c3', 'submit_report', SUBMISSION),
    ])
    const result = await runWorker(makeSpec(llm).spec)
    expect(result.status).toBe('submitted')
    const tools = toolMessages(llm.messages(1))
    expect(tools.map(t => [t.toolCallId, t.isError])).toEqual([
      ['c1', false],
      ['c2', true],
    ])
  })

  it('treats a throwing toOutput as a rejected submission', async () => {
    let calls = 0
    const flaky = defineTool({
      name: 'submit_report',
      description: 'Submit.',
      input: z.object({ summary: z.string(), findings: z.array(z.string()) }),
      terminal: {
        toOutput: (args): Report => {
          if (calls++ === 0) throw new Error('bad mapping')
          return args
        },
      },
    })
    const llm = new FakeLlm([
      callReply('c1', 'submit_report', SUBMISSION),
      callReply('c2', 'submit_report', SUBMISSION),
    ])
    const result = await runWorker(makeSpec(llm, { tools: [flaky] }).spec)
    expect(result.status).toBe('submitted')
    expect(lastToolText(llm, 1)).toBe('Tool failed: bad mapping')
  })
})

describe('runWorker: nudges and the final turn', () => {
  it('nudges twice on plain text, then gives up with no_submission', async () => {
    const llm = new FakeLlm([
      reply([textBlock(0, 'I think it is fine.')]),
      reply([textBlock(0, 'Really fine.')]),
      reply([textBlock(0, 'Done.')]),
    ])
    const { spec, events } = makeSpec(llm)
    const result = await runWorker(spec)
    expect(result.status).toBe('no_submission')
    expect(result.stopReason).toBe('nudges-exhausted')
    expect(result.output).toBeUndefined()
    expect(llm.calls).toHaveLength(3)
    expect(events.filter(e => e.type === 'nudge')).toHaveLength(2)

    const second = llm.messages(1)
    expect(second.map(m => m.role)).toEqual(['user', 'assistant', 'user'])
    expect(second[2]).toEqual({
      role: 'user',
      content: [
        {
          type: 'text',
          text: 'Plain text is not read. Continue with a tool call, or call submit_report when you are done.',
        },
      ],
    })
  })

  it('recovers after a nudge', async () => {
    const llm = new FakeLlm([reply([textBlock(0, 'hmm')]), callReply('c1', 'submit_report', SUBMISSION)])
    const result = await runWorker(makeSpec(llm).spec)
    expect(result.status).toBe('submitted')
  })

  it('handles an empty response (no blocks) without adding an empty assistant message', async () => {
    const llm = new FakeLlm([reply([]), callReply('c1', 'submit_report', SUBMISSION)])
    const result = await runWorker(makeSpec(llm).spec)
    expect(result.status).toBe('submitted')
    expect(llm.messages(1).map(m => m.role)).toEqual(['user'])
    expect(llm.messages(1)[0]?.content).toHaveLength(2)
  })

  it('offers the same tools on every turn and asks for the submission on the final turn', async () => {
    const llm = new FakeLlm([
      callReply('c1', 'read_file', { path: 'a' }),
      callReply('c2', 'read_file', { path: 'b' }),
      callReply('c3', 'submit_report', SUBMISSION),
    ])
    const result = await runWorker(makeSpec(llm, { maxTurns: 3 }).spec)
    expect(result.status).toBe('submitted')
    // A constant tool list keeps the request prefix (and the provider's prompt cache) stable.
    for (const call of llm.calls) expect(call.tools?.map(t => t.name)).toEqual(['read_file', 'submit_report'])
    expect(llm.calls[2]?.tools).toBe(llm.calls[0]?.tools)
    const last = llm.messages(2).at(-1)
    expect(last).toEqual({
      role: 'user',
      content: [
        {
          type: 'text',
          text: 'This is your final turn: call submit_report now with what you have verified so far. Other tools will not run on this turn.',
        },
      ],
    })
  })

  it('rejects non-terminal calls on the final turn and its grace request, then ends with no_submission', async () => {
    const execute = vi.fn(async () => ({ text: 'x' }))
    const reader = defineTool({
      name: 'read_file',
      description: 'Read.',
      input: z.object({ path: z.string() }),
      execute,
    })
    const llm = new FakeLlm([callReply('c1', 'read_file', { path: 'a' }), callReply('c2', 'read_file', { path: 'b' })])
    const result = await runWorker(makeSpec(llm, { tools: [reader, submitReport], maxTurns: 1 }).spec)
    expect(result.status).toBe('no_submission')
    expect(result.stopReason).toBe('max-turns')
    expect(execute).not.toHaveBeenCalled()
    expect(result.turns).toBe(2)
    expect(lastToolText(llm, 1)).toBe(
      'Not run: this is your last request, so only submit_report is accepted. Call submit_report now with what you have verified so far.',
    )
  })

  it('accepts a submission on the grace request after a final turn spent on another tool', async () => {
    const llm = new FakeLlm([callReply('c1', 'read_file', { path: 'a' }), callReply('c2', 'submit_report', SUBMISSION)])
    const result = await runWorker(makeSpec(llm, { maxTurns: 1 }).spec)
    expect(result).toMatchObject({ status: 'submitted', output: SUBMISSION, turns: 2 })
  })

  it('merges the final-turn note into a pending nudge so user messages never repeat', async () => {
    const llm = new FakeLlm([reply([textBlock(0, 'hmm')]), callReply('c1', 'submit_report', SUBMISSION)])
    await runWorker(makeSpec(llm, { maxTurns: 2 }).spec)
    const second = llm.messages(1)
    expect(second.map(m => m.role)).toEqual(['user', 'assistant', 'user'])
    expect(second[2]?.content).toHaveLength(2)
  })

  it('drops a tool call cut off by max-tokens instead of replaying it, and asks for shorter arguments', async () => {
    const llm = new FakeLlm([
      reply([callBlock(0, 'c1', 'submit_report', '{"summary":"long long long')], { finish: 'max-tokens' }),
      callReply('c2', 'submit_report', SUBMISSION),
    ])
    const result = await runWorker(makeSpec(llm).spec)
    expect(result.status).toBe('submitted')
    expect(result.turns).toBe(2)
    // Like DSH's BlockAssembler: no partial JSON arguments and no tool result for the dropped call.
    const second = llm.messages(1)
    expect(second.map(m => m.role)).toEqual(['user'])
    expect(toolMessages(second)).toEqual([])
    const note = lastNote(llm, 1)
    expect(note).toContain('hit the output token limit, so its tool calls were cut off and not run: submit_report')
    expect(note).toContain('shorter arguments')
  })
})

describe('runWorker: retries', () => {
  it('honors providerRetryAfterMs then succeeds', async () => {
    const llm = new FakeLlm([
      errorFinish('RATE_LIMIT', 'slow down', { status: 429, providerRetryAfterMs: 7_000 }),
      errorFinish('RATE_LIMIT', 'slow down', { providerRetryAfterMs: 120_000 }),
      callReply('c1', 'submit_report', SUBMISSION),
    ])
    const budget = countingBudget()
    const { spec, events, sleeps } = makeSpec(llm, { budget })
    const result = await runWorker(spec)
    expect(result.status).toBe('submitted')
    expect(sleeps).toEqual([7_000, 60_000])
    expect(result.turns).toBe(1)
    expect(result.usage.llmCalls).toBe(3)
    expect(budget.admitted).toBe(3)
    expect(budget.recorded).toHaveLength(3)
    expect(budget.recorded[0]).toEqual({ inputTokens: 0, outputTokens: 0 })
    expect(events.filter(e => e.type === 'retry')).toEqual([
      { type: 'retry', turn: 1, code: 'RATE_LIMIT', delayMs: 7_000 },
      { type: 'retry', turn: 1, code: 'RATE_LIMIT', delayMs: 60_000 },
    ])
    expect(events.filter(e => e.type === 'request').map(e => (e as { attempt: number }).attempt)).toEqual([1, 2, 3])
    // Retries resend the identical history.
    expect(llm.messages(2)).toEqual(llm.messages(0))
  })

  it('uses exponential backoff with jitter by default', async () => {
    vi.useFakeTimers()
    const llm = new FakeLlm([
      errorFinish('SERVER'),
      errorFinish('TIMEOUT'),
      callReply('c1', 'submit_report', SUBMISSION),
    ])
    const { spec, events } = makeSpec(llm, { sleep: undefined })
    const pending = runWorker(spec)
    await vi.runAllTimersAsync()
    const result = await pending
    expect(result.status).toBe('submitted')
    const delays = events.filter(e => e.type === 'retry').map(e => (e as { delayMs: number }).delayMs)
    expect(delays[0]).toBeGreaterThanOrEqual(800)
    expect(delays[0]).toBeLessThanOrEqual(1_200)
    expect(delays[1]).toBeGreaterThanOrEqual(1_600)
    expect(delays[1]).toBeLessThanOrEqual(2_400)
    expect(vi.getTimerCount()).toBe(0)
  })

  it('fails after four attempts in one turn', async () => {
    const llm = new FakeLlm([
      errorFinish('SERVER', 'boom 1'),
      errorFinish('TRANSPORT', 'boom 2'),
      errorFinish('EMPTY_RESPONSE', 'boom 3'),
      errorFinish('SERVER', 'boom 4'),
    ])
    const { spec, sleeps } = makeSpec(llm)
    const result = await runWorker(spec)
    expect(result.status).toBe('failed')
    expect(result.stopReason).toBe('retries-exhausted')
    expect(result.error).toEqual({ code: 'SERVER', message: 'boom 4' })
    expect(llm.calls).toHaveLength(4)
    expect(sleeps).toHaveLength(3)
    expect(result.transcript.filter(e => e.kind === 'error')).toHaveLength(4)
  })

  it('retry attempts reset on the next turn', async () => {
    const llm = new FakeLlm([
      errorFinish('SERVER'),
      errorFinish('SERVER'),
      errorFinish('SERVER'),
      callReply('c1', 'read_file', { path: 'a' }),
      errorFinish('SERVER'),
      errorFinish('SERVER'),
      errorFinish('SERVER'),
      callReply('c2', 'submit_report', SUBMISSION),
    ])
    const result = await runWorker(makeSpec(llm).spec)
    expect(result.status).toBe('submitted')
    expect(result.turns).toBe(2)
    expect(result.usage.llmCalls).toBe(8)
  })

  it('records usage reported on a failed attempt', async () => {
    const failed: LlmStreamChunk[] = [
      { type: 'usage', usage: { inputTokens: 40, outputTokens: 0 } },
      ...errorFinish('SERVER'),
    ]
    const llm = new FakeLlm([failed, callReply('c1', 'submit_report', SUBMISSION)])
    const budget = countingBudget()
    const result = await runWorker(makeSpec(llm, { budget }).spec)
    expect(budget.recorded[0]).toEqual({ inputTokens: 40, outputTokens: 0 })
    expect(result.usage.inputTokens).toBe(140)
  })

  it.each([
    ['AUTH', 'bad key'],
    ['INVALID_CREDENTIAL', 'nope'],
    ['MISSING_CREDENTIAL', 'none'],
    ['NO_ADAPTER', 'no adapter'],
    ['QUOTA', 'out of quota'],
    ['ACCOUNT_QUOTA', 'account quota'],
    ['INVALID_REQUEST', 'bad field "foo"'],
    ['SOMETHING_NEW', 'unknown'],
  ])('fails fast on fatal %s without retrying', async (code, message) => {
    const llm = new FakeLlm([errorFinish(code, message)])
    const { spec, sleeps } = makeSpec(llm)
    const result = await runWorker(spec)
    expect(result.status).toBe('failed')
    expect(result.stopReason).toBe('fatal')
    expect(result.error).toEqual({ code, message })
    expect(llm.calls).toHaveLength(1)
    expect(sleeps).toEqual([])
  })

  it('classifies a throwing stream as INTERNAL', async () => {
    const llm = new FakeLlm([
      () =>
        (async function* () {
          yield* textBlock(0, 'partial')
          throw new Error('listener exploded')
        })(),
    ])
    const result = await runWorker(makeSpec(llm).spec)
    expect(result.status).toBe('failed')
    expect(result.error).toEqual({ code: 'INTERNAL', message: 'listener exploded' })
  })

  it('accepts a nonempty clean EOF as stop and nudges for submission', async () => {
    const llm = new FakeLlm([textBlock(0, 'no finish'), callReply('s', 'submit_report', SUBMISSION)])
    const result = await runWorker(makeSpec(llm).spec)
    expect(result.status).toBe('submitted')
    expect(llm.calls).toHaveLength(2)
  })
})

describe('runWorker: blocked by provider', () => {
  it.each([
    ['CONTENT_FILTER', 'blocked'],
    ['SAFETY', 'unsafe'],
    ['POLICY_VIOLATION', 'nope'],
    ['OUTPUT_FILTERED', 'filtered'],
    ['INVALID_REQUEST', 'Content Exists Risk'],
    ['INVALID_REQUEST', 'request rejected by moderation'],
    ['UNSUPPORTED_CONTENT', 'violates our usage policy'],
  ])('%s (%s) ends with blocked_by_provider and is never retried', async (code, message) => {
    const llm = new FakeLlm([errorFinish(code, message)])
    const { spec, sleeps } = makeSpec(llm)
    const result = await runWorker(spec)
    expect(result.status).toBe('blocked_by_provider')
    expect(result.stopReason).toBe('blocked')
    expect(result.error).toEqual({ code, message })
    expect(llm.calls).toHaveLength(1)
    expect(sleeps).toEqual([])
  })
})

describe('runWorker: context overflow', () => {
  it('elides older tool results once and retries the turn', async () => {
    const big = 'x'.repeat(500)
    const reader = defineTool({
      name: 'read_file',
      description: 'Read.',
      input: z.object({ path: z.string() }),
      execute: async ({ path }) => ({ text: `${path}:${big}` }),
    })
    const llm = new FakeLlm([
      callReply('c1', 'read_file', { path: 'a' }),
      callReply('c2', 'read_file', { path: 'b' }),
      callReply('c3', 'read_file', { path: 'c' }),
      errorFinish('CONTEXT_WINDOW_EXCEEDED', 'too long'),
      callReply('c4', 'submit_report', SUBMISSION),
    ])
    const { spec, sleeps } = makeSpec(llm, { tools: [reader, submitReport] })
    const result = await runWorker(spec)
    expect(result.status).toBe('submitted')
    expect(result.turns).toBe(4)
    expect(sleeps).toEqual([])
    expect(new Set(llm.calls.map(call => call.sessionId))).toEqual(new Set([llm.calls[0]?.sessionId]))
    expect(llm.calls[0]?.sessionId).toBeTruthy()

    const before = toolMessages(llm.messages(3))
    const after = toolMessages(llm.messages(4))
    expect(after.map(m => m.toolCallId)).toEqual(['c1', 'c2', 'c3'])
    expect(after[0]?.content).toEqual([
      {
        type: 'text',
        text: '[output of read_file {"path":"a"} elided to fit the context window (502 chars); call the tool again if you still need it]',
      },
    ])
    expect(after[0]?.id).toBe(before[0]?.id)
    expect(after[1]).toEqual(before[1])
    expect(after[2]).toEqual(before[2])
    // The transcript keeps the original output.
    const logged = result.transcript.filter(e => e.kind === 'message' && e.message.role === 'tool')
    expect(JSON.stringify(logged)).toContain(`a:${big}`)
  })

  it('fails when the context still overflows after compaction', async () => {
    const llm = new FakeLlm([
      callReply('c1', 'read_file', { path: 'a' }),
      callReply('c2', 'read_file', { path: 'b' }),
      callReply('c3', 'read_file', { path: 'c' }),
      errorFinish('CONTEXT_WINDOW_EXCEEDED', 'too long'),
      errorFinish('CONTEXT_WINDOW_EXCEEDED', 'still too long'),
    ])
    const result = await runWorker(makeSpec(llm).spec)
    expect(result.status).toBe('failed')
    expect(result.stopReason).toBe('context-overflow')
    expect(result.error).toEqual({ code: 'CONTEXT_WINDOW_EXCEEDED', message: 'still too long' })
    expect(llm.calls).toHaveLength(5)
  })

  it('fails immediately when there is nothing to elide', async () => {
    const llm = new FakeLlm([errorFinish('CONTEXT_WINDOW_EXCEEDED', 'too long')])
    const result = await runWorker(makeSpec(llm).spec)
    expect(result.status).toBe('failed')
    expect(llm.calls).toHaveLength(1)
  })
})

describe('runWorker: budget', () => {
  it('stops with budget_exhausted when the gate refuses mid-run', async () => {
    const llm = new FakeLlm([
      callReply('c1', 'read_file', { path: 'a' }),
      callReply('c2', 'read_file', { path: 'b' }),
      callReply('c3', 'submit_report', SUBMISSION),
    ])
    const budget = countingBudget(2, 'tokens')
    const result = await runWorker(makeSpec(llm, { budget }).spec)
    expect(result.status).toBe('budget_exhausted')
    expect(result.stopReason).toBe('tokens')
    expect(result.turns).toBe(2)
    expect(result.toolCalls).toBe(2)
    expect(llm.calls).toHaveLength(2)
    expect(budget.recorded).toEqual([
      { inputTokens: 100, outputTokens: 20 },
      { inputTokens: 100, outputTokens: 20 },
    ])
  })

  it('a retry also needs admission', async () => {
    const llm = new FakeLlm([errorFinish('SERVER'), callReply('c1', 'submit_report', SUBMISSION)])
    const result = await runWorker(makeSpec(llm, { budget: countingBudget(1, 'calls') }).spec)
    expect(result.status).toBe('budget_exhausted')
    expect(result.stopReason).toBe('calls')
    expect(llm.calls).toHaveLength(1)
  })

  it('maps a cancelled budget to cancelled', async () => {
    const llm = new FakeLlm([])
    const result = await runWorker(makeSpec(llm, { budget: countingBudget(0, 'cancelled') }).spec)
    expect(result.status).toBe('cancelled')
    expect(result.stopReason).toBe('cancelled')
    expect(result.turns).toBe(0)
    expect(llm.calls).toHaveLength(0)
  })

  it('records zero usage when the response reports none', async () => {
    const llm = new FakeLlm([reply([callBlock(0, 'c1', 'submit_report', SUBMISSION)], { usage: null })])
    const budget = countingBudget()
    const result = await runWorker(makeSpec(llm, { budget }).spec)
    expect(budget.recorded).toEqual([{ inputTokens: 0, outputTokens: 0 }])
    expect(result.usage).toEqual({ inputTokens: 0, outputTokens: 0, llmCalls: 1 })
  })

  it('charges cached prompt tokens at the cache-read rate', async () => {
    const usage = { inputTokens: 10, outputTokens: 5, cacheReadTokens: 90, cacheWriteTokens: 1 }
    const llm = new FakeLlm([reply([callBlock(0, 'c1', 'submit_report', SUBMISSION)], { usage })])
    const result = await runWorker(makeSpec(llm).spec)
    // 10 uncached + 90 cache reads charged as 9 + 1 cache write = 20.
    expect(result.usage).toEqual({ inputTokens: 20, outputTokens: 5, llmCalls: 1 })
  })
})

describe('runWorker: cancellation', () => {
  it('returns cancelled when aborted during a backoff sleep, leaving no timers', async () => {
    vi.useFakeTimers()
    const controller = new AbortController()
    const llm = new FakeLlm([errorFinish('RATE_LIMIT', 'later', { providerRetryAfterMs: 30_000 })])
    const { spec } = makeSpec(llm, { signal: controller.signal, sleep: undefined })
    const pending = runWorker(spec)
    await vi.advanceTimersByTimeAsync(1_000)
    expect(vi.getTimerCount()).toBe(1)
    controller.abort()
    const result = await pending
    expect(result.status).toBe('cancelled')
    expect(llm.calls).toHaveLength(1)
    expect(vi.getTimerCount()).toBe(0)
  })

  it('returns cancelled without a request when already aborted', async () => {
    const controller = new AbortController()
    controller.abort()
    const llm = new FakeLlm([])
    const result = await runWorker(makeSpec(llm, { signal: controller.signal }).spec)
    expect(result.status).toBe('cancelled')
    expect(llm.calls).toHaveLength(0)
  })

  it('maps an aborted finish to cancelled', async () => {
    const llm = new FakeLlm([
      [{ type: 'finish', reason: { kind: 'aborted', failure: { code: 'ABORTED', message: 'aborted' } } }],
    ])
    const result = await runWorker(makeSpec(llm).spec)
    expect(result.status).toBe('cancelled')
  })

  it('stops between tool executions after an abort', async () => {
    const controller = new AbortController()
    const second = vi.fn(async () => ({ text: 'b' }))
    const first = defineTool({
      name: 'first',
      description: 'Aborts the run.',
      input: z.object({}),
      execute: async () => {
        controller.abort()
        return { text: 'a' }
      },
    })
    const next = defineTool({ name: 'second', description: 'Second.', input: z.object({}), execute: second })
    const llm = new FakeLlm([reply([callBlock(0, 'c1', 'first', {}), callBlock(1, 'c2', 'second', {})])])
    const result = await runWorker(
      makeSpec(llm, { tools: [first, next, submitReport], signal: controller.signal }).spec,
    )
    expect(result.status).toBe('cancelled')
    expect(second).not.toHaveBeenCalled()
    expect(llm.calls).toHaveLength(1)
  })

  it('does not wait for a tool that ignores the signal', async () => {
    const controller = new AbortController()
    const stuck = defineTool({
      name: 'stuck',
      description: 'Never settles.',
      input: z.object({}),
      execute: () => {
        setTimeout(() => controller.abort(), 5)
        return new Promise(() => {})
      },
    })
    const llm = new FakeLlm([callReply('c1', 'stuck', {})])
    const result = await runWorker(makeSpec(llm, { tools: [stuck, submitReport], signal: controller.signal }).spec)
    expect(result.status).toBe('cancelled')
  })

  it('classifies a stream that throws because of an abort as cancelled', async () => {
    const controller = new AbortController()
    const llm = new FakeLlm([
      () =>
        (async function* (): AsyncGenerator<LlmStreamChunk> {
          yield* textBlock(0, 'partial')
          controller.abort()
          throw new Error('The operation was aborted')
        })(),
    ])
    const result = await runWorker(makeSpec(llm, { signal: controller.signal }).spec)
    expect(result.status).toBe('cancelled')
  })
})

describe('runWorker: output and transcript', () => {
  it('truncates long tool results with a marker', async () => {
    const big = defineTool({
      name: 'big',
      description: 'Big output.',
      input: z.object({}),
      execute: async () => ({ text: 'a'.repeat(150) }),
    })
    const llm = new FakeLlm([callReply('c1', 'big', {}), callReply('c2', 'submit_report', SUBMISSION)])
    await runWorker(makeSpec(llm, { tools: [big, submitReport], maxToolResultChars: 100 }).spec)
    expect(lastToolText(llm, 1)).toBe(`${'a'.repeat(100)}\n[truncated: 50 more chars]`)
  })

  it('defaults to a 24 000 character cap', async () => {
    const big = defineTool({
      name: 'big',
      description: 'Big output.',
      input: z.object({}),
      execute: async () => ({ text: 'a'.repeat(30_000) }),
    })
    const llm = new FakeLlm([callReply('c1', 'big', {}), callReply('c2', 'submit_report', SUBMISSION)])
    await runWorker(makeSpec(llm, { tools: [big, submitReport] }).spec)
    expect(lastToolText(llm, 1)).toBe(`${'a'.repeat(24_000)}\n[truncated: 6000 more chars]`)
  })

  it('produces a JSON-serializable transcript of everything sent and received', async () => {
    const llm = new FakeLlm([
      errorFinish('SERVER', 'hiccup'),
      reply([reasoningBlock(0, 'think'), callBlock(1, 'c1', 'read_file', { path: 'a' })], {
        replayState: { response: { id: 'r1' } },
      }),
      reply([textBlock(0, 'plain')]),
      callReply('c2', 'submit_report', SUBMISSION),
    ])
    const result = await runWorker(makeSpec(llm).spec)
    expect(result.status).toBe('submitted')
    const roundTrip = JSON.parse(JSON.stringify(result.transcript)) as unknown
    expect(roundTrip).toEqual(result.transcript)
    expect(JSON.parse(JSON.stringify(result))).toEqual(result)

    const kinds = result.transcript.map(e => (e.kind === 'message' ? `message:${e.message.role}` : e.kind))
    expect(kinds).toEqual([
      'system',
      'message:user',
      'usage',
      'error',
      'usage',
      'message:assistant',
      'message:tool',
      'usage',
      'message:assistant',
      'message:user',
      'usage',
      'message:assistant',
    ])
    expect(result.transcript[0]).toEqual({ kind: 'system', text: 'You are a security reviewer.' })
    const error = result.transcript.find(e => e.kind === 'error')
    expect(error).toMatchObject({ turn: 1, code: 'SERVER', message: 'hiccup' })
    for (const entry of result.transcript) {
      if (entry.kind !== 'system') expect(Number.isNaN(Date.parse(entry.at))).toBe(false)
    }
  })

  it('never lets a throwing event listener break the worker', async () => {
    const llm = new FakeLlm([
      errorFinish('SERVER'),
      callReply('c1', 'read_file', { path: 'a' }),
      reply([textBlock(0, 'x')]),
      callReply('c2', 'submit_report', SUBMISSION),
    ])
    const { spec } = makeSpec(llm, {
      onEvent: () => {
        throw new Error('listener bug')
      },
    })
    const result = await runWorker(spec)
    expect(result.status).toBe('submitted')
  })

  it('ends the worker even if the model keeps calling tools forever', async () => {
    const llm = new FakeLlm(Array.from({ length: 10 }, (_, i) => callReply(`c${i}`, 'read_file', { path: 'a' })))
    const result = await runWorker(makeSpec(llm, { maxTurns: 5 }).spec)
    expect(result.status).toBe('no_submission')
    expect(result.stopReason).toBe('max-turns')
    // maxTurns plus the single grace request.
    expect(llm.calls).toHaveLength(6)
  })
})

describe('runWorker: spec validation', () => {
  it('requires a terminal tool', async () => {
    const llm = new FakeLlm([])
    await expect(runWorker(makeSpec(llm, { tools: [readFile] }).spec)).rejects.toThrow(/terminal tool/)
  })

  it('rejects duplicate tool names and bad maxTurns', async () => {
    const llm = new FakeLlm([])
    await expect(runWorker(makeSpec(llm, { tools: [readFile, readFile, submitReport] }).spec)).rejects.toThrow(
      /duplicate/,
    )
    await expect(runWorker(makeSpec(llm, { maxTurns: 0 }).spec)).rejects.toThrow(/maxTurns/)
  })
})

describe('helpers', () => {
  it('backoffDelayMs grows exponentially, caps at 30 s, and jitters ±20%', () => {
    const mid = () => 0.5
    expect([1, 2, 3, 4, 5, 6, 7].map(a => backoffDelayMs(a, undefined, mid))).toEqual([
      1_000, 2_000, 4_000, 8_000, 16_000, 30_000, 30_000,
    ])
    expect(backoffDelayMs(1, undefined, () => 0)).toBe(800)
    expect(backoffDelayMs(1, undefined, () => 1)).toBe(1_200)
    expect(backoffDelayMs(1, 2_500)).toBe(2_500)
    expect(backoffDelayMs(1, 90_000)).toBe(60_000)
    expect(backoffDelayMs(1, 0)).toBe(0)
  })

  it('truncateText leaves short text alone and never splits a surrogate pair', () => {
    expect(truncateText('abc', 3)).toBe('abc')
    expect(truncateText('ab😀cd', 3)).toBe('ab\n[truncated: 4 more chars]')
  })

  it('defineTool validates names, executors, and schemas', () => {
    const input = z.object({})
    const bad = (tool: WorkerTool<object, unknown>) => () => defineTool(tool)
    expect(bad({ name: 'Bad-Name', description: 'd', input, execute: async () => ({ text: '' }) })).toThrow(/name/)
    expect(bad({ name: 'x', description: 'd', input, execute: async () => ({ text: '' }) })).toThrow(/name/)
    expect(bad({ name: 'no_exec', description: 'd', input })).toThrow(/execute/)
    expect(() =>
      defineTool({ name: 'not_object', description: 'd', input: z.string(), execute: async () => ({ text: '' }) }),
    ).toThrow(/object schema/)
  })
})

describe('runWorker: per-reply tool limits', () => {
  it(`runs at most ${MAX_TOOL_CALLS_PER_TURN} tool calls per reply and answers the rest with an error`, async () => {
    const executed: string[] = []
    const reader = defineTool({
      name: 'read_file',
      description: 'Read a file.',
      input: z.object({ path: z.string() }),
      execute: async ({ path }) => {
        executed.push(path)
        return { text: `contents of ${path}` }
      },
    })
    const many = Array.from({ length: MAX_TOOL_CALLS_PER_TURN + 4 }, (_, i) =>
      callBlock(i, `c${i}`, 'read_file', { path: `f${i}.ts` }),
    )
    const llm = new FakeLlm([reply(many), callReply('s', 'submit_report', SUBMISSION)])
    const result = await runWorker(makeSpec(llm, { tools: [reader, submitReport] }).spec)
    expect(result.status).toBe('submitted')
    expect(executed).toHaveLength(MAX_TOOL_CALLS_PER_TURN)
    expect(executed.at(-1)).toBe(`f${MAX_TOOL_CALLS_PER_TURN - 1}.ts`)
    const results = toolMessages(llm.messages(1))
    // Every call is answered, in order; the skipped ones say why.
    expect(results.map(m => m.toolCallId)).toEqual(many.map((_, i) => `c${i}`))
    const skipped = results.slice(MAX_TOOL_CALLS_PER_TURN)
    expect(skipped).toHaveLength(4)
    for (const message of skipped) {
      expect(message.isError).toBe(true)
      expect((message.content[0] as { text: string }).text).toContain(
        `only the first ${MAX_TOOL_CALLS_PER_TURN} are run per reply`,
      )
    }
    expect(result.toolCalls).toBe(many.length + 1)
  })

  it('still accepts a valid submission placed after too many other calls', async () => {
    const many = Array.from({ length: MAX_TOOL_CALLS_PER_TURN + 1 }, (_, i) =>
      callBlock(i, `c${i}`, 'read_file', { path: 'a.ts' }),
    )
    const llm = new FakeLlm([reply([...many, callBlock(many.length, 's', 'submit_report', SUBMISSION)])])
    const result = await runWorker(makeSpec(llm).spec)
    expect(result.status).toBe('submitted')
  })

  it('yields to the event loop between tool executions', async () => {
    const order: string[] = []
    const tool = (name: string, schedule: boolean) =>
      defineTool({
        name,
        description: name,
        input: z.object({}),
        // Synchronous work, like a regex search: nothing else could run until the worker yields.
        execute: async () => {
          order.push(name)
          if (schedule) setImmediate(() => order.push('event-loop'))
          return { text: name }
        },
      })
    const llm = new FakeLlm([
      reply([callBlock(0, 'c1', 'first', {}), callBlock(1, 'c2', 'second', {})]),
      callReply('s', 'submit_report', SUBMISSION),
    ])
    await runWorker(makeSpec(llm, { tools: [tool('first', true), tool('second', false), submitReport] }).spec)
    expect(order).toEqual(['first', 'event-loop', 'second'])
  })
})

describe('runWorker: stalled streams', () => {
  /** A stream that sends `chunks` and then never sends anything again, ignoring its signal. */
  function stalled(chunks: readonly LlmStreamChunk[] = []): () => AsyncIterable<LlmStreamChunk> {
    return () =>
      (async function* (): AsyncGenerator<LlmStreamChunk> {
        yield* chunks
        await new Promise(() => {})
      })()
  }

  it('abandons a request with no chunk for idleTimeoutMs and retries it as TIMEOUT', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] })
    const llm = new FakeLlm([
      stalled([{ type: 'block-start', index: 0, blockType: 'text' }]),
      callReply('c1', 'submit_report', SUBMISSION),
    ])
    const { spec, events } = makeSpec(llm)
    const pending = runWorker(spec)
    await vi.advanceTimersByTimeAsync(DEFAULT_IDLE_TIMEOUT_MS - 1)
    expect(llm.calls).toHaveLength(1)
    await vi.advanceTimersByTimeAsync(1)
    const result = await pending
    expect(result.status).toBe('submitted')
    expect(llm.calls).toHaveLength(2)
    expect(llm.calls[0]?.signal?.aborted).toBe(true)
    expect(events).toContainEqual(expect.objectContaining({ type: 'retry', code: 'TIMEOUT' }))
    expect(result.transcript).toContainEqual(expect.objectContaining({ kind: 'error', code: 'TIMEOUT' }))
    expect(vi.getTimerCount()).toBe(0)
  })

  it('resets the idle timer on every chunk and honours a custom timeout', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] })
    const slow = () =>
      (async function* (): AsyncGenerator<LlmStreamChunk> {
        for (const chunk of callReply('c1', 'submit_report', SUBMISSION)) {
          await new Promise(resolve => setTimeout(resolve, 4_000))
          yield chunk
        }
      })()
    const llm = new FakeLlm([slow, stalled(), stalled(), stalled(), stalled()])
    const pending = runWorker(makeSpec(llm, { idleTimeoutMs: 5_000 }).spec)
    await vi.advanceTimersByTimeAsync(60_000)
    const result = await pending
    expect(result.status).toBe('submitted')
    expect(llm.calls).toHaveLength(1)

    const stuck = new FakeLlm([stalled(), stalled(), stalled(), stalled()])
    const failing = runWorker(makeSpec(stuck, { idleTimeoutMs: 5_000, firstChunkTimeoutMs: 5_000 }).spec)
    await vi.advanceTimersByTimeAsync(20_000)
    const failed = await failing
    expect(failed).toMatchObject({ status: 'failed', stopReason: 'retries-exhausted', error: { code: 'TIMEOUT' } })
    expect(stuck.calls).toHaveLength(4)
  })

  it('stops waiting for a stream that ignores its signal once the worker is aborted', async () => {
    const controller = new AbortController()
    const llm = new FakeLlm([stalled()])
    const pending = runWorker(makeSpec(llm, { signal: controller.signal }).spec)
    await new Promise(resolve => setTimeout(resolve, 5))
    controller.abort()
    const result = await pending
    expect(result.status).toBe('cancelled')
    expect(llm.calls[0]?.signal?.aborted).toBe(true)
  })

  it('rejects a non-positive idle timeout', async () => {
    await expect(runWorker(makeSpec(new FakeLlm([]), { idleTimeoutMs: 0 }).spec)).rejects.toThrow(/idleTimeoutMs/)
    await expect(runWorker(makeSpec(new FakeLlm([]), { firstChunkTimeoutMs: -1 }).spec)).rejects.toThrow(
      /firstChunkTimeoutMs/,
    )
  })

  it('waits longer for the first chunk than between chunks', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] })
    const queued = () =>
      (async function* (): AsyncGenerator<LlmStreamChunk> {
        // A provider queue that holds the request (keep-alive comments are not surfaced as chunks).
        await new Promise(resolve => setTimeout(resolve, DEFAULT_IDLE_TIMEOUT_MS * 3))
        yield* callReply('c1', 'submit_report', SUBMISSION)
      })()
    const llm = new FakeLlm([queued])
    const pending = runWorker(makeSpec(llm).spec)
    await vi.advanceTimersByTimeAsync(DEFAULT_IDLE_TIMEOUT_MS * 3)
    expect((await pending).status).toBe('submitted')
    expect(llm.calls).toHaveLength(1)

    const never = new FakeLlm([stalled(), callReply('c2', 'submit_report', SUBMISSION)])
    const { spec, events } = makeSpec(never, { idleTimeoutMs: 10_000, firstChunkTimeoutMs: 30_000 })
    const retried = runWorker(spec)
    await vi.advanceTimersByTimeAsync(30_000)
    const result = await retried
    expect(result.status).toBe('submitted')
    expect(events).toContainEqual(expect.objectContaining({ type: 'retry', code: 'TIMEOUT' }))
    expect(result.transcript).toContainEqual(
      expect.objectContaining({
        kind: 'error',
        message: 'The model did not start responding within 30 s; the request was abandoned',
      }),
    )
    expect(DEFAULT_FIRST_CHUNK_TIMEOUT_MS).toBe(600_000)
  })
})

describe('runWorker: last-chance turns', () => {
  /** A terminal tool that records the context of every validation. */
  function recordingSubmit(reject: (args: Report) => string | undefined = () => undefined) {
    const contexts: TerminalContext[] = []
    const tool = defineTool({
      name: 'submit_report',
      description: 'Submit.',
      input: z.object({ summary: z.string().min(1), findings: z.array(z.string().min(1)).max(3) }),
      terminal: {
        validate: (args, context) => {
          contexts.push(context)
          return context.final ? undefined : reject(args)
        },
        toOutput: (args): Report => args,
      },
    })
    return { tool, contexts }
  }

  it('counts only consecutive plain-text replies toward the nudge limit', async () => {
    const llm = new FakeLlm([
      reply([textBlock(0, 'Reading the route first.')]),
      callReply('c1', 'read_file', { path: 'a' }),
      reply([textBlock(0, 'Now the middleware.')]),
      reply([textBlock(0, 'Still thinking.')]),
      callReply('c2', 'read_file', { path: 'b' }),
      reply([textBlock(0, 'Ready to report.')]),
      callReply('c3', 'submit_report', SUBMISSION),
    ])
    const { spec, events } = makeSpec(llm, { maxTurns: 12 })
    const result = await runWorker(spec)
    expect(result.status).toBe('submitted')
    expect(events.filter(e => e.type === 'nudge')).toHaveLength(4)
  })

  it('warns at three quarters of maxTurns how many turns are left', async () => {
    const llm = new FakeLlm([
      ...Array.from({ length: 6 }, (_, i) => callReply(`r${i}`, 'read_file', { path: `f${i}` })),
      callReply('s', 'submit_report', SUBMISSION),
    ])
    await runWorker(makeSpec(llm, { maxTurns: 8 }).spec)
    const warned = llm.calls.findIndex(call =>
      JSON.stringify(call.messages.at(-1)).includes('You have used 5 of 8 turns'),
    )
    expect(warned).toBe(5)
    expect(lastNote(llm, 5)).toBe(
      'You have used 5 of 8 turns. Finish the checks that matter most and call submit_report within the next 3 turns.',
    )
    // No warning for very short runs.
    const short = new FakeLlm([callReply('a', 'read_file', { path: 'a' }), callReply('b', 'submit_report', SUBMISSION)])
    await runWorker(makeSpec(short, { maxTurns: 3 }).spec)
    expect(JSON.stringify(short.calls.map(c => c.messages))).not.toContain('You have used')
  })

  it('validates with final: true on the last turn and passes the tool calls run so far', async () => {
    const { tool, contexts } = recordingSubmit(() => 'Not yet.')
    const llm = new FakeLlm([
      callReply('c1', 'read_file', { path: 'a' }),
      callReply('c2', 'submit_report', SUBMISSION),
      callReply('c3', 'submit_report', SUBMISSION),
    ])
    const result = await runWorker(makeSpec(llm, { tools: [readFile, tool], maxTurns: 3 }).spec)
    expect(result.status).toBe('submitted')
    expect(contexts).toEqual([
      { final: false, toolCalls: 1 },
      { final: true, toolCalls: 1 },
    ])
  })

  it('a plain-text final turn gets one grace request', async () => {
    const llm = new FakeLlm([
      callReply('c1', 'read_file', { path: 'a' }),
      reply([textBlock(0, 'I am done.')]),
      callReply('c2', 'submit_report', SUBMISSION),
    ])
    const result = await runWorker(makeSpec(llm, { maxTurns: 2 }).spec)
    expect(result).toMatchObject({ status: 'submitted', turns: 3 })
    expect(lastNote(llm, 2)).toContain('This is one extra request: call submit_report now')
  })

  it('drops the invalid list items of a final submission and keeps the rest', async () => {
    const { tool } = recordingSubmit()
    const args = { summary: 'Two real findings', findings: ['real one', '', 'real two', 'extra', 'more'] }
    const strict = new FakeLlm([callReply('c1', 'submit_report', args), callReply('c2', 'submit_report', SUBMISSION)])
    // Earlier turns still send the submission back so the model can fix it.
    expect((await runWorker(makeSpec(strict, { tools: [readFile, tool] }).spec)).output).toEqual(SUBMISSION)
    expect(lastToolText(strict, 1)).toContain('- findings: Too big')

    const last = new FakeLlm([callReply('c1', 'submit_report', args)])
    const result = await runWorker(makeSpec(last, { tools: [readFile, tool], maxTurns: 1 }).spec)
    expect(result.status).toBe('submitted')
    expect(result.output).toEqual({ summary: 'Two real findings', findings: ['real one', 'real two', 'extra'] })
    expect(result.droppedItems).toBe(2)
  })

  it('cannot salvage a final submission whose required top-level field is invalid', async () => {
    const llm = new FakeLlm([
      callReply('c1', 'submit_report', { summary: '', findings: ['x'] }),
      callReply('c2', 'submit_report', { findings: ['x'] }),
    ])
    const result = await runWorker(makeSpec(llm, { maxTurns: 1 }).spec)
    expect(result.status).toBe('no_submission')
    expect(result.turns).toBe(2)
  })
})

describe('runWorker: argument repair', () => {
  it('repairs ordinary slips before validation: null, numeric strings, camelCase keys, a lone object', async () => {
    const seen: unknown[] = []
    const reader = defineTool({
      name: 'read_file',
      description: 'Read.',
      input: z.object({
        path: z.string(),
        start_line: z.number().int().positive().optional(),
        end_line: z.number().int().positive().optional(),
      }),
      execute: async args => {
        seen.push(args)
        return { text: 'ok' }
      },
    })
    const submit = defineTool({
      name: 'submit_report',
      description: 'Submit.',
      input: z.object({ summary: z.string(), findings: z.array(z.object({ line: z.number().int() })) }),
      terminal: { toOutput: args => ({ summary: args.summary, findings: args.findings.map(f => String(f.line)) }) },
    })
    const llm = new FakeLlm([
      callReply('c1', 'read_file', { path: 'a.ts', startLine: '10', end_line: null }),
      callReply('c2', 'submit_report', { summary: 's', findings: { line: '26' } }),
    ])
    const result = await runWorker(makeSpec(llm, { tools: [reader, submit] }).spec)
    expect(seen).toEqual([{ path: 'a.ts', start_line: 10 }])
    expect(result.output).toEqual({ summary: 's', findings: ['26'] })
  })
})

describe('runWorker: budget wrap-up', () => {
  /** Refuses ordinary requests after `normal` admissions; wrap-up requests while `reserve` lasts. */
  function reservingBudget(normal: number, reserve: number, reason: 'calls' | 'tokens' | 'time' = 'calls') {
    const gate = {
      normal: 0,
      wrapUps: 0,
      admit: (request?: { wrapUp?: boolean }) => {
        if (request?.wrapUp) {
          if (gate.wrapUps >= reserve) return { ok: false as const, reason }
          gate.wrapUps++
          return { ok: true as const }
        }
        if (gate.normal >= normal) return { ok: false as const, reason }
        gate.normal++
        return { ok: true as const }
      },
      record: () => {},
    }
    return gate
  }

  it('asks a refused worker that already worked for one submit-only request and keeps its work', async () => {
    const llm = new FakeLlm([
      callReply('c1', 'read_file', { path: 'a' }),
      callReply('c2', 'read_file', { path: 'b' }),
      reply([callBlock(0, 'c3', 'read_file', { path: 'c' }), callBlock(1, 'c4', 'submit_report', SUBMISSION)]),
    ])
    const budget = reservingBudget(2, 1, 'tokens')
    const { spec, events } = makeSpec(llm, { budget })
    const result = await runWorker(spec)
    expect(result).toMatchObject({ status: 'submitted', output: SUBMISSION, turns: 3 })
    expect(budget.wrapUps).toBe(1)
    expect(events).toContainEqual({ type: 'wrap-up', turn: 3, reason: 'tokens' })
    expect(lastNote(llm, 2)).toBe(
      "The scan's token budget for this work is used up. Call submit_report now with what you have verified so far; other tools will not run, and this is your last request.",
    )
    expect(llm.calls[2]?.tools?.map(t => t.name)).toEqual(['read_file', 'submit_report'])
  })

  it('ends as budget_exhausted when the wrap-up request brings no submission or is refused too', async () => {
    const reads = new FakeLlm([
      callReply('c1', 'read_file', { path: 'a' }),
      callReply('c2', 'read_file', { path: 'b' }),
    ])
    const missed = await runWorker(makeSpec(reads, { budget: reservingBudget(1, 1) }).spec)
    expect(missed).toMatchObject({ status: 'budget_exhausted', stopReason: 'calls', turns: 2 })

    const none = new FakeLlm([callReply('c1', 'read_file', { path: 'a' })])
    const refused = await runWorker(makeSpec(none, { budget: reservingBudget(1, 0) }).spec)
    expect(refused).toMatchObject({ status: 'budget_exhausted', stopReason: 'calls', turns: 1 })
  })

  it('does not wrap up a worker refused before its first reply', async () => {
    const budget = reservingBudget(0, 1)
    const result = await runWorker(makeSpec(new FakeLlm([]), { budget }).spec)
    expect(result).toMatchObject({ status: 'budget_exhausted', stopReason: 'calls', turns: 0 })
    expect(budget.wrapUps).toBe(0)
  })
})

describe('runWorker: provider quirks', () => {
  it('drops a temperature the provider rejects and retries at once', async () => {
    const llm = new FakeLlm([
      errorFinish('INVALID_REQUEST', "400 Unsupported value: 'temperature' does not support 0.2 with this model."),
      callReply('c1', 'read_file', { path: 'a' }),
      callReply('c2', 'submit_report', SUBMISSION),
    ])
    const { spec, events, sleeps } = makeSpec(llm, { temperature: 0.2 })
    const result = await runWorker(spec)
    expect(result.status).toBe('submitted')
    expect(llm.calls.map(call => call.temperature)).toEqual([0.2, undefined, undefined])
    expect(events).toContainEqual({ type: 'option-dropped', turn: 1, option: 'temperature' })
    expect(sleeps).toEqual([])
    // Without a temperature the same failure is fatal as before.
    const plain = new FakeLlm([errorFinish('INVALID_REQUEST', 'temperature is not supported')])
    expect((await runWorker(makeSpec(plain).spec)).stopReason).toBe('fatal')
  })

  it('keeps text and reasoning of a max-tokens reply, drops its complete tool calls too, and prunes replay state', async () => {
    const execute = vi.fn(async () => ({ text: 'x' }))
    const reader = defineTool({
      name: 'read_file',
      description: 'Read.',
      input: z.object({ path: z.string() }),
      execute,
    })
    const replay = { response: { id: 'r1' }, blocks: [{ sig: 'thinking' }, { call: 1 }, { call: 2 }] }
    const llm = new FakeLlm([
      reply(
        [
          reasoningBlock(0, 'Two files to read.'),
          callBlock(1, 'c1', 'read_file', { path: 'a' }),
          callBlock(2, 'c2', 'read_file', '{"path":"b'),
        ],
        { finish: 'max-tokens', replayState: replay },
      ),
      callReply('c3', 'submit_report', SUBMISSION),
    ])
    const result = await runWorker(makeSpec(llm, { tools: [reader, submitReport] }).spec)
    expect(result.status).toBe('submitted')
    expect(execute).not.toHaveBeenCalled()
    const [, assistant, note] = llm.messages(1)
    expect(assistant).toMatchObject({
      role: 'assistant',
      content: [{ type: 'reasoning', text: 'Two files to read.' }],
      source: { replayState: { response: { id: 'r1' }, blocks: [{ sig: 'thinking' }] } },
    })
    expect(JSON.stringify(note)).toContain('cut off and not run: read_file ×2')

    // Replay entries that do not line up with the blocks are dropped rather than misapplied.
    const misaligned = new FakeLlm([
      reply([textBlock(0, 'x'), callBlock(1, 'c1', 'read_file', { path: 'a' })], {
        finish: 'max-tokens',
        replayState: { blocks: [{ only: 'one' }] },
      }),
      callReply('c2', 'submit_report', SUBMISSION),
    ])
    await runWorker(makeSpec(misaligned).spec)
    expect('replayState' in (misaligned.messages(1)[1] as { source: object }).source).toBe(false)
  })

  it('compacts the oldest tool results before a request that would come close to a known context window', async () => {
    const reader = defineTool({
      name: 'read_file',
      description: 'Read.',
      input: z.object({ path: z.string() }),
      execute: async ({ path }) => ({ text: `${path}:${'x'.repeat(3_000)}` }),
    })
    // No usage reported: the default estimate of 3 characters per token applies.
    const call = (id: string, path: string) => callBlock(0, id, 'read_file', { path })
    const llm = new FakeLlm([
      reply([call('c1', 'a')], { usage: null }),
      reply([call('c2', 'b')], { usage: null }),
      reply([call('c3', 'c'), callBlock(1, 'c4', 'read_file', { path: 'd' })], { usage: null }),
      reply([callBlock(0, 'c5', 'submit_report', SUBMISSION)], { usage: null }),
    ])
    const { spec, events } = makeSpec(llm, { tools: [reader, submitReport], contextWindow: 4_000 })
    const result = await runWorker(spec)
    expect(result.status).toBe('submitted')
    const last = toolMessages(llm.messages(3))
    expect(last.map(m => (m.content[0] as { text: string }).text.slice(0, 18))).toEqual([
      '[output of read_fi',
      '[output of read_fi',
      `c:${'x'.repeat(16)}`,
      `d:${'x'.repeat(16)}`,
    ])
    expect(events).toContainEqual(expect.objectContaining({ type: 'compact', proactive: true }))
  })
})
