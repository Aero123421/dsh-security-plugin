import { describe, expect, it } from 'vitest'
import { classifyFailure } from '../../../../src/host/agents/runtime/failure.ts'
import { runWorker } from '../../../../src/host/agents/runtime/worker.ts'
import type { LlmStreamChunk } from '../../../../src/host/dsh/ports.ts'
import { callBlock, callReply, errorFinish, FakeLlm, makeSpec, SUBMISSION } from './helpers.ts'

describe('bundled adapter failures', () => {
  it.each([
    ['STREAM_CLOSED', 'pi-ai event stream ended without done/error', 'retryable'],
    ['INTERNAL', 'The model stream ended without a finish chunk', 'retryable'],
    ['PI_AI_ERROR', 'The model refused to complete the request', 'blocked_by_provider'],
    ['PI_AI_ERROR', 'Provider finish_reason: content_filter', 'blocked_by_provider'],
    ['PI_AI_ERROR', 'Provider stopped with: SAFETY', 'blocked_by_provider'],
    ['PI_AI_ERROR', 'Provider stopped with: PROHIBITED_CONTENT', 'blocked_by_provider'],
    ['PI_AI_ERROR', 'Provider stopped with: MALFORMED_FUNCTION_CALL', 'fatal'],
    ['INVALID_REQUEST', '400: messages[0].content must be a string', 'fatal'],
    ['PI_AI_ERROR', 'Provider finish_reason: network_error', 'fatal'],
  ])('%s: %s', (code, message, expected) => expect(classifyFailure({ code, message })).toBe(expected))
})

describe('stream resilience', () => {
  it('retries STREAM_CLOSED then succeeds', async () => {
    const llm = new FakeLlm([errorFinish('STREAM_CLOSED'), callReply('s', 'submit_report', SUBMISSION)])
    expect((await runWorker(makeSpec(llm).spec)).status).toBe('submitted')
    expect(llm.calls).toHaveLength(2)
  })

  it('preserves a bundled adapter thrown STREAM_CLOSED code and retries without losing activity evidence', async () => {
    const llm = new FakeLlm([
      () =>
        (async function* () {
          yield { type: 'text-delta', index: 0, text: 'partial' } as const
          throw Object.assign(new Error('DeepSeek Messages stream ended before message_stop'), {
            code: 'STREAM_CLOSED',
          })
        })(),
      callReply('s', 'submit_report', SUBMISSION),
    ])
    const result = await runWorker(makeSpec(llm).spec)
    expect(result).toMatchObject({ status: 'submitted', receivedAnyStreamChunk: true })
    expect(llm.calls).toHaveLength(2)
  })

  it('retries empty clean EOF without confusing it with an accepted reply', async () => {
    const llm = new FakeLlm([[], [], [], []])
    expect(await runWorker(makeSpec(llm).spec)).toMatchObject({
      status: 'failed',
      stopReason: 'retries-exhausted',
      receivedAnyStreamChunk: false,
      error: { code: 'INTERNAL' },
    })
    expect(llm.calls).toHaveLength(4)
  })

  it.each([true, false])('assembles delta-only tool calls with finish=%s', async finish => {
    const chunks = callBlock(0, 's', 'submit_report', SUBMISSION).filter(c => c.type !== 'block-end')
    if (finish) chunks.push({ type: 'finish', reason: { kind: 'tool-calls' } })
    const result = await runWorker(makeSpec(new FakeLlm([chunks])).spec)
    expect(result.status).toBe('submitted')
    expect(result.output).toEqual(SUBMISSION)
  })

  it('assembles text and reasoning without block-start/end', async () => {
    const llm = new FakeLlm([
      [
        { type: 'text-delta', index: 0, text: 'hello' },
        { type: 'reasoning-delta', index: 1, text: 'think' },
        { type: 'finish', reason: { kind: 'stop' } },
      ],
      callReply('s', 'submit_report', SUBMISSION),
    ])
    expect((await runWorker(makeSpec(llm).spec)).status).toBe('submitted')
    expect(llm.messages(1).find(m => m.role === 'assistant')?.content).toEqual([
      { type: 'text', text: 'hello' },
      { type: 'reasoning', text: 'think' },
    ])
  })

  it('does not await a stuck iterator return after finish', async () => {
    const chunks = callReply('s', 'submit_report', SUBMISSION)
    const llm = new FakeLlm([
      () => ({
        [Symbol.asyncIterator]() {
          return {
            next: async () =>
              chunks.length ? { done: false, value: chunks.shift()! } : { done: true, value: undefined },
            return: () => new Promise<IteratorResult<LlmStreamChunk>>(() => {}),
          }
        },
      }),
    ])
    const outcome = await Promise.race([
      runWorker(makeSpec(llm).spec),
      new Promise<'hung'>(resolve => setTimeout(() => resolve('hung'), 200)),
    ])
    expect(outcome).not.toBe('hung')
  })
})
