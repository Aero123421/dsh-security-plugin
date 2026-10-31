import { Context } from '@deepseek-ai/cordis'
import LlmRuntime, { type GenerateOptions, LlmAdapter, type StreamChunk, ToolCallId } from '@deepseek-ai/dsh-llm'
import { describe, expect, it } from 'vitest'
import { unlimitedBudget } from '../../src/host/agents/runtime/budget.ts'
import { runWorker } from '../../src/host/agents/runtime/worker.ts'
import { asLlm } from '../../src/host/dsh/adapters.ts'
import type { LlmPort } from '../../src/host/dsh/ports.ts'
import { readFile, SUBMISSION, submitReport } from './agents/runtime/helpers.ts'

/** Exercise the installed DSH runtime; only the provider's response is scripted. */
class ScriptedAdapter extends LlmAdapter {
  readonly calls: GenerateOptions[] = []

  async *stream(options: GenerateOptions): AsyncIterable<StreamChunk> {
    this.calls.push(options)
    const first = this.calls.length === 1
    yield {
      type: 'block-end',
      index: 0,
      block: {
        type: 'tool-call',
        id: ToolCallId(`call_${this.calls.length}`),
        name: first ? 'read_file' : 'submit_report',
        arguments: JSON.stringify(first ? { path: 'src/app.ts' } : SUBMISSION),
      },
    }
    yield { type: 'usage', usage: { inputTokens: 10, outputTokens: 5 } }
    yield { type: 'finish', reason: { kind: 'tool-calls' } }
  }
}

function review(llm: LlmPort, signal = new AbortController().signal) {
  return runWorker({
    id: 'sdk-conformance',
    role: 'hunter',
    llm,
    route: { provider: 'scripted', model: 'fixture' },
    system: 'Review the fixture.',
    task: 'Read src/app.ts, then submit the report.',
    tools: [readFile, submitReport],
    maxTurns: 4,
    budget: unlimitedBudget(),
    signal,
  })
}

describe('installed DSH LlmRuntime integration (no network)', () => {
  it('dispatches worker tools, carries tool results, and releases the adapter with its Cordis owner', async () => {
    const ctx = new Context()
    const runtime = await ctx.plugin(LlmRuntime)
    const adapter = new ScriptedAdapter()
    const owner = await ctx.plugin({
      inject: ['llm'],
      apply(scoped: Context) {
        scoped.effect(() => scoped.llm.registerAdapter(['scripted'], adapter))
      },
    })
    try {
      const llm = asLlm(ctx.get('llm'))
      expect(llm).toBeDefined()
      if (!llm) throw new Error('DSH LlmRuntime did not satisfy the plugin port')
      const result = await review(llm)
      expect(result.status).toBe('submitted')
      expect(result.output).toEqual(SUBMISSION)
      expect(result.toolCalls).toBe(2)
      expect(adapter.calls[0]?.tools?.map(tool => tool.name)).toEqual(['read_file', 'submit_report'])
      expect(adapter.calls[1]?.messages).toContainEqual(
        expect.objectContaining({
          role: 'tool',
          toolCallId: 'call_1',
          source: { kind: 'tool', callId: 'call_1' },
          content: [{ type: 'text', text: 'contents of src/app.ts' }],
        }),
      )
      expect(adapter.calls[1]?.sessionId).toBe(adapter.calls[0]?.sessionId)
      await owner.dispose()
      expect(llm.listProviders()).toEqual([])
      await runtime.dispose()
      expect(ctx.get('llm')).toBeUndefined()
    } finally {
      await owner.dispose()
      await runtime.dispose()
    }
  })

  it('forwards worker cancellation through the runtime to the provider', async () => {
    const ctx = new Context()
    const runtime = await ctx.plugin(LlmRuntime)
    const cancel = new AbortController()
    let observed: AbortSignal | undefined
    let started!: () => void
    const ready = new Promise<void>(resolve => {
      started = resolve
    })
    class HeldAdapter extends LlmAdapter {
      async *stream(options: GenerateOptions): AsyncIterable<StreamChunk> {
        observed = options.signal
        started()
        await new Promise<void>(resolve => {
          if (options.signal?.aborted) resolve()
          else options.signal?.addEventListener('abort', () => resolve(), { once: true })
        })
        yield { type: 'finish', reason: { kind: 'stop' } }
      }
    }
    const unregister = ctx.llm.registerAdapter(['scripted'], new HeldAdapter())
    try {
      const llm = asLlm(ctx.get('llm'))
      if (!llm) throw new Error('DSH LlmRuntime did not satisfy the plugin port')
      const pending = review(llm, cancel.signal)
      await ready
      cancel.abort(new Error('Fixture cancellation'))
      expect((await pending).status).toBe('cancelled')
      expect(observed?.aborted).toBe(true)
    } finally {
      cancel.abort()
      unregister()
      await runtime.dispose()
    }
  })
})
