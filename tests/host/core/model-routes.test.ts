import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { Config } from '../../../src/host/config.ts'
import type { LlmGenerateOptions, LlmStreamChunk } from '../../../src/host/dsh/ports.ts'
import type { SettingsPatch } from '../../../src/shared/settings.ts'
import { callReply, errorFinish, reply, textBlock } from '../agents/runtime/helpers.ts'
import {
  AI_SETTINGS,
  copyFixture,
  createHarness,
  oracleLlm,
  roleOf,
  scriptedLlm,
  type TempWorkspace,
} from './helpers.ts'

let shop: TempWorkspace
beforeAll(async () => {
  shop = await copyFixture('express-shop')
})
afterAll(async () => {
  await shop.cleanup()
})

const workspace = () => ({ id: 'ws-shop', path: shop.root, title: 'express-shop' })
const serial: SettingsPatch = { ...AI_SETTINGS, scan: { parallelWorkers: 1 } }

async function* chunks(list: readonly LlmStreamChunk[]): AsyncGenerator<LlmStreamChunk> {
  yield* list
}

describe('model routes', () => {
  it('waits up to ten minutes for a first chunk by default, separately from the idle timeout', () => {
    expect(Config.parse({})).toMatchObject({ llmFirstChunkTimeoutMs: 600_000, llmIdleTimeoutMs: 120_000 })
    expect(Config.safeParse({ llmFirstChunkTimeoutMs: 999 }).success).toBe(false)
  })

  it('sends a low temperature only to routes without reasoning controls, and drops it once rejected', async () => {
    const oracle = await oracleLlm()
    let rejected = 0
    const llm = scriptedLlm(
      options => {
        // The route rejects the parameter outright, as some providers' reasoning models do.
        if (options.model === 'picky' && options.temperature !== undefined) {
          rejected++
          return chunks(errorFinish('INVALID_REQUEST', "Unsupported parameter: 'temperature'"))
        }
        return oracle.stream(options)
      },
      {
        resolveModelInfo: async (provider, model) =>
          model === 'thinker'
            ? { provider, id: model, name: model, reasoning: { efforts: [{ id: 'high', name: 'High' }] } }
            : { provider, id: model, name: model, context: { contextWindow: 128_000 } },
      },
    )
    const settings: SettingsPatch = {
      ...serial,
      models: {
        default: { provider: 'scripted', model: 'oracle' },
        skeptic: { provider: 'scripted', model: 'thinker' },
        hunter: { provider: 'scripted', model: 'picky' },
      },
    }
    const h = createHarness({ llm, workspaces: [workspace()], settings })
    const scan = await h.controller.create({ workspaceId: 'ws-shop', mode: 'deep' })
    expect(await h.settle(scan.id)).toBe('completed')
    const byRole = (role: string) => llm.calls.filter(call => roleOf(call) === role)
    expect(byRole('planner').every(call => call.temperature === 0.2)).toBe(true)
    expect(byRole('skeptic').length).toBeGreaterThan(0)
    expect(byRole('skeptic').every(call => call.temperature === undefined)).toBe(true)
    // The first hunter request was rejected and retried without it; later hunters never send it.
    expect(rejected).toBe(1)
    expect(byRole('hunter').filter(call => call.temperature !== undefined)).toHaveLength(1)
    expect(
      h.store
        .listTasks(scan.id)
        .filter(t => t.role === 'hunter')
        .every(t => t.status === 'done'),
    ).toBe(true)
  })

  it('skips the rest of a route whose model answered two tasks in a row without calling a tool', async () => {
    const oracle = await oracleLlm()
    const llm = scriptedLlm((options: LlmGenerateOptions) =>
      roleOf(options) === 'hunter'
        ? chunks(reply([textBlock(0, 'Here is my analysis of the code, in prose.')]))
        : oracle.stream(options),
    )
    const h = createHarness({ llm, workspaces: [workspace()], settings: serial })
    const scan = await h.controller.create({ workspaceId: 'ws-shop', mode: 'quick' })
    expect(await h.settle(scan.id)).toBe('completed')
    const hunts = h.store.listTasks(scan.id).filter(t => t.role === 'hunter')
    expect(hunts.length).toBeGreaterThan(2)
    expect(hunts.filter(t => t.status === 'failed')).toHaveLength(2)
    const skipped = hunts.filter(t => t.status === 'skipped')
    expect(skipped.length).toBe(hunts.length - 2)
    expect(skipped.every(t => t.error?.code === 'provider-route-no-tools')).toBe(true)
    // Three plain-text replies per run, two runs: nothing more is spent on this route.
    expect(llm.calls.filter(call => roleOf(call) === 'hunter')).toHaveLength(6)
    expect(h.notices(scan.id)).toContain('model-no-tools')
    expect(h.store.getScan(scan.id)?.coverage?.gapDetails?.map(gap => gap.code)).toContain('no-tool-tasks')
  })

  it('does not trip the no-tool breaker for a model that calls tools in between', async () => {
    const oracle = await oracleLlm()
    let hunterRuns = 0
    const llm = scriptedLlm((options: LlmGenerateOptions) => {
      if (roleOf(options) !== 'hunter') return oracle.stream(options)
      const first = options.messages.length === 1
      if (first) hunterRuns++
      // Every other hunter run reads a file before giving up in prose.
      if (hunterRuns % 2 === 0 && first) return chunks(callReply('ls', 'list_files', {}))
      return chunks(reply([textBlock(0, 'Prose only.')]))
    })
    const h = createHarness({ llm, workspaces: [workspace()], settings: serial })
    const scan = await h.controller.create({ workspaceId: 'ws-shop', mode: 'quick' })
    expect(await h.settle(scan.id)).toBe('completed')
    expect(h.notices(scan.id)).not.toContain('model-no-tools')
  })
})
