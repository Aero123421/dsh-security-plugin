/**
 * Privacy settings that apply to scans already queued or running (consent to
 * send code, withheld files), and the scan-level time deadline.
 */

import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest'
import { Config } from '../../../src/host/config.ts'
import type { Harness } from './helpers.ts'
import {
  AI_SETTINGS,
  copyFixture,
  createHarness,
  gatedLlm,
  oracleLlm,
  type RecordingLlm,
  roleOf,
  type TempWorkspace,
} from './helpers.ts'

const WS_ID = 'ws-shop'
let shop: TempWorkspace

beforeAll(async () => {
  shop = await copyFixture('express-shop')
})

afterAll(async () => {
  await shop.cleanup()
})

afterEach(() => {
  vi.useRealTimers()
})

function workspace(id = WS_ID, root = shop.root) {
  return { id, path: root, title: id }
}

function turnOffConsent(h: Harness): void {
  h.settings.update({ privacy: { sendCodeToModel: false } }, h.settings.get().revision, true)
}

/** Everything a model was sent, as one string. */
function sentText(llm: RecordingLlm): string {
  return JSON.stringify(llm.calls.map(call => call.messages))
}

function expectAiStopped(h: Harness, id: string): void {
  const scan = h.store.getScan(id)
  expect(scan?.status).toBe('completed')
  expect(h.notices(id)).toContain('consent-revoked')
  const tasks = h.store.listTasks(id)
  expect(tasks.filter(t => t.status === 'pending' || t.status === 'running')).toEqual([])
  for (const phase of ['hunt', 'review', 'chain'] as const) {
    expect(scan?.phases.find(p => p.phase === phase)?.state).toBe('skipped')
  }
  expect(scan?.coverage?.gaps).toContain('AI review stopped early because sending code to models was turned off.')
  // Deterministic results are kept.
  expect(h.store.listFindings(id).some(f => f.source === 'sast')).toBe(true)
}

describe('withdrawing consent to send code', () => {
  it('stops a running scan promptly and skips a queued one', async () => {
    const other = await copyFixture('express-shop')
    try {
      const llm = gatedLlm(await oracleLlm(), options => roleOf(options) === 'hunter')
      const h = createHarness({
        llm,
        workspaces: [workspace(), workspace('ws-other', other.root)],
        settings: AI_SETTINGS,
      })
      const running = await h.controller.create({ workspaceId: WS_ID, mode: 'deep' })
      const queued = await h.controller.create({ workspaceId: 'ws-other', mode: 'deep' })
      await llm.waitForHeld(2)
      expect(h.store.getScan(queued.id)?.status).toBe('queued')
      const callsBefore = llm.calls.length

      turnOffConsent(h)
      expect(await h.settle(running.id)).toBe('completed')
      expect(await h.settle(queued.id)).toBe('completed')
      llm.open()

      // Only the two requests that were already held; nothing for the queued scan.
      expect(llm.calls).toHaveLength(callsBefore)
      expectAiStopped(h, running.id)
      expectAiStopped(h, queued.id)
      // The interrupted hunters were cancelled and their tasks skipped, not retried.
      const cancelled = h.store.listAgentRuns(running.id).filter(r => r.status === 'cancelled')
      expect(cancelled).toHaveLength(2)
      for (const run of cancelled) {
        expect(h.store.getTask(run.taskId)).toMatchObject({ status: 'skipped', error: { code: 'consent-revoked' } })
      }
      // The planner finished before consent was withdrawn: its threat model is kept.
      expect(h.store.getScan(running.id)?.threatModel).toBeDefined()
      expect(h.store.getScan(running.id)?.phases.find(p => p.phase === 'threat-model')?.state).toBe('done')
      expect(h.store.listTasks(queued.id).every(t => t.status === 'skipped')).toBe(true)
    } finally {
      await other.cleanup()
    }
  })

  it('is checked again when a paused scan resumes', async () => {
    const llm = await oracleLlm()
    const h = createHarness({ llm, workspaces: [workspace()], settings: AI_SETTINGS })
    const scan = await h.controller.create({ workspaceId: WS_ID, mode: 'deep' })
    h.controller.pause(scan.id)
    expect(await h.settle(scan.id)).toBe('paused')
    turnOffConsent(h)
    h.controller.resume(scan.id)
    expect(await h.settle(scan.id)).toBe('completed')
    expect(llm.calls).toHaveLength(0)
    expectAiStopped(h, scan.id)
    // A built-in-only scan is unaffected by the switch.
    const builtin = await h.controller.create({ workspaceId: WS_ID, mode: 'quick', aiReview: false })
    expect(await h.settle(builtin.id)).toBe('completed')
    expect(h.notices(builtin.id)).not.toContain('consent-revoked')
  })

  it('applies withheld patterns added after the scan was created when it resumes', async () => {
    const llm = await oracleLlm()
    const h = createHarness({ llm, workspaces: [workspace()], settings: AI_SETTINGS })
    const scan = await h.controller.create({ workspaceId: WS_ID, mode: 'deep' })
    h.controller.pause(scan.id)
    expect(await h.settle(scan.id)).toBe('paused')
    h.settings.update({ privacy: { withheldGlobs: ['src/routes/orders.ts'] } }, h.settings.get().revision, true)
    h.controller.resume(scan.id)
    expect(await h.settle(scan.id)).toBe('completed')
    expect(llm.calls.length).toBeGreaterThan(0)
    expect(sentText(llm)).not.toContain('SELECT * FROM orders WHERE id = ?')
    expect(h.store.listTasks(scan.id).some(t => t.input.targetPaths.includes('src/routes/orders.ts'))).toBe(false)
    // The scan record keeps the settings it was created with.
    expect(h.store.getScan(scan.id)?.settings.privacy.withheldGlobs).toEqual([])
  })
})

describe('scan deadline', () => {
  it('aborts in-flight model requests when the time budget runs out', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'Date'], shouldAdvanceTime: true })
    const llm = gatedLlm(await oracleLlm(), options => roleOf(options) === 'hunter')
    const h = createHarness({
      llm,
      workspaces: [workspace()],
      settings: { ...AI_SETTINGS, budgets: { deep: { maxMinutes: 1 } } },
    })
    const scan = await h.controller.create({ workspaceId: WS_ID, mode: 'deep' })
    await llm.waitForHeld(2)
    const callsBefore = llm.calls.length
    await vi.advanceTimersByTimeAsync(60_000)
    expect(await h.settle(scan.id)).toBe('completed')
    expect(llm.calls).toHaveLength(callsBefore)
    expect(h.notices(scan.id)).toContain('budget-time')
    expect(h.notices(scan.id)).not.toContain('consent-revoked')
    const tasks = h.store.listTasks(scan.id)
    expect(tasks.filter(t => t.status === 'pending' || t.status === 'running')).toEqual([])
    const cut = h.store.listAgentRuns(scan.id).filter(r => r.stopReason === 'time')
    expect(cut).toHaveLength(2)
    for (const run of cut) expect(h.store.getTask(run.taskId)?.status).toBe('skipped')
    expect(h.store.getScan(scan.id)?.usage.elapsedMs).toBeGreaterThanOrEqual(60_000)
    llm.open()
  })
})

describe('llmIdleTimeoutMs', () => {
  it('defaults to two minutes and accepts 1 s to 1 h', () => {
    expect(Config.parse({}).llmIdleTimeoutMs).toBe(120_000)
    expect(Config.parse({ llmIdleTimeoutMs: 30_000 }).llmIdleTimeoutMs).toBe(30_000)
    expect(Config.safeParse({ llmIdleTimeoutMs: 999 }).success).toBe(false)
    expect(Config.safeParse({ llmIdleTimeoutMs: 3_600_001 }).success).toBe(false)
  })
})
