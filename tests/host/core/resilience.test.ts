import { readFile, writeFile, rm } from 'node:fs/promises'
import { join } from 'node:path'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { callReply } from '../agents/runtime/helpers.ts'
import { fakeGitleaksToolkit } from './toolkit-helpers.ts'
import {
  AI_SETTINGS,
  copyFixture,
  createHarness,
  failingStream,
  gatedLlm,
  oracleLlm,
  roleOf,
  scriptedLlm,
} from './helpers.ts'

const cleanups: (() => Promise<void>)[] = []
afterEach(async () => {
  vi.useRealTimers()
  await Promise.all(cleanups.splice(0).map(fn => fn()))
})
async function setup() {
  const ws = await copyFixture('express-shop')
  cleanups.push(ws.cleanup)
  return { id: 'b3', path: ws.root, title: 'shop' }
}
const serial = { ...AI_SETTINGS, scan: { parallelWorkers: 1 } }

describe('B3 scan resilience', () => {
  it.each(['unknown', 'effort', 'tokens'])('rejects invalid model settings before snapshot: %s', async kind => {
    const workspace = await setup()
    const resolve = vi.fn(async (provider: string, model: string) => {
      if (kind === 'unknown') throw new Error('Unknown renamed model')
      return {
        provider,
        id: model,
        name: model,
        context: { contextWindow: 4096 },
        reasoning: { efforts: [{ id: 'low', name: 'Low' }] },
      }
    })
    const llm = scriptedLlm(() => failingStream('AUTH', 'unused'), { resolveModelInfo: resolve })
    const h = createHarness({
      llm,
      workspaces: [workspace],
      settings: {
        ...AI_SETTINGS,
        models: {
          default: {
            provider: 'scripted',
            model: 'renamed',
            ...(kind === 'effort' ? { reasoningEffort: 'extreme' } : {}),
            ...(kind === 'tokens' ? { maxOutputTokens: 8192 } : {}),
          },
        },
      },
    })
    await expect(h.controller.create({ workspaceId: workspace.id, mode: 'deep' })).rejects.toMatchObject({
      code: 'security/no-model',
    })
    expect(h.store.listScans()).toHaveLength(0)
    expect(llm.calls).toHaveLength(0)
  })

  it('resolves each model only once per creation', async () => {
    const workspace = await setup()
    const resolve = vi.fn(async (provider: string, model: string) => ({ provider, id: model, name: model }))
    const h = createHarness({
      llm: scriptedLlm(() => failingStream('AUTH', 'bad'), { resolveModelInfo: resolve }),
      workspaces: [workspace],
      settings: serial,
    })
    const scan = await h.controller.create({ workspaceId: workspace.id, mode: 'deep' })
    expect(resolve).toHaveBeenCalledTimes(1)
    await h.settle(scan.id)
    // The run resolves the shared route once more (context window, reasoning support), not once per worker.
    expect(resolve).toHaveBeenCalledTimes(2)
  })

  it('does not trip the rejection breaker after partial output without usage', async () => {
    const workspace = await setup()
    const llm = scriptedLlm(async function* () {
      yield { type: 'text-delta', index: 0, text: 'accepted' }
      yield* failingStream('INTERNAL', 'mid-stream error')
    })
    const h = createHarness({ llm, workspaces: [workspace], settings: serial })
    const scan = await h.controller.create({ workspaceId: workspace.id, mode: 'quick' })
    await h.settle(scan.id)
    const tasks = h.store.listTasks(scan.id)
    expect(tasks.length).toBeGreaterThan(1)
    expect(tasks.every(t => t.status === 'failed')).toBe(true)
    expect(llm.calls).toHaveLength(tasks.length)
  })

  it('retries failed tasks on explicit resume with a three-run cap', async () => {
    const workspace = await setup()
    let failing = true
    const llm = scriptedLlm(async function* () {
      yield { type: 'text-delta', index: 0, text: 'accepted' }
      if (failing) yield* failingStream('INTERNAL', 'transient')
      else yield* callReply('submit', 'submit_findings', { findings: [], reviewed_paths: [] })
    })
    const h = createHarness({ llm, workspaces: [workspace], settings: serial })
    const scan = await h.controller.create({ workspaceId: workspace.id, mode: 'quick' })
    await h.settle(scan.id)
    const task = h.store.listTasks(scan.id).find(t => t.role === 'hunter')!
    // A failed task is retained even if another task/run caused the scan to be interrupted.
    h.store.updateScan(scan.id, { status: 'interrupted' })
    h.controller.resume(scan.id)
    await h.settle(scan.id)
    expect(h.store.getTask(task.id)?.attempts).toBe(2)
    h.store.updateScan(scan.id, { status: 'interrupted' })
    failing = false
    h.controller.resume(scan.id)
    await h.settle(scan.id)
    expect(h.store.getTask(task.id)).toMatchObject({ attempts: 3, status: 'done' })
    h.store.updateTask(task.id, { status: 'failed' })
    h.store.updateScan(scan.id, { status: 'interrupted' })
    const calls = llm.calls.length
    h.controller.resume(scan.id)
    await h.settle(scan.id)
    expect(h.store.getTask(task.id)).toMatchObject({ attempts: 3, status: 'failed' })
    expect(llm.calls).toHaveLength(calls)
  })

  it('does not reset failed tasks at crash recovery and refreshes pending work after a plugin upgrade', async () => {
    const workspace = await setup()
    const llm = gatedLlm(await oracleLlm(), () => true)
    const h = createHarness({ llm, workspaces: [workspace], settings: serial, pluginVersion: 'old' })
    const scan = await h.controller.create({ workspaceId: workspace.id, mode: 'quick' })
    await llm.waitForHeld(1)
    h.controller.pause(scan.id)
    await h.settle(scan.id)
    const task = h.store.listTasks(scan.id)[0]!
    h.store.updateTask(task.id, { status: 'failed', attempts: 1 })
    h.store.updateScan(scan.id, { status: 'running' })
    await h.controller.dispose()
    const next = createHarness({ store: h.store, llm, workspaces: [workspace], pluginVersion: 'new' })
    next.controller.start()
    expect(h.store.getScan(scan.id)?.status).toBe('interrupted')
    expect(h.store.getTask(task.id)?.status).toBe('failed')
    llm.open()
    next.controller.resume(scan.id)
    await next.settle(scan.id)
    expect(h.store.getTask(task.id)).toMatchObject({ status: 'done', attempts: 2 })
    expect(next.events(scan.id).some(e => e.type === 'plugin-version-changed')).toBe(true)
  })

  it('applies the same busy workspace rule to resume with two concurrent scans allowed', async () => {
    const workspace = await setup()
    const llm = gatedLlm(await oracleLlm(), () => true)
    const h = createHarness({ llm, workspaces: [workspace], settings: serial, config: { maxConcurrentScans: 2 } })
    const first = await h.controller.create({ workspaceId: workspace.id, mode: 'quick' })
    await llm.waitForHeld(1)
    h.controller.pause(first.id)
    await h.settle(first.id)
    const second = await h.controller.create({ workspaceId: workspace.id, mode: 'quick' })
    await llm.waitForHeld(1)
    expect(() => h.controller.resume(first.id)).toThrow(/already queued or running/)
    h.controller.cancel(second.id)
    await h.settle(second.id)
  })

  it('re-reads transcript storage on worker completion', async () => {
    const workspace = await setup()
    const llm = gatedLlm(await oracleLlm(), () => true)
    const h = createHarness({ llm, workspaces: [workspace], settings: serial })
    const scan = await h.controller.create({ workspaceId: workspace.id, mode: 'quick' })
    await llm.waitForHeld(1)
    const settings = h.settings.get()
    h.settings.update({ storage: { keepTranscripts: false } }, settings.revision, true)
    llm.open()
    await h.settle(scan.id)
    expect(h.store.listAgentRuns(scan.id).every(r => h.store.loadTranscript(r.id) === undefined)).toBe(true)
  })

  it.each(['pending', 'done'] as const)(
    'replans an existing positional endpoint group without mutating %s history',
    async status => {
      const workspace = await setup()
      // Reconnaissance plans no units, so the endpoints get the Host's positional endpoint groups.
      const oracle = await oracleLlm()
      const inner = scriptedLlm(async function* (options) {
        if (roleOf(options) === 'planner') yield* callReply('plan', 'submit_review_plan', { summary: 'A shop.' })
        else yield* oracle.stream(options)
      })
      const llm = gatedLlm(inner, options => roleOf(options) === 'hunter')
      const h = createHarness({
        llm,
        workspaces: [workspace],
        settings: { ...serial, budgets: { quick: { maxTasks: 40, maxLlmCalls: 200 } } },
      })
      const scan = await h.controller.create({ workspaceId: workspace.id, mode: 'quick' })
      await llm.waitForHeld(1)
      h.controller.pause(scan.id)
      await h.settle(scan.id)
      const task = h.store.listTasks(scan.id).find(t => t.key === 'endpoints:src/routes/orders.ts#0')!
      expect(task).toBeDefined()
      if (status === 'done') h.store.updateTask(task.id, { status: 'done', attempts: 1 })
      const file = join(workspace.path, 'src/routes/orders.ts')
      await writeFile(
        file,
        `${await readFile(file, 'utf8')}\nrouter.delete('/resume-added', (req, res) => res.send('ok'))\n`,
      )
      llm.open()
      h.controller.resume(scan.id)
      await h.settle(scan.id)
      const refreshed = h.store
        .listTasks(scan.id)
        .find(t => t.status === 'done' && t.input.endpointIds?.some(id => id.includes('/resume-added')))
      expect(refreshed).toBeDefined()
      if (status === 'pending') expect(refreshed?.id).toBe(task.id)
      else {
        expect(refreshed?.id).not.toBe(task.id)
        expect(h.store.getTask(task.id)?.input).toEqual(task.input)
      }
    },
  )

  it('refreshes pending positional tasks and skips removed targets on resume', async () => {
    const workspace = await setup()
    const llm = gatedLlm(await oracleLlm(), () => true)
    const h = createHarness({
      llm,
      workspaces: [workspace],
      settings: { ...serial, budgets: { quick: { maxTasks: 40, maxLlmCalls: 200 } } },
    })
    const scan = await h.controller.create({ workspaceId: workspace.id, mode: 'quick' })
    await llm.waitForHeld(1)
    h.controller.pause(scan.id)
    await h.settle(scan.id)
    await rm(join(workspace.path, 'src/routes/profile.ts'))
    await writeFile(
      join(workspace.path, 'src/routes/new.ts'),
      "import express from 'express'\nconst router = express.Router()\nrouter.get('/brand-new', (req, res) => res.send('ok'))\nexport default router\n",
    )
    // This models an older plan/version's pending task that no longer appears in the new plan.
    h.store.ensureTask({
      id: 'phantom',
      scanId: scan.id,
      key: 'old-file',
      kind: 'hunt-file',
      role: 'hunter',
      title: 'Old file',
      priority: 1,
      status: 'pending',
      input: { targetPaths: ['src/routes/profile.ts'], focus: [] },
      attempts: 0,
      createdAt: new Date().toISOString(),
    })
    llm.open()
    h.controller.resume(scan.id)
    await h.settle(scan.id)
    expect(h.store.getTask('phantom')).toMatchObject({
      status: 'skipped',
      attempts: 0,
      error: { code: 'stale-target' },
    })
    expect(
      h.store
        .listTasks(scan.id)
        .some(t => t.status === 'done' && t.input.endpointIds?.some(id => id.includes('/brand-new'))),
    ).toBe(true)
  })

  it.skipIf(process.platform === 'win32').each([
    [false, false],
    [true, false],
    [false, true],
  ])('kills external analysis at deadline (AI=%s, resumed=%s)', async (aiReview, resumed) => {
    const workspace = await setup()
    const marker = join(workspace.path, '.dsh-security', 'tool.pid')
    const toolkit = await fakeGitleaksToolkit(
      join(workspace.path, '.dsh-security'),
      `require('node:fs').writeFileSync(${JSON.stringify(marker)}, String(process.pid)); setInterval(() => {}, 1000)`,
    )
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'Date'], shouldAdvanceTime: true })
    const h = createHarness({
      workspaces: [workspace],
      toolkit,
      llm: await oracleLlm(),
      settings: { ...AI_SETTINGS, budgets: { quick: { maxMinutes: 1 } } },
    })
    const scan = await h.controller.create({ workspaceId: workspace.id, mode: 'quick', aiReview })
    if (resumed) {
      h.controller.pause(scan.id)
      await h.settle(scan.id)
      h.store.updateScan(scan.id, { usage: { ...h.store.getScan(scan.id)!.usage, elapsedMs: 59_000 } })
      h.controller.resume(scan.id)
    }
    let pid = 0
    await vi.waitFor(
      async () => {
        pid = Number(await readFile(marker, 'utf8'))
        expect(pid).toBeGreaterThan(0)
      },
      { timeout: 5000 },
    )
    await vi.advanceTimersByTimeAsync(resumed ? 1_000 : 60_000)
    expect(await h.settle(scan.id)).toBe('interrupted')
    expect(h.store.getScan(scan.id)?.error?.code).toBe('budget-time')
    expect(() => process.kill(pid, 0)).toThrow()
  })

  it('aborts deterministic analysis on the shared deadline, not completed with zero AI', async () => {
    const workspace = await setup()
    let now = Date.now()
    const h = createHarness({
      workspaces: [workspace],
      astGrep: async () => {
        now += 61_000
        vi.setSystemTime(now)
        return undefined
      },
      settings: { budgets: { quick: { maxMinutes: 1 } } },
    })
    vi.useFakeTimers({ toFake: ['Date'] })
    const scan = await h.controller.create({ workspaceId: workspace.id, mode: 'quick', aiReview: false })
    await h.settle(scan.id)
    expect(h.store.getScan(scan.id)).toMatchObject({ status: 'interrupted', error: { code: 'budget-time' } })
    expect(h.notices(scan.id)).toContain('budget-time')
  })
})
