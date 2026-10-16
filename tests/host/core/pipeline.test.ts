import { cp, readFile, rm, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { loadAstGrep } from '../../../src/host/analysis/astgrep.ts'
import type { FindingRecord } from '../../../src/host/core/model.ts'
import type { LlmGenerateOptions, LlmStreamChunk } from '../../../src/host/dsh/ports.ts'
import { RpcError } from '../../../src/host/rpc/errors.ts'
import { initialPhases } from '../../../src/host/scan/pipeline.ts'
import { openSecurityStore } from '../../../src/host/store/sqlite.ts'
import type { SettingsPatch } from '../../../src/shared/settings.ts'
import { scanRecord } from './factories.ts'
import {
  AI_SETTINGS,
  copyFixture,
  createHarness,
  FIXTURE_APPS,
  failingStream,
  gatedLlm,
  type Harness,
  ORACLE_MODEL,
  ORACLE_PROVIDER,
  oracleLlm,
  type RecordingLlm,
  roleOf,
  scriptedLlm,
  type TempWorkspace,
  until,
} from './helpers.ts'
import { callReply } from '../agents/runtime/helpers.ts'

const WS_ID = 'ws-shop'
let shop: TempWorkspace

beforeAll(async () => {
  shop = await copyFixture('express-shop')
})

afterAll(async () => {
  await shop.cleanup()
})

function workspace(root = shop.root) {
  return { id: WS_ID, path: root, title: 'express-shop' }
}

async function runScan(
  h: Harness,
  input: { mode: 'quick' | 'deep' | 'research'; aiReview?: boolean; workspaceId?: string },
): Promise<string> {
  const scan = await h.controller.create({ workspaceId: input.workspaceId ?? WS_ID, ...input })
  await h.settle(scan.id)
  return scan.id
}

async function rpcCode(promise: Promise<unknown>): Promise<string | undefined> {
  try {
    await promise
  } catch (error) {
    if (error instanceof RpcError) return error.code
    throw error
  }
  return undefined
}

function byLocation(findings: readonly FindingRecord[], path: string, line: number): FindingRecord | undefined {
  return findings.find(f => f.location?.path === path && f.location.startLine === line)
}

/** Task keys without the per-scan finding ids that review keys carry. */
function taskShape(h: Harness, scanId: string): string[] {
  return h.store
    .listTasks(scanId)
    .map(t =>
      t.kind === 'review' ? `review:${h.store.getFinding(scanId, t.input.findingId ?? '')?.fingerprint}` : t.key,
    )
    .sort()
}

describe('deterministic-only scan', () => {
  it('runs the built-in analyzers without a model, consent, or network', async () => {
    const llm = await oracleLlm()
    const h = createHarness({ llm, workspaces: [workspace()] })
    const id = await runScan(h, { mode: 'deep', aiReview: false })
    const scan = h.store.getScan(id)
    expect(scan).toMatchObject({ status: 'completed', phase: 'done', models: {}, language: 'en' })
    expect(scan?.finishedAt).toBeDefined()
    expect(llm.calls).toHaveLength(0)
    expect(h.store.listTasks(id)).toEqual([])
    expect(h.store.listAgentRuns(id)).toEqual([])

    const phases = Object.fromEntries((scan?.phases ?? []).map(p => [p.phase, p.state]))
    expect(phases).toEqual({
      snapshot: 'done',
      inventory: 'done',
      deterministic: 'done',
      surface: 'done',
      'threat-model': 'skipped',
      hunt: 'skipped',
      review: 'skipped',
      chain: 'skipped',
      reconcile: 'done',
      report: 'done',
    })
    expect(h.notices(id)).toContain('ai-disabled')

    const findings = h.store.listFindings(id)
    expect(new Set(findings.map(f => f.source))).toEqual(new Set(['sast', 'secret']))
    expect(byLocation(findings, 'src/routes/products.ts', 27)).toMatchObject({ source: 'sast', cwe: 'CWE-89' })
    expect(byLocation(findings, 'src/routes/invoices.ts', 18)).toMatchObject({ category: 'path-traversal' })
    expect(byLocation(findings, 'scripts/sync-catalog.ts', 8)).toMatchObject({
      source: 'secret',
      verification: 'strong_static_evidence',
    })
    expect(findings.every(f => f.isNew === false)).toBe(true)
    expect(findings.some(f => f.source === 'ai')).toBe(false)

    expect(scan?.coverage).toMatchObject({
      files: { total: 17, readByAi: 0 },
      endpoints: { total: 15, reviewed: 0 },
      tasks: { planned: 0, completed: 0, failed: 0, skipped: 0 },
      discardedUnverifiable: 0,
    })
    expect(scan?.coverage?.gaps).toContain(
      'AI review was not used; logic flaws such as broken authorization are not covered.',
    )
    expect(scan?.snapshotDigest).toMatch(/^[0-9a-f]{64}$/)
    expect(scan?.usage.llmCalls).toBe(0)
  })

  it('uses the native ast-grep engine when it loads', async () => {
    const engine = await loadAstGrep()
    const h = createHarness({ workspaces: [workspace()], astGrep: () => loadAstGrep() })
    const id = await runScan(h, { mode: 'quick', aiReview: false })
    const scan = h.store.getScan(id)
    expect(scan?.status).toBe('completed')
    expect(scan?.analyzers?.find(a => a.id === 'ast-grep')?.available).toBe(engine !== undefined)
    const findings = h.store.listFindings(id)
    expect(byLocation(findings, 'src/routes/products.ts', 27)?.category).toBe('injection')
    expect(byLocation(findings, 'src/routes/invoices.ts', 18)?.category).toBe('path-traversal')
  })
})

describe('deep scan with the oracle model', () => {
  let h: Harness
  let llm: RecordingLlm
  let id: string
  let findings: FindingRecord[]

  beforeAll(async () => {
    llm = await oracleLlm()
    h = createHarness({ llm, workspaces: [workspace()], settings: AI_SETTINGS })
    id = await runScan(h, { mode: 'deep' })
    findings = h.store.listFindings(id)
  })

  it('completes every phase with every role', () => {
    const scan = h.store.getScan(id)
    expect(scan?.status).toBe('completed')
    expect(scan?.error).toBeUndefined()
    const phases = Object.fromEntries((scan?.phases ?? []).map(p => [p.phase, p.state]))
    expect(phases).toMatchObject({ 'threat-model': 'done', hunt: 'done', review: 'done', chain: 'skipped' })
    const route = { provider: ORACLE_PROVIDER, model: ORACLE_MODEL }
    expect(scan?.models).toEqual({ planner: route, hunter: route, skeptic: route, chain: route })
    expect(new Set(llm.calls.map(roleOf))).toEqual(new Set(['planner', 'hunter', 'skeptic']))
    const runs = h.store.listAgentRuns(id)
    expect(runs.every(r => r.status === 'submitted')).toBe(true)
    expect(runs.filter(r => r.role === 'planner')).toHaveLength(1)
    expect(runs.filter(r => r.role === 'hunter').length).toBeGreaterThan(5)
    expect(runs.filter(r => r.role === 'skeptic').length).toBeGreaterThan(3)
    expect(h.store.loadTranscript(runs[0]?.id ?? '')).toBeDefined()
  })

  it('stores the planner threat model and turns its hypotheses into tasks', () => {
    const scan = h.store.getScan(id)
    expect(scan?.threatModel?.summary).toContain('scripted test model')
    expect(scan?.threatModel?.hypotheses.map(x => x.targetPaths[0])).toEqual([
      'src/routes/orders.ts',
      'src/routes/products.ts',
      'src/routes/admin.ts',
      'src/routes/webhooks.ts',
    ])
    const tasks = h.store.listTasks(id)
    expect(tasks.filter(t => t.kind === 'hunt-hypothesis')).toHaveLength(4)
    expect(tasks.find(t => t.kind === 'threat-model')).toMatchObject({ status: 'done', outcome: { hypotheses: 4 } })
  })

  it('finds and confirms the IDOR and the missing authentication', () => {
    const idor = byLocation(findings, 'src/routes/orders.ts', 26)
    expect(idor).toMatchObject({
      source: 'ai',
      category: 'authz',
      cwe: 'CWE-639',
      severity: 'high',
      verification: 'strong_static_evidence',
      title: 'IDOR: any signed-in customer can read any order',
      createdBy: { role: 'hunter', model: 'scripted/oracle' },
      review: { verdict: 'confirmed', model: 'scripted/oracle' },
    })
    const admin = byLocation(findings, 'src/routes/admin.ts', 12)
    expect(admin).toMatchObject({
      source: 'ai',
      category: 'authn',
      cwe: 'CWE-306',
      verification: 'strong_static_evidence',
    })
    const evidence = h.store.getEvidence(id, idor?.supportEvidenceIds ?? [])
    expect(evidence.some(e => e.origin === 'hunter' && e.quoteCheck === 'match')).toBe(true)
    expect(evidence.some(e => e.origin === 'skeptic')).toBe(true)
  })

  it('merges hunter findings into rule hits and confirms them', () => {
    for (const [path, line, cwe] of [
      ['src/routes/products.ts', 27, 'CWE-89'],
      ['src/routes/invoices.ts', 18, 'CWE-22'],
      ['src/routes/webhooks.ts', 12, 'CWE-918'],
      ['src/routes/profile.ts', 24, 'CWE-915'],
    ] as const) {
      const finding = byLocation(findings, path, line)
      expect(finding, path).toMatchObject({ source: 'sast', cwe, verification: 'strong_static_evidence' })
      expect(finding?.mergedFingerprints, path).toHaveLength(1)
      expect(finding?.attackPath[0]?.quoteCheck, path).toBe('match')
    }
    // Merged: no AI duplicate next to a rule hit.
    expect(findings.filter(f => f.location?.path === 'src/routes/products.ts')).toHaveLength(1)
    expect(new Set(findings.map(f => f.fingerprint)).size).toBe(findings.length)
    // Mass assignment was raised to the hunter's severity.
    expect(byLocation(findings, 'src/routes/profile.ts', 24)?.severity).toBe('high')
    // Secrets are not reviewed by the skeptic.
    expect(byLocation(findings, 'src/config.ts', 12)).toMatchObject({ source: 'secret', verification: 'potential' })
  })

  it('discards fabricated findings and counts them in coverage', () => {
    expect(findings.some(f => f.title.includes('Fabricated'))).toBe(false)
    const evidence = h.store.listEvidence(id)
    expect(evidence.some(e => e.quote?.includes('backdoor_that_does_not_exist'))).toBe(false)
    const coverage = h.store.getScan(id)?.coverage
    const discarded = h.store.listTasks(id).reduce((n, t) => n + Number(t.outcome?.discarded ?? 0), 0)
    expect(discarded).toBeGreaterThan(0)
    expect(coverage?.discardedUnverifiable).toBe(discarded)
    expect(h.events(id).some(e => e.type === 'evidence-discarded')).toBe(true)
  })

  it('reports sane coverage and usage', () => {
    const scan = h.store.getScan(id)
    const coverage = scan?.coverage
    const tasks = h.store.listTasks(id)
    expect(coverage?.files.total).toBe(17)
    expect(coverage?.files.analyzed).toBeLessThanOrEqual(17)
    expect(coverage?.files.readByAi).toBeGreaterThan(0)
    expect(coverage?.files.readByAi).toBeLessThanOrEqual(17)
    expect(coverage?.endpoints).toEqual({ total: 15, reviewed: 15 })
    expect(coverage?.tasks).toEqual({ planned: tasks.length, completed: tasks.length, failed: 0, skipped: 0 })
    expect(coverage?.gaps.some(g => g.includes('endpoints were not reviewed'))).toBe(false)
    const runs = h.store.listAgentRuns(id)
    expect(scan?.usage.llmCalls).toBe(runs.reduce((n, r) => n + r.llmCalls, 0))
    expect(scan?.usage.llmCalls).toBe(llm.calls.length)
    expect(scan?.usage.inputTokens).toBeGreaterThan(0)
    expect(Number.isInteger(scan?.usage.inputTokens)).toBe(true)
    expect(scan?.usage.toolCalls).toBeGreaterThan(0)
    expect(scan?.progress).toBeUndefined()
  })

  it('records the activity log', () => {
    const types = new Set(h.events(id).map(e => e.type))
    for (const type of [
      'created',
      'run-start',
      'phase',
      'deterministic-done',
      'worker-start',
      'worker-end',
      'run-complete',
    ]) {
      expect(types, type).toContain(type)
    }
    expect(types).not.toContain('run-failed')
  })

  it('marks nothing as new on the first scan of a workspace', () => {
    expect(findings.every(f => f.isNew === false)).toBe(true)
  })
})

describe('new findings across scans', () => {
  it('marks only genuinely new fingerprints as new on the next scan', async () => {
    const copy = await copyFixture('express-shop')
    try {
      const llm = await oracleLlm()
      const h = createHarness({ llm, workspaces: [workspace(copy.root)], settings: AI_SETTINGS })
      const first = await runScan(h, { mode: 'deep' })
      expect(h.store.listFindings(first).every(f => !f.isNew)).toBe(true)

      await writeFile(
        join(copy.root, 'src/routes/debug.ts'),
        [
          "import { Router } from 'express'",
          "import { exec } from 'node:child_process'",
          '',
          'const router = Router()',
          '',
          "router.get('/run', (req, res) => {",
          "  exec('ls ' + req.query.dir, (_err, out) => res.send(out))",
          '})',
          '',
          'export default router',
          '',
        ].join('\n'),
      )
      const second = await runScan(h, { mode: 'deep' })
      const findings = h.store.listFindings(second)
      const fresh = findings.filter(f => f.isNew)
      expect(fresh).toHaveLength(1)
      expect(fresh[0]).toMatchObject({ category: 'command-execution', location: { path: 'src/routes/debug.ts' } })
      const before = h.store.scanFingerprints(first)
      for (const finding of findings.filter(f => !f.isNew)) expect(before.has(finding.fingerprint)).toBe(true)
      // The rest of the result is stable across scans.
      expect(findings.length).toBe(h.store.listFindings(first).length + 1)
    } finally {
      await copy.cleanup()
    }
  })
})

describe('quick scan', () => {
  it('reviews endpoints in a rule-clean Flask fixture copy and receives route steering sinks', async () => {
    const copy = await copyFixture('flask-secure')
    try {
      // Cookie rules now detect the planted config issue. Harden only this temporary
      // copy so the regression still proves Quick reviews endpoints with zero rule hits.
      const configPath = join(copy.root, 'app/config.py')
      const config = await readFile(configPath, 'utf8')
      expect(config).toContain('SESSION_COOKIE_SECURE = False')
      await writeFile(configPath, config.replace('SESSION_COOKIE_SECURE = False', 'SESSION_COOKIE_SECURE = True'))
      const llm = await oracleLlm()
      const h = createHarness({ llm, workspaces: [workspace(copy.root)], settings: AI_SETTINGS })
      const id = await runScan(h, { mode: 'quick' })
      const scan = h.store.getScan(id)
      expect(scan?.status).toBe('completed')
      const tasks = h.store.listTasks(id)
      expect(tasks.length).toBeGreaterThan(0)
      expect(tasks.length).toBeLessThanOrEqual(scan?.budget.maxTasks ?? 0)
      expect(tasks.every(t => t.kind === 'hunt-endpoints' && t.status === 'done')).toBe(true)
      const prompts = JSON.stringify(llm.calls)
      expect(prompts).toContain('routes.unguarded')
      expect(prompts).toContain('Review steering observations (not findings;')
      expect(h.store.listFindings(id).every(f => f.source === 'ai')).toBe(true)
    } finally {
      await copy.cleanup()
    }
  })

  it('triages rule hits and fills spare slots with endpoints: no planner and no reviewer', async () => {
    const llm = await oracleLlm()
    const h = createHarness({ llm, workspaces: [workspace()], settings: AI_SETTINGS })
    const id = await runScan(h, { mode: 'quick' })
    const scan = h.store.getScan(id)
    expect(scan?.status).toBe('completed')
    expect(new Set(llm.calls.map(roleOf))).toEqual(new Set(['hunter']))
    const phases = Object.fromEntries((scan?.phases ?? []).map(p => [p.phase, p.state]))
    expect(phases).toMatchObject({ 'threat-model': 'skipped', hunt: 'done', review: 'skipped', chain: 'skipped' })
    expect(scan?.threatModel).toBeUndefined()
    const tasks = h.store.listTasks(id)
    expect(tasks.length).toBeGreaterThan(0)
    expect(tasks.length).toBeLessThanOrEqual(scan?.budget.maxTasks ?? 0)
    expect(tasks.every(t => ['triage-signals', 'hunt-endpoints'].includes(t.kind) && t.status === 'done')).toBe(true)
    expect(tasks.some(t => t.kind === 'triage-signals')).toBe(true)
    expect(tasks.some(t => t.kind === 'hunt-endpoints')).toBe(true)
    expect(scan?.usage.llmCalls).toBeLessThanOrEqual(scan?.budget.maxLlmCalls ?? 0)
    const sql = byLocation(h.store.listFindings(id), 'src/routes/products.ts', 27)
    // Enriched by the hunter but not independently reviewed.
    expect(sql).toMatchObject({ title: 'SQL injection in product search', verification: 'potential' })
    expect(
      h.store.listFindings(id).some(f => f.verification === 'strong_static_evidence' && f.source !== 'secret'),
    ).toBe(false)
  })
})

describe('research scan', () => {
  it('runs the chain phase after reviewing every severity down to low', async () => {
    const llm = await oracleLlm()
    const settings: SettingsPatch = { ...AI_SETTINGS, scan: { reviewThreshold: 'critical' } }
    const h = createHarness({ llm, workspaces: [workspace()], settings })
    const id = await runScan(h, { mode: 'research' })
    const scan = h.store.getScan(id)
    expect(scan?.status).toBe('completed')
    expect(scan?.phases.find(p => p.phase === 'chain')?.state).toBe('done')
    expect(new Set(llm.calls.map(roleOf))).toEqual(new Set(['planner', 'hunter', 'skeptic', 'chain']))
    const chain = h.store.listTasks(id).find(t => t.kind === 'chain')
    expect(chain).toMatchObject({ status: 'done', outcome: { created: 0, discarded: 0 } })
    expect(chain?.input.findingIds?.length).toBeGreaterThan(1)
    // Research ignores the configured threshold: the high findings were still reviewed.
    expect(byLocation(h.store.listFindings(id), 'src/routes/orders.ts', 26)?.verification).toBe(
      'strong_static_evidence',
    )
  })
})

describe('pause, resume, cancel, and shutdown', () => {
  let reference: { shape: string[]; fingerprints: string[] }

  beforeAll(async () => {
    const h = createHarness({ llm: await oracleLlm(), workspaces: [workspace()], settings: AI_SETTINGS })
    const id = await runScan(h, { mode: 'deep' })
    reference = {
      shape: taskShape(h, id),
      fingerprints: h.store
        .listFindings(id)
        .map(f => f.fingerprint)
        .sort(),
    }
  })

  async function startHeld() {
    const llm = gatedLlm(await oracleLlm(), options => roleOf(options) === 'hunter')
    const h = createHarness({ llm, workspaces: [workspace()], settings: AI_SETTINGS })
    const scan = await h.controller.create({ workspaceId: WS_ID, mode: 'deep' })
    await llm.waitForHeld(2)
    return { h, llm, id: scan.id }
  }

  it('pauses mid-hunt and resumes without repeating or duplicating work', async () => {
    const { h, llm, id } = await startHeld()
    const running = h.store.listTasks(id, ['running'])
    expect(running.map(t => t.role)).toEqual(['hunter', 'hunter'])
    expect(h.controller.liveWorkers(id).filter(w => w.state === 'running')).toHaveLength(2)

    expect(h.controller.pause(id).id).toBe(id)
    expect(await h.settle(id)).toBe('paused')
    const paused = h.store.getScan(id)
    expect(paused?.phase).toBe('hunt')
    expect(h.store.listTasks(id, ['running'])).toEqual([])
    for (const task of running) expect(h.store.getTask(task.id)?.status).toBe('pending')
    expect(h.store.listTasks(id).find(t => t.kind === 'threat-model')?.status).toBe('done')
    expect(h.events(id).some(e => e.type === 'run-pause')).toBe(true)
    expect(h.controller.liveWorkers(id)).toEqual([])
    const plannerCalls = llm.calls.filter(c => roleOf(c) === 'planner').length

    llm.open()
    expect(h.controller.resume(id).status).toBe('queued')
    expect(await h.settle(id)).toBe('completed')
    expect(
      h
        .events(id)
        .filter(e => e.type === 'run-start')
        .map(e => e.message),
    ).toEqual(['Scan started', 'Scan resumed'])

    // The planner is not asked again; the interrupted tasks ran a second time.
    expect(llm.calls.filter(c => roleOf(c) === 'planner')).toHaveLength(plannerCalls)
    for (const task of running) expect(h.store.getTask(task.id)).toMatchObject({ status: 'done', attempts: 2 })
    const runs = h.store.listAgentRuns(id)
    expect(runs.filter(r => r.status === 'cancelled')).toHaveLength(2)
    // Same work and the same findings as an uninterrupted scan.
    expect(taskShape(h, id)).toEqual(reference.shape)
    expect(
      h.store
        .listFindings(id)
        .map(f => f.fingerprint)
        .sort(),
    ).toEqual(reference.fingerprints)
    const scan = h.store.getScan(id)
    expect(scan?.usage.llmCalls).toBe(llm.calls.length)
    expect(scan?.usage.elapsedMs).toBeGreaterThanOrEqual(paused?.usage.elapsedMs ?? 0)
    expect(scan?.usage.llmCalls).toBeGreaterThan(paused?.usage.llmCalls ?? 0)
  })

  it('cancels a running scan and skips the remaining tasks', async () => {
    const { h, llm, id } = await startHeld()
    h.controller.cancel(id)
    expect(await h.settle(id)).toBe('cancelled')
    llm.open()
    const scan = h.store.getScan(id)
    expect(scan?.finishedAt).toBeDefined()
    const tasks = h.store.listTasks(id)
    expect(tasks.filter(t => t.status === 'pending' || t.status === 'running')).toEqual([])
    expect(tasks.filter(t => t.status === 'skipped').length).toBeGreaterThan(2)
    expect(h.events(id).some(e => e.type === 'run-cancelled')).toBe(true)
    expect(await rpcCode(Promise.resolve().then(() => h.controller.resume(id)))).toBe('security/invalid-state')
    expect(await rpcCode(Promise.resolve().then(() => h.controller.cancel(id)))).toBe('security/invalid-state')
  })

  it('abandons a provider that ignores the abort, and writes nothing afterwards', async () => {
    const oracle = await oracleLlm()
    let release: () => void = () => {}
    const released = new Promise<void>(resolve => {
      release = resolve
    })
    let hunters = 0
    let waiting = 0
    const llm = scriptedLlm(async function* (options: LlmGenerateOptions): AsyncGenerator<LlmStreamChunk> {
      if (roleOf(options) !== 'hunter') {
        yield* oracle.stream(options)
        return
      }
      const n = ++hunters
      waiting++
      if (n === 1) {
        // A provider that stops as soon as the request is aborted.
        await new Promise<void>(resolve => options.signal?.addEventListener('abort', () => resolve(), { once: true }))
        waiting--
        yield { type: 'finish', reason: { kind: 'aborted', failure: { code: 'ABORTED', message: 'aborted' } } }
        return
      }
      // A provider that notices the abort late and still delivers its answer.
      await released
      waiting--
      yield* callReply(`late-${n}`, 'submit_findings', { findings: [], reviewed_paths: [] })
    })
    const h = createHarness({ llm, workspaces: [workspace()], settings: AI_SETTINGS })
    const scan = await h.controller.create({ workspaceId: WS_ID, mode: 'deep' })
    await until(() => waiting === 2)
    h.controller.cancel(scan.id)
    // The second provider has not noticed the abort, but its request is abandoned at once.
    expect(await h.settle(scan.id)).toBe('cancelled')
    expect(waiting).toBe(1)
    const eventsAtStop = h.events(scan.id).length
    release()
    await until(() => waiting === 0)
    await new Promise(resolve => setTimeout(resolve, 20))

    const events = h.events(scan.id)
    expect(events).toHaveLength(eventsAtStop)
    expect(events.at(-1)?.type).toBe('run-cancelled')
    expect(h.store.listAgentRuns(scan.id).filter(r => r.status === 'running')).toEqual([])
    expect(h.store.listTasks(scan.id, ['pending', 'running'])).toEqual([])
    // The late answer came after its request was abandoned and was not used.
    expect(h.store.listTasks(scan.id).filter(t => t.role === 'hunter' && t.status === 'done')).toHaveLength(0)
    expect(h.controller.liveWorkers(scan.id)).toEqual([])
  })

  it('cancels a paused scan', async () => {
    const { h, llm, id } = await startHeld()
    h.controller.pause(id)
    await h.settle(id)
    llm.open()
    expect(h.controller.cancel(id).status).toBe('cancelled')
    expect(h.store.listTasks(id, ['pending', 'running'])).toEqual([])
    expect(h.controller.isRunning(id)).toBe(false)
  })

  it('leaves a scan interrupted on shutdown; a new controller keeps it resumable', async () => {
    const { h, llm, id } = await startHeld()
    await h.controller.dispose()
    expect(h.store.getScan(id)?.status).toBe('interrupted')
    expect(h.store.listTasks(id, ['running'])).toEqual([])
    expect(h.events(id).some(e => e.type === 'run-shutdown')).toBe(true)
    expect(await rpcCode(h.controller.create({ workspaceId: WS_ID, mode: 'deep' }))).toBe('security/invalid-state')

    llm.open()
    const next = createHarness({ store: h.store, llm, workspaces: [workspace()] })
    next.controller.start()
    await new Promise(resolve => setTimeout(resolve, 5))
    expect(h.store.getScan(id)?.status).toBe('interrupted')
    expect(next.controller.isRunning(id)).toBe(false)

    next.controller.resume(id)
    expect(await next.settle(id)).toBe('completed')
    expect(taskShape(next, id)).toEqual(reference.shape)
    await next.controller.dispose()
  })

  it('recovers scans left running by a crash and purges expired scans on start', async () => {
    const h = createHarness({ workspaces: [workspace()] })
    const crashed = scanRecord({ id: 'crashed', workspaceId: WS_ID, workspaceRoot: shop.root, status: 'running' })
    h.store.insertScan(crashed)
    const task = h.store.ensureTask({
      id: 'task-crashed',
      scanId: 'crashed',
      key: 'file:src/app.ts',
      kind: 'hunt-file',
      role: 'hunter',
      title: 't',
      status: 'running',
      priority: 1,
      input: { targetPaths: ['src/app.ts'], focus: [] },
      attempts: 1,
      createdAt: crashed.createdAt,
    })
    h.store.insertAgentRun({
      id: 'run-crashed',
      scanId: 'crashed',
      taskId: task.id,
      role: 'hunter',
      title: 't',
      provider: ORACLE_PROVIDER,
      model: ORACLE_MODEL,
      status: 'running',
      turns: 1,
      toolCalls: 0,
      llmCalls: 1,
      inputTokens: 0,
      outputTokens: 0,
      startedAt: crashed.createdAt,
      filesRead: [],
    })
    h.store.insertScan(
      scanRecord({ id: 'ancient', status: 'completed', createdAt: '2020-01-01T00:00:00.000Z', workspaceId: 'old' }),
    )
    h.controller.start()
    expect(h.store.getScan('crashed')?.status).toBe('interrupted')
    expect(h.store.getTask(task.id)?.status).toBe('pending')
    // The run that was in flight is closed, so the scan shows no phantom running worker.
    expect(h.store.listAgentRuns('crashed')[0]).toMatchObject({ status: 'cancelled', stopReason: 'interrupted' })
    expect(h.store.listAgentRuns('crashed')[0]?.finishedAt).toBeDefined()
    expect(h.events('crashed').map(e => e.type)).toContain('run-interrupted')
    expect(h.store.getScan('ancient')).toBeUndefined()
  })

  it('queues scans beyond maxConcurrentScans and runs them in order', async () => {
    const other = await copyFixture('express-shop')
    try {
      const llm = gatedLlm(await oracleLlm(), options => roleOf(options) === 'hunter')
      const h = createHarness({
        llm,
        workspaces: [workspace(), { id: 'ws-other', path: other.root, title: 'other' }],
        settings: AI_SETTINGS,
      })
      const a = await h.controller.create({ workspaceId: WS_ID, mode: 'deep' })
      const b = await h.controller.create({ workspaceId: 'ws-other', mode: 'quick', aiReview: false })
      expect(h.store.getScan(b.id)?.status).toBe('queued')
      await llm.waitForHeld(1)
      expect(h.store.getScan(b.id)?.status).toBe('queued')
      llm.open()
      expect(await h.settle(a.id)).toBe('completed')
      expect(await h.settle(b.id)).toBe('completed')
    } finally {
      await other.cleanup()
    }
  })
})

describe('budgets and provider failures', () => {
  it('completes with a budget notice and skipped tasks when model calls run out', async () => {
    const llm = await oracleLlm()
    const settings: SettingsPatch = { ...AI_SETTINGS, budgets: { deep: { maxLlmCalls: 3 } } }
    const h = createHarness({ llm, workspaces: [workspace()], settings })
    const id = await runScan(h, { mode: 'deep' })
    const scan = h.store.getScan(id)
    expect(scan?.status).toBe('completed')
    expect(llm.calls.length).toBeLessThanOrEqual(3)
    expect(scan?.usage.llmCalls).toBe(3)
    expect(h.notices(id)).toContain('budget-calls')
    const tasks = h.store.listTasks(id)
    const skipped = tasks.filter(t => t.status === 'skipped')
    expect(skipped.length).toBeGreaterThan(0)
    expect(tasks.filter(t => t.status === 'pending' || t.status === 'running')).toEqual([])
    expect(skipped.some(t => t.error?.code === 'budget')).toBe(true)
    expect(scan?.coverage?.tasks.skipped).toBe(skipped.length)
    expect(scan?.coverage?.gaps).toContain(`${skipped.length} review task(s) did not run (budget or task limit).`)
    // Deterministic findings are still reported.
    expect(byLocation(h.store.listFindings(id), 'src/routes/products.ts', 27)?.source).toBe('sast')
  })

  it('records a provider refusal once and never retries on another model', async () => {
    const oracle = await oracleLlm()
    const llm = scriptedLlm(
      (options: LlmGenerateOptions): AsyncIterable<LlmStreamChunk> =>
        options.model === 'strict'
          ? failingStream('INVALID_REQUEST', 'The request was rejected by the content policy.')
          : oracle.stream(options),
    )
    const settings: SettingsPatch = {
      ...AI_SETTINGS,
      models: { ...AI_SETTINGS.models, hunter: { provider: ORACLE_PROVIDER, model: 'strict' } },
    }
    const h = createHarness({ llm, workspaces: [workspace()], settings })
    const id = await runScan(h, { mode: 'deep' })
    expect(h.store.getScan(id)?.status).toBe('completed')
    expect(h.notices(id).filter(k => k === 'blocked-by-provider')).toHaveLength(1)

    const hunterCalls = llm.calls.filter(c => roleOf(c) === 'hunter')
    expect(hunterCalls.length).toBeGreaterThan(0)
    expect(hunterCalls.every(c => c.model === 'strict')).toBe(true)
    const hunters = h.store.listAgentRuns(id).filter(r => r.role === 'hunter')
    expect(hunters.every(r => r.status === 'blocked_by_provider' && r.llmCalls === 1)).toBe(true)
    expect(hunterCalls).toHaveLength(hunters.length)
    const huntTasks = h.store.listTasks(id).filter(t => t.role === 'hunter')
    expect(huntTasks.every(t => t.status === 'failed' && t.error?.code === 'INVALID_REQUEST')).toBe(true)
    expect(h.store.listFindings(id).some(f => f.source === 'ai')).toBe(false)
    // Other roles keep their own model and still work.
    expect(h.store.getScan(id)?.threatModel).toBeDefined()
    expect(h.store.listAgentRuns(id).some(r => r.role === 'skeptic' && r.status === 'submitted')).toBe(true)
    expect(h.store.getScan(id)?.coverage?.gaps).toContain(
      `${huntTasks.length} review task(s) failed; see the activity log.`,
    )
  })
})

describe('failures', () => {
  it('fails a scan whose workspace disappears without exposing its absolute path, and can retry it', async () => {
    const gone = await copyFixture('express-shop')
    // A store clock that runs ahead, so `updatedAt` never equals `startedAt`.
    const store = openSecurityStore(':memory:', { now: () => new Date(Date.now() + 60_000) })
    let removeFirst = true
    const h = createHarness({
      store,
      workspaces: [{ id: 'ws-gone', path: gone.root, title: 'gone' }],
      astGrep: async () => {
        if (removeFirst) await rm(gone.root, { recursive: true, force: true })
        removeFirst = false
        return undefined
      },
    })
    const scan = await h.controller.create({ workspaceId: 'ws-gone', mode: 'quick', aiReview: false })
    expect(await h.settle(scan.id)).toBe('failed')
    const failed = h.store.getScan(scan.id)
    expect(failed?.error?.code).toBe('scan-failed')
    expect(failed?.finishedAt).toBeDefined()
    const failure = h.events(scan.id).find(e => e.type === 'run-failed')
    expect(failure?.level).toBe('error')
    for (const text of [failed?.error?.message ?? '', failure?.message ?? '']) {
      expect(text).toContain('ENOENT')
      expect(text).not.toContain(gone.root)
    }
    expect(h.events(scan.id).find(e => e.type === 'run-start')?.message).toBe('Scan started')
    expect(h.logger.entries.some(e => e.level === 'error')).toBe(true)

    // A failed scan can be retried once the folder is back.
    await cp(join(FIXTURE_APPS, 'express-shop'), gone.root, { recursive: true })
    expect(h.controller.resume(scan.id).error).toBeUndefined()
    expect(await h.settle(scan.id)).toBe('completed')
    expect(h.store.getScan(scan.id)?.error).toBeUndefined()
    await gone.cleanup()
  })
})

describe('creating scans', () => {
  const create = (h: Harness, workspaceId = WS_ID) => rpcCode(h.controller.create({ workspaceId, mode: 'deep' }))

  it('needs a model for the hunter role and a connected provider', async () => {
    const llm = await oracleLlm()
    expect(await create(createHarness({ llm, workspaces: [workspace()] }))).toBe('security/no-model')
    expect(await create(createHarness({ workspaces: [workspace()], settings: AI_SETTINGS }))).toBe('security/no-model')
    const gone: SettingsPatch = { ...AI_SETTINGS, models: { default: { provider: 'gone', model: 'x' } } }
    const h = createHarness({ llm, workspaces: [workspace()], settings: gone })
    let details: unknown
    try {
      await h.controller.create({ workspaceId: WS_ID, mode: 'deep' })
    } catch (error) {
      details = (error as RpcError).details
    }
    expect(details).toEqual({ roles: ['planner', 'hunter', 'skeptic', 'chain'] })
  })

  it('needs consent before sending code to a model', async () => {
    const llm = await oracleLlm()
    const h = createHarness({ llm, workspaces: [workspace()], settings: { models: AI_SETTINGS.models } })
    expect(await create(h)).toBe('security/consent-required')
    expect(h.store.listScans()).toEqual([])
  })

  it('refuses a second scan of a busy workspace', async () => {
    const llm = gatedLlm(await oracleLlm(), () => true)
    const h = createHarness({ llm, workspaces: [workspace()], settings: AI_SETTINGS })
    const first = await h.controller.create({ workspaceId: WS_ID, mode: 'deep' })
    let failure: RpcError | undefined
    try {
      await h.controller.create({ workspaceId: WS_ID, mode: 'quick', aiReview: false })
    } catch (error) {
      failure = error as RpcError
    }
    expect(failure?.code).toBe('security/busy')
    expect(failure?.details).toEqual({ scanId: first.id })
    h.controller.cancel(first.id)
    await h.settle(first.id)
    llm.open()
  })

  it('rejects unknown or unreadable workspaces', async () => {
    const h = createHarness({
      workspaces: [workspace(), { id: 'ws-missing', path: join(shop.root, 'does-not-exist'), title: 'gone' }],
    })
    expect(await create(h, 'ws-unknown')).toBe('security/not-found')
    expect(await create(h, 'ws-missing')).toBe('security/workspace-unavailable')
    expect(await rpcCode(Promise.resolve().then(() => h.controller.pause('nope')))).toBe('security/not-found')
  })

  it('freezes settings, budget, and phases into the scan record', async () => {
    const h = createHarness({ workspaces: [workspace()], settings: { budgets: { quick: { maxTasks: 3 } } } })
    const scan = await h.controller.create({ workspaceId: WS_ID, mode: 'quick', aiReview: false, language: 'ja' })
    expect(scan).toMatchObject({ mode: 'quick', language: 'ja', budget: { maxTasks: 3 }, models: {} })
    expect(scan.phases).toEqual(initialPhases('quick', false))
    await h.settle(scan.id)
  })
})

describe('initialPhases', () => {
  it('skips the phases a mode never runs', () => {
    const skipped = (mode: 'quick' | 'deep' | 'research', ai: boolean) =>
      initialPhases(mode, ai)
        .filter(p => p.state === 'skipped')
        .map(p => p.phase)
    expect(skipped('quick', true)).toEqual(['threat-model', 'review', 'chain'])
    expect(skipped('deep', true)).toEqual(['chain'])
    expect(skipped('research', true)).toEqual([])
    expect(skipped('research', false)).toEqual(['threat-model', 'hunt', 'review', 'chain'])
    expect(initialPhases('deep', true).map(p => p.phase)).not.toContain('done')
  })
})
