import { mkdtemp, rm } from 'node:fs/promises'
import { homedir, tmpdir } from 'node:os'
import { DatabaseSync } from 'node:sqlite'
import { openSecurityStore } from '../../../src/host/store/sqlite.ts'
import { join, sep } from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import type { WorkspaceEntity } from '../../../src/host/dsh/ports.ts'
import { RpcError } from '../../../src/host/rpc/errors.ts'
import type { RpcCallContext, RpcHandlers } from '../../../src/host/rpc/server.ts'
import { createHandlers } from '../../../src/host/service.ts'
import type { SecurityStore } from '../../../src/host/store/types.ts'
import type { FindingSummary, RpcMethodName, RpcRequest } from '../../../src/shared/contracts.ts'
import { DEFAULT_SETTINGS } from '../../../src/shared/settings.ts'
import {
  AI_SETTINGS,
  copyFixture,
  createHarness,
  gatedLlm,
  type Harness,
  ORACLE_PROVIDER,
  oracleLlm,
  type RecordingLlm,
  registryOf,
  roleOf,
  scriptedLlm,
  type TempWorkspace,
} from './helpers.ts'

const WS_ID = 'ws-shop'

let shop: TempWorkspace
/** A registered project under the home directory (never touched on disk: only its path is shown). */
const HOME_PROJECT = join(homedir(), 'projects', 'dshsec-test-home')
let llm: RecordingLlm
let h: Harness
let handlers: RpcHandlers
let workspaces: WorkspaceEntity[]
let completedScan: string
let japaneseScan = ''

/** Hiragana or katakana. */
const KANA = /[\u3040-\u30ff]/
let ready = false

/** Every JSON response, to check for leaked absolute paths at the end. */
const responses: { method: string; json: string }[] = []

function call(loopback = true): RpcCallContext {
  return {
    request: new Request('http://localhost/api/dsh-security/test', { method: 'POST' }),
    loopback,
    signal: new AbortController().signal,
  }
}

async function invoke<M extends RpcMethodName>(
  method: M,
  payload: RpcRequest<M>,
  options: { loopback?: boolean } = {},
): Promise<Awaited<ReturnType<RpcHandlers[M]>>> {
  const handler = handlers[method] as (p: RpcRequest<M>, c: RpcCallContext) => ReturnType<RpcHandlers[M]>
  const value = await handler(payload, call(options.loopback ?? true))
  responses.push({ method, json: JSON.stringify(value) })
  return value
}

async function failure(promise: Promise<unknown>): Promise<RpcError> {
  try {
    await promise
  } catch (error) {
    if (error instanceof RpcError) return error
    throw error
  }
  throw new Error('expected an RpcError')
}

function makeHandlers(harness: Harness, model: RecordingLlm | undefined, list: WorkspaceEntity[]): RpcHandlers {
  return createHandlers({
    store: harness.store,
    settings: harness.settings,
    controller: harness.controller,
    toolkit: undefined,
    config: harness.config,
    llm: () => model,
    workspaces: () => registryOf(list),
    astGrep: async () => undefined,
    logger: harness.logger,
    pluginVersion: '0.0.0-test',
    now: () => new Date('2026-10-13T12:00:00.000Z'),
  })
}

beforeAll(async () => {
  shop = await copyFixture('express-shop')
  llm = await oracleLlm()
  workspaces = [
    { id: WS_ID, path: shop.root, title: 'express-shop' },
    { id: 'ws-home', path: HOME_PROJECT, title: 'home project' },
  ]
  h = createHarness({ llm, workspaces, settings: { ...AI_SETTINGS, ui: { language: 'ja' } } })
  handlers = makeHandlers(h, llm, workspaces)
  const { scanId } = await invoke('createScan', { workspaceId: WS_ID, mode: 'deep' })
  await h.settle(scanId)
  completedScan = scanId
  ready = true
})

afterAll(async () => {
  await h.controller.dispose()
  await shop.cleanup()
})

async function findings(filter?: RpcRequest<'listFindings'>['filter']): Promise<readonly FindingSummary[]> {
  return await invoke('listFindings', { scanId: completedScan, ...(filter ? { filter } : {}) })
}

async function findingAt(path: string, line: number): Promise<FindingSummary> {
  const found = (await findings()).find(f => f.location?.path === path && f.location.startLine === line)
  if (!found) throw new Error(`no finding at ${path}:${line}`)
  return found
}

describe('bootstrap, workspaces, and models', () => {
  it('bootstraps defaults for corrupt JSON and repairs the row without resetting its revision', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'dsh-corrupt-settings-'))
    const path = join(dir, 'security.db')
    const store = openSecurityStore(path)
    const db = new DatabaseSync(path)
    db.prepare('INSERT INTO settings (id, json, revision) VALUES (1, ?, ?)').run('{broken-json', 7)
    db.close()
    const local = createHarness({ store })
    try {
      const handlers = makeHandlers(local, undefined, [])
      const bootstrap = await handlers.getBootstrap({}, call())
      expect(bootstrap.settings).toEqual(DEFAULT_SETTINGS)
      expect(bootstrap.settingsRevision).toBe(7)
      expect(local.logger.entries.some(entry => entry.level === 'warn')).toBe(true)
      const updated = await handlers.updateSettings({ patch: { ui: { language: 'ja' } }, expectedRevision: 7 }, call())
      expect(updated.revision).toBe(8)
      expect(store.readSettings()).toMatchObject({ revision: 8, value: { ui: { language: 'ja' } } })
    } finally {
      await local.controller.dispose()
      store.close()
      await rm(dir, { recursive: true, force: true })
    }
  })

  it('allows a remote page to start a scan using existing consent without widening settings', async () => {
    const model = await oracleLlm()
    const local = createHarness({ llm: model, workspaces, settings: AI_SETTINGS, allowRemoteHighRisk: false })
    try {
      const service = makeHandlers(local, model, workspaces)
      const boot = await service.getBootstrap({}, call(false))
      expect(boot.canEditHighRiskSettings).toBe(false)
      const { scanId } = await service.createScan({ workspaceId: WS_ID, mode: 'quick' }, call(false))
      expect(await local.settle(scanId)).toBe('completed')
      expect(model.calls.length).toBeGreaterThan(0)
      expect(local.settings.get().revision).toBe(boot.settingsRevision)
    } finally {
      await local.controller.dispose()
    }
  })

  it('describes the plugin, settings, capabilities, and limits', async () => {
    const local = await invoke('getBootstrap', {})
    expect(local).toMatchObject({
      pluginVersion: '0.0.0-test',
      contractVersion: 3,
      settingsRevision: 1,
      loopback: true,
      canEditHighRiskSettings: true,
      capabilities: { llm: true, workspaces: true },
      limits: { maxParallelWorkers: 4, maxConcurrentScans: 1, maxLlmCallsPerScan: 6000 },
    })
    expect(local.settings.privacy.sendCodeToModel).toBe(true)
    expect(local.settings.ui.language).toBe('ja')
    const analyzers = Object.fromEntries(local.capabilities.analyzers.map(a => [a.id, a.available]))
    expect(analyzers).toEqual({
      secrets: true,
      sast: true,
      routes: true,
      dependencies: true,
      osv: false,
      'ast-grep': false,
    })
    const remote = await invoke('getBootstrap', {}, { loopback: false })
    expect(remote).toMatchObject({ loopback: false, canEditHighRiskSettings: true })
  })

  it('reports missing DSH services as capabilities', async () => {
    const bare = createHarness({ allowRemoteHighRisk: false })
    const service = createHandlers({
      store: bare.store,
      settings: bare.settings,
      controller: bare.controller,
      toolkit: undefined,
      config: bare.config,
      llm: () => undefined,
      workspaces: () => undefined,
      astGrep: async () => undefined,
      logger: bare.logger,
      pluginVersion: 'x',
      now: () => new Date(),
    })
    const boot = await service.getBootstrap({}, call(false))
    expect(boot).toMatchObject({
      settings: DEFAULT_SETTINGS,
      settingsRevision: 0,
      canEditHighRiskSettings: false,
      capabilities: { llm: false, workspaces: false },
    })
    expect(await service.listWorkspaces({}, call())).toEqual([])
    expect(await service.listModels({}, call())).toEqual([])
    expect(await service.listToolkit({}, call())).toEqual([])
    expect((await failure(service.installTool({ toolId: 'gitleaks', acceptLicense: true }, call()))).code).toBe(
      'security/toolkit-unavailable',
    )
  })

  it('lists workspaces with home-relative display paths and their last scan', async () => {
    const list = await invoke('listWorkspaces', {})
    const shopRow = list.find(w => w.id === WS_ID)
    const homeRow = list.find(w => w.id === 'ws-home')
    // Home-relative, keeping the platform's own separator (`~\projects\…` on Windows).
    expect(homeRow?.displayPath).toBe(['~', 'projects', 'dshsec-test-home'].join(sep))
    expect(homeRow?.lastScan).toBeUndefined()
    expect(shopRow?.displayPath).toBe(
      shop.root.toLowerCase().startsWith(`${homedir()}${sep}`.toLowerCase())
        ? `~${shop.root.slice(homedir().length)}`
        : shop.root,
    )
    expect(shopRow?.lastScan).toMatchObject({ id: completedScan, status: 'completed', mode: 'deep' })
  })

  it('lists models per provider and isolates a provider that fails', async () => {
    const flaky = scriptedLlm(async function* () {}, {
      providers: [
        { id: ORACLE_PROVIDER, name: 'Scripted' },
        { id: 'broken', name: 'Broken' },
      ],
      listModels: async provider => {
        if (provider === 'broken') throw new Error('provider offline: /secret/path')
        return [
          { provider, id: 'oracle', name: 'Oracle', description: 'test model' },
          { provider, id: 'slow', name: 'Slow' },
        ]
      },
      resolveModelInfo: async (provider, model) => {
        if (model === 'slow') throw new Error('no info')
        return {
          provider,
          id: model,
          name: model,
          context: { contextWindow: 128_000 },
          reasoning: { efforts: [{ id: 'high', name: 'High', description: 'x' }], defaultEffort: 'high' },
        }
      },
    })
    const service = makeHandlers(h, flaky, workspaces)
    const providers = await service.listModels({}, call())
    responses.push({ method: 'listModels', json: JSON.stringify(providers) })
    expect(providers).toEqual([
      {
        id: ORACLE_PROVIDER,
        name: 'Scripted',
        models: [
          {
            id: 'oracle',
            name: 'Oracle',
            description: 'test model',
            contextWindow: 128_000,
            reasoningEfforts: [{ id: 'high', name: 'High' }],
            defaultEffort: 'high',
          },
          { id: 'slow', name: 'Slow' },
        ],
      },
      { id: 'broken', name: 'Broken', models: [], error: 'Could not list models for this provider.' },
    ])
    expect(h.logger.entries.some(e => e.level === 'warn' && String(e.args[0]).includes('broken'))).toBe(true)
  })

  it('updates settings with optimistic concurrency', async () => {
    const before = await invoke('getBootstrap', {})
    const updated = await invoke('updateSettings', {
      patch: { scan: { reviewThreshold: 'high' } },
      expectedRevision: before.settingsRevision,
    })
    expect(updated.revision).toBe(before.settingsRevision + 1)
    expect(updated.settings.scan.reviewThreshold).toBe('high')
    const stale = await failure(
      invoke('updateSettings', {
        patch: { scan: { reviewThreshold: 'low' } },
        expectedRevision: before.settingsRevision,
      }),
    )
    expect(stale.code).toBe('security/conflict')
    await invoke('updateSettings', {
      patch: { scan: { reviewThreshold: 'medium' } },
      expectedRevision: updated.revision,
    })
  })
})

describe('scans and findings', () => {
  it('keeps the default page size and returns older history with an offset', async () => {
    const local = createHarness({ workspaces })
    const routes = makeHandlers(local, undefined, workspaces)
    try {
      const template = h.store.getScan(completedScan)!
      for (let i = 0; i < 51; i++) {
        local.store.insertScan({ ...template, id: `history_${String(i).padStart(3, '0')}` })
      }
      const first = await routes.listScans({ workspaceId: WS_ID }, call())
      const second = await routes.listScans({ workspaceId: WS_ID, offset: 50 }, call())
      expect(first).toHaveLength(50)
      expect(second.map(scan => scan.id)).toEqual(['history_000'])
      expect(new Set([...first, ...second].map(scan => scan.id)).size).toBe(51)
      expect(second[0]?.review).toMatchObject({ state: 'complete' })
      local.store.updateScan('history_000', {
        coverage: {
          ...template.coverage!,
          gapDetails: [{ code: 'test-gap', fallback: `Unavailable under ${shop.root}`, params: { path: shop.root } }],
          analyzers: [
            {
              id: 'sast',
              available: false,
              source: 'builtin',
              reasonCode: 'test-reason',
              reasonParams: { path: shop.root },
            },
          ],
        },
      })
      const detail = await routes.getScan({ scanId: 'history_000' }, call())
      expect(JSON.stringify(detail.coverage)).not.toContain(shop.root)
      expect(detail.coverage?.gapDetails?.[0]?.code).toBe('test-gap')
    } finally {
      await local.controller.dispose()
      local.store.close()
    }
  })

  it('extends a stopped scan budget and requeues only budget-skipped work', async () => {
    const local = createHarness({ workspaces })
    const routes = makeHandlers(local, undefined, workspaces)
    const template = h.store.getScan(completedScan)!
    const budget = { maxLlmCalls: 10, maxTokens: 1000, maxMinutes: 5, maxTurnsPerWorker: 5, maxTasks: 5 }
    const usage = { llmCalls: 9, inputTokens: 900, outputTokens: 100, toolCalls: 3, elapsedMs: 1000 }
    const task = (id: string, status: 'done' | 'skipped', code?: string) =>
      local.store.ensureTask({
        id,
        scanId: 'extendable',
        key: id,
        kind: 'hunt-file',
        role: 'hunter',
        title: id,
        status,
        priority: 1,
        input: { targetPaths: [], focus: [] },
        attempts: 0,
        ...(code ? { error: { code, message: code } } : {}),
        createdAt: template.createdAt,
        finishedAt: template.createdAt,
      })
    try {
      local.store.insertScan({ ...template, id: 'extendable', status: 'completed', budget, usage })
      task('extend_budget', 'skipped', 'budget')
      task('extend_exhausted', 'skipped', 'budget_exhausted')
      task('extend_stale', 'skipped', 'stale-target')
      task('extend_done', 'done')

      // Rejections first, while nothing is running: at the operator ceiling,
      // without resumable work, and for a cancelled scan.
      local.store.insertScan({
        ...template,
        id: 'extend_ceiling',
        status: 'completed',
        budget: { ...budget, maxTokens: local.config.maxTokensPerScan },
        usage,
      })
      expect((await failure(routes.extendScanBudget({ scanId: 'extend_ceiling', addTokens: 1 }, call()))).code).toBe(
        'security/invalid-state',
      )
      local.store.insertScan({ ...template, id: 'extend_none', status: 'completed', budget, usage })
      expect((await failure(routes.extendScanBudget({ scanId: 'extend_none', addTokens: 1 }, call()))).code).toBe(
        'security/invalid-state',
      )
      local.store.insertScan({ ...template, id: 'extend_cancelled', status: 'cancelled', budget, usage })
      expect((await failure(routes.extendScanBudget({ scanId: 'extend_cancelled', addTokens: 1 }, call()))).code).toBe(
        'security/invalid-state',
      )

      const extended = await routes.extendScanBudget({ scanId: 'extendable', addTokens: 500 }, call())
      expect(extended.status).toBe('queued')
      expect(local.store.getScan('extendable')?.budget.maxTokens).toBe(1500)
      expect(local.store.getScan('extendable')?.usage).toEqual(usage)
      // The local harness has no model, so the rerun completes without AI work;
      // budget-skipped tasks must have been returned to the queue, others untouched.
      expect(await local.settle('extendable')).toBe('completed')
      const byId = new Map(local.store.listTasks('extendable').map(t => [t.id, t.status]))
      expect(byId.get('extend_budget')).toBe('pending')
      expect(byId.get('extend_exhausted')).toBe('pending')
      expect(byId.get('extend_stale')).toBe('skipped')
      expect(byId.get('extend_done')).toBe('done')
      expect(local.events('extendable').some(event => event.type === 'budget-extended')).toBe(true)
    } finally {
      await local.controller.dispose()
      local.store.close()
    }
  })

  it('fills visible event pages across debug-only batches and reaches the latest error after continuation', async () => {
    const local = createHarness({ workspaces })
    const routes = makeHandlers(local, undefined, workspaces)
    try {
      const scanId = 'debug-paged-events'
      local.store.insertScan({ ...h.store.getScan(completedScan)!, id: scanId })
      const visibleSeqs: number[] = []
      local.store.transaction(() => {
        for (let group = 0; group < 3; group++) {
          for (let i = 0; i < 1000; i++) {
            local.store.appendEvent(scanId, 'debug', 'worker-progress', `Debug ${group}:${i}`)
          }
          visibleSeqs.push(
            local.store.appendEvent(
              scanId,
              group === 2 ? 'error' : group === 1 ? 'warn' : 'info',
              group === 2 ? 'latest-error' : 'visible-progress',
              group === 2 ? `Latest error under ${shop.root}` : `Visible ${group}`,
            ),
          )
        }
      })
      const first = await routes.listEvents({ scanId, limit: 2 }, call())
      expect(first.map(event => event.seq)).toEqual(visibleSeqs.slice(0, 2))
      expect(first.map(event => event.level)).toEqual(['info', 'warn'])
      const continuation = await routes.listEvents({ scanId, limit: 2, afterSeq: first.at(-1)!.seq }, call())
      expect(continuation.map(event => event.seq)).toEqual(visibleSeqs.slice(2))
      expect(continuation[0]).toMatchObject({ level: 'error', type: 'latest-error' })
      expect(continuation[0]?.message).not.toContain(shop.root)
      const whole = await routes.listEvents({ scanId, limit: 3 }, call())
      expect(whole.map(event => event.seq)).toEqual(visibleSeqs)
      expect(await routes.listEvents({ scanId, afterSeq: continuation[0]!.seq, limit: 2 }, call())).toEqual([])
    } finally {
      await local.controller.dispose()
      local.store.close()
    }
  })

  it('terminates an event read when every raw page contains only debug events', async () => {
    const local = createHarness({ workspaces })
    const routes = makeHandlers(local, undefined, workspaces)
    try {
      const scanId = 'all-debug-events'
      local.store.insertScan({ ...h.store.getScan(completedScan)!, id: scanId })
      local.store.transaction(() => {
        for (let i = 0; i < 2000; i++) local.store.appendEvent(scanId, 'debug', 'worker-progress', `Debug ${i}`)
      })
      expect(await routes.listEvents({ scanId, limit: 2 }, call())).toEqual([])
    } finally {
      await local.controller.dispose()
      local.store.close()
    }
  })

  it('summarizes and details the completed scan', async () => {
    const list = await invoke('listScans', { workspaceId: WS_ID })
    expect(list.map(s => s.id)).toContain(completedScan)
    const detail = await invoke('getScan', { scanId: completedScan })
    expect(detail.summary).toMatchObject({ id: completedScan, status: 'completed', workspaceTitle: 'express-shop' })
    expect(detail.summary.confirmed).toBeGreaterThan(0)
    expect(detail.summary.counts.high).toBeGreaterThan(0)
    expect(detail.threatModel?.summary).toContain('scripted')
    expect(detail.threatModel).not.toHaveProperty('hypotheses')
    expect(detail.workers.length).toBeGreaterThan(0)
    expect(detail.workers.every(w => w.state === 'done')).toBe(true)
    expect(detail.coverage?.files.readByAi).toBeGreaterThan(0)
    expect(detail.budget).toEqual({ maxLlmCalls: 900, maxTokens: 9_000_000, maxMinutes: 180 })
    expect(detail.progress).toBeUndefined()
    expect(detail).not.toHaveProperty('summary.workspaceRoot')
    const events = await invoke('listEvents', { scanId: completedScan, limit: 1000 })
    expect(events.length).toBeGreaterThan(10)
    expect(events.every(e => e.seq > 0 && typeof e.message === 'string')).toBe(true)
    const tail = await invoke('listEvents', { scanId: completedScan, afterSeq: events.at(-2)?.seq ?? 0 })
    expect(tail).toHaveLength(1)
  })

  it('filters findings by severity, closure, source, triage, and text', async () => {
    const all = await findings()
    expect(all.length).toBeGreaterThan(5)
    const confirmed = await findings({ closures: ['confirmed'] })
    expect(confirmed.length).toBeGreaterThan(0)
    expect(confirmed.every(f => f.closure === 'confirmed')).toBe(true)
    const ai = await findings({ sources: ['ai'] })
    expect(ai.map(f => f.location?.path).sort()).toEqual(['src/routes/admin.ts', 'src/routes/orders.ts'])
    expect(ai.every(f => f.independentlyReviewed === true)).toBe(true)
    for (const finding of all) {
      expect(finding.independentlyReviewed).toBe(h.store.getFinding(completedScan, finding.id)?.review !== undefined)
    }
    expect(await findings({ severities: ['medium'] })).toEqual(all.filter(f => f.severity === 'medium'))
    expect((await findings({ text: 'CWE-639' })).map(f => f.location?.path)).toEqual(['src/routes/orders.ts'])
    expect((await findings({ text: 'orders.ts:26' })).length).toBe(1)
    expect((await findings({ text: 'idor' })).length).toBe(1)
    expect(await findings({ text: 'no such thing' })).toEqual([])
    expect(await findings({ triage: ['open'] })).toEqual(all)
  })

  it('returns finding details with evidence, counterevidence, and snippets', async () => {
    const idor = await findingAt('src/routes/orders.ts', 26)
    const detail = await invoke('getFinding', { scanId: completedScan, findingId: idor.id })
    expect(detail).toMatchObject({
      verification: 'strong_static_evidence',
      closure: 'confirmed',
      review: { verdict: 'confirmed', model: 'scripted/oracle' },
      independentlyReviewed: true,
      createdBy: { role: 'hunter', model: 'scripted/oracle' },
    })
    expect(detail.attackPath[0]).toMatchObject({ quoteCheck: 'match', location: { path: 'src/routes/orders.ts' } })
    expect(detail.attackPath[0]?.snippet).toContain('SELECT * FROM orders WHERE id = ?')
    expect(detail.evidence.length).toBeGreaterThan(1)
    expect(detail.evidence.every(e => e.snippet !== undefined)).toBe(true)
    expect(new Set(detail.evidence.map(e => e.originRole))).toEqual(new Set(['hunter', 'skeptic']))
    expect(detail.counterevidence).toEqual([])

    const secret = await findingAt('scripts/sync-catalog.ts', 8)
    const secretDetail = await invoke('getFinding', { scanId: completedScan, findingId: secret.id })
    expect(secretDetail.evidence[0]).toMatchObject({
      trust: 'observed',
      originRole: 'analyzer',
      kind: 'tool_observation',
    })
    expect(secretDetail.evidence[0]?.snippet).toContain('[REDACTED:')
    expect(JSON.stringify(secretDetail)).not.toMatch(/ghp_[A-Za-z0-9]{20,}/)

    expect((await failure(invoke('getFinding', { scanId: completedScan, findingId: 'nope' }))).code).toBe(
      'security/not-found',
    )
    expect((await failure(invoke('getFinding', { scanId: 'nope', findingId: idor.id }))).code).toBe(
      'security/not-found',
    )
  })

  it('shows counterevidence on findings refuted by a hunter', async () => {
    const store: SecurityStore = h.store
    const target = (await findings()).find(f => f.source === 'secret' && f.verification === 'potential')
    if (!target) throw new Error('expected a potential secret finding')
    const record = store.getFinding(completedScan, target.id)
    const evidence = {
      id: 'counter-1',
      scanId: completedScan,
      origin: 'skeptic' as const,
      kind: 'counterevidence' as const,
      trust: 'inferred' as const,
      claim: 'Only a placeholder.',
      location: { path: 'src/config.ts', startLine: 12, endLine: 12 },
      quote: 'placeholder',
      quoteCheck: 'match' as const,
      createdAt: '2026-10-13T12:00:00.000Z',
    }
    store.insertEvidence(evidence)
    store.updateFinding(target.id, { counterEvidenceIds: [...(record?.counterEvidenceIds ?? []), 'counter-1'] })
    const detail = await invoke('getFinding', { scanId: completedScan, findingId: target.id })
    expect(detail.counterevidence).toEqual([
      {
        id: 'counter-1',
        kind: 'counterevidence',
        trust: 'inferred',
        claim: 'Only a placeholder.',
        location: { path: 'src/config.ts', startLine: 12, endLine: 12 },
        snippet: 'placeholder',
        quoteCheck: 'match',
        originRole: 'skeptic',
      },
    ])
    store.updateFinding(target.id, { counterEvidenceIds: record?.counterEvidenceIds ?? [] })
  })

  it('builds fix prompts in the scan language', async () => {
    const idor = await findingAt('src/routes/orders.ts', 26)
    const en = await invoke('getFixPrompt', { scanId: completedScan, findingId: idor.id })
    expect(en.prompt).toMatch(/^Please fix the following security issue found by DSH Security/)
    expect(en.prompt).toContain('- Location: src/routes/orders.ts:26')
    expect(en.prompt).toContain('- CWE: CWE-639')
    expect(en.prompt).toContain('### Attack path (code checked against the source)')
    expect(en.prompt).toMatch(/```\n.*SELECT \* FROM orders WHERE id = \?/)
    expect(en.prompt).not.toContain(shop.root)

    for (const [language, intro] of [
      ['ja', 'DSH Security がこのプロジェクトで見つけた'],
      ['zh', '请修复 DSH Security 在本项目中发现的'],
    ] as const) {
      const scan = await h.controller.create({ workspaceId: WS_ID, mode: 'quick', aiReview: false, language })
      await h.settle(scan.id)
      const finding = (await invoke('listFindings', { scanId: scan.id }))[0]
      if (!finding) throw new Error('expected a finding')
      const { prompt } = await invoke('getFixPrompt', { scanId: scan.id, findingId: finding.id })
      expect(prompt.startsWith(intro)).toBe(true)
      if (language === 'ja') japaneseScan = scan.id
    }
  })

  it('persists triage across scans by fingerprint and leaves it out of open counts', async () => {
    const idor = await findingAt('src/routes/orders.ts', 26)
    const before = (await invoke('getScan', { scanId: completedScan })).summary
    const summary = await invoke('setTriage', {
      scanId: completedScan,
      findingId: idor.id,
      triage: 'accepted_risk',
      note: 'Support console needs it.',
    })
    expect(summary).toMatchObject({ id: idor.id, triage: 'accepted_risk' })
    const after = (await invoke('getScan', { scanId: completedScan })).summary
    expect(after.counts.high).toBe(before.counts.high - 1)
    expect(after.confirmed).toBe(before.confirmed - 1)
    expect((await findings({ triage: ['accepted_risk'] })).map(f => f.id)).toEqual([idor.id])
    expect((await invoke('getFinding', { scanId: completedScan, findingId: idor.id })).triageNote).toBe(
      'Support console needs it.',
    )

    // A later scan of the same workspace sees the same disposition.
    const next = await invoke('createScan', { workspaceId: WS_ID, mode: 'deep' })
    await h.settle(next.scanId)
    const again = (await invoke('listFindings', { scanId: next.scanId })).find(f => f.fingerprint === idor.fingerprint)
    // (`isNew` is relative to the previous completed scan, here a deterministic-only one, so it is not checked.)
    expect(again?.triage).toBe('accepted_risk')
    expect(again?.id).not.toBe(idor.id)

    await invoke('setTriage', { scanId: next.scanId, findingId: again?.id ?? '', triage: 'open' })
    expect((await findingAt('src/routes/orders.ts', 26)).triage).toBe('open')
  })

  it('estimates a scan without touching the network or a model', async () => {
    const calls = llm.calls.length
    const deep = await invoke('estimateScan', { workspaceId: WS_ID, mode: 'deep' })
    expect(deep).toMatchObject({ files: 17, endpoints: 15, truncated: false, dependencyManifests: 2 })
    expect(deep.frameworks).toContain('express')
    expect(deep.languages[0]).toMatchObject({ language: 'typescript' })
    expect(deep.plannedTasks).toBeGreaterThan(0)
    expect(deep.plannedTasks).toBeLessThanOrEqual(120)
    expect(deep.tokens.min).toBeLessThan(deep.tokens.max)
    const quick = await invoke('estimateScan', { workspaceId: WS_ID, mode: 'quick' })
    expect(quick.plannedTasks).toBeLessThanOrEqual(18)
    expect(quick.tokens.max).toBeLessThanOrEqual(deep.tokens.max)
    expect(llm.calls.length).toBe(calls)
    expect((await failure(invoke('estimateScan', { workspaceId: 'nope', mode: 'deep' }))).code).toBe(
      'security/not-found',
    )
  })
})

describe('exports and lifecycle', () => {
  it('renders all three report formats for a completed scan', async () => {
    const markdown = await invoke('exportReport', { scanId: completedScan, format: 'markdown' })
    expect(markdown.mime).toMatch(/^text\/markdown/)
    expect(markdown.filename).toMatch(/^dsh-security-express-shop-.*\.md$/)
    expect(markdown.content).toContain('IDOR: any signed-in customer can read any order')
    expect(markdown.content).not.toMatch(KANA)
    // A Japanese scan renders Japanese Markdown labels.
    const ja = await invoke('exportReport', { scanId: japaneseScan, format: 'markdown' })
    expect(ja.content).toMatch(KANA)
    const json = await invoke('exportReport', { scanId: completedScan, format: 'json' })
    const parsed = JSON.parse(json.content) as { findings: unknown[] }
    expect(parsed.findings.length).toBe((await findings()).length)
    const sarif = await invoke('exportReport', { scanId: completedScan, format: 'sarif' })
    const log = JSON.parse(sarif.content) as { version: string; runs: { results: unknown[] }[] }
    expect(log.version).toBe('2.1.0')
    expect(log.runs[0]?.results.length).toBeGreaterThan(0)
  })

  it('refuses to export a running scan and deletes a running scan after cancelling it', async () => {
    const gated = gatedLlm(await oracleLlm(), options => roleOf(options) === 'hunter')
    const harness = createHarness({ llm: gated, workspaces, settings: AI_SETTINGS })
    const service = makeHandlers(harness, gated, workspaces)
    const { scanId } = await service.createScan({ workspaceId: WS_ID, mode: 'deep' }, call())
    await gated.waitForHeld(1)
    const live = await service.getScan({ scanId }, call())
    expect(live.summary.status).toBe('running')
    expect(live.workers.some(w => w.state === 'running')).toBe(true)
    expect((await failure(service.exportReport({ scanId, format: 'json' }, call()))).code).toBe(
      'security/invalid-state',
    )
    expect((await failure(service.resumeScan({ scanId }, call()))).code).toBe('security/invalid-state')

    expect(await service.deleteScan({ scanId }, call())).toEqual({ deleted: true })
    expect(harness.controller.isRunning(scanId)).toBe(false)
    expect(harness.store.getScan(scanId)).toBeUndefined()
    expect((await failure(service.getScan({ scanId }, call()))).code).toBe('security/not-found')
    expect((await failure(service.deleteScan({ scanId }, call()))).code).toBe('security/not-found')
    gated.open()
  })

  it('pauses, exports, resumes, and cancels through the RPC handlers', async () => {
    const gated = gatedLlm(await oracleLlm(), options => roleOf(options) === 'hunter')
    const harness = createHarness({ llm: gated, workspaces, settings: AI_SETTINGS })
    const service = makeHandlers(harness, gated, workspaces)
    const { scanId } = await service.createScan({ workspaceId: WS_ID, mode: 'deep' }, call())
    await gated.waitForHeld(1)
    await service.pauseScan({ scanId }, call())
    await harness.settle(scanId)
    expect((await service.getScan({ scanId }, call())).summary.status).toBe('paused')
    // A paused scan can be exported as a partial report.
    expect((await service.exportReport({ scanId, format: 'markdown' }, call())).content.length).toBeGreaterThan(0)
    gated.open()
    expect((await service.resumeScan({ scanId }, call())).status).toBe('queued')
    expect(await harness.settle(scanId)).toBe('completed')
    expect((await failure(service.pauseScan({ scanId }, call()))).code).toBe('security/invalid-state')
    expect((await failure(service.cancelScan({ scanId }, call()))).code).toBe('security/invalid-state')
    await harness.controller.dispose()
  })

  it('never puts an absolute workspace path in a response, except display paths and fix prompts', () => {
    expect(ready).toBe(true)
    expect(responses.length).toBeGreaterThan(20)
    for (const { method, json } of responses) {
      const value: unknown = JSON.parse(json)
      const scrubbed = JSON.stringify(value, (key, field: unknown) =>
        key === 'displayPath' || (method === 'getFixPrompt' && key === 'prompt') ? undefined : field,
      )
      for (const root of [shop.root, HOME_PROJECT]) {
        expect(scrubbed.includes(root), `${method} leaks ${root}`).toBe(false)
      }
    }
  })
})
