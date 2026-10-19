/**
 * The review plan end to end: reconnaissance units in every AI mode and any
 * language, the coverage critic and its budget, gap filling, the coverage
 * ledger, and resume with a stored plan or with tasks from before the plan.
 */

import { mkdir, mkdtemp, realpath, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import type { LlmGenerateOptions, LlmStreamChunk } from '../../../src/host/dsh/ports.ts'
import { initialPhases } from '../../../src/host/scan/pipeline.ts'
import type { SettingsPatch } from '../../../src/shared/settings.ts'
import { callReply } from '../agents/runtime/helpers.ts'
import { scanRecord } from './factories.ts'
import {
  AI_SETTINGS,
  copyFixture,
  createHarness,
  gatedLlm,
  type Harness,
  ORACLE_MODEL,
  ORACLE_PROVIDER,
  roleOf,
  scriptedLlm,
  type TempWorkspace,
} from './helpers.ts'

/** A Java/PHP/Go service the route extractors do not know, plus a vendored copy and docs. */
const POLYGLOT: Record<string, string> = {
  'src/main/java/com/shop/OrderController.java': [
    'package com.shop;',
    '@RestController',
    'public class OrderController {',
    '  @GetMapping("/orders/{id}")',
    '  public Order get(@PathVariable long id) { return repo.findById(id); }',
    '}',
    '',
  ].join('\n'),
  'src/main/java/com/shop/AuthFilter.java': 'package com.shop;\npublic class AuthFilter { }\n',
  'app/Http/Controllers/UserController.php': '<?php\nclass UserController { public function show($id) { } }\n',
  'internal/api/handlers.go': 'package api\n\nfunc Export(w http.ResponseWriter, r *http.Request) {}\n',
  'cmd/server/main.go': 'package main\n\nfunc main() {}\n',
  'tools/upstream/lib.go': 'package upstream\n\nfunc Helper() {}\n',
  'docs/architecture.md': '# Architecture\n',
}

let polyglot: string
let shop: TempWorkspace

beforeAll(async () => {
  polyglot = await realpath(await mkdtemp(join(tmpdir(), 'dshsec-polyglot-')))
  for (const [path, text] of Object.entries(POLYGLOT)) {
    await mkdir(dirname(join(polyglot, path)), { recursive: true })
    await writeFile(join(polyglot, path), text)
  }
  shop = await copyFixture('express-shop')
})

afterAll(async () => {
  await rm(polyglot, { recursive: true, force: true })
  await shop.cleanup()
})

const unit = (title: string, path: string, extra: Record<string, unknown> = {}) => ({
  title,
  focus: ['authz', 'injection'],
  target_paths: [path],
  priority: 'high',
  rationale: `Check ${title}.`,
  ...extra,
})

interface Script {
  /** Arguments of submit_review_plan. */
  readonly recon?: () => Record<string, unknown>
  /** Arguments of submit_coverage_review for pass 1, 2, … */
  readonly critic?: (pass: number) => Record<string, unknown>
  /** Extra submit_findings arguments, by the unit's first starting file. */
  readonly hunter?: (start: string | undefined) => Record<string, unknown>
  /** Replies a hunter investigates before submitting (default 1). */
  readonly hunterTurns?: number
}

function textOf(options: LlmGenerateOptions): string {
  return options.messages[0]?.content.map(block => (block as { text?: string }).text ?? '').join('\n') ?? ''
}

/** A model that plays every role from `script`; hunters read their first starting file before submitting. */
function scriptedModel(script: Script) {
  let id = 0
  return scriptedLlm(async function* (options): AsyncGenerator<LlmStreamChunk> {
    const role = roleOf(options)
    const task = textOf(options)
    const replies = options.messages.filter(message => message.role === 'assistant').length
    if (role === 'planner') {
      yield* callReply(`p${++id}`, 'submit_review_plan', script.recon?.() ?? { summary: 'A service.' })
      return
    }
    if (role === 'critic') {
      const pass = Number(/critic pass (\d+)/.exec(task)?.[1] ?? 1)
      yield* callReply(`c${++id}`, 'submit_coverage_review', script.critic?.(pass) ?? { done: true })
      return
    }
    if (role === 'skeptic') {
      yield* callReply(`k${++id}`, 'submit_verdict', { verdict: 'inconclusive', reasoning: 'Not decided here.' })
      return
    }
    if (role === 'chain') {
      yield* callReply(`x${++id}`, 'submit_chains', { chains: [] })
      return
    }
    const start = /Start with these files:\n- (\S+)/.exec(task)?.[1]
    const lastChance = /Call submit_\w+ now|This is your final turn|budget for this work is used up/.test(
      JSON.stringify(options.messages.at(-1)),
    )
    if (!lastChance && replies < (script.hunterTurns ?? 1)) {
      yield* start ? callReply(`r${++id}`, 'read_file', { path: start }) : callReply(`l${++id}`, 'list_files', {})
      return
    }
    const ids = [...task.matchAll(/^(S\d+):/gm)].map(match => match[1])
    yield* callReply(`h${++id}`, 'submit_findings', {
      findings: [],
      signal_assessments: ids.map(s => ({ id: s, verdict: 'uncertain', reason: 'Not decided here.' })),
      ...script.hunter?.(start),
    })
  })
}

const polyglotPlan = () => ({
  summary: 'A shop service in Java with a PHP admin and a Go export API.',
  components: [{ name: 'orders', paths: ['src/main/java/com/shop'] }],
  units: [
    unit('Order API', 'src/main/java/com/shop/OrderController.java', { surface: 'GET /orders/{id}' }),
    unit('User admin', 'app/Http/Controllers/UserController.php', { surface: 'GET /users/{id}' }),
    unit('Export API', 'internal/api/handlers.go', { component: 'export' }),
  ],
  excluded: [{ path: 'tools/upstream', reason: 'vendored copy of an upstream tool' }],
})

async function scan(
  h: Harness,
  mode: 'quick' | 'deep' | 'research',
  workspaceId = 'poly',
): Promise<{ id: string; harness: Harness }> {
  const created = await h.controller.create({ workspaceId, mode })
  expect(await h.settle(created.id)).toBe('completed')
  return { id: created.id, harness: h }
}

function harness(llm: ReturnType<typeof scriptedLlm>, settings: SettingsPatch = AI_SETTINGS) {
  return createHarness({
    llm,
    workspaces: [
      { id: 'poly', path: polyglot, title: 'polyglot' },
      { id: 'shop', path: shop.root, title: 'shop' },
    ],
    settings,
  })
}

describe('reconnaissance units in any language', () => {
  it.each(['quick', 'deep'] as const)('plan and run Java, PHP and Go units in %s', async mode => {
    const llm = scriptedModel({
      recon: polyglotPlan,
      hunter: start =>
        start?.endsWith('.php') ? { coverage: 'needs-runtime', coverage_note: 'Depends on the web server.' } : {},
    })
    const { id, harness: h } = await scan(harness(llm), mode)
    const record = h.store.getScan(id)
    expect(record?.threatModel?.units?.map(u => u.targetPaths)).toEqual([
      ['src/main/java/com/shop/OrderController.java'],
      ['app/Http/Controllers/UserController.php'],
      ['internal/api/handlers.go'],
    ])
    expect(record?.threatModel?.components).toEqual([
      {
        name: 'orders',
        paths: expect.arrayContaining(['src/main/java/com/shop/OrderController.java']),
      },
    ])
    expect(record?.threatModel?.excluded).toEqual([{ path: 'tools/upstream', reason: 'vendored' }])
    const units = h.store.listTasks(id).filter(t => t.kind === 'hunt-unit')
    expect(units).toHaveLength(3)
    expect(units.every(t => t.status === 'done')).toBe(true)
    // The hunter is told what its unit is.
    const prompt = JSON.stringify(llm.calls.filter(call => call.sessionId === units[0]?.id)[0]?.messages[0])
    expect(prompt).toContain('Entry surface: GET /orders/{id}')

    const ledger = record?.coverage?.units ?? []
    const byTitle = Object.fromEntries(ledger.map(u => [u.title, u]))
    expect(byTitle['Order API']).toMatchObject({ status: 'covered', origin: 'recon', surface: 'GET /orders/{id}' })
    expect(byTitle['User admin']).toMatchObject({
      status: 'blocked',
      reason: { code: 'needs-runtime', params: { note: 'Depends on the web server.' } },
    })
    expect(byTitle['Export API']).toMatchObject({ status: 'covered', component: 'export' })
    // The remaining sources are swept (the excluded vendored copy is not); nothing is left unassigned.
    const swept = ledger.filter(u => u.origin === 'gap').flatMap(u => u.paths)
    expect(swept.sort()).toEqual(['cmd/server/main.go', 'src/main/java/com/shop/AuthFilter.java'])
    expect(record?.coverage?.unassignedFiles).toBe(0)
    expect(record?.coverage?.gapDetails).toContainEqual(expect.objectContaining({ code: 'excluded-by-plan' }))
    // Quick has no critic; Deep runs one pass.
    expect(h.store.listTasks(id).filter(t => t.kind === 'critic')).toHaveLength(mode === 'quick' ? 0 : 1)
  })

  it('falls back to the Host gap filling when reconnaissance submits nothing usable', async () => {
    const llm = scriptedModel({ recon: () => ({ summary: 'A service.', units: [unit('Gone', 'no/such/file.go')] }) })
    const { id, harness: h } = await scan(harness(llm), 'quick')
    expect(h.store.listTasks(id).some(t => t.kind === 'hunt-unit')).toBe(false)
    expect(h.store.listTasks(id).find(t => t.kind === 'threat-model')?.outcome).toMatchObject({
      units: 0,
      dropped: 1,
    })
    const swept = h.store
      .listTasks(id)
      .filter(t => t.key.startsWith('sweep:'))
      .flatMap(t => t.input.targetPaths)
    expect(swept).toContain('src/main/java/com/shop/OrderController.java')
    // The unresolved unit was sent back once with suggestions before it was dropped.
    expect(llm.calls.filter(call => roleOf(call) === 'planner')).toHaveLength(2)
  })
})

describe('coverage critic', () => {
  it('adds units for gaps in Deep, runs a wave for them and records them as critic units', async () => {
    const llm = scriptedModel({
      recon: polyglotPlan,
      critic: () => ({ units: [unit('Auth filter', 'src/main/java/com/shop/AuthFilter.java', { focus: ['authn'] })] }),
    })
    const { id, harness: h } = await scan(harness(llm), 'deep')
    const critic = h.store.listTasks(id).filter(t => t.kind === 'critic')
    expect(critic).toMatchObject([{ key: 'critic:1', status: 'done', outcome: { units: 1, done: false } }])
    // The critic saw the ledger so far and the files nobody read.
    const criticPrompt = JSON.stringify(llm.calls.find(call => roleOf(call) === 'critic')?.messages[0])
    expect(criticPrompt).toContain(
      '[covered] Order API — GET /orders/{id} — src/main/java/com/shop/OrderController.java',
    )
    expect(criticPrompt).toContain('Source files no reviewer opened')
    const added = h.store.listTasks(id).find(t => t.kind === 'hunt-unit' && t.input.origin === 'critic')
    expect(added).toMatchObject({ title: 'Auth filter', status: 'done' })
    expect(h.store.getScan(id)?.coverage?.units?.find(u => u.title === 'Auth filter')).toMatchObject({
      origin: 'critic',
      status: 'covered',
    })
    expect(h.events(id).some(e => e.type === 'coverage-critic')).toBe(true)
  })

  it('runs at most two passes in Research and stops when a pass finds nothing to add', async () => {
    const proposals = [
      [unit('Auth filter', 'src/main/java/com/shop/AuthFilter.java', { focus: ['authn'] })],
      [unit('Server bootstrap', 'cmd/server/main.go', { focus: ['misconfiguration'] })],
      [unit('Never asked', 'internal/api/handlers.go', { focus: ['ssrf'] })],
    ]
    const llm = scriptedModel({ recon: polyglotPlan, critic: pass => ({ units: proposals[pass - 1] ?? [] }) })
    const { id, harness: h } = await scan(harness(llm), 'research')
    expect(
      h.store
        .listTasks(id)
        .filter(t => t.kind === 'critic')
        .map(t => t.key),
    ).toEqual(['critic:1', 'critic:2'])
    expect(
      h.store
        .listTasks(id)
        .filter(t => t.input.origin === 'critic')
        .map(t => t.title)
        .sort(),
    ).toEqual(['Auth filter', 'Server bootstrap'])

    const stopping = scriptedModel({ recon: polyglotPlan, critic: () => ({ done: true }) })
    const second = await scan(harness(stopping), 'research')
    expect(second.harness.store.listTasks(second.id).filter(t => t.kind === 'critic')).toHaveLength(1)
  })

  const routerUnits = () =>
    Array.from({ length: 10 }, (_, i) =>
      unit(`Router ${i}`, 'src/routes/orders.ts', { focus: [['authz', 'injection', 'ssrf', 'xss', 'crypto'][i % 5]] }),
    ).map((u, i) => ({ ...u, target_paths: [['src/routes/orders.ts', 'src/routes/admin.ts'][i % 2]] }))
  const tightBudget = (parallelWorkers: number): SettingsPatch => ({
    ...AI_SETTINGS,
    scan: { parallelWorkers, reviewThreshold: 'critical' },
    budgets: { deep: { maxLlmCalls: 100 } },
  })

  it('keeps budget back for the critic: the first wave leaves room, then the rest of the hunt runs', async () => {
    const units = routerUnits()
    const llm = scriptedModel({
      recon: () => ({ summary: 'A shop.', units }),
      critic: () => ({ units: [unit('Webhooks', 'src/routes/webhooks.ts', { focus: ['ssrf', 'authn'] })] }),
      hunterTurns: 8,
    })
    const h = harness(llm, tightBudget(1))
    const { id } = await scan(h, 'deep', 'shop')
    const runs = h.store.listAgentRuns(id)
    const criticRun = runs.find(run => run.title.startsWith('Check review coverage'))
    expect(criticRun?.status).toBe('submitted')
    // Tasks the wave ceiling left for later are shown to the critic as queued, not as failed gaps.
    const criticPrompt = textOf(llm.calls.find(call => roleOf(call) === 'critic') as LlmGenerateOptions)
    expect(criticPrompt).toMatch(/Units already queued for the next review wave \((\d+)/)
    expect(criticPrompt).not.toContain('not-run: failed')
    expect(criticPrompt).toContain('[queued] Router')
    expect(h.store.getScan(id)?.coverage?.units?.some(u => u.reason?.code === 'failed')).toBe(false)
    // Hunting went on after the critic: the reserve was for the critic, not taken from the hunt.
    const after = runs.filter(run => run.role === 'hunter' && run.startedAt > (criticRun?.startedAt ?? ''))
    expect(after.length).toBeGreaterThan(0)
    expect(h.store.getScan(id)?.usage.llmCalls).toBeLessThanOrEqual(100)
    // What did not fit is in the ledger as not run for budget.
    const ledger = h.store.getScan(id)?.coverage?.units ?? []
    expect(ledger.some(u => u.status === 'not-run' && u.reason?.code === 'budget')).toBe(true)
  })

  it('stops wave hunters at the wave ceiling, so long tasks started in parallel cannot use up the critic reserve', async () => {
    const units = routerUnits()
    const llm = scriptedModel({
      recon: () => ({ summary: 'A shop.', units }),
      critic: () => ({ done: true }),
      hunterTurns: 20,
    })
    const h = harness(llm, tightBudget(3))
    const { id } = await scan(h, 'deep', 'shop')
    expect(h.store.listTasks(id).filter(t => t.kind === 'critic')).toMatchObject([{ status: 'done' }])
    expect(h.store.getScan(id)?.usage.llmCalls).toBeLessThanOrEqual(100)
    // Wave hunters were asked to wrap up at the wave ceiling.
    expect(h.events(id).some(e => e.type === 'worker-wrap-up')).toBe(true)
  })
})

describe('gap filling and the task limit', () => {
  it('records work beyond the task limit as not run, and gives every rule hit a task', async () => {
    const llm = scriptedModel({
      recon: () => ({ summary: 'A shop.', units: [unit('Orders', 'src/routes/orders.ts')] }),
    })
    const settings: SettingsPatch = { ...AI_SETTINGS, budgets: { deep: { maxTasks: 4 } } }
    const h = harness(llm, settings)
    const { id } = await scan(h, 'deep', 'shop')
    const hunts = h.store.listTasks(id).filter(t => t.role === 'hunter')
    const limited = hunts.filter(t => t.error?.code === 'task-limit')
    expect(limited.length).toBeGreaterThan(0)
    expect(limited.every(t => t.status === 'skipped' && t.attempts === 0)).toBe(true)
    expect(hunts.filter(t => t.status === 'done')).toHaveLength(4)
    const ledger = h.store.getScan(id)?.coverage?.units ?? []
    expect(ledger.filter(u => u.reason?.code === 'task-limit').length).toBe(limited.length + 1)
    expect(ledger.find(u => u.id === 'unassigned')).toMatchObject({ status: 'not-run', reason: { code: 'task-limit' } })
    expect(h.store.getScan(id)?.coverage?.unassignedFiles).toBeGreaterThan(0)
    // Every reportable rule hit sits in some hunt task, run or not.
    const fingerprints = new Set(hunts.flatMap(t => t.input.signalFingerprints ?? []))
    const ruleFindings = h.store.listFindings(id).filter(f => f.source === 'sast' && !f.location?.path.includes('test'))
    expect(ruleFindings.length).toBeGreaterThan(0)
    for (const finding of ruleFindings) expect(fingerprints.has(finding.fingerprint)).toBe(true)
  })

  it('has no ledger for a scan with the built-in analyzers only', async () => {
    const h = harness(scriptedModel({}))
    const created = await h.controller.create({ workspaceId: 'poly', mode: 'deep', aiReview: false })
    await h.settle(created.id)
    const coverage = h.store.getScan(created.id)?.coverage
    expect(coverage?.units).toBeUndefined()
    expect(coverage?.unassignedFiles).toBeUndefined()
  })
})

describe('resume', () => {
  it('never runs reconnaissance again once the plan is stored', async () => {
    const inner = scriptedModel({ recon: polyglotPlan })
    const llm = gatedLlm(inner, options => roleOf(options) === 'hunter')
    const h = createHarness({
      llm,
      workspaces: [{ id: 'poly', path: polyglot, title: 'polyglot' }],
      settings: AI_SETTINGS,
    })
    const created = await h.controller.create({ workspaceId: 'poly', mode: 'deep' })
    await llm.waitForHeld(1)
    h.controller.pause(created.id)
    expect(await h.settle(created.id)).toBe('paused')
    const plan = h.store.getScan(created.id)?.threatModel
    expect(plan?.units).toHaveLength(3)
    llm.open()
    h.controller.resume(created.id)
    expect(await h.settle(created.id)).toBe('completed')
    expect(llm.calls.filter(call => roleOf(call) === 'planner')).toHaveLength(1)
    expect(h.store.getScan(created.id)?.threatModel).toEqual(plan)
    expect(h.store.listTasks(created.id).filter(t => t.kind === 'hunt-unit' && t.status === 'done')).toHaveLength(3)
  })

  it('runs and reports the tasks of a scan planned before coverage units existed', async () => {
    const h = createHarness({
      llm: scriptedModel({ recon: polyglotPlan }),
      workspaces: [{ id: 'shop', path: shop.root, title: 'shop' }],
      settings: AI_SETTINGS,
    })
    const route = { provider: ORACLE_PROVIDER, model: ORACLE_MODEL }
    const frozen = h.settings.get().settings
    const old = (mode: 'quick' | 'deep', id: string) =>
      scanRecord({
        id,
        workspaceId: 'shop',
        workspaceRoot: shop.root,
        mode,
        status: 'interrupted',
        startedAt: '2026-10-01T10:00:00.000Z',
        settings: frozen,
        budget: frozen.budgets[mode],
        models: { planner: route, hunter: route, skeptic: route },
        // Quick scans of earlier versions skipped the threat-model phase.
        phases: initialPhases(mode, true).map(p =>
          p.phase === 'threat-model' && mode === 'quick' ? { ...p, state: 'skipped' as const } : p,
        ),
        ...(mode === 'deep'
          ? {
              threatModel: {
                summary: 'A shop.',
                assets: [],
                actors: [],
                trustBoundaries: [],
                priorities: [],
                hypotheses: [
                  { title: 'Order IDOR', category: 'authz', targetPaths: ['src/routes/orders.ts'], rationale: 'r' },
                ],
              },
            }
          : {}),
      })
    const oldTask = (scanId: string, key: string, kind: 'hunt-hypothesis' | 'hunt-file' | 'hunt-endpoints') =>
      h.store.ensureTask({
        id: `${scanId}-${key}`,
        scanId,
        key,
        kind,
        role: 'hunter',
        title: `old ${key}`,
        status: 'pending',
        priority: 70,
        input: { targetPaths: ['src/routes/orders.ts'], focus: ['authz'] },
        attempts: 0,
        createdAt: '2026-10-01T10:00:00.000Z',
      })
    h.store.insertScan(old('deep', 'old-deep'))
    oldTask('old-deep', 'hypothesis:0123456789abcdef', 'hunt-hypothesis')
    oldTask('old-deep', 'file:src/middleware/auth.ts', 'hunt-file')
    h.store.insertScan(old('quick', 'old-quick'))
    oldTask('old-quick', 'endpoints:src/routes/orders.ts#0', 'hunt-endpoints')

    h.controller.start()
    for (const id of ['old-deep', 'old-quick']) {
      h.controller.resume(id)
      expect(await h.settle(id)).toBe('completed')
    }
    // No reconnaissance in the middle of an older scan.
    expect(h.store.listTasks('old-deep').some(t => t.kind === 'threat-model')).toBe(false)
    expect(h.store.listTasks('old-quick').some(t => t.kind === 'threat-model')).toBe(false)
    expect(h.store.getScan('old-deep')?.threatModel?.units).toBeUndefined()
    for (const key of ['hypothesis:0123456789abcdef', 'file:src/middleware/auth.ts']) {
      expect(h.store.listTasks('old-deep').find(t => t.key === key)?.status).toBe('done')
    }
    const ledger = h.store.getScan('old-deep')?.coverage?.units ?? []
    expect(ledger.find(u => u.id === 'hypothesis:0123456789abcdef')).toMatchObject({ origin: 'recon' })
    expect(ledger.find(u => u.id === 'file:src/middleware/auth.ts')).toMatchObject({ origin: 'gap' })
    expect(h.store.listTasks('old-quick').find(t => t.key === 'endpoints:src/routes/orders.ts#0')?.status).toBe('done')
  })
})
