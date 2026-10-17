import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'
import { extractRoutes } from '../../../src/host/analysis/routes/index.ts'
import { takeSnapshot } from '../../../src/host/analysis/snapshot.ts'
import type { Endpoint, Signal, Snapshot, SnapshotFile } from '../../../src/host/analysis/types.ts'
import { signalFingerprint } from '../../../src/host/scan/findings.ts'
import { type HuntPlanInput, type Hypothesis, planHuntTasks, planReviewTasks } from '../../../src/host/scan/planning.ts'
import { DEFAULT_BUDGETS } from '../../../src/shared/settings.ts'
import { fileOf, snapshotOf } from '../analysis/helpers.ts'
import { endpointOf, findingRecord, signalOf } from './factories.ts'

const FILES: Record<string, string> = {
  'src/app.ts': 'app.use(router)\n',
  'src/routes/orders.ts': 'router.get("/:id", handler)\n'.repeat(20),
  'src/routes/admin.ts': 'router.get("/users", handler)\n',
  'src/lib/db.ts': 'export function query(sql) { return pool.query(sql) }\n',
  'src/lib/render.ts': 'export const render = html => html\n',
  'src/middleware/auth.ts': 'export function requireAuth(req, res, next) { next() }\n'.repeat(5),
  'src/services/payments.ts': 'export function charge() {}\n',
  'src/services/tokens.py': 'def issue(): pass\n'.repeat(3),
  'docs/auth.md': '# Auth\n',
  'tests/routes/orders.test.ts': 'it("works", () => {})\n',
}

function snapshot(extra: readonly SnapshotFile[] = []): Snapshot {
  const base = snapshotOf(FILES)
  const files = new Map(base.files)
  for (const file of extra) files.set(file.path, file)
  return { ...base, files }
}

function plan(overrides: Partial<HuntPlanInput>) {
  return planHuntTasks({
    mode: 'deep',
    snapshot: snapshot(),
    endpoints: [],
    signals: [],
    hypotheses: [],
    includeTests: false,
    maxTasks: 100,
    ...overrides,
  })
}

const at = (path: string, line: number) => ({ path, startLine: line, endLine: line })

describe('planHuntTasks — quick mode', () => {
  it('triages medium-or-worse vulnerability signals before endpoint tasks', () => {
    const signals: Signal[] = [
      signalOf({ location: at('src/lib/db.ts', 1), severity: 'high' }),
      signalOf({ location: at('src/lib/db.ts', 2), severity: 'medium', ruleId: 'js.ssrf', category: 'ssrf' }),
      signalOf({ location: at('src/lib/render.ts', 1), severity: 'low' }),
      signalOf({ location: at('src/routes/admin.ts', 1), kind: 'sink', severity: 'critical' }),
      signalOf({ location: at('src/app.ts', 1), kind: 'secret', category: 'secrets', severity: 'critical' }),
      signalOf({ location: at('tests/routes/orders.test.ts', 1), severity: 'critical' }),
    ]
    const result = plan({
      mode: 'quick',
      signals,
      endpoints: [endpointOf('GET', '/orders/:id', 'src/routes/orders.ts', 1)],
      hypotheses: [{ title: 'IDOR', category: 'authz', targetPaths: ['src/routes/orders.ts'], rationale: 'r' }],
    })
    expect(result.overflow).toBe(0)
    expect(result.tasks).toHaveLength(2)
    expect(result.tasks[0]!.priority).toBeGreaterThan(result.tasks[1]!.priority)
    const [task] = result.tasks
    expect(task).toMatchObject({
      key: 'triage:src/lib/db.ts#0',
      kind: 'triage-signals',
      role: 'hunter',
      title: 'Verify 2 rule hits in src/lib/db.ts',
      input: { targetPaths: ['src/lib/db.ts'], focus: ['injection', 'ssrf'] },
    })
    // Most severe first.
    expect(task?.input.signalFingerprints).toEqual([signalFingerprint(signals[0]!), signalFingerprint(signals[1]!)])
  })

  it('fills spare quick slots with endpoints even when no vulnerability rule fires', () => {
    const endpoints = [
      endpointOf('GET', '/public', 'src/public.ts', 1),
      endpointOf('POST', '/orders', 'src/orders.ts', 1),
      endpointOf('POST', '/guarded', 'src/guarded.ts', 1, { authHints: ['requireAuth'] }),
      ...Array.from({ length: DEFAULT_BUDGETS.quick.maxTasks }, (_, i) =>
        endpointOf('GET', `/extra/${i}`, `src/extra${i}.ts`, 1),
      ),
    ]
    const { tasks } = plan({ mode: 'quick', endpoints, maxTasks: DEFAULT_BUDGETS.quick.maxTasks })
    expect(tasks).toHaveLength(DEFAULT_BUDGETS.quick.maxTasks)
    expect(tasks[0]?.input.targetPaths).toEqual(['src/orders.ts'])
    expect(tasks.every(t => t.kind === 'hunt-endpoints')).toBe(true)
    const triaged = plan({ mode: 'quick', endpoints, signals: [signalOf()], maxTasks: 1 })
    expect(triaged.tasks).toHaveLength(1)
    expect(triaged.tasks[0]?.kind).toBe('triage-signals')
  })

  it('chunks more than 12 hits of one file into several tasks', () => {
    const signals = Array.from({ length: 13 }, (_, i) => signalOf({ location: at('src/lib/db.ts', i + 1) }))
    const { tasks } = plan({ mode: 'quick', signals })
    expect(tasks.map(t => t.key).sort()).toEqual(['triage:src/lib/db.ts#0', 'triage:src/lib/db.ts#1'])
    expect(tasks.map(t => t.input.signalFingerprints?.length).sort()).toEqual([1, 12])
    expect(tasks.find(t => t.key.endsWith('#1'))?.title).toBe('Verify 1 rule hit in src/lib/db.ts')
  })

  it('plans nothing without vulnerability signals', () => {
    expect(plan({ mode: 'quick' }).tasks).toEqual([])
  })
})

describe('planHuntTasks — deep and research modes', () => {
  it('groups endpoints per file in chunks of at most 8, attaching file signals to the first chunk', () => {
    const endpoints = Array.from({ length: 10 }, (_, i) =>
      endpointOf(i % 2 === 0 ? 'GET' : 'POST', `/orders/${i}`, 'src/routes/orders.ts', 20 - i, { params: ['id'] }),
    )
    const signals = [
      signalOf({ location: at('src/routes/orders.ts', 4), kind: 'sink', severity: 'low', category: 'xss' }),
      signalOf({ location: at('src/routes/orders.ts', 3), severity: 'high' }),
    ]
    const { tasks } = plan({ endpoints, signals })
    const first = tasks.find(t => t.key === 'endpoints:src/routes/orders.ts#0')
    const second = tasks.find(t => t.key === 'endpoints:src/routes/orders.ts#1')
    expect(first?.input.endpointIds).toHaveLength(8)
    expect(second?.input.endpointIds).toHaveLength(2)
    // Ordered by declaration line within the file.
    expect(first?.input.endpointIds?.[0]).toBe('POST /orders/9 @ src/routes/orders.ts:11')
    expect(second?.input.endpointIds).toEqual([
      'POST /orders/1 @ src/routes/orders.ts:19',
      'GET /orders/0 @ src/routes/orders.ts:20',
    ])
    expect(first?.input.signalFingerprints).toEqual([signalFingerprint(signals[1]!), signalFingerprint(signals[0]!)])
    expect(second?.input.signalFingerprints).toBeUndefined()
    expect(first).toMatchObject({
      kind: 'hunt-endpoints',
      role: 'hunter',
      title: 'Review 8 endpoints in src/routes/orders.ts',
    })
    expect(first?.input.focus).toEqual(['authz', 'authn', 'injection', 'business-logic', 'xss'])
    expect(second?.input.focus).toEqual(['authz', 'authn', 'injection', 'business-logic', 'xss'])
    // The file's signals are covered by the endpoint task, not a separate signal task.
    expect(tasks.some(t => t.kind === 'hunt-signals')).toBe(false)
  })

  it('ranks unguarded and mutating endpoints higher', () => {
    const guarded = endpointOf('GET', '/users', 'src/routes/admin.ts', 1, {
      middleware: ['requireAuth'],
      authHints: ['requireAuth'],
    })
    const open = endpointOf('DELETE', '/orders/:id', 'src/routes/orders.ts', 1, { params: ['id'] })
    const { tasks } = plan({ endpoints: [guarded, open] })
    const admin = tasks.find(t => t.key === 'endpoints:src/routes/admin.ts#0')
    const orders = tasks.find(t => t.key === 'endpoints:src/routes/orders.ts#0')
    expect(admin?.priority).toBe(50)
    expect(orders?.priority).toBe(50 + 4 + 3 + 2)
    expect(tasks.indexOf(orders!)).toBeLessThan(tasks.indexOf(admin!))
  })

  it('targets both the router file and a handler declared in another file', () => {
    const endpoint = endpointOf('GET', '/orders/:id', 'src/app.ts', 1, {
      handler: { path: 'src/routes/orders.ts', startLine: 3, endLine: 9 },
    })
    const { tasks } = plan({ endpoints: [endpoint] })
    const task = tasks.find(t => t.kind === 'hunt-endpoints')
    expect(task?.key).toBe('endpoints:src/routes/orders.ts#0')
    expect(task?.input.targetPaths).toEqual(['src/routes/orders.ts', 'src/app.ts'])
  })

  it('creates signal tasks for files without endpoints, sinks included', () => {
    const signals = [
      signalOf({ location: at('src/lib/db.ts', 1), kind: 'sink', severity: 'medium' }),
      signalOf({ location: at('src/lib/render.ts', 1), severity: 'low', category: 'xss' }),
      signalOf({ location: at('src/app.ts', 1), kind: 'info', severity: 'info' }),
    ]
    const { tasks } = plan({ signals })
    const keys = tasks.filter(t => t.kind === 'hunt-signals').map(t => t.key)
    expect(keys.sort()).toEqual(['signals:src/lib/db.ts#0', 'signals:src/lib/render.ts#0'])
    expect(tasks.find(t => t.key === 'signals:src/lib/db.ts#0')).toMatchObject({
      title: 'Trace 1 risky operation in src/lib/db.ts',
      input: { targetPaths: ['src/lib/db.ts'], signalFingerprints: [signalFingerprint(signals[0]!)] },
    })
  })

  it('turns hypotheses into tasks ranked by the planner order', () => {
    const hypotheses: Hypothesis[] = [
      { title: 'Order IDOR', category: 'authz', targetPaths: ['src/routes/orders.ts'], rationale: 'by id only' },
      {
        title: 'Admin without auth',
        category: 'authn',
        targetPaths: ['src/routes/admin.ts', 'src/app.ts', 'src/routes/admin.ts', 'a', 'b', 'c', 'd', 'e'],
        rationale: 'mounted without guard',
      },
      { title: 'Test-only', category: 'other', targetPaths: ['tests/routes/orders.test.ts'], rationale: 'x' },
    ]
    const { tasks } = plan({ hypotheses })
    const hyp = tasks.filter(t => t.kind === 'hunt-hypothesis')
    expect(hyp.map(t => t.title)).toEqual(['Order IDOR', 'Admin without auth'])
    expect(hyp.map(t => t.priority)).toEqual([70, 69])
    expect(hyp[0]?.key).toMatch(/^hypothesis:[0-9a-f]{16}$/)
    expect(hyp[1]?.input).toEqual({
      targetPaths: ['src/routes/admin.ts', 'src/app.ts', 'a', 'b', 'c', 'd'],
      focus: ['authn'],
      hypothesis: 'Admin without auth\nmounted without guard',
    })
    // Hypotheses outrank ordinary endpoint groups.
    const withEndpoints = plan({ hypotheses, endpoints: [endpointOf('GET', '/', 'src/app.ts', 1)] }).tasks
    expect(withEndpoints[0]?.kind).toBe('hunt-hypothesis')
  })

  it('adds the 6 largest sensitive source files nobody targets yet', () => {
    const extra = [
      fileOf('src/auth/session.ts', 'x\n'.repeat(900)),
      fileOf('src/auth/jwt.ts', 'x\n'.repeat(800)),
      fileOf('src/admin/panel.ts', 'x\n'.repeat(700)),
      fileOf('src/billing/invoice.ts', 'x\n'.repeat(600)),
      fileOf('src/services/payments.ts', 'x\n'.repeat(500)),
      fileOf('src/generated/auth.ts', 'x\n'.repeat(1000), { isGenerated: true }),
    ]
    const { tasks } = plan({
      snapshot: snapshot(extra),
      endpoints: [endpointOf('POST', '/login', 'src/auth/session.ts', 1)],
    })
    const files = tasks.filter(t => t.key.startsWith('file:'))
    // The 6 largest candidates (src/routes/admin.ts, 30 bytes, is the 7th), ranked by key at equal priority.
    expect(files.map(t => t.key)).toEqual([
      'file:src/admin/panel.ts',
      'file:src/auth/jwt.ts',
      'file:src/billing/invoice.ts',
      'file:src/middleware/auth.ts',
      'file:src/services/payments.ts',
      'file:src/services/tokens.py',
    ])
    expect(files[1]).toMatchObject({
      role: 'hunter',
      priority: 45,
      title: 'Review security-sensitive logic in src/auth/jwt.ts',
      input: { targetPaths: ['src/auth/jwt.ts'], focus: ['authn', 'authz', 'business-logic', 'crypto'] },
    })
    // Already targeted (src/auth/session.ts), generated, test, and non-source files are left out.
    const keys = files.map(t => t.key)
    expect(keys).not.toContain('file:src/auth/session.ts')
    expect(keys).not.toContain('file:src/generated/auth.ts')
    expect(keys).not.toContain('file:docs/auth.md')
    // Quick mode never adds them.
    expect(plan({ mode: 'quick', snapshot: snapshot(extra) }).tasks).toEqual([])
  })

  it.each(['deep', 'research'] as const)(
    'sweeps otherwise-untargeted source files in %s within remaining budget',
    mode => {
      const extra = Array.from({ length: 24 }, (_, i) => fileOf(`src/plain${i}.ts`, 'x'.repeat(i + 1)))
      const snap = snapshot([
        ...extra,
        fileOf('src/generated.ts', 'x', { isGenerated: true }),
        fileOf('tests/huge.test.ts', 'x'.repeat(100_000)),
        fileOf('src/hidden.ts', 'x'),
      ])
      const input = {
        mode,
        snapshot: snap,
        endpoints: [endpointOf('POST', '/orders', 'src/routes/orders.ts', 1)],
        signals: [signalOf({ location: at('src/lib/db.ts', 1) })],
        isWithheld: (path: string) => path === 'src/hidden.ts',
      }
      const full = plan(input)
      const sweep = full.tasks.filter(t => t.key.startsWith('sweep:'))
      expect(sweep.length).toBeGreaterThan(0)
      expect(sweep.every((task, i) => i === 0 || sweep[i - 1]!.priority > task.priority)).toBe(true)
      expect(Math.max(...sweep.map(t => t.priority))).toBeLessThan(
        Math.min(...full.tasks.filter(t => !t.key.startsWith('sweep:')).map(t => t.priority)),
      )
      expect(sweep.flatMap(t => t.input.targetPaths)).toContain('src/plain23.ts')
      const targets = full.tasks.flatMap(t => t.input.targetPaths)
      expect(new Set(targets).size).toBe(targets.length)
      expect(targets).not.toContain('src/generated.ts')
      expect(targets).not.toContain('src/hidden.ts')
      expect(targets).not.toContain('tests/huge.test.ts')
      const beforeSweep = full.tasks.length - sweep.length
      for (const maxTasks of [0, 1, 2, beforeSweep, beforeSweep + 1]) {
        const bounded = plan({ ...input, maxTasks })
        expect(bounded.tasks.length).toBeLessThanOrEqual(maxTasks)
        expect(bounded.tasks).toEqual(full.tasks.slice(0, maxTasks))
        if (maxTasks <= 2) expect(bounded.tasks.every(t => !t.key.startsWith('sweep:'))).toBe(true)
      }
      expect(plan({ ...input, maxTasks: 2 }).tasks.map(t => t.kind)).toEqual(['hunt-endpoints', 'hunt-signals'])
      const included = plan({ ...input, includeTests: true }).tasks.filter(t => t.key.startsWith('sweep:'))
      const sweptPaths = included.flatMap(t => t.input.targetPaths)
      expect(sweptPaths).toContain('tests/huge.test.ts')
      expect(sweptPaths.indexOf('tests/huge.test.ts')).toBeGreaterThan(sweptPaths.indexOf('src/plain0.ts'))
      expect(
        plan({ ...input, includeTests: true, maxTasks: beforeSweep + 1 }).tasks.at(-1)?.input.targetPaths,
      ).not.toContain('tests/huge.test.ts')
    },
  )

  it('ranks sensitive names ahead of size when they overflow the sensitive-file family', () => {
    const snap = snapshotOf(
      Object.fromEntries([
        ...Array.from({ length: 8 }, (_, i) => [`src/security/settings${i}.ts`, 'x']),
        ['src/large.ts', 'x'.repeat(10_000)],
      ]),
    )
    const { tasks } = plan({ snapshot: snap, maxTasks: 7 })
    expect(tasks.at(-1)?.key).toMatch(/^sweep:/)
    expect(tasks.at(-1)?.input.targetPaths.slice(0, 2)).toEqual([
      'src/security/settings6.ts',
      'src/security/settings7.ts',
    ])
  })

  it('targets the previously missed Flask configuration with default deep planning', async () => {
    const root = fileURLToPath(new URL('../../fixtures/apps/flask-secure/', import.meta.url))
    const snap = await takeSnapshot(root, {
      excludeGlobs: ['README.md', 'expected.json'],
      maxFiles: 1000,
      maxFileBytes: 1_000_000,
      maxTotalBytes: 10_000_000,
    })
    const { endpoints } = await extractRoutes(snap)
    expect(endpoints.length).toBeGreaterThan(0)
    const { tasks } = plan({ snapshot: snap, endpoints, maxTasks: DEFAULT_BUDGETS.deep.maxTasks })
    expect(tasks.flatMap(t => t.input.targetPaths)).toContain('app/config.py')
  })

  it('excludes test files unless includeTests is set', () => {
    const endpoints = [endpointOf('GET', '/t', 'tests/routes/orders.test.ts', 1)]
    const signals = [signalOf({ location: at('tests/routes/orders.test.ts', 1) })]
    const hypotheses: Hypothesis[] = [
      { title: 'Test helper leaks', category: 'other', targetPaths: ['tests/routes/orders.test.ts'], rationale: 'r' },
    ]
    const excluded = plan({ endpoints, signals, hypotheses }).tasks
    expect(excluded.some(t => t.input.targetPaths.some(p => p.startsWith('tests/')))).toBe(false)

    const included = plan({ endpoints, signals, hypotheses, includeTests: true }).tasks
    expect(included.map(t => t.key)).toEqual(
      expect.arrayContaining(['endpoints:tests/routes/orders.test.ts#0', expect.stringMatching(/^hypothesis:/)]),
    )
    expect(plan({ mode: 'quick', signals }).tasks).toEqual([])
    expect(plan({ mode: 'quick', signals, includeTests: true }).tasks).toHaveLength(1)
  })

  it('produces the same tasks and keys for the same input in any order', () => {
    const endpoints = [
      endpointOf('GET', '/orders/:id', 'src/routes/orders.ts', 2),
      endpointOf('GET', '/users', 'src/routes/admin.ts', 1),
    ]
    const signals = [signalOf({ location: at('src/lib/db.ts', 1) }), signalOf({ location: at('src/lib/render.ts', 2) })]
    const hypotheses: Hypothesis[] = [{ title: 'A', category: 'authz', targetPaths: ['src/app.ts'], rationale: 'r' }]
    const a = plan({ endpoints, signals, hypotheses })
    const b = plan({ endpoints: [...endpoints].reverse(), signals: [...signals].reverse(), hypotheses })
    expect(b).toEqual(a)
    expect(plan({ endpoints, signals, hypotheses })).toEqual(a)
    expect(new Set(a.tasks.map(t => t.key)).size).toBe(a.tasks.length)
  })

  it('cuts the ranked list at maxTasks and reports the overflow', () => {
    const endpoints = ['a', 'b', 'c', 'd'].map(n => endpointOf('GET', `/${n}`, `src/routes/${n}.ts`, 1))
    const hypotheses: Hypothesis[] = [{ title: 'H', category: 'authz', targetPaths: ['src/app.ts'], rationale: 'r' }]
    const full = plan({ endpoints, hypotheses })
    const cut = plan({ endpoints, hypotheses, maxTasks: 2 })
    expect(cut.tasks).toEqual(full.tasks.slice(0, 2))
    expect(cut.overflow).toBe(full.tasks.length - 2)
    expect(cut.tasks[0]?.kind).toBe('hunt-hypothesis')
    expect(plan({ endpoints, maxTasks: 100 }).overflow).toBe(0)
  })
})

describe('planReviewTasks', () => {
  const findings = [
    findingRecord({ id: 'low-ai', title: 'Low', severity: 'low', source: 'ai' }),
    findingRecord({ id: 'med-sast', title: 'Medium', severity: 'medium', source: 'sast' }),
    findingRecord({ id: 'high-b', title: 'B high', severity: 'high', source: 'external' }),
    findingRecord({ id: 'high-a', title: 'A high', severity: 'high', source: 'ai', category: 'authz' }),
    findingRecord({ id: 'crit', title: 'Critical', severity: 'critical', source: 'ai', location: undefined }),
    findingRecord({ id: 'secret', title: 'Secret', severity: 'critical', source: 'secret' }),
    findingRecord({ id: 'dep', title: 'Dep', severity: 'critical', source: 'dependency' }),
    findingRecord({ id: 'done', title: 'Confirmed', severity: 'critical', verification: 'strong_static_evidence' }),
    findingRecord({ id: 'refuted', title: 'Refuted', severity: 'critical', verification: 'refuted' }),
    findingRecord({ id: 'info', title: 'Info', severity: 'info' }),
  ]

  it('plans nothing in quick mode', () => {
    expect(planReviewTasks(findings, 'quick', 'info', 100)).toEqual([])
  })

  it('reviews potential ai/sast/external findings at or above the threshold, most severe first', () => {
    const tasks = planReviewTasks(findings, 'deep', 'medium', 100)
    expect(tasks.map(t => t.input.findingId)).toEqual(['crit', 'high-a', 'high-b', 'med-sast'])
    expect(tasks[0]).toEqual({
      key: 'review:crit',
      kind: 'review',
      role: 'skeptic',
      title: 'Review: Critical',
      priority: 100,
      input: { targetPaths: [], findingId: 'crit', focus: ['injection'] },
    })
    expect(tasks[1]).toMatchObject({ priority: 90, input: { targetPaths: ['src/app.ts'], focus: ['authz'] } })
    expect(planReviewTasks(findings, 'deep', 'high', 100).map(t => t.input.findingId)).toEqual([
      'crit',
      'high-a',
      'high-b',
    ])
  })

  it('lowers the threshold to low in research mode', () => {
    const tasks = planReviewTasks(findings, 'research', 'critical', 100)
    expect(tasks.map(t => t.input.findingId)).toEqual(['crit', 'high-a', 'high-b', 'med-sast', 'low-ai'])
  })

  it('caps the number of reviews', () => {
    expect(planReviewTasks(findings, 'deep', 'low', 2).map(t => t.input.findingId)).toEqual(['crit', 'high-a'])
  })
})

describe('endpoint grouping', () => {
  it('uses the declaration file when no handler was located', () => {
    const endpoint: Endpoint = endpointOf('GET', '/x', 'src/routes/admin.ts', 3)
    expect(plan({ endpoints: [endpoint] }).tasks[0]?.input.targetPaths).toEqual(['src/routes/admin.ts'])
  })
})
