import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'
import { extractRoutes } from '../../../src/host/analysis/routes/index.ts'
import { takeSnapshot } from '../../../src/host/analysis/snapshot.ts'
import type { Endpoint, Signal, Snapshot, SnapshotFile } from '../../../src/host/analysis/types.ts'
import { signalFingerprint } from '../../../src/host/scan/findings.ts'
import { type HuntPlanInput, planHuntTasks, planReviewTasks } from '../../../src/host/scan/planning.ts'
import { DEFAULT_BUDGETS } from '../../../src/shared/settings.ts'
import { fileOf, snapshotOf } from '../analysis/helpers.ts'
import { endpointOf, findingRecord, signalOf, unitOf } from './factories.ts'

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
    units: [],
    includeTests: false,
    maxTasks: 100,
    ...overrides,
  })
}

const at = (path: string, line: number) => ({ path, startLine: line, endLine: line })
const notSweep = (tasks: readonly { key: string }[]) => tasks.filter(t => !t.key.startsWith('sweep:'))

describe('planHuntTasks — quick mode', () => {
  it('triages medium-or-worse rule hits first, then the plan units, then endpoints no unit covers', () => {
    const signals: Signal[] = [
      signalOf({ location: at('src/lib/db.ts', 1), severity: 'high' }),
      signalOf({ location: at('src/lib/db.ts', 2), severity: 'medium', ruleId: 'js.ssrf', category: 'ssrf' }),
      signalOf({ location: at('src/lib/render.ts', 1), severity: 'low' }),
      signalOf({ location: at('src/routes/admin.ts', 1), kind: 'sink', severity: 'critical' }),
      signalOf({ location: at('src/app.ts', 1), kind: 'secret', category: 'secrets', severity: 'critical' }),
      signalOf({ location: at('tests/routes/orders.test.ts', 1), severity: 'critical' }),
    ]
    const unit = unitOf('Orders IDOR', ['src/routes/orders.ts'])
    const result = plan({
      mode: 'quick',
      signals,
      endpoints: [
        endpointOf('GET', '/orders/:id', 'src/routes/orders.ts', 1),
        endpointOf('POST', '/users', 'src/routes/admin.ts', 1),
      ],
      units: [unit],
      budgetTasks: 4,
    })
    expect(result.overflow).toBeGreaterThan(0)
    // The SQL sink in admin.ts is a sink of a high-severity rule, so it is triaged too.
    expect(result.tasks.map(t => t.key)).toEqual([
      'triage:src/lib/db.ts#0',
      'triage:src/routes/admin.ts#0',
      unit.id,
      'endpoints:src/routes/admin.ts#0',
    ])
    const [task] = result.tasks
    expect(task).toMatchObject({
      key: 'triage:src/lib/db.ts#0',
      kind: 'triage-signals',
      role: 'hunter',
      title: 'Verify 2 rule hits in src/lib/db.ts',
      input: { targetPaths: ['src/lib/db.ts'], focus: ['injection', 'ssrf'], origin: 'gap' },
    })
    // Most severe first.
    expect(task?.input.signalFingerprints).toEqual([signalFingerprint(signals[0]!), signalFingerprint(signals[1]!)])
    // The unit covers the orders endpoint, so no endpoint task repeats it.
    expect(result.tasks[2]?.input.endpointIds).toEqual(['GET /orders/:id @ src/routes/orders.ts:1'])
    expect(result.tasks.map(t => t.priority)).toEqual([...result.tasks.map(t => t.priority)].sort((a, b) => b - a))
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
    const tasks = notSweep(plan({ mode: 'quick', signals }).tasks)
    expect(tasks.map(t => t.key).sort()).toEqual(['triage:src/lib/db.ts#0', 'triage:src/lib/db.ts#1'])
    const full = plan({ mode: 'quick', signals }).tasks
    expect(
      full
        .filter(t => t.kind === 'triage-signals')
        .map(t => t.input.signalFingerprints?.length)
        .sort(),
    ).toEqual([1, 12])
    expect(full.find(t => t.key.endsWith('#1'))?.title).toBe('Verify 1 rule hit in src/lib/db.ts')
  })

  it('plans only sweeps, within the budget room, without rule hits, endpoints or units', () => {
    expect(notSweep(plan({ mode: 'quick' }).tasks)).toEqual([])
    expect(plan({ mode: 'quick', budgetTasks: 0 }).tasks).toEqual([])
    expect(plan({ mode: 'quick', budgetTasks: 1 }).tasks).toHaveLength(1)
  })
})

describe('planHuntTasks — coverage units', () => {
  it('turns each unit into a hunt-unit task carrying its context, ranked by priority then plan order', () => {
    const units = [
      unitOf('Admin area', ['src/routes/admin.ts', 'src/app.ts'], {
        priority: 'medium',
        surface: 'GET /users',
        component: 'admin',
      }),
      unitOf('Orders', ['src/routes/orders.ts'], { priority: 'critical', hypothesis: 'IDOR by id' }),
      unitOf('Tokens', ['src/services/tokens.py'], { priority: 'critical', focus: ['crypto', 'authn'] }),
    ]
    const { tasks } = plan({ units })
    const unitTasks = tasks.filter(t => t.kind === 'hunt-unit')
    expect(unitTasks.map(t => t.title)).toEqual(['Orders', 'Tokens', 'Admin area'])
    expect(unitTasks[0]?.priority).toBeGreaterThan(unitTasks[1]!.priority)
    expect(unitTasks[1]!.priority).toBeGreaterThan(80)
    expect(unitTasks[2]).toMatchObject({
      key: units[0]!.id,
      role: 'hunter',
      input: {
        targetPaths: ['src/routes/admin.ts', 'src/app.ts'],
        focus: ['authz'],
        unitId: units[0]!.id,
        origin: 'recon',
        component: 'admin',
        surface: 'GET /users',
        rationale: 'Check Admin area.',
      },
    })
    expect(unitTasks[0]?.input.hypothesis).toBe('IDOR by id')
    // Units outrank gap endpoint groups of ordinary risk.
    const withEndpoints = plan({ units, endpoints: [endpointOf('GET', '/', 'src/lib/render.ts', 1)] }).tasks
    expect(withEndpoints[0]?.kind).toBe('hunt-unit')
  })

  it('gives units the rule hits, sinks and endpoints of their files; gap tasks take the rest', () => {
    const hit = signalOf({ location: at('src/routes/orders.ts', 3), severity: 'high' })
    const sink = signalOf({ location: at('src/routes/orders.ts', 5), kind: 'sink', severity: 'high' })
    const elsewhere = signalOf({ location: at('src/lib/db.ts', 1), severity: 'high' })
    const lonelySink = signalOf({ location: at('src/lib/render.ts', 1), kind: 'sink', severity: 'medium' })
    const inUnit = endpointOf('GET', '/orders/:id', 'src/routes/orders.ts', 1)
    const declaredInUnit = endpointOf('GET', '/orders', 'src/routes/orders.ts', 2, {
      handler: { path: 'src/services/payments.ts', startLine: 1, endLine: 1 },
    })
    const outside = endpointOf('GET', '/users', 'src/routes/admin.ts', 1)
    const unit = unitOf('Orders', ['src/routes/orders.ts'])
    const { tasks } = plan({
      units: [unit],
      signals: [hit, sink, elsewhere, lonelySink],
      endpoints: [inUnit, declaredInUnit, outside],
    })
    const task = tasks.find(t => t.kind === 'hunt-unit')
    expect(task?.input.signalFingerprints).toEqual([signalFingerprint(hit), signalFingerprint(sink)])
    // An endpoint whose route or handler file is in the unit belongs to it.
    expect(task?.input.endpointIds).toEqual([inUnit.id, declaredInUnit.id])
    expect(task?.input.focus).toEqual(['authz', 'injection'])
    expect(tasks.filter(t => t.kind === 'hunt-endpoints').map(t => t.input.endpointIds)).toEqual([[outside.id]])
    expect(tasks.find(t => t.kind === 'hunt-endpoints')?.input).toMatchObject({ origin: 'gap', surface: 'GET /users' })
    // Every rule hit is still assessed; a sink no task looks at gets a signal task of its own.
    expect(
      tasks
        .filter(t => t.kind === 'hunt-signals')
        .map(t => t.key)
        .sort(),
    ).toEqual(['signals:src/lib/db.ts#0', 'signals:src/lib/render.ts#0'])
  })

  it('sweeps no excluded path and reports what the room leaves unassigned', () => {
    const extra = [
      ...Array.from({ length: 10 }, (_, i) => fileOf(`src/plain${i}.ts`, 'x'.repeat(i + 1))),
      fileOf('vendor/lib/big.php', '<?php echo 1;'),
      fileOf('src/generated/client.ts', 'x'),
    ]
    const input = { snapshot: snapshot(extra), excluded: ['vendor', 'src/generated/client.ts'] }
    const full = plan(input)
    const swept = full.tasks.flatMap(t => t.input.targetPaths)
    expect(swept).not.toContain('vendor/lib/big.php')
    expect(swept).not.toContain('src/generated/client.ts')
    expect(full.unassigned).toEqual([])
    const limited = plan({ ...input, budgetTasks: 1 })
    expect(limited.tasks).toHaveLength(1)
    expect(limited.unassignedReason).toBe('budget')
    expect(limited.unassigned.length).toBeGreaterThan(0)
    expect(limited.unassigned).not.toContain('vendor/lib/big.php')
    expect(new Set([...limited.tasks.flatMap(t => t.input.targetPaths), ...limited.unassigned])).toEqual(new Set(swept))
    expect(plan({ ...input, maxTasks: 1 }).unassignedReason).toBe('task-limit')
    // Files other tasks target (critic units of a resumed scan) are not swept again.
    const targeted = plan({ ...input, targeted: new Set(['src/plain9.ts']) }).tasks.flatMap(t => t.input.targetPaths)
    expect(targeted).not.toContain('src/plain9.ts')
  })

  it('plans units in any language, and sweeps Java, PHP and Go sources', () => {
    const snap = snapshotOf({
      'src/main/java/com/shop/OrderController.java': 'class OrderController {}\n',
      'src/main/java/com/shop/AuthFilter.java': 'class AuthFilter {}\n',
      'app/Http/Controllers/UserController.php': '<?php class UserController {}\n',
      'internal/api/handlers.go': 'package api\n',
      'README.md': '# Shop\n',
    })
    const unit = unitOf('Order controller', ['src/main/java/com/shop/OrderController.java'])
    for (const mode of ['quick', 'deep'] as const) {
      const { tasks } = plan({ mode, snapshot: snap, units: [unit], maxTasks: 18 })
      expect(tasks[0]).toMatchObject({ kind: 'hunt-unit', key: unit.id })
      const swept = tasks.filter(t => t.key.startsWith('sweep:')).flatMap(t => t.input.targetPaths)
      expect(swept.sort()).toEqual([
        'app/Http/Controllers/UserController.php',
        'internal/api/handlers.go',
        'src/main/java/com/shop/AuthFilter.java',
      ])
    }
  })

  it('returns the tasks beyond maxTasks so they can be recorded as not run', () => {
    const units = ['a', 'b', 'c'].map(name => unitOf(name, [`src/routes/${name}.ts`]))
    const full = plan({ units })
    const limited = plan({ units, maxTasks: 1 })
    expect(limited.tasks.map(t => t.key)).toEqual([units[0]!.id])
    expect(limited.cut.map(t => t.key)).toEqual([units[1]!.id, units[2]!.id])
    expect(limited.overflow).toBeGreaterThanOrEqual(2)
    expect(notSweep(full.tasks)).toHaveLength(3)
  })
})

describe('planHuntTasks — gap filling without units', () => {
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
    expect(first?.input.surface).toBe('POST /orders/9, GET /orders/8, POST /orders/7 (+5 more)')
    const focus = [
      'authz',
      'authn',
      'injection',
      'command-execution',
      'ssrf',
      'path-traversal',
      'xss',
      'business-logic',
    ]
    expect(first?.input.focus).toEqual(focus)
    expect(second?.input.focus).toEqual(focus)
    // The file's signals are covered by the endpoint task, not a separate signal task.
    expect(tasks.some(t => t.kind === 'hunt-signals')).toBe(false)
  })

  it('gives rule hits beyond the first endpoint task their own signal tasks, so every hit is assessed', () => {
    const endpoints = [endpointOf('GET', '/r', 'src/routes/orders.ts', 1)]
    // Six high steering sinks plus fourteen medium vulnerability hits in one endpoint file (audit repro).
    const signals = [
      ...Array.from({ length: 6 }, (_, i) =>
        signalOf({ kind: 'sink', severity: 'high', ruleId: `sink${i}`, location: at('src/routes/orders.ts', 2 + i) }),
      ),
      ...Array.from({ length: 14 }, (_, i) =>
        signalOf({ severity: 'medium', ruleId: `vuln${i}`, location: at('src/routes/orders.ts', 10 + i) }),
      ),
    ]
    const { tasks } = plan({ endpoints, signals })
    const assigned = new Set(tasks.flatMap(t => t.input.signalFingerprints ?? []))
    const vulns = signals.filter(s => s.kind === 'vulnerability')
    expect(vulns.every(s => assigned.has(signalFingerprint(s)))).toBe(true)
    const spill = tasks.find(t => t.key === 'signals:src/routes/orders.ts#0')
    expect(spill).toMatchObject({ kind: 'hunt-signals', title: 'Trace 8 risky operations in src/routes/orders.ts' })
    // Quick triages rule hits on its own and needs no spill tasks.
    expect(plan({ mode: 'quick', endpoints, signals }).tasks.some(t => t.key.startsWith('signals:'))).toBe(false)
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
      expect(sweep[0]?.input).toMatchObject({ origin: 'gap' })
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

  it('sweeps sensitive names ahead of larger files', () => {
    const snap = snapshotOf(
      Object.fromEntries([
        ...Array.from({ length: 8 }, (_, i) => [`src/security/settings${i}.ts`, 'x']),
        ['src/large.ts', 'x'.repeat(10_000)],
      ]),
    )
    const { tasks } = plan({ snapshot: snap, maxTasks: 7 })
    expect(tasks.map(t => t.input.targetPaths)).toEqual([
      [
        'src/security/settings0.ts',
        'src/security/settings1.ts',
        'src/security/settings2.ts',
        'src/security/settings3.ts',
      ],
      [
        'src/security/settings4.ts',
        'src/security/settings5.ts',
        'src/security/settings6.ts',
        'src/security/settings7.ts',
      ],
      ['src/large.ts'],
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
    const excluded = plan({ endpoints, signals }).tasks
    expect(excluded.some(t => t.input.targetPaths.some(p => p.startsWith('tests/')))).toBe(false)

    const included = plan({ endpoints, signals, includeTests: true }).tasks
    expect(included.map(t => t.key)).toEqual(expect.arrayContaining(['endpoints:tests/routes/orders.test.ts#0']))
    expect(notSweep(plan({ mode: 'quick', signals }).tasks)).toEqual([])
    expect(notSweep(plan({ mode: 'quick', signals, includeTests: true }).tasks)).toHaveLength(1)
  })

  it('produces the same tasks and keys for the same input in any order', () => {
    const endpoints = [
      endpointOf('GET', '/orders/:id', 'src/routes/orders.ts', 2),
      endpointOf('GET', '/users', 'src/routes/admin.ts', 1),
    ]
    const signals = [signalOf({ location: at('src/lib/db.ts', 1) }), signalOf({ location: at('src/lib/render.ts', 2) })]
    const units = [unitOf('A', ['src/app.ts'])]
    const a = plan({ endpoints, signals, units })
    const b = plan({ endpoints: [...endpoints].reverse(), signals: [...signals].reverse(), units })
    expect(b).toEqual(a)
    expect(plan({ endpoints, signals, units })).toEqual(a)
    expect(new Set(a.tasks.map(t => t.key)).size).toBe(a.tasks.length)
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
