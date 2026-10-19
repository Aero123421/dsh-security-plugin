import { describe, expect, it } from 'vitest'
import { resolveTargetPath } from '../../../src/host/agents/tools/paths.ts'
import type { EvidenceRecord, TaskRecord } from '../../../src/host/core/model.ts'
import { targetIndex } from '../../../src/host/scan/planning.ts'
import {
  coverageLedger,
  directoryTree,
  type RawUnit,
  resolveUnits,
  unitId,
  validExclusions,
} from '../../../src/host/scan/units.ts'
import { fileOf, snapshotOf } from '../analysis/helpers.ts'
import { endpointOf, findingRecord } from './factories.ts'

const snapshot = snapshotOf({
  'src/app.ts': 'x\n',
  'src/routes/orders.ts': 'x\n',
  'src/routes/admin.ts': 'x\n',
  'src/lib/db.ts': 'x\n',
  'src/lib/render.ts': 'x\n',
  'src/middleware/auth.ts': 'x\n'.repeat(5),
  'src/services/payments.ts': 'x\n',
  'tests/routes/orders.test.ts': 'x\n',
})
const withheld = (path: string) => path === 'src/lib/render.ts'
const inScope = (path: string) => !withheld(path) && snapshot.files.get(path)?.isTest !== true
const index = targetIndex(snapshot, inScope)
const resolve = (target: string) => {
  const resolution = resolveTargetPath(target, index)
  return {
    paths: resolution.paths.filter(path => !withheld(path)),
    suggestions: resolution.suggestions.filter(path => !withheld(path)),
  }
}
const raw = (title: string, ...targets: string[]): RawUnit => ({
  title,
  focus: ['authz'],
  target_paths: targets,
  priority: 'high',
  rationale: 'r',
})
const options = { resolve, inScope, limit: 40, origin: 'recon' as const }

describe('resolveUnits', () => {
  it('resolves how planners spell targets', () => {
    const { units, unresolved, dropped } = resolveUnits(
      [
        raw('dot slash', './src/routes/orders.ts'),
        raw('leading slash', '/src/routes/admin.ts'),
        raw('root placeholder', '<root>/src/lib/db.ts'),
        raw('backslashes', 'src\\services\\payments.ts'),
        raw('line suffix', 'src/app.ts:12'),
        raw('directory', 'src/middleware'),
        raw('missing prefix', 'routes/orders.ts', 'src/app.ts'),
        raw('typo', 'src/route/ordrs.ts'),
        raw('withheld only', 'src/lib/render.ts'),
        raw('tests only', 'tests/routes/orders.test.ts'),
      ],
      options,
    )
    expect(Object.fromEntries(units.map(u => [u.title, u.targetPaths]))).toEqual({
      'dot slash': ['src/routes/orders.ts'],
      'leading slash': ['src/routes/admin.ts'],
      'root placeholder': ['src/lib/db.ts'],
      backslashes: ['src/services/payments.ts'],
      'line suffix': ['src/app.ts'],
      directory: ['src/middleware/auth.ts'],
      'missing prefix': ['src/routes/orders.ts', 'src/app.ts'],
    })
    // Unresolvable and withheld-only targets are reported for one correction request; out-of-scope ones drop.
    expect(unresolved.map(u => u.title)).toEqual(['typo', 'withheld only'])
    expect(unresolved[0]?.targets[0]?.suggestions).toContain('src/routes/orders.ts')
    expect(unresolved[1]?.targets[0]?.suggestions).not.toContain('src/lib/render.ts')
    expect(dropped).toBe(3)
    expect(units.every(u => u.origin === 'recon' && u.id === unitId(u.targetPaths, u.focus))).toBe(true)
  })

  it('drops duplicates (same files and focus, in any order), also of existing units, and keeps at most the limit', () => {
    const a = raw('A', 'src/app.ts', 'src/lib/db.ts')
    const sameFiles = raw('A again', 'src/lib/db.ts', './src/app.ts')
    const otherFocus = { ...raw('A crypto', 'src/app.ts', 'src/lib/db.ts'), focus: ['crypto' as const] }
    const first = resolveUnits([a, sameFiles, otherFocus], options)
    expect(first.units.map(u => u.title)).toEqual(['A', 'A crypto'])
    expect(first.dropped).toBe(1)
    const again = resolveUnits([sameFiles, raw('B', 'src/routes/admin.ts')], {
      ...options,
      existing: new Set(first.units.map(u => u.id)),
    })
    expect(again.units.map(u => u.title)).toEqual(['B'])
    const limited = resolveUnits([raw('1', 'src/app.ts'), raw('2', 'src/lib/db.ts'), raw('3', 'src/routes/admin.ts')], {
      ...options,
      limit: 2,
    })
    expect(limited.units.map(u => u.title)).toEqual(['1', '2'])
    expect(limited.dropped).toBe(1)
  })

  it('keeps at most 8 files per unit and scrubs and clips the model text', () => {
    const many = snapshotOf(Object.fromEntries(Array.from({ length: 12 }, (_, i) => [`src/f${i}.go`, 'package f\n'])))
    const manyIndex = targetIndex(many, () => true)
    const { units } = resolveUnits(
      [
        {
          ...raw('Secret sk_FAKE_123', ...Array.from({ length: 8 }, (_, i) => `src/f${i}.go`), 'src'),
          surface: '  ',
          component: 'api',
          hypothesis: 'h',
        },
      ],
      {
        ...options,
        resolve: target => resolveTargetPath(target, manyIndex),
        inScope: () => true,
        scrub: text => text.replace('sk_FAKE_123', '[REDACTED]'),
      },
    )
    expect(units[0]?.targetPaths).toHaveLength(8)
    expect(units[0]).toMatchObject({ title: 'Secret [REDACTED]', component: 'api', hypothesis: 'h' })
    expect(units[0]?.surface).toBeUndefined()
  })
})

describe('validExclusions', () => {
  it('keeps vendored, generated, docs and fixture paths that exist, and never the root', () => {
    const paths = ['vendor/lib/a.php', 'src/gen/api.ts', 'docs/guide.md', 'tests/fixtures/x.json', 'src/app.ts']
    expect(
      validExclusions(
        [
          { path: 'vendor/', reason: 'Vendored third-party library' },
          { path: './src/gen', reason: 'generated by protoc' },
          { path: 'docs', reason: 'Documentation' },
          { path: 'tests/fixtures', reason: 'test fixtures' },
          { path: 'src/app.ts', reason: 'not important' },
          { path: '.', reason: 'vendored' },
          { path: 'missing', reason: 'vendored' },
        ],
        paths,
      ),
    ).toEqual([
      { path: 'vendor', reason: 'vendored' },
      { path: 'src/gen', reason: 'generated' },
      { path: 'docs', reason: 'docs' },
      { path: 'tests/fixtures', reason: 'fixtures' },
    ])
  })
})

describe('directoryTree', () => {
  it('lists directories with counts, languages and markers, collapsing depth to fit', () => {
    const files = [
      fileOf('src/main/java/com/shop/OrderController.java', 'class A {}'),
      fileOf('src/main/java/com/shop/Auth.java', 'class B {}'),
      fileOf('vendor/lib/a.php', '<?php'),
      fileOf('tests/a_test.go', 'package a'),
      fileOf('main.go', 'package main'),
    ]
    expect(directoryTree(files)).toEqual([
      '(root)  1 file (go 1)',
      'src/main/java/com/  2 files (java 2)',
      'tests/  1 file (go 1) [tests]',
      'vendor/lib/  1 file (php 1) [vendored?]',
    ])
    const wide = Array.from({ length: 200 }, (_, i) => fileOf(`pkg${i % 100}/sub${i}/f.go`, 'package f'))
    const rows = directoryTree(wide, 60)
    expect(rows.length).toBeLessThanOrEqual(61)
    expect(rows.at(-1)).toBe('… 40 smaller directories not shown')
  })
})

describe('coverageLedger', () => {
  const task = (key: string, overrides: Partial<TaskRecord> = {}): TaskRecord => ({
    id: `t-${key}`,
    scanId: 's',
    key,
    kind: 'hunt-unit',
    role: 'hunter',
    title: key,
    status: 'done',
    priority: 1,
    input: { targetPaths: ['src/app.ts'], focus: ['authz'], unitId: `unit:${key}`, origin: 'recon' },
    attempts: 1,
    createdAt: '2026-10-01T00:00:00.000Z',
    ...overrides,
  })
  const evidence = (id: string, taskId: string): EvidenceRecord => ({
    id,
    scanId: 's',
    taskId,
    origin: 'hunter',
    kind: 'source_span',
    trust: 'observed',
    claim: 'c',
    quoteCheck: 'match',
    createdAt: '2026-10-01T00:00:00.000Z',
  })

  it('maps tasks to units by outcome, and adds the unassigned files', () => {
    const endpoint = endpointOf('GET', '/orders/:id', 'src/routes/orders.ts', 1)
    const tasks: TaskRecord[] = [
      task('found'),
      task('refuted'),
      task('runtime', { outcome: { coverage: 'needs-runtime', coverageNote: 'Depends on the proxy.' } }),
      task('partial', { outcome: { coverage: 'partial' } }),
      task('clean', { outcome: { coverage: 'complete' } }),
      task('budget', { status: 'skipped', error: { code: 'budget', message: 'm' } }),
      task('limit', { status: 'skipped', error: { code: 'task-limit', message: 'm' } }),
      task('failed', { status: 'failed', error: { code: 'INTERNAL', message: 'm' } }),
      task('rejected', { status: 'skipped', error: { code: 'provider-route-rejected', message: 'm' } }),
      // As failTask records a provider refusal (the provider's own code goes in the message).
      task('blocked', {
        status: 'failed',
        error: { code: 'blocked_by_provider', message: 'CONTENT_FILTER: The response was filtered.' },
      }),
      task('toolless', { status: 'skipped', error: { code: 'provider-route-no-tools', message: 'm' } }),
      task('consent', { status: 'skipped', error: { code: 'consent-revoked', message: 'm' } }),
      task('stale', { status: 'skipped', error: { code: 'stale-target', message: 'm' } }),
      task('pending', { status: 'pending' }),
      task('endpoints:src/routes/orders.ts#0', {
        kind: 'hunt-endpoints',
        title: 'Review 1 endpoint in src/routes/orders.ts',
        input: { targetPaths: ['src/routes/orders.ts'], focus: ['authz'], endpointIds: [endpoint.id] },
      }),
      task('hypothesis:abc', { kind: 'hunt-hypothesis', input: { targetPaths: [], focus: ['authz'] } }),
      // Re-planned with an endpoint added on resume: same unit, new task key.
      task('clean:refresh:0123', {
        input: { targetPaths: ['src/app.ts'], focus: ['authz'], unitId: 'unit:clean', origin: 'recon' },
      }),
      task('threat-model', { kind: 'threat-model', role: 'planner' }),
      task('review:x', { kind: 'review', role: 'skeptic' }),
    ]
    const units = coverageLedger({
      tasks,
      findings: [
        findingRecord({ id: 'f1', supportEvidenceIds: ['e1', 'e2'] }),
        findingRecord({ id: 'f2', supportEvidenceIds: ['e3'], verification: 'refuted' }),
      ],
      evidence: [evidence('e1', 't-found'), evidence('e2', 't-found'), evidence('e3', 't-refuted')],
      endpoints: new Map([[endpoint.id, endpoint]]),
      unassigned: { paths: ['src/a.go', 'src/b.go'], reason: 'budget' },
    })
    const byId = Object.fromEntries(units.map(u => [u.id, u]))
    expect(byId['unit:found']).toMatchObject({ status: 'finding', findings: 1, origin: 'recon' })
    // A finding the reviewer refuted does not count.
    expect(byId['unit:refuted']).toMatchObject({ status: 'covered', findings: 0 })
    expect(byId['unit:runtime']).toMatchObject({
      status: 'blocked',
      reason: { code: 'needs-runtime', params: { note: 'Depends on the proxy.' } },
    })
    expect(byId['unit:partial']).toMatchObject({ status: 'blocked', reason: { code: 'partial' } })
    expect(byId['unit:clean']?.status).toBe('covered')
    expect(byId['unit:clean']?.reason).toBeUndefined()
    const notRun = Object.fromEntries(
      units.filter(u => u.status === 'not-run').map(u => [u.id, u.reason?.code] as const),
    )
    expect(notRun).toEqual({
      'unit:budget': 'budget',
      'unit:limit': 'task-limit',
      'unit:failed': 'failed',
      'unit:rejected': 'provider-rejected',
      'unit:blocked': 'provider-rejected',
      'unit:toolless': 'no-tools',
      'unit:consent': 'consent-revoked',
      'unit:stale': 'stale-target',
      'unit:pending': 'budget',
      unassigned: 'budget',
    })
    // Gap tasks become units too; their surface comes from their endpoints; older hypothesis tasks were planned.
    expect(byId['endpoints:src/routes/orders.ts#0']).toMatchObject({
      origin: 'gap',
      surface: 'GET /orders/:id',
      title: 'Review 1 endpoint in src/routes/orders.ts',
    })
    expect(byId['hypothesis:abc']?.origin).toBe('recon')
    expect(byId['hypothesis:abc']?.kind).toBe('legacy')
    expect(byId['endpoints:src/routes/orders.ts#0']?.kind).toBe('endpoints')
    expect(byId['unit:found']?.kind).toBe('plan')
    expect(byId.unassigned?.kind).toBeUndefined()
    expect(byId['clean:refresh:0123']?.status).toBe('covered')
    expect(new Set(units.map(u => u.id)).size).toBe(units.length)
    expect(byId.unassigned).toMatchObject({
      title: '2 source files not assigned to any review unit',
      paths: ['src/a.go', 'src/b.go'],
      reason: { code: 'budget', params: { count: 2 } },
      origin: 'gap',
    })
    // Planner, reviewer and chain tasks are not coverage units.
    expect(units.some(u => u.id === 'threat-model' || u.id === 'review:x')).toBe(false)
    expect(units.every(u => u.reason === undefined || u.reason.fallback.length > 0)).toBe(true)
  })

  it('tells what produced each Host-made unit, so the UI can localize its title', () => {
    const made = (key: string, kind: TaskRecord['kind']) =>
      task(key, { kind, input: { targetPaths: ['src/app.ts'], focus: ['authz'], origin: 'gap' } })
    const units = coverageLedger({
      tasks: [
        made('endpoints:src/app.ts#0', 'hunt-endpoints'),
        made('signals:src/app.ts#0', 'hunt-signals'),
        made('triage:src/app.ts#0', 'triage-signals'),
        made('sweep:0123456789abcdef', 'hunt-file'),
        made('file:src/app.ts', 'hunt-file'),
        made('hypothesis:abc', 'hunt-hypothesis'),
      ],
      findings: [],
      evidence: [],
      endpoints: new Map(),
      unassigned: { paths: [], reason: 'task-limit' },
    })
    expect(units.map(u => [u.id, u.kind])).toEqual([
      ['endpoints:src/app.ts#0', 'endpoints'],
      ['signals:src/app.ts#0', 'signals'],
      ['triage:src/app.ts#0', 'triage'],
      ['sweep:0123456789abcdef', 'sweep'],
      ['file:src/app.ts', 'file'],
      ['hypothesis:abc', 'legacy'],
    ])
  })
})
