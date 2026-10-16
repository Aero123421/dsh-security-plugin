import { realpathSync, renameSync, symlinkSync } from 'node:fs'
import { cp, mkdir, mkdtemp, realpath, rm, symlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { createWorkspaceTools } from '../../../src/host/agents/tools/workspace.ts'
import { parseGitleaksReport } from '../../../src/host/analysis/external/gitleaks.ts'
import { parseSemgrepOutput } from '../../../src/host/analysis/external/semgrep.ts'
import { parseOsvScannerReport } from '../../../src/host/analysis/external/osv-scanner.ts'
import { requestSchemas } from '../../../src/host/rpc/schemas.ts'
import { analyzeWorkspace, snapshotWorkspace } from '../../../src/host/scan/analysis.ts'
import { resolveScanRoot } from '../../../src/host/scan/root.ts'
import { createHandlers } from '../../../src/host/service.ts'
import { scanParams } from '../../../src/host/store/records.ts'
import { MIGRATIONS } from '../../../src/host/store/schema.ts'
import { openSecurityStore } from '../../../src/host/store/sqlite.ts'
import { findingOf, scanOf } from '../store/fixtures.ts'
import { copyFixture, createHarness, type Harness, noNetwork, registryOf } from './helpers.ts'

let root: string
let h: Harness
const signal = () => new AbortController().signal
const call = () => ({ request: new Request('http://localhost/'), loopback: true, signal: signal() })
const workspace = () => ({ id: 'new-uuid', title: 'Umbrella', path: root })

beforeEach(async () => {
  root = await realpath(await mkdtemp(join(tmpdir(), 'dsh-subpath-')))
  await mkdir(join(root, 'packages', 'a'), { recursive: true })
  await mkdir(join(root, 'packages', 'b'), { recursive: true })
  await writeFile(join(root, 'file.txt'), 'outside selected scope')
  h = createHarness({ workspaces: [workspace()] })
})

afterEach(async () => {
  await h.controller.dispose()
  h.store.close()
  await rm(root, { recursive: true, force: true })
})

function handlers(list = [workspace()]) {
  return createHandlers({
    ...h,
    llm: () => undefined,
    workspaces: () => registryOf(list),
    astGrep: async () => undefined,
    toolkit: undefined,
    pluginVersion: 'test',
    now: () => new Date(),
  })
}

async function scan(subpath?: string) {
  const result = await h.controller.create({ workspaceId: workspace().id, mode: 'quick', aiReview: false, subpath })
  expect(await h.settle(result.id)).toBe('completed')
  return result.id
}

describe('subfolder admission', () => {
  it.each([
    '/tmp',
    '../outside',
    'packages/../b',
    'packages//a',
    './packages/a',
    'packages/a/',
    'a\u0000b',
    'a\nb',
    'C:/Windows',
    'packages\\a',
    'a\u0085b',
  ])('rejects unsafe input %j for both estimates and scans', async subpath => {
    await expect(resolveScanRoot(workspace(), subpath)).rejects.toMatchObject({ code: 'security/bad-request' })
    await expect(
      handlers().estimateScan({ workspaceId: workspace().id, mode: 'quick', subpath }, call()),
    ).rejects.toMatchObject({ code: 'security/bad-request' })
    await expect(
      h.controller.create({ workspaceId: workspace().id, mode: 'quick', aiReview: false, subpath }),
    ).rejects.toMatchObject({ code: 'security/bad-request' })
    expect(h.store.listScans()).toEqual([])
  })

  it('rejects missing folders, non-directories, and symlink escapes including prefix siblings', async () => {
    for (const subpath of ['missing', 'file.txt']) {
      await expect(resolveScanRoot(workspace(), subpath)).rejects.toMatchObject({ code: 'security/not-found' })
    }
    const outside = `${root}-sibling`
    await mkdir(outside)
    try {
      await symlink(outside, join(root, 'escape'))
      await symlink(root, join(root, 'same'))
      const failure = {
        code: 'security/not-found',
        message: 'The subfolder was not found in this project.',
        details: {},
      }
      for (const subpath of ['escape', 'escape/nonexistent-descendant', 'same', 'missing', 'file.txt']) {
        await expect(resolveScanRoot(workspace(), subpath)).rejects.toMatchObject(failure)
        await expect(
          handlers().estimateScan({ workspaceId: workspace().id, mode: 'quick', subpath }, call()),
        ).rejects.toMatchObject(failure)
        await expect(
          h.controller.create({ workspaceId: workspace().id, mode: 'quick', aiReview: false, subpath }),
        ).rejects.toMatchObject(failure)
      }
    } finally {
      await rm(outside, { recursive: true, force: true })
    }
  })

  it('canonicalizes internal aliases and treats empty scope as the whole project', async () => {
    await symlink(join(root, 'packages/a'), join(root, 'alias'))
    expect(await resolveScanRoot(workspace(), 'alias')).toEqual({
      workspaceRoot: root,
      root: join(root, 'packages/a'),
      subpath: 'packages/a',
    })
    expect(await resolveScanRoot(workspace(), '')).toEqual({ workspaceRoot: root, root })
    expect(
      requestSchemas.createScan.safeParse({ workspaceId: 'ws', mode: 'quick', subpath: 'a'.repeat(1025) }).success,
    ).toBe(false)
    expect(requestSchemas.estimateScan.safeParse({ workspaceId: 'ws', mode: 'quick', subpath: 'a\nb' }).success).toBe(
      false,
    )
  })
})

it('keeps workspace-relative fingerprints, triage, history labels and same-root newness', async () => {
  const fixture = await copyFixture('express-shop')
  try {
    await cp(fixture.root, join(root, 'packages/a'), { recursive: true })
  } finally {
    await fixture.cleanup()
  }
  await cp(join(root, 'packages/a'), join(root, 'packages/b'), { recursive: true })
  const whole = await scan()
  const wholeFindings = h.store.listFindings(whole).filter(f => f.location?.path.startsWith('packages/a/'))
  expect(wholeFindings.length).toBeGreaterThan(0)
  const a = await scan('packages/a')
  const aFindings = h.store.listFindings(a)
  expect(aFindings.map(f => f.fingerprint).sort()).toEqual(wholeFindings.map(f => f.fingerprint).sort())
  expect(aFindings.every(f => !f.isNew)).toBe(true)
  const b = await scan('packages/b')
  expect(h.store.listFindings(b).every(f => !f.isNew)).toBe(true)
  await cp(join(root, 'packages/a/scripts/sync-catalog.ts'), join(root, 'packages/a/fresh.ts'))
  const a2 = await scan('packages/a')
  const next = h.store.listFindings(a2)
  expect(next.filter(f => f.location?.path === 'packages/a/fresh.ts').every(f => f.isNew)).toBe(true)
  expect(next.some(f => f.location?.path === 'packages/a/fresh.ts')).toBe(true)
  expect(next.filter(f => f.location?.path !== 'packages/a/fresh.ts').every(f => !f.isNew)).toBe(true)
  const finding = aFindings[0]!
  const before = (await handlers().getScan({ scanId: whole }, call())).summary.counts[finding.severity]
  await handlers().setTriage({ scanId: a, findingId: finding.id, triage: 'accepted_risk' }, call())
  const wholeFinding = wholeFindings.find(f => f.fingerprint === finding.fingerprint)!
  expect(await handlers().getFinding({ scanId: whole, findingId: wholeFinding.id }, call())).toMatchObject({
    triage: 'accepted_risk',
  })
  expect((await handlers().getScan({ scanId: whole }, call())).summary.counts[finding.severity]).toBe(before - 1)
  const detail = await handlers().getScan({ scanId: a }, call())
  expect(detail.summary.subpath).toBe('packages/a')
  expect(JSON.stringify(detail)).not.toContain(root)
  const estimate = await handlers().estimateScan(
    { workspaceId: workspace().id, mode: 'quick', subpath: 'packages/b' },
    call(),
  )
  const wholeEstimate = await handlers().estimateScan({ workspaceId: workspace().id, mode: 'quick' }, call())
  expect(estimate.files).toBeLessThan(wholeEstimate.files)
})

it('confines workers to scoped content while retaining workspace paths and git metadata', async () => {
  await mkdir(join(root, '.git'))
  await writeFile(join(root, '.git/HEAD'), 'a'.repeat(40))
  await writeFile(join(root, '.gitignore'), 'packages/a/ignored.ts\n')
  await writeFile(join(root, 'packages/a/ignored.ts'), 'ignored')
  await writeFile(join(root, 'packages/a/withheld.ts'), 'private content')
  await writeFile(join(root, 'packages/a/app.ts'), 'export const visible = 1\n')
  const settings = h.settings.get().settings
  const analysis = await analyzeWorkspace({
    root: join(root, 'packages/a'),
    workspaceRoot: root,
    settings,
    config: h.config,
    toolkit: undefined,
    astGrep: undefined,
    fetch: noNetwork,
    signal: signal(),
  })
  const snapshot = analysis.snapshot
  expect(snapshot.commit).toBe('a'.repeat(40))
  expect(snapshot.root).toBe(join(root, 'packages/a'))
  expect([...snapshot.files.keys()]).toEqual(['packages/a/app.ts', 'packages/a/withheld.ts'])
  const tools = createWorkspaceTools(analysis.view())
  const list = tools.find(t => t.name === 'list_files')!
  const read = tools.find(t => t.name === 'read_file')!
  const listed = JSON.stringify(
    await list.execute!(list.input.parse({}), { signal: signal(), workerId: 'test', turn: 1 }),
  )
  expect(listed).toContain('packages/a/app.ts')
  expect(listed).not.toContain('file.txt')
  expect(
    JSON.stringify(
      await read.execute!(read.input.parse({ path: 'file.txt' }), { signal: signal(), workerId: 'test', turn: 1 }),
    ),
  ).not.toContain('outside selected scope')
  const excluded = await snapshotWorkspace(
    join(root, 'packages/a'),
    { ...settings, scan: { ...settings.scan, excludeGlobs: ['packages/a/withheld.ts'] } },
    h.config,
    signal(),
    root,
  )
  expect([...excluded.files.keys()]).toEqual(['packages/a/app.ts'])
  const report = [{ RuleID: 'test', File: 'app.ts', StartLine: 1, Match: 'redacted' }]
  expect(parseGitleaksReport(report, { root: snapshot.root, snapshot }, [])[0]?.location.path).toBe('packages/a/app.ts')
  expect(
    parseGitleaksReport([{ ...report[0], File: join(root, 'file.txt') }], { root: snapshot.root, snapshot }, []),
  ).toEqual([])
  expect(
    parseSemgrepOutput(
      { results: [{ check_id: 'test', path: join(snapshot.root, 'app.ts'), start: { line: 1 }, end: { line: 1 } }] },
      { root: snapshot.root, snapshot },
      [],
    )[0]?.location.path,
  ).toBe('packages/a/app.ts')
  expect(
    parseOsvScannerReport(
      {
        results: [
          {
            source: { path: 'app.ts' },
            packages: [
              {
                package: { name: 'minimist', version: '1.2.5', ecosystem: 'npm' },
                vulnerabilities: [{ id: 'GHSA-xvch-5gv4-984h', summary: 'Prototype pollution', affected: [] }],
              },
            ],
          },
        ],
      },
      { root: snapshot.root, snapshot },
      [],
    )[0]?.location.path,
  ).toBe('packages/a/app.ts')
  expect(
    parseOsvScannerReport(
      { results: [{ source: { path: '../file.txt' }, packages: [] }] },
      { root: snapshot.root, snapshot },
      [],
    ),
  ).toEqual([])
})

it.each([
  { status: 'paused', subpath: undefined },
  { status: 'paused', subpath: 'packages/a' },
  { status: 'queued', subpath: undefined },
] as const)('runs a legacy $status scan under a canonical-equivalent root ($subpath)', async ({ status, subpath }) => {
  await symlink(root, join(root, 'legacy-alias'), 'dir')
  h.store.insertScan(
    scanOf({
      id: 'legacy-resume',
      workspaceRoot: `${root}/legacy-alias/`,
      workspaceId: workspace().id,
      status,
      subpath,
      startedAt: '2026-10-01T10:00:00.000Z',
      finishedAt: '2026-10-01T10:01:00.000Z',
    }),
  )
  if (status === 'paused') expect(h.controller.resume('legacy-resume')).not.toHaveProperty('finishedAt')
  else h.controller.start()
  // Job start clears old terminal times even for an already-queued legacy row.
  expect(h.store.getScan('legacy-resume')?.status).toBe('running')
  expect(h.store.getScan('legacy-resume')).not.toHaveProperty('finishedAt')
  expect(await h.settle('legacy-resume')).toBe('completed')
  expect(h.store.getScan('legacy-resume')?.error).toBeUndefined()
})

it('refuses a resumed scan whose selected folder was retargeted by a symlink', async () => {
  h.store.insertScan(
    scanOf({
      id: 'paused-scope',
      workspaceId: workspace().id,
      workspaceRoot: root,
      subpath: 'packages/a',
      status: 'paused',
    }),
  )
  await rm(join(root, 'packages/a'), { recursive: true })
  await symlink(join(root, 'packages/b'), join(root, 'packages/a'))
  h.controller.resume('paused-scope')
  expect(await h.settle('paused-scope')).toBe('failed')
  const failed = h.store.getScan('paused-scope')
  expect(failed?.error?.message).toContain('The scan folder changed')
  expect(JSON.stringify(await handlers().getScan({ scanId: 'paused-scope' }, call()))).not.toContain(root)
})

it.each(['v1', 'already-v2'])(
  'reconciles %s symlink and trailing-slash history and triage on registration',
  async version => {
    await symlink(root, join(root, 'legacy-alias'), 'dir')
    const dbPath = join(root, 'legacy.db')
    const legacy = new DatabaseSync(dbPath)
    legacy.exec('CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL) STRICT')
    legacy.exec("INSERT INTO meta VALUES ('schema_version', '1')")
    for (const step of MIGRATIONS[0] ?? []) legacy.exec(step)
    const old = scanOf({
      id: 'legacy',
      workspaceId: 'orphan',
      workspaceRoot: `${root}/legacy-alias/`,
      status: 'completed',
    })
    const params = scanParams(old).slice(0, -1)
    legacy
      .prepare(
        'INSERT INTO scans (id,workspace_id,status,mode,phase,created_at,updated_at,started_at,finished_at,data) VALUES (?,?,?,?,?,?,?,?,?,?)',
      )
      .run(...params)
    legacy.prepare('INSERT INTO triage VALUES (?,?,?,?,?)').run('orphan', 'fp', 'accepted_risk', 'kept', old.createdAt)
    // Same root under a second UUID: the most recent triage decision wins.
    legacy
      .prepare(
        'INSERT INTO scans (id,workspace_id,status,mode,phase,created_at,updated_at,started_at,finished_at,data) VALUES (?,?,?,?,?,?,?,?,?,?)',
      )
      .run(
        ...scanParams({ ...old, id: 'second', workspaceId: 'another-orphan', workspaceRoot: `${root}/` }).slice(0, -1),
      )
    legacy
      .prepare('INSERT INTO triage VALUES (?,?,?,?,?)')
      .run('another-orphan', 'fp', 'fixed', 'latest', '2026-10-02T00:00:00.000Z')
    legacy.close()
    // Simulate users who already ran the SQL-only v2 migration in a released version.
    if (version === 'already-v2') openSecurityStore(dbPath).close()
    const migrated = openSecurityStore(dbPath, { now: () => new Date('2026-10-02T00:00:00.000Z') })
    migrated.setTriage(`${root}/`, 'tie', 'fixed', 'alias tie loses')
    const canonicalTie = migrated.setTriage(root, 'tie', 'open', 'canonical tie wins')
    // Compose root-spelling reconciliation with triage stored only under a
    // merged fingerprint, rather than this finding's current primary identity.
    migrated.insertFinding(
      findingOf({ id: 'legacy-finding', scanId: 'legacy', fingerprint: 'primary-fp', mergedFingerprints: ['fp'] }),
    )
    try {
      expect(migrated.previousCompletedScan(root, '2026-11-01T00:00:00.000Z')).toBeUndefined()
      const registered = version === 'v1' ? [workspace()] : []
      const rpc = createHandlers({
        ...h,
        store: migrated,
        llm: () => undefined,
        workspaces: () => registryOf(registered),
        astGrep: async () => undefined,
        toolkit: undefined,
        pluginVersion: 'test',
        now: () => new Date(),
      })
      if (version === 'already-v2') {
        expect(migrated.getTriage(root, ['fp']).size).toBe(0)
        registered.push(workspace())
        // The first project-list read must reconcile before querying history.
        expect((await rpc.listWorkspaces({}, call()))[0]?.lastScan?.id).toBe('second')
      }
      expect(migrated.getTriage(root, ['fp']).get('fp')).toMatchObject({
        state: 'fixed',
        note: 'latest',
        rootKeyBase: root,
      })
      expect(migrated.getTriage(root, ['tie']).get('tie')).toEqual(canonicalTie)
      expect(migrated.getTriage(`${root}/legacy-alias/`, ['fp']).size).toBe(0)
      expect(migrated.getTriage(`${root}/`, ['fp']).size).toBe(0)
      expect(migrated.previousCompletedScan(root, '2026-11-01T00:00:00.000Z')?.id).toBe('second')
      expect(migrated.getScan('legacy')?.workspaceRoot).toBe(root)
      migrated.reconcileTriageRoot(workspace().id, root)
      expect(migrated.getScan('legacy')?.updatedAt).toBe(old.updatedAt)
      const list = await rpc.listScans({ workspaceId: workspace().id }, call())
      expect(list).toHaveLength(2)
      expect(list.every(scan => scan.workspaceId === workspace().id)).toBe(true)
      expect(list.find(scan => scan.id === 'legacy')?.counts.high).toBe(0)
      expect(await rpc.listFindings({ scanId: 'legacy' }, call())).toMatchObject([
        { id: 'legacy-finding', triage: 'fixed' },
      ])
      expect(await rpc.getFinding({ scanId: 'legacy', findingId: 'legacy-finding' }, call())).toMatchObject({
        triage: 'fixed',
        triageNote: 'latest',
      })
      const report = JSON.parse((await rpc.exportReport({ scanId: 'legacy', format: 'json' }, call())).content)
      expect(report.findings[0]).toMatchObject({ id: 'legacy-finding', triage: 'fixed' })
      await rpc.setTriage(
        { scanId: 'legacy', findingId: 'legacy-finding', triage: 'accepted_risk', note: 'all aliases' },
        call(),
      )
      expect([...migrated.getTriage(root, ['primary-fp', 'fp']).values()].map(triage => triage.state)).toEqual([
        'accepted_risk',
        'accepted_risk',
      ])
      expect(JSON.stringify(list)).not.toContain(root)
      expect((await rpc.listWorkspaces({}, call()))[0]?.lastScan?.id).toBe('second')
      migrated.deleteScan('legacy')
      migrated.deleteScan('second')
      expect(migrated.getTriage(root, ['fp']).get('fp')?.state).toBe('accepted_risk')
    } finally {
      migrated.close()
    }
  },
)

it.each([undefined, 'packages/a'])('masks workspace-base and sibling absolute paths for scope %s', async subpath => {
  const content = `${root}\n${root}/packages/b/private.ts\n${root}/packages/a/app.ts\n`
  const expected = '<root>\n<root>/packages/b/private.ts\n<root>/packages/a/app.ts\n'
  await writeFile(join(root, 'packages/a/app.ts'), content)
  const analysis = await analyzeWorkspace({
    root: subpath ? join(root, subpath) : root,
    workspaceRoot: root,
    settings: h.settings.get().settings,
    config: h.config,
    toolkit: undefined,
    astGrep: undefined,
    fetch: noNetwork,
    signal: signal(),
  })
  expect(analysis.snapshot.workspaceRoot).toBe(root)
  expect(analysis.privacy.scrub(content)).toBe(expected)
  expect(analysis.privacy.excerpt('packages/a/app.ts', content)).toBe(expected)
  expect(analysis.quoteSource.redact('packages/a/app.ts', content)).toBe(expected)
  const read = createWorkspaceTools(analysis.view()).find(tool => tool.name === 'read_file')!
  const result = await read.execute!(read.input.parse({ path: 'packages/a/app.ts' }), {
    signal: signal(),
    workerId: 'mask-test',
    turn: 1,
  })
  expect(result.text).not.toContain(root)
  expect(result.text).toContain('<root>/packages/b/private.ts')
  expect(result.text).toContain('<root>/packages/a/app.ts')
})

it('revalidates the selected root at the walk boundary', async () => {
  const selected = join(root, 'packages/a')
  const saved = join(root, 'packages/saved')
  await writeFile(join(root, 'packages/b/private.ts'), 'must not enter snapshot')
  const boundary = signal()
  let calls = 0
  Object.defineProperty(boundary, 'throwIfAborted', {
    value() {
      if (++calls !== 2) return
      expect(realpathSync(selected)).toBe(selected)
      expect(saved).toBe(join(root, 'packages/saved'))
      renameSync(selected, saved)
      symlinkSync(join(root, 'packages/b'), selected)
    },
  })
  const snapshot = await snapshotWorkspace(selected, h.settings.get().settings, h.config, boundary, root)
  expect(snapshot.files.size).toBe(0)
  expect(snapshot.excluded).toContainEqual({ path: 'packages/a', reason: 'outside-root' })
})

it('recovers scan-less legacy triage lazily for registered UUIDs with deterministic collisions', async () => {
  const fixture = await copyFixture('express-shop')
  try {
    await cp(join(fixture.root, 'scripts/sync-catalog.ts'), join(root, 'packages/a/app.ts'))
  } finally {
    await fixture.cleanup()
  }
  const first = await scan('packages/a')
  const fingerprint = h.store.listFindings(first)[0]!.fingerprint
  const dbPath = join(root, 'scanless.db')
  const legacy = new DatabaseSync(dbPath)
  legacy.exec('CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL) STRICT')
  legacy.exec("INSERT INTO meta VALUES ('schema_version', '1')")
  for (const step of MIGRATIONS[0] ?? []) legacy.exec(step)
  const insert = legacy.prepare('INSERT INTO triage VALUES (?,?,?,?,?)')
  insert.run(workspace().id, fingerprint, 'accepted_risk', 'recovered', '2026-02-02T00:00:00.000Z')
  for (const fp of ['legacy-newer', 'base-newer', 'tie'])
    insert.run(workspace().id, fp, 'fixed', 'legacy', '2026-02-02T00:00:00.000Z')
  insert.run('unknown-uuid', fingerprint, 'false_positive', 'unknown remains', '2026-02-02T00:00:00.000Z')
  legacy.close()
  let clock = new Date('2026-02-01T00:00:00.000Z')
  const migrated = openSecurityStore(dbPath, { now: () => clock })
  expect(migrated.listScans()).toEqual([])
  expect(migrated.getTriage(workspace().id, [fingerprint]).get(fingerprint)?.state).toBe('accepted_risk')
  migrated.setTriage(root, 'legacy-newer', 'open', 'older base')
  clock = new Date('2026-02-03T00:00:00.000Z')
  migrated.setTriage(root, 'base-newer', 'accepted_risk', 'newer base')
  clock = new Date('2026-02-02T00:00:00.000Z')
  migrated.setTriage(root, 'tie', 'open', 'canonical tie wins')
  await h.controller.dispose()
  h.store.close()
  h = createHarness({ store: migrated, workspaces: [workspace()] })
  const registered: ReturnType<typeof workspace>[] = []
  const rpc = handlers(registered)
  expect(migrated.getTriage(workspace().id, [fingerprint]).size).toBe(1)
  registered.push(workspace())
  const next = await scan('packages/a')
  const finding = h.store.listFindings(next).find(f => f.fingerprint === fingerprint)!
  expect(await rpc.getFinding({ scanId: next, findingId: finding.id }, call())).toMatchObject({
    triage: 'accepted_risk',
    triageNote: 'recovered',
  })
  const states = migrated.getTriage(root, ['legacy-newer', 'base-newer', 'tie'])
  expect(states.get('legacy-newer')?.state).toBe('fixed')
  expect(states.get('base-newer')?.state).toBe('accepted_risk')
  expect(states.get('tie')?.note).toBe('canonical tie wins')
  expect(migrated.getTriage(workspace().id, [fingerprint, 'legacy-newer', 'base-newer', 'tie']).size).toBe(0)
  expect(migrated.getTriage('unknown-uuid', [fingerprint]).get(fingerprint)?.note).toBe('unknown remains')
  // The successful service hook is cached, and the store operation is independently idempotent.
  migrated.reconcileTriageRoot(workspace().id, root)
  expect(await rpc.getFinding({ scanId: next, findingId: finding.id }, call())).toMatchObject({
    triage: 'accepted_risk',
  })
})
