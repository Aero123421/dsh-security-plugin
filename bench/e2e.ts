/**
 * `pnpm e2e` — run every fixture app as its own project inside a real DSH and
 * check the multi-project flow end to end, without an API key.
 *
 *   pnpm e2e [--dsh <dir>] [--dsh-version <tag|version>] [--app <name>]... [--mode quick|deep|research]
 *            [--no-build] [--keep] [--json] [--timeout <seconds>]
 *
 * Steps:
 *   1. Build `lib/` (unless --no-build), install DSH into a scratch directory (or use --dsh <dir>, a directory
 *      where `npm install @deepseek-ai/dsh` was run), and create a scratch `DSH_HOME` with this checkout linked
 *      into the `web` profile.
 *   2. Start DSH with the scripted model (`tests/e2e/scripted-llm`) overlaid for this run only.
 *   3. Copy each fixture app without its answer key and register it as a DSH project over DSH's own API.
 *   4. Select the scripted model, allow sending code, and start one scan per project at the same time.
 *   5. Wait for the queue to drain, export every scan as JSON, and score it against that app's ground truth.
 *
 * Checks per project: the scan completed; every scheduled AI task finished; the report cites only files of
 * that project; the fabricated finding of each hunter run was discarded; in-scope recall is 100% (the
 * scripted model answers from the ground truth, so a miss is a plumbing loss). Across projects: no more
 * scans ran at once than `maxConcurrentScans` allowed, and the others waited queued.
 *
 * The scripted model measures plumbing, not detection quality. Exits 1 when a check fails, 2 on usage errors.
 * Needs network (npm) unless --dsh points at an existing install, and pnpm on PATH (DSH's plugin command).
 */

import { type ChildProcess, spawn, spawnSync } from 'node:child_process'
import { existsSync } from 'node:fs'
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { parseArgs } from 'node:util'
import { copyFixtureApp, FIXTURE_APPS_DIR, type FixtureManifest, loadFixtures } from './fixtures.ts'
import { count, pct, seconds, table } from './format.ts'
import { parseJsonReport } from './report.ts'
import { type AppScore, scoreApp } from './scoring.ts'

const ROOT = resolve(fileURLToPath(new URL('..', import.meta.url)))
const ORACLE = join(ROOT, 'tests', 'e2e', 'scripted-llm', 'index.mjs')
const MODES = ['quick', 'deep', 'research'] as const
type Mode = (typeof MODES)[number]
const WINDOWS = process.platform === 'win32'
const TERMINAL = new Set(['completed', 'failed', 'cancelled', 'interrupted'])

const USAGE = `Usage: pnpm e2e [--dsh <dir>] [--dsh-version <tag|version>] [--app <name>]... [--mode quick|deep|research]
                [--no-build] [--keep] [--json] [--timeout <seconds>]

  --dsh <dir>           use an existing DSH install (a directory with node_modules/.bin/dsh)
  --dsh-version <v>     DSH dist-tag or version to install when --dsh is not given (default: alpha)
  --app <name>          scan only this fixture app; repeat for several (default: every app)
  --mode <mode>         scan depth for every project (default: deep)
  --no-build            use the committed lib/ instead of rebuilding it
  --keep                keep the scratch directory and print its path
  --json                print the machine-readable result instead of tables
  --timeout <seconds>   give up waiting for the scans after this long (default 600)`

interface Options {
  readonly dsh?: string
  readonly dshVersion: string
  readonly apps: readonly string[]
  readonly mode: Mode
  readonly build: boolean
  readonly keep: boolean
  readonly json: boolean
  readonly timeoutMs: number
}

interface ScanRow {
  readonly app: string
  readonly scanId: string
  readonly status: string
  readonly review: string
  readonly maxQueuedWhileOtherRan: boolean
  readonly score?: AppScore
  readonly discarded: number | null
  readonly llmCalls: number
  readonly elapsedMs: number
  readonly foreignPaths: readonly string[]
  readonly problems: readonly string[]
}

class UsageError extends Error {}

async function main(): Promise<number> {
  let options: Options
  try {
    options = parse()
  } catch (error) {
    if (error instanceof UsageError && error.message === 'help') {
      process.stdout.write(`${USAGE}\n`)
      return 0
    }
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n\n${USAGE}\n`)
    return 2
  }

  const manifests = await loadFixtures()
  const unknown = options.apps.filter(app => !manifests.some(m => m.app === app))
  if (unknown.length) {
    process.stderr.write(
      `Unknown fixture app(s): ${unknown.join(', ')}. Known: ${manifests.map(m => m.app).join(', ')}\n`,
    )
    return 2
  }
  const selected = options.apps.length ? manifests.filter(m => options.apps.includes(m.app)) : manifests

  const work = await mkdtemp(join(tmpdir(), 'dsh-security-e2e-'))
  let server: ChildProcess | undefined
  try {
    if (options.build) run(process.execPath, [join(ROOT, 'scripts', 'build.mjs')], { cwd: ROOT })
    const dshBin = installDsh(options, work)
    const home = join(work, 'home')
    await mkdir(home, { recursive: true })
    const env = { ...process.env, DSH_HOME: home }
    log(options, `linking ${ROOT} into the scratch web profile`)
    run(dshBin, ['plugin', '--profile', 'web', 'add', '-w', ROOT], { cwd: work, env })

    const overlay = join(work, 'overlay.yml')
    await writeFile(
      overlay,
      [
        '- insert:',
        '    - id: scripted-llm',
        `      name: ${JSON.stringify(ORACLE)}`,
        '      config:',
        `        fixturesDir: ${JSON.stringify(FIXTURE_APPS_DIR)}`,
        '        delayMs: 5',
        '',
      ].join('\n'),
    )

    const appsDir = join(work, 'apps')
    const copies = new Map<string, string>()
    for (const manifest of selected) copies.set(manifest.app, await copyFixtureApp(manifest, appsDir))

    const started = await startDsh(dshBin, overlay, work, env)
    server = started.child
    const api = await connect(started.url)
    log(options, `DSH is up at ${started.url.replace(/\?token=.*/, '')}`)

    for (const [app, path] of copies) {
      await createWorkspace(api, path)
      log(options, `registered ${app}`)
    }
    const workspaces = (await api.plugin('listWorkspaces', {})) as { id: string; title: string; displayPath: string }[]
    const idOf = new Map<string, string>()
    for (const [app, path] of copies) {
      const workspace = workspaces.find(w => resolve(w.displayPath.replace(/^~/, process.env.HOME ?? '~')) === path)
      const byTitle = workspaces.find(w => w.title === app)
      const id = (workspace ?? byTitle)?.id
      if (!id) throw new Error(`DSH did not list the project for ${app}`)
      idOf.set(app, id)
    }

    const bootstrap = (await api.plugin('getBootstrap', {})) as {
      settingsRevision: number
      limits: { maxConcurrentScans: number }
    }
    await api.plugin('updateSettings', {
      patch: {
        models: { default: { provider: 'scripted', model: 'oracle' } },
        privacy: { sendCodeToModel: true },
      },
      expectedRevision: bootstrap.settingsRevision,
    })

    const scanIds = new Map<string, string>()
    for (const [app, workspaceId] of idOf) {
      const created = (await api.plugin('createScan', { workspaceId, mode: options.mode })) as { scanId: string }
      scanIds.set(app, created.scanId)
    }
    log(options, `started ${scanIds.size} scans (${options.mode})`)

    const observed = await waitForScans(api, scanIds, options)
    const limit = bootstrap.limits.maxConcurrentScans

    const rows: ScanRow[] = []
    for (const manifest of selected) {
      const scanId = scanIds.get(manifest.app) ?? ''
      rows.push(await checkScan(api, manifest, scanId, observed, copies.get(manifest.app) ?? ''))
    }

    const overlapProblems: string[] = []
    if (observed.maxRunning > limit) {
      overlapProblems.push(`${observed.maxRunning} scans ran at once; maxConcurrentScans is ${limit}`)
    }
    if (selected.length > limit && !observed.sawQueued) {
      overlapProblems.push('no scan was ever seen waiting in the queue')
    }

    const ok = rows.every(r => r.problems.length === 0) && overlapProblems.length === 0
    if (options.json) {
      process.stdout.write(
        `${JSON.stringify({ ok, mode: options.mode, maxConcurrentScans: limit, maxRunning: observed.maxRunning, overlapProblems, rows: rows.map(({ score, ...rest }) => ({ ...rest, totals: score?.totals })) }, null, 2)}\n`,
      )
    } else {
      process.stdout.write(`${render(rows, observed.maxRunning, limit, overlapProblems)}\n`)
      if (options.keep) process.stdout.write(`\nScratch directory kept: ${work}\n`)
    }
    return ok ? 0 : 1
  } catch (error) {
    process.stderr.write(`e2e failed: ${error instanceof Error ? error.message : String(error)}\n`)
    return 1
  } finally {
    await stop(server)
    if (!options.keep) await rm(work, { recursive: true, force: true }).catch(() => undefined)
  }
}

// ---------------------------------------------------------------------------
// DSH process and API
// ---------------------------------------------------------------------------

function installDsh(options: Options, work: string): string {
  const bin = (dir: string) => join(dir, 'node_modules', '.bin', WINDOWS ? 'dsh.cmd' : 'dsh')
  if (options.dsh) {
    const dir = resolve(options.dsh)
    if (!existsSync(bin(dir)))
      throw new UsageError(`${dir} has no node_modules/.bin/dsh; run npm i @deepseek-ai/dsh there`)
    return bin(dir)
  }
  const dir = join(work, 'dsh')
  spawnSync(WINDOWS ? 'npm.cmd' : 'npm', ['init', '-y'], { cwd: work, stdio: 'ignore', shell: WINDOWS })
  log(options, `installing @deepseek-ai/dsh@${options.dshVersion}`)
  run(
    WINDOWS ? 'npm.cmd' : 'npm',
    ['install', '--prefix', dir, '--no-audit', '--no-fund', `@deepseek-ai/dsh@${options.dshVersion}`],
    {
      cwd: work,
    },
  )
  return bin(dir)
}

async function startDsh(
  bin: string,
  overlay: string,
  cwd: string,
  env: NodeJS.ProcessEnv,
): Promise<{ child: ChildProcess; url: string }> {
  const child = spawn(bin, ['--profile', 'web', '--patch', overlay, '--no-open', '--port', '0'], {
    cwd,
    env,
    shell: WINDOWS,
    stdio: ['ignore', 'pipe', 'pipe'],
  })
  let output = ''
  return await new Promise((resolvePromise, reject) => {
    const timer = setTimeout(() => {
      reject(new Error(`DSH did not print its URL within 90 s.\n${tail(output)}`))
    }, 90_000)
    const onData = (chunk: Buffer) => {
      output += chunk.toString('utf8')
      const match = /dsh web: (http:\/\/127\.0\.0\.1:\d+\/\?token=\S+)/.exec(output)
      if (match?.[1]) {
        clearTimeout(timer)
        resolvePromise({ child, url: match[1] })
      }
    }
    child.stdout?.on('data', onData)
    child.stderr?.on('data', onData)
    child.once('exit', code => {
      clearTimeout(timer)
      reject(new Error(`DSH exited with code ${code} before it was ready.\n${tail(output)}`))
    })
  })
}

async function stop(child: ChildProcess | undefined): Promise<void> {
  if (!child || child.exitCode !== null) return
  const exited = new Promise<void>(resolvePromise => child.once('exit', () => resolvePromise()))
  child.kill('SIGINT')
  const timeout = new Promise<'timeout'>(resolvePromise => setTimeout(() => resolvePromise('timeout'), 10_000))
  if ((await Promise.race([exited, timeout])) === 'timeout') child.kill('SIGKILL')
}

interface Api {
  /** Calls a DSH API endpoint, e.g. `workspace/create`; returns the raw result object. */
  raw(
    method: string,
    payload: unknown,
  ): Promise<{ ok: boolean; value?: unknown; error?: { code: string; message: string } }>
  /** Calls a Security plugin method and returns its value, throwing on an error result. */
  plugin(method: string, payload: unknown): Promise<unknown>
}

async function connect(url: string): Promise<Api> {
  const base = url.replace(/\/\?token=.*/, '')
  const login = await fetch(url, { redirect: 'manual' })
  const cookie = login.headers
    .getSetCookie()
    .map(c => c.split(';')[0])
    .join('; ')
  if (!cookie) throw new Error(`DSH login returned no cookie (HTTP ${login.status})`)
  let rpcId = 0
  const raw: Api['raw'] = async (method, payload) => {
    const response = await fetch(`${base}/api/${method}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ type: 'client-request', rpcId: String(++rpcId), method, payload }),
    })
    if (!response.ok) throw new Error(`${method}: HTTP ${response.status}`)
    const body = (await response.json()) as {
      result?: { ok: boolean; value?: unknown; error?: { code: string; message: string } }
    }
    if (!body.result) throw new Error(`${method}: unexpected response`)
    return body.result
  }
  return {
    raw,
    async plugin(method, payload) {
      const result = await raw(`dsh-security/${method}`, payload)
      if (!result.ok) throw new Error(`${method}: ${result.error?.code} ${result.error?.message}`)
      return result.value
    },
  }
}

/** `workspace/create` changed its argument envelope across DSH 0.2 prereleases; try the known shapes. */
async function createWorkspace(api: Api, path: string): Promise<void> {
  const shapes = [{ args: { request: { path } } }, { args: { path } }, { path }]
  let last = ''
  for (const payload of shapes) {
    const result = await api.raw('workspace/create', payload)
    if (result.ok) return
    last = `${result.error?.code}: ${result.error?.message}`
    if (!/arguments|payload|args/i.test(last)) break
  }
  throw new Error(`could not register ${path} as a DSH project (${last})`)
}

// ---------------------------------------------------------------------------
// Waiting and checks
// ---------------------------------------------------------------------------

interface Observed {
  maxRunning: number
  sawQueued: boolean
  /** Scans that were seen queued while another project's scan was running. */
  queuedBehindOther: Set<string>
}

async function waitForScans(api: Api, scanIds: ReadonlyMap<string, string>, options: Options): Promise<Observed> {
  const observed: Observed = { maxRunning: 0, sawQueued: false, queuedBehindOther: new Set() }
  const deadline = Date.now() + options.timeoutMs
  const wanted = new Set(scanIds.values())
  for (;;) {
    // One list across all projects is one store read, so the statuses below are a single instant. Asking per
    // project would mix instants: a scan seen running before it finished and the next one seen running after
    // it started would count as two at once.
    const statuses = new Map<string, string>()
    const scans = (await api.plugin('listScans', { limit: 100 })) as { id: string; status: string }[]
    for (const scan of scans) if (wanted.has(scan.id)) statuses.set(scan.id, scan.status)
    const running = [...statuses.values()].filter(s => s === 'running').length
    observed.maxRunning = Math.max(observed.maxRunning, running)
    for (const [id, status] of statuses) {
      if (status !== 'queued') continue
      observed.sawQueued = true
      if (running > 0) observed.queuedBehindOther.add(id)
    }
    if ([...wanted].every(id => TERMINAL.has(statuses.get(id) ?? ''))) return observed
    if (Date.now() > deadline) {
      throw new Error(
        `scans did not finish within ${options.timeoutMs / 1000} s: ${JSON.stringify(Object.fromEntries(statuses))}`,
      )
    }
    await new Promise(resolvePromise => setTimeout(resolvePromise, 250))
  }
}

async function checkScan(
  api: Api,
  manifest: FixtureManifest,
  scanId: string,
  observed: Observed,
  projectDir: string,
): Promise<ScanRow> {
  const problems: string[] = []
  const detail = (await api.plugin('getScan', { scanId })) as {
    summary: { status: string; review?: { state: string; completed: number; planned: number } }
  }
  const status = detail.summary.status
  const review = detail.summary.review
  if (status !== 'completed') problems.push(`scan ${status}`)
  if (review && review.state !== 'complete') {
    problems.push(`AI review ${review.state} (${review.completed}/${review.planned} tasks)`)
  }
  const file = (await api.plugin('exportReport', { scanId, format: 'json' })) as { content: string }
  const report = parseJsonReport(JSON.parse(file.content))
  const score = scoreApp(
    manifest,
    report.findings,
    report.activeDetectors ? { activeDetectors: report.activeDetectors } : {},
  )
  const scoped = score.totals.scopedRecall
  if (scoped !== null && scoped < 1) problems.push(`in-scope recall ${pct(scoped)}`)
  if (score.totals.negativeHits > 0) problems.push(`${score.totals.negativeHits} report(s) on negative controls`)
  if ((report.discardedUnverifiable ?? 0) === 0) problems.push('the fabricated finding was not discarded')
  const foreignPaths = report.findings
    .map(f => f.location?.path)
    .filter((path): path is string => typeof path === 'string' && !existsSync(join(projectDir, path)))
  if (foreignPaths.length) problems.push(`cites files outside this project: ${[...new Set(foreignPaths)].join(', ')}`)
  return {
    app: manifest.app,
    scanId,
    status,
    review: review ? `${review.state} ${review.completed}/${review.planned}` : 'unknown',
    maxQueuedWhileOtherRan: observed.queuedBehindOther.has(scanId),
    score,
    discarded: report.discardedUnverifiable,
    llmCalls: report.usage.llmCalls,
    elapsedMs: report.usage.elapsedMs,
    foreignPaths,
    problems,
  }
}

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------

function render(rows: readonly ScanRow[], maxRunning: number, limit: number, overlap: readonly string[]): string {
  const out: string[] = []
  out.push(
    table(
      [
        { header: 'project', value: (r: ScanRow) => r.app },
        { header: 'status', value: (r: ScanRow) => r.status },
        { header: 'AI tasks', value: (r: ScanRow) => r.review },
        { header: 'waited', value: (r: ScanRow) => (r.maxQueuedWhileOtherRan ? 'yes' : 'no') },
        { header: 'in-scope', value: (r: ScanRow) => pct(r.score?.totals.scopedRecall ?? null), align: 'right' },
        { header: 'FP', value: (r: ScanRow) => count(r.score?.totals.falsePositives), align: 'right' },
        { header: 'discarded', value: (r: ScanRow) => count(r.discarded), align: 'right' },
        { header: 'llm', value: (r: ScanRow) => String(r.llmCalls), align: 'right' },
        { header: 'time', value: (r: ScanRow) => seconds(r.elapsedMs), align: 'right' },
        { header: 'result', value: (r: ScanRow) => (r.problems.length ? `FAIL: ${r.problems.join('; ')}` : 'ok') },
      ],
      rows,
    ),
  )
  out.push('')
  out.push(`Concurrent scans: at most ${maxRunning} running at once (maxConcurrentScans ${limit}).`)
  for (const problem of overlap) out.push(`FAIL: ${problem}`)
  return out.join('\n')
}

function log(options: Options, message: string): void {
  if (!options.json) process.stderr.write(`e2e: ${message}\n`)
}

function tail(text: string): string {
  return text.split('\n').slice(-20).join('\n')
}

function run(command: string, args: readonly string[], options: { cwd: string; env?: NodeJS.ProcessEnv }): void {
  const result = spawnSync(command, args, {
    cwd: options.cwd,
    env: options.env ?? process.env,
    encoding: 'utf8',
    shell: WINDOWS,
    timeout: 300_000,
  })
  if (result.status !== 0) {
    throw new Error(
      `${command} ${args.join(' ')} failed (${result.status ?? result.signal}).\n${tail(`${result.stdout ?? ''}${result.stderr ?? ''}`)}`,
    )
  }
}

function parse(): Options {
  const { values } = parseArgs({
    strict: true,
    options: {
      dsh: { type: 'string' },
      'dsh-version': { type: 'string', default: 'alpha' },
      app: { type: 'string', multiple: true, default: [] },
      mode: { type: 'string', default: 'deep' },
      'no-build': { type: 'boolean', default: false },
      keep: { type: 'boolean', default: false },
      json: { type: 'boolean', default: false },
      timeout: { type: 'string', default: '600' },
      help: { type: 'boolean', short: 'h', default: false },
    },
  })
  if (values.help) throw new UsageError('help')
  if (!MODES.includes(values.mode as Mode)) throw new UsageError(`--mode must be one of ${MODES.join(', ')}`)
  const version = values['dsh-version']
  if (!/^[A-Za-z0-9][A-Za-z0-9.+-]*$/.test(version)) throw new UsageError('--dsh-version must be a dist-tag or version')
  const timeout = Number(values.timeout)
  if (!Number.isFinite(timeout) || timeout <= 0) throw new UsageError('--timeout must be a positive number of seconds')
  return {
    ...(values.dsh ? { dsh: values.dsh } : {}),
    dshVersion: version,
    apps: values.app,
    mode: values.mode as Mode,
    build: !values['no-build'],
    keep: values.keep,
    json: values.json,
    timeoutMs: timeout * 1000,
  }
}

process.exitCode = await main()
