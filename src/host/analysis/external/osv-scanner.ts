/**
 * osv-scanner runner. Call analysis is disabled for every language: Go call
 * analysis invokes the `go` toolchain on the scanned module (a hostile
 * `toolchain` directive can trigger a toolchain download) and Rust call
 * analysis runs `build.rs` scripts. Transitive resolution is disabled so no
 * package registry is contacted. Unless `offline` is set, osv-scanner sends
 * package names and versions to osv.dev, like `queryOsv`.
 *
 * The repository's own `osv-scanner.toml` files are never used: an empty,
 * plugin-written config is passed with `--config`, which overrides the
 * per-directory lookup for every scanned file, so `[[IgnoredVulns]]` and
 * `[[PackageOverrides]]` in the scanned project cannot hide advisories.
 */

import { mkdtemp, readdir, rm, stat, writeFile } from 'node:fs/promises'
import { homedir, tmpdir } from 'node:os'
import { join } from 'node:path'
import { z } from 'zod'
import { type OsvPackageRef, osvVulnSchema, osvVulnToSignal } from '../osv.ts'
import { redactText } from '../secrets.ts'
import type { AnalyzerRun, Signal } from '../types.ts'
import {
  compareVersions,
  completedRun,
  DEFAULT_EXTERNAL_TIMEOUT_MS,
  DEFAULT_MAX_OUTPUT_BYTES,
  type ExternalRunOptions,
  errorMessage,
  failedRun,
  firstLine,
  toWorkspacePath,
  unavailableRun,
} from './common.ts'
import { runTool } from './process.ts'

export interface OsvScannerRunOptions extends ExternalRunOptions {
  /**
   * Use only a previously downloaded local database (`--offline`). When no
   * database exists the run reports the analyzer as unavailable.
   */
  readonly offline: boolean
  /** Override for the local DB directory (`OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY`). */
  readonly localDbDir?: string
}

const V2 = '2.0.0'
const MAX_PACKAGES = 20_000
/** Written to a private temp file and passed with `--config` (same flag in v1 and v2). */
const PLUGIN_CONFIG = '# Written by dsh-security: no ignored vulnerabilities or package overrides.\n'

const packageSchema = z.object({
  package: z.object({ name: z.string(), version: z.string().default(''), ecosystem: z.string().default('') }),
  vulnerabilities: z.array(z.unknown()).nullish(),
})
const reportSchema = z.object({
  results: z
    .array(
      z.object({
        source: z.object({ path: z.string().default(''), type: z.string().optional() }).optional(),
        packages: z.array(packageSchema).nullish(),
      }),
    )
    .nullish(),
})

export interface OsvScannerRun extends AnalyzerRun {
  /** In-snapshot packages with version results, including those with no advisories. */
  readonly checkedDependencies?: number
}

/** Run osv-scanner over the workspace root and convert its results to signals. */
export async function runOsvScanner(options: OsvScannerRunOptions): Promise<OsvScannerRun> {
  const started = Date.now()
  const { tool } = options
  if (!tool) return unavailableRun('osv-scanner', 'osv-scanner is not installed', started)
  options.signal?.throwIfAborted()

  if (options.offline && !(await hasLocalDatabase(options.localDbDir))) {
    return unavailableRun('osv-scanner', 'offline mode is on and no local osv-scanner database was found', started)
  }

  const v2 = tool.version === undefined || compareVersions(tool.version, V2) >= 0
  const work = await mkdtemp(join(tmpdir(), 'dsh-osv-scanner-'))
  let result: Awaited<ReturnType<typeof runTool>>
  try {
    const configPath = join(work, 'osv-scanner.toml')
    await writeFile(configPath, PLUGIN_CONFIG, { mode: 0o600 })
    const flags = ['--format', 'json', '--recursive', '--config', configPath]
    if (options.offline) flags.push('--offline')
    if (v2) flags.push('--no-resolve', '--no-call-analysis=all')
    const args = v2
      ? ['scan', 'source', ...flags, options.root]
      : ['--format', 'json', '-r', '--config', configPath, ...offlineV1(options), options.root]
    try {
      result = await runTool(tool.path, args, {
        cwd: work,
        timeoutMs: options.timeoutMs ?? DEFAULT_EXTERNAL_TIMEOUT_MS,
        maxOutputBytes: options.maxOutputBytes ?? DEFAULT_MAX_OUTPUT_BYTES,
        ...(options.signal ? { signal: options.signal } : {}),
        ...(options.localDbDir ? { env: { OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY: options.localDbDir } } : {}),
      })
    } catch (error) {
      if (options.signal?.aborted) throw error
      return failedRun('osv-scanner', tool, `could not start osv-scanner: ${errorMessage(error)}`, started)
    }
  } finally {
    await rm(work, { recursive: true, force: true }).catch(() => undefined)
  }
  if (result.timedOut) return failedRun('osv-scanner', tool, 'osv-scanner timed out', started)
  // 0: clean, 1: vulnerabilities found, 128: no lock files found.
  if (result.code === 128) return completedRun('osv-scanner', tool, [], started, [])
  if (result.code !== 0 && result.code !== 1) {
    const detail = firstLine(redactText(result.stderr)) || `exit code ${result.code ?? result.signal}`
    return failedRun('osv-scanner', tool, `osv-scanner failed: ${detail}`, started)
  }
  if (result.truncated) {
    return failedRun('osv-scanner', tool, 'osv-scanner output exceeded the size limit', started)
  }
  let raw: unknown
  try {
    raw = result.stdout.trim() === '' ? { results: [] } : JSON.parse(result.stdout)
  } catch (error) {
    return failedRun('osv-scanner', tool, `could not parse osv-scanner output: ${errorMessage(error)}`, started)
  }
  const warnings: string[] = []
  const parsed = parseReport(raw, options, warnings)
  return {
    ...completedRun('osv-scanner', tool, parsed.signals, started, warnings),
    checkedDependencies: parsed.checkedDependencies,
  }
}

/** Convert osv-scanner JSON output into signals (one per advisory per package version). */
export function parseOsvScannerReport(
  raw: unknown,
  options: Pick<ExternalRunOptions, 'root' | 'snapshot'>,
  warnings: string[],
): Signal[] {
  return parseReport(raw, options, warnings).signals
}

function parseReport(
  raw: unknown,
  options: Pick<ExternalRunOptions, 'root' | 'snapshot'>,
  warnings: string[],
): { signals: Signal[]; checkedDependencies: number } {
  const parsed = reportSchema.safeParse(raw)
  if (!parsed.success) {
    warnings.push('osv-scanner output had an unexpected shape')
    return { signals: [], checkedDependencies: 0 }
  }
  const signals: Signal[] = []
  const seen = new Set<string>()
  let packages = 0
  let checkedDependencies = 0
  let malformed = 0
  for (const result of parsed.data.results ?? []) {
    const manifest = result.source?.path
      ? toWorkspacePath(options.root, result.source.path, options.snapshot?.pathPrefix)
      : undefined
    if (!manifest) continue
    if (options.snapshot && !options.snapshot.files.has(manifest)) continue
    const lines = options.snapshot?.files.get(manifest)?.content
    for (const pkg of result.packages ?? []) {
      if (++packages > MAX_PACKAGES) {
        if (packages === MAX_PACKAGES + 1)
          warnings.push(`osv-scanner reported over ${MAX_PACKAGES} packages; rest skipped`)
        continue
      }
      const { name, version, ecosystem } = pkg.package
      if (name && version && ecosystem) checkedDependencies++
      const ref: OsvPackageRef = {
        ecosystem,
        name,
        version,
        manifest,
        ...(lines ? { line: findLine(lines, name) } : {}),
      }
      for (const entry of pkg.vulnerabilities ?? []) {
        const vuln = osvVulnSchema.safeParse(entry)
        if (!vuln.success) {
          malformed++
          continue
        }
        if (vuln.data.withdrawn) continue
        const key = `${vuln.data.id}\0${ecosystem}\0${name}\0${version}\0${manifest}`
        if (seen.has(key)) continue
        seen.add(key)
        signals.push(osvVulnToSignal(vuln.data, [ref], 'osv-scanner'))
      }
    }
  }
  if (malformed > 0) warnings.push(`${malformed} osv-scanner advisories had an unexpected shape and were skipped`)
  return { signals, checkedDependencies }
}

function offlineV1(options: OsvScannerRunOptions): string[] {
  return ['--no-call-analysis=all', ...(options.offline ? ['--experimental-offline'] : [])]
}

/** Whether a local OSV database exists in the locations osv-scanner checks. */
async function hasLocalDatabase(override: string | undefined): Promise<boolean> {
  const candidates = override
    ? [override]
    : [process.env.OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY, userCacheDir(), tmpdir()].filter(
        (dir): dir is string => typeof dir === 'string' && dir !== '',
      )
  for (const base of candidates) {
    const root = join(base, 'osv-scanner')
    try {
      for (const ecosystem of await readdir(root)) {
        const st = await stat(join(root, ecosystem, 'all.zip')).catch(() => undefined)
        if (st?.isFile() && st.size > 0) return true
      }
    } catch {
      // Try the next location.
    }
  }
  return false
}

/** Go's `os.UserCacheDir` for the current platform. */
function userCacheDir(): string | undefined {
  switch (process.platform) {
    case 'win32':
      return process.env.LocalAppData ?? process.env.LOCALAPPDATA
    case 'darwin':
      return join(homedir(), 'Library', 'Caches')
    default:
      return process.env.XDG_CACHE_HOME || join(homedir(), '.cache')
  }
}

/** 1-based line where a package name first appears in its manifest (best effort). */
function findLine(content: string, name: string): number | undefined {
  const quoted = content.indexOf(`"${name}"`)
  const index = quoted >= 0 ? quoted : content.indexOf(name)
  if (index < 0) return undefined
  let line = 1
  for (let i = content.indexOf('\n'); i >= 0 && i < index; i = content.indexOf('\n', i + 1)) line++
  return line
}
