/**
 * Runs one real scan in-process: the plugin's `ScanController` over an
 * in-memory store, a temporary copy of one fixture app registered as the only
 * workspace, no toolkit and no network. The finished scan is exported through
 * the same `exportReport` RPC handler the Security page uses, so the bench
 * scores exactly what a user would download as JSON.
 *
 * This module imports plugin source that needs TypeScript transforms beyond
 * Node's strip-only mode; `bench/run.ts` registers `bench/hooks.ts` before it
 * imports this file. Vitest handles the transforms itself.
 */

import { readFileSync } from 'node:fs'
import { copyFile, mkdir, mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { type AstGrepHandle, loadAstGrep } from '../src/host/analysis/astgrep.ts'
import { Config, operatorLimits } from '../src/host/config.ts'
import type {
  LlmGenerateOptions,
  LlmModelInfo,
  LlmPort,
  LlmProviderInfo,
  LlmResolvedModelInfo,
  LlmStreamChunk,
  LoggerPort,
  WorkspaceEntity,
  WorkspaceRegistryPort,
} from '../src/host/dsh/ports.ts'
import { ScanController } from '../src/host/scan/controller.ts'
import { createHandlers } from '../src/host/service.ts'
import { SettingsService } from '../src/host/settings.ts'
import { openSecurityStore } from '../src/host/store/sqlite.ts'
import type { ScanMode } from '../src/shared/domain.ts'
import type { SettingsPatch } from '../src/shared/settings.ts'
import { copyFixtureApp, type FixtureManifest } from './fixtures.ts'
import { type ParsedReport, parseJsonReport } from './report.ts'
import { type AppScore, scoreApp } from './scoring.ts'

/** One way of running the scanner over a fixture app. */
export interface BenchConfig {
  readonly name: string
  /** Selected by `--config`. */
  readonly group: 'deterministic' | 'oracle'
  readonly description: string
  readonly mode: ScanMode
  readonly aiReview: boolean
  /** Use the native ast-grep engine (when it loads on this platform). */
  readonly astGrep: boolean
}

export const BENCH_CONFIGS: readonly BenchConfig[] = [
  {
    name: 'deterministic',
    group: 'deterministic',
    description: 'built-in analyzers with the ast-grep engine; no model, no network',
    mode: 'deep',
    aiReview: false,
    astGrep: true,
  },
  {
    name: 'deterministic-builtin',
    group: 'deterministic',
    description: 'built-in analyzers with the fallback lexer (ast-grep off); no model, no network',
    mode: 'deep',
    aiReview: false,
    astGrep: false,
  },
  {
    name: 'oracle',
    group: 'oracle',
    description:
      'deep scan driven by the scripted fixture-aware model: measures plumbing and verification loss, NOT model quality',
    mode: 'deep',
    aiReview: true,
    astGrep: true,
  },
]

/** Provider and model id registered by `tests/e2e/scripted-llm`. */
export const ORACLE_ROUTE = { provider: 'scripted', model: 'oracle' } as const

export interface BenchRun {
  readonly app: string
  readonly config: string
  readonly status: 'completed' | 'failed' | 'skipped'
  /** Why the run failed or was skipped. */
  readonly reason?: string
  /** Final scan status as stored by the plugin. */
  readonly scanStatus?: string
  /** Wall time from `createScan` until the job settled. */
  readonly wallMs: number
  readonly engine: 'ast-grep' | 'builtin'
  readonly report?: ParsedReport
  /** The exported JSON report exactly as the Security page would download it. */
  readonly reportJson?: string
  readonly score?: AppScore
  /** Errors the plugin logged while scanning (warnings are only counted). */
  readonly logged: { readonly warnings: number; readonly errors: readonly string[] }
}

export interface RunOptions {
  /** Parent of the temporary workspace copy; default a fresh directory under the OS temp dir. */
  readonly workRoot?: string
  /** Kill a scan that runs longer than this; default 10 minutes. */
  readonly timeoutMs?: number
  /** Line tolerance for matching; default 3. */
  readonly tolerance?: number
}

const PLUGIN_VERSION = (
  JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')) as { readonly version: string }
).version

/** Scan one fixture app with one configuration and score the exported JSON report. */
export async function runBenchScan(
  manifest: FixtureManifest,
  config: BenchConfig,
  options: RunOptions = {},
): Promise<BenchRun> {
  const astGrep = config.astGrep ? await loadAstGrep() : undefined
  const engine = astGrep ? 'ast-grep' : 'builtin'
  const logged = { warnings: 0, errors: [] as string[] }
  if (config.astGrep && !astGrep) {
    return {
      app: manifest.app,
      config: config.name,
      status: 'skipped',
      reason: 'the ast-grep native module is not available on this platform',
      wallMs: 0,
      engine,
      logged,
    }
  }

  const ownRoot = options.workRoot === undefined
  const workRoot = options.workRoot ?? (await mkdtemp(join(tmpdir(), 'dsh-security-bench-')))
  const workspaceDir = await copyFixtureApp(manifest, join(workRoot, `${config.name}-workspace`))
  const llm = config.aiReview
    ? await loadOracle(await truthDir(manifest, join(workRoot, `${config.name}-truth`)))
    : undefined
  const logger: LoggerPort = {
    debug: () => undefined,
    info: () => undefined,
    warn: () => {
      logged.warnings++
    },
    error: (...args: unknown[]) => {
      logged.errors.push(args.map(describe).join(' ').slice(0, 500))
    },
  }
  const pluginConfig = Config.parse({ maxConcurrentScans: 1, maxParallelWorkers: 4 })
  const store = openSecurityStore(':memory:')
  const settings = new SettingsService(store, operatorLimits(pluginConfig), true, logger)
  const workspace: WorkspaceEntity = { id: `bench-${manifest.app}`, path: workspaceDir, title: manifest.app }
  const workspaces: WorkspaceRegistryPort = {
    list: () => [workspace],
    get: id => (id === workspace.id ? workspace : undefined),
  }
  const now = () => new Date()
  const deps = {
    store,
    settings,
    llm: () => llm,
    workspaces: () => workspaces,
    toolkit: undefined,
    config: pluginConfig,
    logger,
    fetch: offlineFetch,
    astGrep: () => Promise.resolve<AstGrepHandle | undefined>(astGrep),
    now,
    pluginVersion: PLUGIN_VERSION,
  }
  const controller = new ScanController(deps)
  const handlers = createHandlers({ ...deps, controller })
  const started = performance.now()
  try {
    settings.update(benchSettings(config), settings.get().revision, true)
    controller.start()
    const scan = await controller.create({ workspaceId: workspace.id, mode: config.mode, aiReview: config.aiReview })
    await settle(controller, scan.id, options.timeoutMs ?? 10 * 60_000)
    const wallMs = performance.now() - started
    const final = store.getScan(scan.id)
    const exported = await handlers.exportReport(
      { scanId: scan.id, format: 'json' },
      { request: new Request('http://127.0.0.1/'), loopback: true, signal: new AbortController().signal },
    )
    const report = parseJsonReport(JSON.parse(exported.content))
    const score = scoreApp(manifest, report.findings, {
      ...(report.activeDetectors ? { activeDetectors: report.activeDetectors } : {}),
      ...(options.tolerance !== undefined ? { tolerance: options.tolerance } : {}),
    })
    const completed = final?.status === 'completed'
    return {
      app: manifest.app,
      config: config.name,
      status: completed ? 'completed' : 'failed',
      ...(completed ? {} : { reason: final?.error?.message ?? `scan ended as ${final?.status ?? 'unknown'}` }),
      ...(final ? { scanStatus: final.status } : {}),
      wallMs,
      engine,
      report,
      reportJson: exported.content,
      score,
      logged,
    }
  } catch (error) {
    return {
      app: manifest.app,
      config: config.name,
      status: 'failed',
      reason: describe(error),
      wallMs: performance.now() - started,
      engine,
      logged,
    }
  } finally {
    await controller.dispose()
    store.close()
    if (ownRoot) await rm(workRoot, { recursive: true, force: true })
  }
}

/** Settings for a bench scan: the oracle route when AI review runs; nothing leaves the machine. */
function benchSettings(config: BenchConfig): SettingsPatch {
  return {
    ...(config.aiReview ? { models: { default: { ...ORACLE_ROUTE } } } : {}),
    scan: { parallelWorkers: 4 },
    privacy: { sendCodeToModel: config.aiReview, allowDependencyLookup: false, useExternalAnalyzers: false },
    storage: { keepTranscripts: false },
  }
}

/** Wait until the controller no longer runs the scan. */
async function settle(controller: ScanController, scanId: string, timeoutMs: number): Promise<void> {
  const deadline = Date.now() + timeoutMs
  while (controller.isRunning(scanId)) {
    if (Date.now() > deadline) {
      controller.cancel(scanId)
      while (controller.isRunning(scanId)) await sleep(10)
      throw new Error(`scan did not finish within ${Math.round(timeoutMs / 1000)} s and was cancelled`)
    }
    await sleep(10)
  }
}

/** The bench never reaches the network: OSV lookups are off, and anything else fails loudly. */
const offlineFetch: typeof fetch = async () => {
  throw new Error('network access is disabled in the bench')
}

// ---------------------------------------------------------------------------
// Oracle model
// ---------------------------------------------------------------------------

interface ScriptedAdapter {
  providerInfo(provider: string): LlmProviderInfo
  listModels(provider: string): Promise<LlmModelInfo[]>
  resolveModel(provider: string, model: string, signal?: AbortSignal): Promise<LlmResolvedModelInfo>
  stream(options: LlmGenerateOptions): AsyncIterable<LlmStreamChunk>
}

/** A truth directory holding only this app's manifest, so the oracle cannot mix up apps that share paths. */
async function truthDir(manifest: FixtureManifest, root: string): Promise<string> {
  await mkdir(join(root, manifest.app), { recursive: true })
  await copyFile(join(manifest.dir, 'expected.json'), join(root, manifest.app, 'expected.json'))
  return root
}

/**
 * Load the scripted e2e model in-process. Its DSH plugin entry is applied to a
 * minimal fake context that captures the adapter it registers, and the
 * adapter is exposed as an {@link LlmPort} exactly like `ctx.llm` would.
 */
export async function loadOracle(fixturesDir: string): Promise<LlmPort> {
  const specifier = new URL('../tests/e2e/scripted-llm/index.mjs', import.meta.url).href
  const mod: unknown = await import(/* @vite-ignore */ specifier)
  const apply = isRecord(mod) ? mod.apply : undefined
  if (typeof apply !== 'function') throw new Error('tests/e2e/scripted-llm does not export apply()')
  let captured: unknown
  const ctx = {
    effect(execute: () => unknown): void {
      execute()
    },
    llm: {
      registerAdapter(_providers: string[], adapter: unknown): () => void {
        captured = adapter
        return () => undefined
      },
    },
  }
  Reflect.apply(apply, undefined, [ctx, { fixturesDir, delayMs: 0 }])
  if (!isAdapter(captured)) throw new Error('tests/e2e/scripted-llm did not register a usable adapter')
  const adapter = captured
  return {
    listProviders: () => [adapter.providerInfo(ORACLE_ROUTE.provider)],
    listModels: provider => adapter.listModels(provider),
    resolveModelInfo: (provider, model, signal) => adapter.resolveModel(provider, model, signal),
    stream: options => adapter.stream(options),
  }
}

function isAdapter(value: unknown): value is ScriptedAdapter {
  return (
    isRecord(value) &&
    ['providerInfo', 'listModels', 'resolveModel', 'stream'].every(name => typeof value[name] === 'function')
  )
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null
}

function describe(value: unknown): string {
  if (value instanceof Error) return value.message
  return typeof value === 'string' ? value : (JSON.stringify(value) ?? String(value))
}

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms))
}
