/**
 * The deterministic half of a scan: snapshot, inventory, secrets and
 * redaction, pattern rules, routes, dependencies, and optional external
 * analyzers. Everything here is local and reproducible; network access is
 * limited to OSV lookups the user enabled (package names and versions only).
 */

import type { AnalyzerStatus } from '../../shared/contracts.ts'
import type { SecuritySettings } from '../../shared/settings.ts'
import type { AstGrepHandle } from '../analysis/astgrep.ts'
import { parseDependencies } from '../analysis/dependencies.ts'
import { runGitleaks } from '../analysis/external/gitleaks.ts'
import { runOsvScanner } from '../analysis/external/osv-scanner.ts'
import { runSemgrep } from '../analysis/external/semgrep.ts'
import { buildInventory } from '../analysis/inventory.ts'
import { queryOsv } from '../analysis/osv.ts'
import { extractRoutes } from '../analysis/routes/index.ts'
import { runSast } from '../analysis/sast/engine.ts'
import { Redactor, redactKnownSecrets, scanSecrets, secretSignals } from '../analysis/secrets.ts'
import { takeSnapshot } from '../analysis/snapshot.ts'
import type { Toolkit } from '../analysis/toolkit.ts'
import type { AnalyzerRun, Dependency, Endpoint, Inventory, Signal, Snapshot } from '../analysis/types.ts'
import { workspaceQuoteSource, type WorkspaceView } from '../agents/tools/workspace.ts'
import type { Config } from '../config.ts'
import type { QuoteSource } from '../evidence/quote.ts'
import { ModelPrivacy } from './privacy.ts'

export interface AnalysisContext {
  readonly snapshot: Snapshot
  readonly inventory: Inventory
  readonly redactor: Redactor
  readonly signals: readonly Signal[]
  readonly endpoints: readonly Endpoint[]
  readonly dependencies: readonly Dependency[]
  readonly analyzers: readonly AnalyzerStatus[]
  readonly warnings: readonly string[]
  readonly astGrep?: AstGrepHandle
  /** Quote verification over exactly what the workspace tools show. */
  readonly quoteSource: QuoteSource
  readonly withheldGlobs: readonly string[]
  /** Policy for text the host writes into model requests (withheld files, secret redaction). */
  readonly privacy: ModelPrivacy
  /** Workspace view for one worker; `onRead` records files the worker read. */
  view(onRead?: (path: string) => void): WorkspaceView
}

export type AnalysisStep = 'snapshot' | 'inventory' | 'secrets' | 'sast' | 'routes' | 'dependencies' | 'external'

export interface AnalysisOptions {
  readonly root: string
  readonly settings: SecuritySettings
  readonly config: Config
  readonly toolkit: Toolkit | undefined
  readonly fetch: typeof fetch
  readonly astGrep: AstGrepHandle | undefined
  readonly signal: AbortSignal
  /** Skip analyzers that cost time but are not needed (estimates). */
  readonly lightweight?: boolean
  readonly onStep?: (step: AnalysisStep) => void
}

/** Snapshot only, for estimates. */
export async function snapshotWorkspace(
  root: string,
  settings: SecuritySettings,
  config: Config,
  signal: AbortSignal,
): Promise<Snapshot> {
  return await takeSnapshot(root, {
    excludeGlobs: settings.scan.excludeGlobs,
    maxFiles: config.maxFiles,
    maxFileBytes: config.maxFileBytes,
    maxTotalBytes: config.maxTotalBytes,
    signal,
  })
}

export async function analyzeWorkspace(options: AnalysisOptions): Promise<AnalysisContext> {
  const { settings, config, signal } = options
  const step = (name: AnalysisStep) => options.onStep?.(name)
  const warnings: string[] = []
  const analyzers: AnalyzerStatus[] = []
  const signals: Signal[] = []

  step('snapshot')
  const snapshot = await snapshotWorkspace(options.root, settings, config, signal)
  if (snapshot.truncated) {
    warnings.push(
      `The snapshot reached the configured size limit; ${snapshot.excluded.filter(e => e.reason === 'limit-files' || e.reason === 'limit-bytes').length} or more files were not analyzed.`,
    )
  }

  step('inventory')
  const inventory = buildInventory(snapshot)

  step('secrets')
  const matches = await scanSecrets(snapshot, signal)
  const redactor = new Redactor(matches)
  signals.push(...secretSignals(matches, snapshot))
  analyzers.push({ id: 'secrets', available: true, source: 'builtin' })

  let endpoints: Endpoint[] = []
  let dependencies: Dependency[] = []
  if (!options.lightweight) {
    step('sast')
    collect(await runSast(snapshot, { ...(options.astGrep ? { astGrep: options.astGrep } : {}), signal }))
    analyzers.push(
      options.astGrep
        ? { id: 'ast-grep', available: true, source: 'builtin' }
        : {
            id: 'ast-grep',
            available: false,
            source: 'builtin',
            reason: config.disableAstGrep ? 'disabled by configuration' : 'native module unavailable on this platform',
          },
    )
  }

  if (!options.lightweight) {
    step('dependencies')
    const deps = await parseDependencies(snapshot)
    dependencies = deps.dependencies
    warnings.push(...deps.warnings.slice(0, 20))
    analyzers.push({ id: 'dependencies', available: true, source: 'builtin' })

    if (settings.privacy.allowDependencyLookup) {
      const osv = await queryOsv(deps.dependencies, { endpoint: config.osvEndpoint, fetch: options.fetch, signal })
      signals.push(...osv.signals)
      warnings.push(...osv.warnings.slice(0, 10))
      analyzers.push({ id: 'osv', available: true, source: 'builtin' })
    } else {
      analyzers.push({
        id: 'osv',
        available: false,
        source: 'disabled',
        reason: 'dependency lookup is turned off in Privacy settings',
      })
    }

    step('external')
    await runExternal()
  }

  step('routes')
  const routes = await extractRoutes(snapshot, { ...(options.astGrep ? { astGrep: options.astGrep } : {}), signal })
  endpoints = routes.endpoints
  warnings.push(...routes.warnings.slice(0, 20))
  analyzers.push({ id: 'routes', available: true, source: 'builtin' })

  function collect(run: AnalyzerRun): void {
    analyzers.push(run.status)
    signals.push(...run.signals)
    warnings.push(...run.warnings.slice(0, 20))
  }

  async function runExternal(): Promise<void> {
    if (!settings.privacy.useExternalAnalyzers || !options.toolkit) {
      for (const id of ['gitleaks', 'osv-scanner', 'semgrep'] as const) {
        analyzers.push({ id, available: false, source: 'disabled', reason: 'external analyzers are turned off' })
      }
      return
    }
    const toolkit = options.toolkit
    const common = {
      root: snapshot.root,
      snapshot,
      redactor,
      timeoutMs: config.externalTimeoutMs,
      signal,
    }
    collect(await runGitleaks({ ...common, tool: await toolkit.resolveHandle('gitleaks') }))
    collect(
      await runOsvScanner({
        ...common,
        tool: await toolkit.resolveHandle('osv-scanner'),
        // Without OSV consent the scanner must not reach the network.
        offline: !settings.privacy.allowDependencyLookup,
      }),
    )
    collect(
      await runSemgrep({
        ...common,
        tool: await toolkit.resolveHandle('semgrep'),
        ...(config.semgrepConfig ? { configPath: config.semgrepConfig } : {}),
      }),
    )
  }

  const withheldGlobs = settings.privacy.withheldGlobs
  const quoteSource = workspaceQuoteSource({ snapshot, redactor, withheldGlobs })
  const astGrep = options.astGrep
  // SAST and external analyzers redact only the high-confidence patterns; a value the secret scan found
  // (for example a generic password assignment) must not survive in their excerpts either.
  const secretValues = redactor.secretValues(path => snapshot.files.get(path)?.content)
  const redacted = dedupeSignals(signals).map(signal =>
    signal.analyzer === 'secrets' || secretValues.length === 0
      ? signal
      : { ...signal, snippet: redactKnownSecrets(signal.snippet, secretValues) },
  )
  return {
    snapshot,
    inventory,
    redactor,
    signals: redacted,
    endpoints,
    dependencies,
    analyzers,
    warnings,
    ...(astGrep ? { astGrep } : {}),
    quoteSource,
    withheldGlobs,
    privacy: new ModelPrivacy({ snapshot, redactor, withheldGlobs }),
    view: onRead => ({
      snapshot,
      redactor,
      withheldGlobs,
      endpoints,
      ...(astGrep ? { astGrep } : {}),
      ...(onRead ? { onRead } : {}),
    }),
  }
}

/** Builtin and external analyzers can report the same issue; keep the first per location and category. */
function dedupeSignals(signals: readonly Signal[]): Signal[] {
  const seen = new Set<string>()
  const out: Signal[] = []
  for (const signal of signals) {
    const key =
      signal.kind === 'dependency'
        ? `dep\u0000${signal.ruleId}\u0000${signal.snippet}`
        : `${signal.kind}\u0000${signal.category}\u0000${signal.location.path}\u0000${signal.location.startLine}`
    if (seen.has(key)) continue
    seen.add(key)
    out.push(signal)
  }
  return out
}
