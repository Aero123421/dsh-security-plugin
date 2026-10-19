/**
 * The deterministic half of a scan: snapshot, inventory, secrets and
 * redaction, pattern rules, routes, dependencies, and optional external
 * analyzers. Everything here is local and reproducible; network access is
 * limited to OSV lookups the user enabled (package names and versions only).
 */

import type { AnalyzerStatus } from '../../shared/contracts.ts'
import { severityRank } from '../../shared/domain.ts'
import type { SecuritySettings } from '../../shared/settings.ts'
import type { AstGrepHandle } from '../analysis/astgrep.ts'
import { parseDependencies } from '../analysis/dependencies.ts'
import { runGitleaks } from '../analysis/external/gitleaks.ts'
import { runOsvScanner } from '../analysis/external/osv-scanner.ts'
import { runSemgrep } from '../analysis/external/semgrep.ts'
import { buildInventory } from '../analysis/inventory.ts'
import { queryOsv } from '../analysis/osv.ts'
import { extractRoutes } from '../analysis/routes/index.ts'
import { routeSignals } from '../analysis/routes/signals.ts'
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
  /** OSV-Scanner returned package results (a clean result counts too). */
  readonly dependencyScannerChecked: boolean
  readonly dependencyLookupComplete: boolean
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
  readonly workspaceRoot?: string
  readonly registeredWorkspaceRoot?: string
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
  workspaceRoot?: string,
): Promise<Snapshot> {
  return await takeSnapshot(root, {
    ...(workspaceRoot ? { workspaceRoot } : {}),
    excludeGlobs: settings.scan.excludeGlobs,
    maxFiles: config.maxFiles,
    maxEntries: config.maxEntries,
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
  const snapshot: Snapshot = {
    ...(await snapshotWorkspace(options.root, settings, config, signal, options.workspaceRoot)),
    ...(options.registeredWorkspaceRoot ? { registeredWorkspaceRoot: options.registeredWorkspaceRoot } : {}),
  }
  if (snapshot.truncated) {
    warnings.push(
      `The snapshot reached the configured size limit; ${snapshot.excluded.filter(e => e.reason.startsWith('limit-')).length} or more files were not analyzed.`,
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
  let dependencyScannerChecked = false
  let dependencyLookupComplete = false
  if (!options.lightweight) {
    step('sast')
    collect(await runSast(snapshot, { ...(options.astGrep ? { astGrep: options.astGrep } : {}), signal }))
    analyzers.push(
      options.astGrep
        ? {
            id: 'ast-grep',
            available: true,
            source: 'builtin',
            reasonCode: options.astGrep.supportsPython ? 'python-available' : 'python-fallback',
            reason: options.astGrep.supportsPython
              ? 'Python AST available'
              : 'Python AST unavailable; Python uses the built-in parser',
          }
        : {
            id: 'ast-grep',
            available: false,
            source: 'builtin',
            reasonCode: config.disableAstGrep ? 'disabled' : 'native-unavailable',
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
      const osv = await queryOsv(deps.dependencies, {
        endpoint: config.osvEndpoint,
        fetch: options.fetch,
        signal,
        withheldGlobs: settings.privacy.withheldGlobs,
      })
      signals.push(...osv.signals)
      warnings.push(...osv.warnings.slice(0, 10))
      dependencyLookupComplete =
        deps.dependencies.length === 0 ||
        (osv.queried > 0 && osv.queried === osv.requested && osv.skipped === 0 && osv.warnings.length === 0)
      analyzers.push({
        id: 'osv',
        available: dependencyLookupComplete,
        source: 'builtin',
        ...(!dependencyLookupComplete
          ? {
              reasonCode: 'incomplete',
              reason:
                `OSV dependency lookup was incomplete (${osv.queried}/${osv.requested} package versions answered; ${osv.skipped} declarations not eligible or withheld). ${osv.warnings.slice(0, 3).join('; ')}`.trim(),
            }
          : {}),
      })
    } else {
      analyzers.push({
        id: 'osv',
        available: false,
        source: 'disabled',
        reasonCode: 'lookup-off',
        reason: 'dependency lookup is turned off in Privacy settings',
      })
    }

    step('external')
    await runExternal()
  }

  step('routes')
  const routes = await extractRoutes(snapshot, { ...(options.astGrep ? { astGrep: options.astGrep } : {}), signal })
  endpoints = routes.endpoints
  signals.push(...routeSignals(endpoints, snapshot))
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
        analyzers.push({
          id,
          available: false,
          source: 'disabled',
          reasonCode: 'external-off',
          reason: 'external analyzers are turned off',
        })
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
    const scanner = await runOsvScanner({
      ...common,
      tool: await toolkit.resolveHandle('osv-scanner'),
      // Without OSV consent the scanner must not reach the network.
      offline: !settings.privacy.allowDependencyLookup,
      withheldGlobs: settings.privacy.withheldGlobs,
    })
    collect(scanner)
    dependencyScannerChecked =
      (scanner.checkedDependencies ?? 0) > 0 || scanner.signals.some(s => s.kind === 'dependency')
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
    dependencyScannerChecked,
    dependencyLookupComplete,
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

const EXTERNAL_ANALYZERS: ReadonlySet<Signal['analyzer']> = new Set(['gitleaks', 'osv-scanner', 'semgrep'])

/**
 * Drop repeated observations of one issue, in input order:
 * - one dependency advisory for one package version (the built-in OSV lookup and OSV-Scanner both report it);
 * - an external result (Gitleaks, Semgrep) at the start line of a built-in signal of the same kind and
 *   category (for secrets, with overlapping columns when both sides know them): it is merged into the
 *   built-in signal, preferring one with the same CWE;
 * - the same rule reported twice at one line and secret span.
 * A merged signal keeps the higher severity. Different rules on one line (`algorithms: ['none']` next to
 * `ignoreExpiration: true`), and different credentials on one line, stay separate.
 */
export function dedupeSignals(signals: readonly Signal[]): Signal[] {
  const kept: (Signal | undefined)[] = [...signals]
  const firstOf = new Map<string, number>()
  const builtinAt = new Map<string, number[]>()
  const raise = (index: number, other: Signal): void => {
    const signal = kept[index]!
    if (severityRank(other.severity) < severityRank(signal.severity))
      kept[index] = { ...signal, severity: other.severity }
  }
  // Built-in signals first, so an external result can merge into one reported later in the list.
  for (const external of [false, true]) {
    signals.forEach((signal, index) => {
      if (signal.kind !== 'dependency' && EXTERNAL_ANALYZERS.has(signal.analyzer) !== external) return
      if (signal.kind === 'dependency' && external) return
      const key =
        signal.kind === 'dependency'
          ? `dep\u0000${signal.ruleId}\u0000${signal.snippet}`
          : [
              signal.analyzer,
              signal.ruleId,
              signal.kind,
              signal.location.path,
              signal.location.startLine,
              spanKey(signal),
            ].join('\u0000')
      const first = firstOf.get(key)
      if (first !== undefined) {
        raise(first, signal)
        kept[index] = undefined
        return
      }
      const lineKey = `${signal.kind}\u0000${signal.category}\u0000${signal.location.path}\u0000${signal.location.startLine}`
      if (external) {
        const candidates = (builtinAt.get(lineKey) ?? []).filter(i => sameSpan(kept[i]!, signal))
        const match = candidates.find(i => signal.cwe !== undefined && kept[i]!.cwe === signal.cwe) ?? candidates[0]
        if (match !== undefined) {
          raise(match, signal)
          kept[index] = undefined
          return
        }
      } else if (signal.kind !== 'dependency') {
        const list = builtinAt.get(lineKey)
        if (list) list.push(index)
        else builtinAt.set(lineKey, [index])
      }
      firstOf.set(key, index)
    })
  }
  return kept.filter((signal): signal is Signal => signal !== undefined)
}

/** What distinguishes two hits of one rule on one line: the secret span, else the reported column. */
function spanKey(signal: Signal): string {
  const start = signal.metadata?.secretStart
  const end = signal.metadata?.secretEnd
  if (typeof start === 'number' && typeof end === 'number') return `${start}-${end}`
  const column = signal.metadata?.column
  return typeof column === 'number' ? `col${column}` : ''
}

/** 1-based column range `[from, to)` on the start line, when the signal records one. */
function columnRange(signal: Signal): readonly [number, number] | undefined {
  const column = signal.metadata?.column
  if (typeof column !== 'number') return undefined
  const endColumn = signal.metadata?.endColumn
  if (typeof endColumn === 'number' && endColumn > column) return [column, endColumn]
  const start = signal.metadata?.secretStart
  const end = signal.metadata?.secretEnd
  if (typeof start === 'number' && typeof end === 'number' && signal.location.endLine === signal.location.startLine)
    return [column, column + Math.max(1, end - start)]
  return undefined
}

/**
 * A secret span the external tool located elsewhere on the line is a different credential. Columns are
 * compared with one character of slack: Gitleaks counts bytes and is off by one after the first line.
 */
function sameSpan(builtin: Signal, external: Signal): boolean {
  if (builtin.kind !== 'secret') return true
  const a = columnRange(builtin)
  const b = columnRange(external)
  return a === undefined || b === undefined || (a[0] <= b[1] && b[0] <= a[1])
}
