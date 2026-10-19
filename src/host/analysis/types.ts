/**
 * Internal vocabulary for the deterministic analysis layer. Nothing here
 * crosses the wire; the RPC layer maps these to `shared/contracts.ts` shapes.
 */

import type { AnalyzerId, AnalyzerStatus, ExcludeReason } from '../../shared/contracts.ts'
import type { CodeRef, FindingCategory, Severity } from '../../shared/domain.ts'

export type { ExcludeReason }

export type Language =
  | 'javascript'
  | 'typescript'
  | 'python'
  | 'go'
  | 'java'
  | 'kotlin'
  | 'ruby'
  | 'php'
  | 'csharp'
  | 'rust'
  | 'shell'
  | 'html'
  | 'vue'
  | 'svelte'
  | 'sql'
  | 'yaml'
  | 'json'
  | 'toml'
  | 'xml'
  | 'dockerfile'
  | 'terraform'
  | 'markdown'
  | 'env'
  | 'other'

export interface SnapshotFile {
  /** Workspace-relative POSIX path; never absolute, never contains `..`. */
  readonly path: string
  readonly size: number
  /** Hex SHA-256 of the raw bytes. */
  readonly sha256: string
  readonly language: Language
  /** UTF-8 text. Binary files are excluded from the snapshot entirely. */
  readonly content: string
  /** Under a test/spec/fixture/example directory or named like a test. */
  readonly isTest: boolean
  /** Minified, generated, or vendored-looking content. */
  readonly isGenerated: boolean
}

export interface ExcludedPath {
  readonly path: string
  readonly reason: ExcludeReason
}

export interface Snapshot {
  /** Absolute canonical root. Host-only; never sent to the browser or a model. */
  readonly root: string
  /** Canonical workspace base for consistent masking across scan scopes. Host-only. */
  readonly workspaceRoot?: string
  /** Registered spelling before canonicalization (for model-side path masking). Host-only. */
  readonly registeredWorkspaceRoot?: string
  /** Workspace-relative prefix of the effective root. */
  readonly pathPrefix?: string
  readonly files: ReadonlyMap<string, SnapshotFile>
  readonly excluded: readonly ExcludedPath[]
  readonly totalBytes: number
  /** All visited excluded paths, even when the displayed exclusion list is capped. */
  readonly excludedCount?: number
  /** Counts behind `excludedCount`, not limited by the excluded-path cap. */
  readonly excludedByReason?: Readonly<Partial<Record<ExcludeReason, number>>>
  /** Known unvisited entries (lower bound; unopened directory descendants are unknown). */
  readonly unvisitedEntries?: number
  /** Queued directories not opened due to the walk budget (not a count of their files). */
  readonly unvisitedDirectories?: number
  /** A file/byte/entry ceiling limited coverage. */
  readonly truncated: boolean
  /** `HEAD` commit when the root is a git checkout. */
  readonly commit?: string
  readonly takenAt: string
}

export interface SnapshotOptions {
  /** Canonical registered workspace root; paths remain relative to this root. */
  readonly workspaceRoot?: string
  /** Extra gitignore-style patterns. */
  readonly excludeGlobs: readonly string[]
  readonly maxFiles: number
  /** Entries visited, directories and excluded paths included; default 100,000. */
  readonly maxEntries?: number
  readonly maxFileBytes: number
  readonly maxTotalBytes: number
  readonly signal?: AbortSignal
}

export interface Inventory {
  readonly languages: readonly { readonly language: Language; readonly files: number; readonly bytes: number }[]
  /** Detected frameworks, e.g. `express`, `next`, `fastapi`, `django`. */
  readonly frameworks: readonly string[]
  /** Manifest and lock files, workspace-relative. */
  readonly manifests: readonly string[]
  readonly testFiles: number
}

export type SignalKind = 'vulnerability' | 'sink' | 'secret' | 'dependency' | 'info'

/**
 * One deterministic observation. A `vulnerability`/`secret`/`dependency`
 * signal becomes a finding candidate; a `sink` only steers AI review.
 */
export interface Signal {
  readonly analyzer: AnalyzerId
  readonly ruleId: string
  readonly kind: SignalKind
  readonly title: string
  readonly category: FindingCategory
  readonly severity: Severity
  readonly confidence: 'low' | 'medium' | 'high'
  readonly cwe?: string
  readonly location: CodeRef
  /** Source excerpt with secrets redacted; at most a few lines. */
  readonly snippet: string
  /** Plain-language explanation for beginners (English). */
  readonly message: string
  readonly recommendation?: string
  /**
   * Stable parts identifying "the same issue" across scans, e.g.
   * `[ruleId, path, normalizedSnippet]`. Never include line numbers alone.
   */
  readonly fingerprintParts: readonly string[]
  readonly references?: readonly string[]
  readonly metadata?: Readonly<Record<string, string | number | boolean>>
}

export interface Endpoint {
  /** Stable id: `${method} ${route} @ ${declaredAt.path}:${declaredAt.startLine}`. */
  readonly id: string
  readonly framework: string
  /** Upper-case HTTP method, or `ANY`. */
  readonly method: string
  /** Route pattern as written (e.g. `/users/:id`, `/items/{item_id}`). */
  readonly route: string
  readonly declaredAt: CodeRef
  /** Handler body when it could be located (may equal `declaredAt`). */
  readonly handler?: CodeRef
  /** Middleware, decorators, dependencies, or guards attached at the route. */
  readonly middleware: readonly string[]
  /** Subset of `middleware` (or nearby code) whose names suggest authentication/authorization. */
  readonly authHints: readonly string[]
  /** Path parameter names. */
  readonly params: readonly string[]
  /**
   * Other files whose code shaped this endpoint: mount calls that contribute
   * its prefix or inherited middleware (`app.use('/api', auth, router)`),
   * receiver-scoped middleware, and prefixes declared elsewhere. Sorted;
   * omitted when everything is in the declaring file.
   */
  readonly mountedAt?: readonly string[]
}

/**
 * Whether an endpoint can be shown to a model without revealing a withheld
 * file: route text, prefixes and middleware names are file content, so the
 * declaration, the handler, and every contributing mount must be visible.
 */
export function isEndpointVisible(endpoint: Endpoint, isWithheld: (path: string) => boolean): boolean {
  if (isWithheld(endpoint.declaredAt.path)) return false
  if (endpoint.handler !== undefined && isWithheld(endpoint.handler.path)) return false
  return !(endpoint.mountedAt ?? []).some(path => isWithheld(path))
}

export interface OutlineSymbol {
  readonly name: string
  readonly kind: 'function' | 'method' | 'class' | 'variable'
  readonly startLine: number
  readonly endLine: number
  readonly exported: boolean
}

export interface OutlineImport {
  readonly source: string
  readonly names: readonly string[]
  readonly line: number
}

export interface FileOutline {
  readonly path: string
  readonly language: Language
  readonly imports: readonly OutlineImport[]
  readonly symbols: readonly OutlineSymbol[]
}

export type Ecosystem = 'npm' | 'PyPI' | 'Go' | 'crates.io' | 'Maven' | 'RubyGems' | 'Packagist'

export interface Dependency {
  readonly ecosystem: Ecosystem
  readonly name: string
  /** Exact resolved version when a lock file provides one; otherwise the declared spec. */
  readonly version: string
  readonly exact: boolean
  /** Workspace-relative manifest or lock file. */
  readonly manifest: string
  readonly line?: number
  readonly direct: boolean
  readonly dev: boolean
}

/** Result of one analyzer run, for coverage reporting. */
export interface AnalyzerRun {
  readonly status: AnalyzerStatus
  readonly signals: readonly Signal[]
  readonly durationMs: number
  /** Non-fatal problems (e.g. a file the parser rejected). */
  readonly warnings: readonly string[]
}

/** Cooperative yield so long analyses do not starve the DSH Host event loop. */
export function yieldToEventLoop(): Promise<void> {
  return new Promise(resolve => setImmediate(resolve))
}
