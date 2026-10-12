/**
 * Internal vocabulary for the deterministic analysis layer. Nothing here
 * crosses the wire; the RPC layer maps these to `shared/contracts.ts` shapes.
 */

import type { AnalyzerId, AnalyzerStatus } from '../../shared/contracts.ts'
import type { CodeRef, FindingCategory, Severity } from '../../shared/domain.ts'

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

/** Why a path is not part of the analyzed snapshot. */
export type ExcludeReason =
  | 'default-ignore'
  | 'gitignore'
  | 'user-exclude'
  | 'binary'
  | 'too-large'
  | 'symlink'
  | 'outside-root'
  | 'limit-files'
  | 'limit-bytes'
  | 'unreadable'

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
  readonly files: ReadonlyMap<string, SnapshotFile>
  readonly excluded: readonly ExcludedPath[]
  readonly totalBytes: number
  /** A file/byte ceiling stopped the walk early. */
  readonly truncated: boolean
  /** `HEAD` commit when the root is a git checkout. */
  readonly commit?: string
  readonly takenAt: string
}

export interface SnapshotOptions {
  /** Extra gitignore-style patterns. */
  readonly excludeGlobs: readonly string[]
  readonly maxFiles: number
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
