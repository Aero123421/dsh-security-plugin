/**
 * Wire contract between the browser half and the Host half.
 *
 * Every method is one exact DSH Connection route
 * `POST /api/dsh-security/<method>` carrying the standard Connection
 * `client-request` envelope. Requests and responses are plain JSON. The Host
 * validates every request payload; the browser trusts the Host's shapes.
 */

import type {
  Closure,
  CodeRef,
  EvidenceKind,
  EvidenceTrust,
  FindingCategory,
  FindingSource,
  QuoteCheck,
  RoleName,
  ScanMode,
  ScanPhase,
  ScanStatus,
  Severity,
  TriageState,
  Verification,
} from './domain.ts'
import type { ModelRef, SecuritySettings, SettingsPatch } from './settings.ts'

/** Endpoint prefix under the shared `/api` channel. */
export const RPC_NAMESPACE = 'dsh-security'
/** Bumped on any incompatible change to this file. */
export const CONTRACT_VERSION = 1

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/** Stable failure codes; the UI branches on these, never on messages. */
export const ERROR_CODES = [
  'security/bad-request',
  'security/not-found',
  'security/conflict',
  'security/forbidden-remote',
  'security/workspace-unavailable',
  'security/no-model',
  'security/consent-required',
  'security/busy',
  'security/invalid-state',
  'security/toolkit-unavailable',
  'security/internal',
] as const
export type ErrorCode = (typeof ERROR_CODES)[number]

export interface RpcFailure {
  readonly code: ErrorCode | string
  readonly message: string
  readonly details: Readonly<Record<string, unknown>>
}

export type RpcResult<T> = { readonly ok: true; readonly value: T } | { readonly ok: false; readonly error: RpcFailure }

// ---------------------------------------------------------------------------
// Capabilities, workspaces, models
// ---------------------------------------------------------------------------

export type AnalyzerId =
  | 'secrets'
  | 'sast'
  | 'routes'
  | 'dependencies'
  | 'osv'
  | 'ast-grep'
  | 'gitleaks'
  | 'osv-scanner'
  | 'semgrep'

export interface AnalyzerStatus {
  readonly id: AnalyzerId
  readonly available: boolean
  /** Version string when known. */
  readonly version?: string
  /** `builtin`, `managed`, `path`, or `disabled`. */
  readonly source: 'builtin' | 'managed' | 'path' | 'disabled'
  /** Why it is unavailable, in English (the UI maps known reasons). */
  readonly reason?: string
}

export interface Bootstrap {
  readonly pluginVersion: string
  readonly contractVersion: number
  readonly settings: SecuritySettings
  readonly settingsRevision: number
  /** Whether this request came from the same machine as the Host. */
  readonly loopback: boolean
  /** Whether high-risk settings may be enabled from this page. */
  readonly canEditHighRiskSettings: boolean
  readonly capabilities: {
    /** DSH LLM registry present with at least one provider. */
    readonly llm: boolean
    /** DSH workspace registry present. */
    readonly workspaces: boolean
    readonly analyzers: readonly AnalyzerStatus[]
  }
  /** Operator ceilings, so the settings form can show valid ranges. */
  readonly limits: OperatorLimits
}

export interface OperatorLimits {
  readonly maxParallelWorkers: number
  readonly maxConcurrentScans: number
  readonly maxFiles: number
  readonly maxFileBytes: number
  readonly maxTotalBytes: number
  readonly maxTokensPerScan: number
  readonly maxLlmCallsPerScan: number
}

export interface WorkspaceSummary {
  readonly id: string
  readonly title: string
  /** Display path (home-relative when possible). */
  readonly displayPath: string
  readonly lastScan?: ScanSummary
}

export interface ModelOption {
  readonly id: string
  readonly name: string
  readonly description?: string
  readonly contextWindow?: number
  readonly reasoningEfforts?: readonly { readonly id: string; readonly name: string }[]
  readonly defaultEffort?: string
}

export interface ProviderOption {
  readonly id: string
  readonly name: string
  readonly models: readonly ModelOption[]
  /** Listing failure, when the provider could not enumerate models. */
  readonly error?: string
}

// ---------------------------------------------------------------------------
// Scans
// ---------------------------------------------------------------------------

export interface ScanUsage {
  readonly llmCalls: number
  readonly inputTokens: number
  readonly outputTokens: number
  readonly toolCalls: number
  /** Milliseconds spent in `running`. */
  readonly elapsedMs: number
}

export interface Coverage {
  readonly files: { readonly total: number; readonly analyzed: number; readonly readByAi: number; readonly excluded: number }
  readonly endpoints: { readonly total: number; readonly reviewed: number }
  readonly tasks: {
    readonly planned: number
    readonly completed: number
    readonly failed: number
    readonly skipped: number
  }
  readonly analyzers: readonly AnalyzerStatus[]
  /** Candidates dropped because none of their cited evidence matched the source. */
  readonly discardedUnverifiable: number
  /** Human-readable gaps, e.g. "budget exhausted before 12 tasks". */
  readonly gaps: readonly string[]
}

export interface SeverityCounts {
  readonly critical: number
  readonly high: number
  readonly medium: number
  readonly low: number
  readonly info: number
}

export interface ScanSummary {
  readonly id: string
  readonly workspaceId: string
  readonly workspaceTitle: string
  readonly mode: ScanMode
  readonly status: ScanStatus
  readonly phase: ScanPhase
  readonly createdAt: string
  readonly startedAt?: string
  readonly finishedAt?: string
  /** Open (not ruled out, not triaged away) findings by severity. */
  readonly counts: SeverityCounts
  readonly confirmed: number
  readonly error?: { readonly code: string; readonly message: string }
  /** Git commit at snapshot time, when the workspace is a git checkout. */
  readonly commit?: string
  readonly dirty?: boolean
}

export type WorkerState = 'running' | 'done' | 'failed' | 'cancelled'

export interface WorkerView {
  readonly id: string
  readonly role: RoleName
  readonly title: string
  readonly model: string
  readonly state: WorkerState
  readonly turns: number
  readonly toolCalls: number
  readonly startedAt: string
}

export interface ScanNotice {
  readonly level: 'info' | 'warn' | 'error'
  /** Stable message key; the UI localizes known keys and falls back to `text`. */
  readonly key: string
  readonly text: string
  readonly at: string
}

export interface PhaseProgress {
  readonly phase: ScanPhase
  readonly state: 'pending' | 'running' | 'done' | 'skipped'
}

export interface ScanDetail {
  readonly summary: ScanSummary
  readonly phases: readonly PhaseProgress[]
  /** Work units done/total within the current phase, when countable. */
  readonly progress?: { readonly done: number; readonly total: number; readonly unit: string }
  readonly usage: ScanUsage
  readonly budget: { readonly maxLlmCalls: number; readonly maxTokens: number; readonly maxMinutes: number }
  readonly workers: readonly WorkerView[]
  readonly coverage?: Coverage
  readonly notices: readonly ScanNotice[]
  /** Model routes used, by role. */
  readonly models: { readonly [R in RoleName]?: ModelRef }
  readonly threatModel?: ThreatModelView
}

export interface ThreatModelView {
  readonly summary: string
  readonly assets: readonly string[]
  readonly actors: readonly string[]
  readonly trustBoundaries: readonly string[]
}

export interface ScanEstimate {
  readonly files: number
  readonly bytes: number
  readonly excluded: number
  readonly languages: readonly { readonly language: string; readonly files: number }[]
  readonly frameworks: readonly string[]
  readonly endpoints: number
  readonly plannedTasks: number
  /** Rough token envelope for the AI phases at this mode's budget. */
  readonly tokens: { readonly min: number; readonly max: number }
  readonly truncated: boolean
}

// ---------------------------------------------------------------------------
// Findings
// ---------------------------------------------------------------------------

export interface FindingSummary {
  readonly id: string
  readonly scanId: string
  readonly fingerprint: string
  readonly title: string
  readonly category: FindingCategory
  readonly severity: Severity
  readonly verification: Verification
  readonly closure: Closure
  readonly source: FindingSource
  readonly cwe?: string
  readonly ruleId?: string
  readonly location?: CodeRef
  /** One or two plain-language sentences for beginners. */
  readonly summary: string
  readonly triage: TriageState
  /** Not present in the previous completed scan of the same workspace. */
  readonly isNew: boolean
}

export interface EvidenceView {
  readonly id: string
  readonly kind: EvidenceKind
  readonly trust: EvidenceTrust
  readonly claim: string
  readonly location?: CodeRef
  /** Redacted source excerpt as stored in the snapshot. */
  readonly snippet?: string
  readonly quoteCheck: QuoteCheck
  readonly originRole: RoleName | 'analyzer'
}

export interface AttackStepView {
  readonly order: number
  readonly description: string
  readonly location?: CodeRef
  readonly snippet?: string
  readonly quoteCheck: QuoteCheck
}

export interface FindingDetail extends FindingSummary {
  readonly impact: string
  readonly preconditions: readonly string[]
  readonly attackPath: readonly AttackStepView[]
  readonly recommendation: string
  readonly evidence: readonly EvidenceView[]
  readonly counterevidence: readonly EvidenceView[]
  /** What the independent review concluded and why. */
  readonly review?: { readonly verdict: 'confirmed' | 'refuted' | 'inconclusive'; readonly reasoning: string; readonly model: string }
  /** What could not be established (e.g. deployment configuration unknown). */
  readonly limitations: readonly string[]
  readonly references: readonly string[]
  readonly triageNote?: string
  readonly createdBy: { readonly role: RoleName | 'analyzer'; readonly model?: string; readonly analyzer?: string }
}

export interface FindingFilter {
  readonly severities?: readonly Severity[]
  readonly closures?: readonly Closure[]
  readonly sources?: readonly FindingSource[]
  readonly triage?: readonly TriageState[]
  readonly text?: string
}

export type ReportFormat = 'markdown' | 'json' | 'sarif'

export interface ReportFile {
  readonly filename: string
  readonly mime: string
  readonly content: string
}

export interface ScanEvent {
  readonly seq: number
  readonly at: string
  readonly level: 'debug' | 'info' | 'warn' | 'error'
  readonly type: string
  readonly message: string
}

// ---------------------------------------------------------------------------
// Toolkit
// ---------------------------------------------------------------------------

export interface ToolkitEntry {
  readonly id: 'gitleaks' | 'osv-scanner' | 'semgrep'
  readonly name: string
  readonly license: string
  readonly homepage: string
  readonly status: AnalyzerStatus
  /** Present when this platform has a pinned, hash-verified download. */
  readonly managed?: {
    readonly version: string
    readonly url: string
    readonly sizeBytes?: number
    readonly sha256: string
  }
  /** Manual installation guidance when no managed download exists. */
  readonly installHint: string
}

// ---------------------------------------------------------------------------
// Method map
// ---------------------------------------------------------------------------

export interface RpcMethods {
  getBootstrap: { request: Record<string, never>; response: Bootstrap }
  listWorkspaces: { request: Record<string, never>; response: readonly WorkspaceSummary[] }
  listModels: { request: Record<string, never>; response: readonly ProviderOption[] }
  updateSettings: {
    request: { readonly patch: SettingsPatch; readonly expectedRevision: number }
    response: { readonly settings: SecuritySettings; readonly revision: number }
  }
  estimateScan: { request: { readonly workspaceId: string; readonly mode: ScanMode }; response: ScanEstimate }
  createScan: {
    request: { readonly workspaceId: string; readonly mode: ScanMode }
    response: { readonly scanId: string }
  }
  listScans: {
    request: { readonly workspaceId?: string; readonly limit?: number }
    response: readonly ScanSummary[]
  }
  getScan: { request: { readonly scanId: string }; response: ScanDetail }
  pauseScan: { request: { readonly scanId: string }; response: ScanSummary }
  resumeScan: { request: { readonly scanId: string }; response: ScanSummary }
  cancelScan: { request: { readonly scanId: string }; response: ScanSummary }
  deleteScan: { request: { readonly scanId: string }; response: { readonly deleted: boolean } }
  listFindings: {
    request: { readonly scanId: string; readonly filter?: FindingFilter }
    response: readonly FindingSummary[]
  }
  getFinding: { request: { readonly scanId: string; readonly findingId: string }; response: FindingDetail }
  setTriage: {
    request: { readonly scanId: string; readonly findingId: string; readonly triage: TriageState; readonly note?: string }
    response: FindingSummary
  }
  getFixPrompt: {
    request: { readonly scanId: string; readonly findingId: string }
    response: { readonly prompt: string }
  }
  exportReport: { request: { readonly scanId: string; readonly format: ReportFormat }; response: ReportFile }
  listEvents: {
    request: { readonly scanId: string; readonly afterSeq?: number; readonly limit?: number }
    response: readonly ScanEvent[]
  }
  listToolkit: { request: Record<string, never>; response: readonly ToolkitEntry[] }
  installTool: {
    request: { readonly toolId: ToolkitEntry['id']; readonly acceptLicense: true }
    response: ToolkitEntry
  }
}

export type RpcMethodName = keyof RpcMethods
export type RpcRequest<M extends RpcMethodName> = RpcMethods[M]['request']
export type RpcResponse<M extends RpcMethodName> = RpcMethods[M]['response']

export const RPC_METHOD_NAMES = [
  'getBootstrap',
  'listWorkspaces',
  'listModels',
  'updateSettings',
  'estimateScan',
  'createScan',
  'listScans',
  'getScan',
  'pauseScan',
  'resumeScan',
  'cancelScan',
  'deleteScan',
  'listFindings',
  'getFinding',
  'setTriage',
  'getFixPrompt',
  'exportReport',
  'listEvents',
  'listToolkit',
  'installTool',
] as const satisfies readonly RpcMethodName[]

/** Compile-time check that RPC_METHOD_NAMES lists every method. */
type _MissingMethods = Exclude<RpcMethodName, (typeof RPC_METHOD_NAMES)[number]>
const _exhaustive: [_MissingMethods] extends [never] ? true : never = true
void _exhaustive
