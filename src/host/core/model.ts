/**
 * Durable domain records owned by the Host. The store persists exactly these
 * shapes; RPC handlers project them into `shared/contracts.ts` DTOs.
 */

import type { AnalyzerStatus, Coverage, PhaseProgress, ScanUsage, ThreatModelView } from '../../shared/contracts.ts'
import type {
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
} from '../../shared/domain.ts'
import type { ModelRef, ScanBudget, SecuritySettings } from '../../shared/settings.ts'

/** Role or deterministic analyzer that produced a record. */
export type Origin = RoleName | 'analyzer'

export interface ScanError {
  readonly code: string
  readonly message: string
}

/** Planner output kept for later workers and the report. */
export interface ThreatModelRecord extends ThreatModelView {
  /** Entry points the planner considers most important, with reasons. */
  readonly priorities: readonly { readonly target: string; readonly reason: string }[]
  /** Planner hypotheses; each becomes a hunter task. */
  readonly hypotheses: readonly {
    readonly title: string
    readonly category: FindingCategory
    readonly targetPaths: readonly string[]
    readonly rationale: string
  }[]
}

export interface ScanRecord {
  readonly id: string
  readonly workspaceId: string
  readonly workspaceTitle: string
  /** Absolute canonical root. Host-only; never leaves the Host. */
  readonly workspaceRoot: string
  readonly subpath?: string
  readonly mode: ScanMode
  readonly status: ScanStatus
  readonly phase: ScanPhase
  readonly createdAt: string
  readonly updatedAt: string
  readonly startedAt?: string
  readonly finishedAt?: string
  readonly error?: ScanError
  readonly commit?: string
  /** Settings frozen when the scan was created, so a resume behaves the same. */
  readonly settings: SecuritySettings
  /** Effective budget after clamping to operator limits. */
  readonly budget: ScanBudget
  /** Resolved model route per role (absent role → not used in this scan). */
  readonly models: { readonly [R in RoleName]?: ModelRef }
  readonly usage: ScanUsage
  readonly phases: readonly PhaseProgress[]
  readonly progress?: { readonly done: number; readonly total: number; readonly unit: string }
  readonly coverage?: Coverage
  readonly analyzers?: readonly AnalyzerStatus[]
  readonly threatModel?: ThreatModelRecord
  readonly pluginVersion: string
  /** Language models write human-readable fields in. */
  readonly language?: 'en' | 'ja' | 'zh'
  /** SHA-256 over the sorted (path, sha256) list of the snapshot taken when the scan started. */
  readonly snapshotDigest?: string
}

export type TaskKind =
  | 'threat-model'
  | 'triage-signals'
  | 'hunt-endpoints'
  | 'hunt-signals'
  | 'hunt-file'
  | 'hunt-hypothesis'
  | 'review'
  | 'chain'

export type TaskStatus = 'pending' | 'running' | 'done' | 'failed' | 'skipped'

/** Work handed to one AI worker. Fully serializable so a scan can resume. */
export interface TaskInput {
  /** Workspace-relative files the worker should start from. */
  readonly targetPaths: readonly string[]
  /** Endpoint ids (see analysis `Endpoint.id`) in scope. */
  readonly endpointIds?: readonly string[]
  /** Deterministic signal fingerprints that motivated this task. */
  readonly signalFingerprints?: readonly string[]
  /** Finding under review (review tasks). */
  readonly findingId?: string
  /** Findings considered together (chain tasks). */
  readonly findingIds?: readonly string[]
  /** Category focus, e.g. `authz`, `injection`. */
  readonly focus: readonly FindingCategory[]
  /** Free-text hypothesis or instructions from the planner. */
  readonly hypothesis?: string
}

export interface TaskRecord {
  readonly id: string
  readonly scanId: string
  /** Deterministic identity within a scan; inserting the same key twice is a no-op. */
  readonly key: string
  readonly kind: TaskKind
  readonly role: RoleName
  readonly title: string
  readonly status: TaskStatus
  /** Higher runs first. */
  readonly priority: number
  readonly input: TaskInput
  readonly attempts: number
  readonly error?: ScanError
  /** Short machine summary of the outcome (e.g. counts). */
  readonly outcome?: Readonly<Record<string, string | number | boolean>>
  readonly createdAt: string
  readonly startedAt?: string
  readonly finishedAt?: string
}

export type AgentRunStatus =
  | 'running'
  | 'submitted'
  | 'no_submission'
  | 'budget_exhausted'
  | 'cancelled'
  | 'failed'
  | 'blocked_by_provider'

export interface AgentRunRecord {
  readonly id: string
  readonly scanId: string
  readonly taskId: string
  readonly role: RoleName
  readonly title: string
  readonly provider: string
  readonly model: string
  readonly status: AgentRunStatus
  readonly turns: number
  readonly toolCalls: number
  readonly llmCalls: number
  readonly inputTokens: number
  readonly outputTokens: number
  readonly startedAt: string
  readonly finishedAt?: string
  readonly stopReason?: string
  readonly error?: ScanError
  /** Workspace-relative files this worker read through its tools. */
  readonly filesRead: readonly string[]
}

export interface EvidenceRecord {
  readonly id: string
  readonly scanId: string
  readonly taskId?: string
  readonly agentRunId?: string
  readonly origin: Origin
  readonly kind: EvidenceKind
  readonly trust: EvidenceTrust
  /** Redacted, length-bounded statement. */
  readonly claim: string
  readonly location?: CodeRef
  /** SHA-256 of the file the location refers to, at snapshot time. */
  readonly fileHash?: string
  /** The quote as the model cited it (redacted). */
  readonly quote?: string
  /** The redacted source excerpt at the verified location. */
  readonly snippet?: string
  readonly quoteCheck: QuoteCheck
  readonly createdAt: string
}

export interface AttackStepRecord {
  readonly order: number
  readonly description: string
  readonly location?: CodeRef
  readonly quote?: string
  readonly snippet?: string
  readonly quoteCheck: QuoteCheck
}

export interface FindingReview {
  readonly verdict: 'confirmed' | 'refuted' | 'inconclusive'
  readonly reasoning: string
  readonly model: string
  readonly severityAdjustment?: Severity
}

export interface FindingRecord {
  readonly id: string
  readonly scanId: string
  readonly fingerprint: string
  readonly title: string
  readonly category: FindingCategory
  readonly severity: Severity
  readonly verification: Verification
  readonly source: FindingSource
  readonly cwe?: string
  readonly ruleId?: string
  readonly location?: CodeRef
  readonly summary: string
  readonly impact: string
  readonly preconditions: readonly string[]
  readonly attackPath: readonly AttackStepRecord[]
  readonly recommendation: string
  readonly limitations: readonly string[]
  readonly references: readonly string[]
  readonly review?: FindingReview
  readonly createdBy: { readonly role: Origin; readonly model?: string; readonly analyzer?: string }
  readonly supportEvidenceIds: readonly string[]
  readonly counterEvidenceIds: readonly string[]
  /** Fingerprints of duplicates merged into this finding during reconciliation. */
  readonly mergedFingerprints: readonly string[]
  /** Not present in the previous completed scan of the same workspace (set at reconcile). */
  readonly isNew: boolean
  readonly createdAt: string
  readonly updatedAt: string
}

export interface TriageRecord {
  readonly rootKeyBase: string
  readonly fingerprint: string
  readonly state: TriageState
  readonly note?: string
  readonly updatedAt: string
}

export type EventLevel = 'debug' | 'info' | 'warn' | 'error'

export interface EventRecord {
  readonly seq: number
  readonly scanId: string
  readonly at: string
  readonly level: EventLevel
  readonly type: string
  readonly message: string
  readonly data?: Readonly<Record<string, unknown>>
}
