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

/** Priority a reconnaissance or critic unit was given, most important first. */
export type UnitPriority = 'critical' | 'high' | 'medium' | 'low'

/** Who proposed a coverage unit. */
export type UnitOrigin = 'recon' | 'critic' | 'gap'

/**
 * One part of the project the review plan sets out to examine, after the
 * Host resolved its target paths onto the snapshot. Each becomes a
 * `hunt-unit` task with the same id as key.
 */
export interface PlanUnitRecord {
  /** `unit:<hash of sorted target paths and focus>`; also the task key. */
  readonly id: string
  readonly title: string
  readonly component?: string
  /** Entry surface, e.g. `POST /api/orders/:id`, `CLI arguments`, `queue consumer`. */
  readonly surface?: string
  readonly focus: readonly FindingCategory[]
  /** Snapshot files the hunter starts from (resolved, in scope, at most 8). */
  readonly targetPaths: readonly string[]
  readonly priority: UnitPriority
  readonly rationale: string
  readonly hypothesis?: string
  readonly origin: 'recon' | 'critic'
}

/**
 * The reconnaissance result kept for later workers, the critic and the
 * report: the threat model plus the review plan. Stored as a JSON object
 * column; records written before the plan existed have only the threat
 * model, `priorities` and `hypotheses`.
 */
export interface ThreatModelRecord extends ThreatModelView {
  /** Entry points the planner considered most important (records before the review plan). */
  readonly priorities?: readonly { readonly target: string; readonly reason: string }[]
  /** Planner hypotheses of records before the review plan; each became a `hunt-hypothesis` task. */
  readonly hypotheses?: readonly {
    readonly title: string
    readonly category: FindingCategory
    readonly targetPaths: readonly string[]
    readonly rationale: string
  }[]
  /** Components or subsystems with their (resolved) files. */
  readonly components?: readonly { readonly name: string; readonly paths: readonly string[] }[]
  /** Coverage units of the reconnaissance plan, most important first. */
  readonly units?: readonly PlanUnitRecord[]
  /** Paths the reconnaissance left out of the source sweep (vendored, generated, docs, fixtures). */
  readonly excluded?: readonly { readonly path: string; readonly reason: ExcludedReason }[]
}

/** Why reconnaissance may leave a path out of the sweep. */
export type ExcludedReason = 'vendored' | 'generated' | 'docs' | 'fixtures'

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
  | 'hunt-unit'
  | 'critic'
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
  /** Coverage unit this task examines (`hunt-unit`), see {@link PlanUnitRecord}. */
  readonly unitId?: string
  /** Who proposed the work; absent on tasks from before the coverage ledger (derived from the kind). */
  readonly origin?: UnitOrigin
  /** Component or subsystem of the unit. */
  readonly component?: string
  /** Entry surface of the unit. */
  readonly surface?: string
  /** Why the planner wants this examined. */
  readonly rationale?: string
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
  /** Matching prose/literal/punctuation evidence, not verified code; absent in older rows. */
  readonly commentOnly?: boolean
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
