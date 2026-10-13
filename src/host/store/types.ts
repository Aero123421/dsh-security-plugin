/**
 * Persistence contract. The SQLite implementation lives in `sqlite.ts`; the
 * controller and RPC handlers depend only on this interface.
 *
 * All methods are synchronous (node:sqlite is synchronous and fast for these
 * row counts) and throw `StoreError` on corruption or I/O failure.
 */

import type { SeverityCounts } from '../../shared/contracts.ts'
import type { ScanStatus, TriageState } from '../../shared/domain.ts'
import type { SecuritySettings } from '../../shared/settings.ts'
import type {
  AgentRunRecord,
  EventLevel,
  EventRecord,
  EvidenceRecord,
  FindingRecord,
  ScanRecord,
  TaskRecord,
  TaskStatus,
  TriageRecord,
} from '../core/model.ts'

export class StoreError extends Error {
  constructor(
    readonly code: 'corrupt' | 'io' | 'schema-too-new' | 'not-found' | 'constraint',
    message: string,
    options?: ErrorOptions,
  ) {
    super(message, options)
    this.name = 'StoreError'
  }
}

/** Fields of a scan that change while it runs. */
export type ScanPatch = Partial<
  Pick<
    ScanRecord,
    | 'status'
    | 'phase'
    | 'startedAt'
    | 'finishedAt'
    | 'error'
    | 'commit'
    | 'usage'
    | 'phases'
    | 'progress'
    | 'coverage'
    | 'analyzers'
    | 'threatModel'
    | 'models'
  >
> & { readonly clearError?: boolean; readonly clearProgress?: boolean }

export type TaskPatch = Partial<
  Pick<TaskRecord, 'status' | 'attempts' | 'error' | 'outcome' | 'startedAt' | 'finishedAt'>
>

export type AgentRunPatch = Partial<
  Pick<
    AgentRunRecord,
    | 'status'
    | 'turns'
    | 'toolCalls'
    | 'llmCalls'
    | 'inputTokens'
    | 'outputTokens'
    | 'finishedAt'
    | 'stopReason'
    | 'error'
    | 'filesRead'
  >
>

export type FindingPatch = Partial<
  Pick<
    FindingRecord,
    | 'title'
    | 'severity'
    | 'verification'
    | 'summary'
    | 'impact'
    | 'preconditions'
    | 'attackPath'
    | 'recommendation'
    | 'limitations'
    | 'references'
    | 'review'
    | 'supportEvidenceIds'
    | 'counterEvidenceIds'
    | 'mergedFingerprints'
    | 'isNew'
    | 'location'
  >
>

export interface ScanQuery {
  readonly workspaceId?: string
  readonly statuses?: readonly ScanStatus[]
  /** Default 50, max 500. Newest first by `createdAt`. */
  readonly limit?: number
}

export interface SecurityStore {
  /** Close the database. Further calls throw. Idempotent. */
  close(): void

  /** Run `fn` inside one write transaction (nested calls join the outer one). */
  transaction<T>(fn: () => T): T

  // Settings -----------------------------------------------------------------
  /** Stored settings JSON (unvalidated) and its revision; revision 0 when none were saved. */
  readSettings(): { readonly value: unknown; readonly revision: number }
  /** Compare-and-set. Returns the new revision, or `undefined` when `expectedRevision` is stale. */
  writeSettings(value: SecuritySettings, expectedRevision: number): number | undefined

  // Scans --------------------------------------------------------------------
  insertScan(scan: ScanRecord): void
  /** Apply a patch and bump `updatedAt`. Throws `not-found`. Returns the updated record. */
  updateScan(id: string, patch: ScanPatch): ScanRecord
  getScan(id: string): ScanRecord | undefined
  listScans(query?: ScanQuery): ScanRecord[]
  /** The newest `completed` scan of a workspace created before `before` (exclusive), if any. */
  previousCompletedScan(workspaceId: string, before: string): ScanRecord | undefined
  /** Delete a scan and everything that belongs to it. Returns false when absent. */
  deleteScan(id: string): boolean
  /** Delete scans (any status except running/queued/paused) older than `days`. Returns the count. */
  purgeScansOlderThan(days: number, now?: Date): number

  // Tasks --------------------------------------------------------------------
  /** Insert unless `(scanId, key)` exists; returns the stored record either way. */
  ensureTask(task: TaskRecord): TaskRecord
  updateTask(id: string, patch: TaskPatch): TaskRecord
  getTask(id: string): TaskRecord | undefined
  /** Ordered by priority desc, then createdAt, then id. */
  listTasks(scanId: string, statuses?: readonly TaskStatus[]): TaskRecord[]

  // Agent runs -----------------------------------------------------------------
  insertAgentRun(run: AgentRunRecord): void
  updateAgentRun(id: string, patch: AgentRunPatch): AgentRunRecord
  listAgentRuns(scanId: string): AgentRunRecord[]
  /** Store a gzip-compressed JSON transcript (replaces any previous one for the run). */
  saveTranscript(runId: string, transcript: unknown): void
  /** Decompressed transcript, or undefined. */
  loadTranscript(runId: string): unknown

  // Evidence -------------------------------------------------------------------
  insertEvidence(evidence: EvidenceRecord): void
  getEvidence(scanId: string, ids: readonly string[]): EvidenceRecord[]
  listEvidence(scanId: string): EvidenceRecord[]

  // Findings -------------------------------------------------------------------
  insertFinding(finding: FindingRecord): void
  updateFinding(id: string, patch: FindingPatch): FindingRecord
  getFinding(scanId: string, id: string): FindingRecord | undefined
  findFindingByFingerprint(scanId: string, fingerprint: string): FindingRecord | undefined
  /** Ordered by severity (critical first), then verification strength, then title. */
  listFindings(scanId: string): FindingRecord[]
  deleteFinding(id: string): void
  /** Every fingerprint in a scan, including merged duplicates. */
  scanFingerprints(scanId: string): Set<string>
  /**
   * Open-finding counts for list views: excludes `refuted` findings and those
   * whose triage (by workspace + fingerprint) is false_positive, accepted_risk, or fixed.
   */
  countOpenFindings(
    scanId: string,
    workspaceId: string,
  ): { readonly counts: SeverityCounts; readonly confirmed: number }

  // Triage ---------------------------------------------------------------------
  getTriage(workspaceId: string, fingerprints: readonly string[]): Map<string, TriageRecord>
  setTriage(workspaceId: string, fingerprint: string, state: TriageState, note: string | undefined): TriageRecord

  // Events ---------------------------------------------------------------------
  /** Append an event; returns its sequence number (monotonic per database). */
  appendEvent(
    scanId: string,
    level: EventLevel,
    type: string,
    message: string,
    data?: Readonly<Record<string, unknown>>,
  ): number
  /** Events with `seq > afterSeq`, oldest first, at most `limit` (default 200, max 1000). */
  listEvents(scanId: string, afterSeq?: number, limit?: number): EventRecord[]
}
