/**
 * Row ⇄ record mapping for the SQLite store.
 *
 * Each table keeps the fields that queries filter or sort on as scalar columns
 * and the rest of the record as one JSON `data` column. Rows are written only
 * by this plugin, so validation on read is deliberately light: it checks the
 * JSON parses to an object, that required fields exist with the right
 * primitive kind, and that enum columns hold known values. Anything else
 * raises `StoreError('corrupt')` naming the table and row id instead of
 * returning a half-formed record.
 */

import type { SQLOutputValue } from 'node:sqlite'
import {
  ROLE_NAMES,
  SCAN_MODES,
  SCAN_PHASES,
  SCAN_STATUSES,
  SEVERITIES,
  TRIAGE_STATES,
  VERIFICATIONS,
} from '../../shared/domain.ts'
import type {
  AgentRunRecord,
  AgentRunStatus,
  EventLevel,
  EventRecord,
  EvidenceRecord,
  FindingRecord,
  ScanRecord,
  TaskKind,
  TaskRecord,
  TaskStatus,
  TriageRecord,
} from '../core/model.ts'
import { StoreError } from './types.ts'

/** A row as returned by `node:sqlite`. */
export type Row = Record<string, SQLOutputValue>

type FieldKind = 'string' | 'number' | 'boolean' | 'object' | 'array'

interface DataShape {
  readonly required: Readonly<Record<string, FieldKind>>
  readonly optional?: Readonly<Record<string, FieldKind>>
}

// Exhaustive membership tables for model.ts unions that have no runtime list.
const TASK_STATUS: Readonly<Record<TaskStatus, true>> = {
  pending: true,
  running: true,
  done: true,
  failed: true,
  skipped: true,
}
const TASK_KIND: Readonly<Record<TaskKind, true>> = {
  'threat-model': true,
  'triage-signals': true,
  'hunt-endpoints': true,
  'hunt-signals': true,
  'hunt-file': true,
  'hunt-hypothesis': true,
  review: true,
  chain: true,
}
const AGENT_RUN_STATUS: Readonly<Record<AgentRunStatus, true>> = {
  running: true,
  submitted: true,
  no_submission: true,
  budget_exhausted: true,
  cancelled: true,
  failed: true,
  blocked_by_provider: true,
}
const EVENT_LEVEL: Readonly<Record<EventLevel, true>> = { debug: true, info: true, warn: true, error: true }

function kindOf(value: unknown): FieldKind | 'null' | 'other' {
  if (value === null) return 'null'
  if (Array.isArray(value)) return 'array'
  switch (typeof value) {
    case 'string':
    case 'number':
    case 'boolean':
    case 'object':
      return typeof value as FieldKind
    default:
      return 'other'
  }
}

/** Reads typed columns from one row, reporting problems against `table`/`id`. */
export class RowReader {
  readonly id: string

  constructor(
    readonly table: string,
    private readonly row: Row,
    idColumn = 'id',
  ) {
    const id = row[idColumn]
    this.id = typeof id === 'string' || typeof id === 'number' ? String(id) : '?'
    if (typeof id !== 'string' && typeof id !== 'number') this.fail(`column ${idColumn} is not a key`)
  }

  /** Throw `StoreError('corrupt')` for this row. */
  fail(reason: string, cause?: unknown): never {
    throw new StoreError(
      'corrupt',
      `${this.table} row ${this.id}: ${reason}`,
      cause === undefined ? undefined : { cause },
    )
  }

  text(column: string): string {
    const value = this.row[column]
    if (typeof value !== 'string') this.fail(`column ${column} is not text`)
    return value
  }

  optText(column: string): string | undefined {
    const value = this.row[column]
    if (value === null || value === undefined) return undefined
    if (typeof value !== 'string') this.fail(`column ${column} is not text`)
    return value
  }

  num(column: string): number {
    const value = this.row[column]
    if (typeof value !== 'number' || !Number.isFinite(value)) this.fail(`column ${column} is not a number`)
    return value
  }

  blob(column: string): Uint8Array {
    const value = this.row[column]
    if (!(value instanceof Uint8Array)) this.fail(`column ${column} is not a blob`)
    return value
  }

  oneOf<T extends string>(column: string, allowed: readonly T[] | Readonly<Record<T, true>>): T {
    const value = this.text(column)
    const ok = Array.isArray(allowed) ? allowed.includes(value as T) : Object.hasOwn(allowed, value)
    if (!ok) this.fail(`column ${column} has unknown value ${JSON.stringify(value)}`)
    return value as T
  }

  /** Parse a JSON text column holding any JSON value. */
  anyJson(column: string): unknown {
    const raw = this.text(column)
    try {
      return JSON.parse(raw) as unknown
    } catch (error) {
      this.fail(`column ${column} is not valid JSON`, error)
    }
  }

  /** Parse a JSON column that must hold an object matching `shape`. */
  json(column: string, shape: DataShape): Record<string, unknown> {
    const value = this.optJson(column, shape)
    if (value === undefined) this.fail(`column ${column} is null`)
    return value
  }

  /** Like `json`, but SQL NULL yields `undefined`. */
  optJson(column: string, shape: DataShape = { required: {} }): Record<string, unknown> | undefined {
    const raw = this.row[column]
    if (raw === null || raw === undefined) return undefined
    if (typeof raw !== 'string') this.fail(`column ${column} is not JSON text`)
    let parsed: unknown
    try {
      parsed = JSON.parse(raw)
    } catch (error) {
      this.fail(`column ${column} is not valid JSON`, error)
    }
    if (kindOf(parsed) !== 'object') this.fail(`column ${column} is not a JSON object`)
    const data = parsed as Record<string, unknown>
    for (const [key, kind] of Object.entries(shape.required)) {
      if (kindOf(data[key]) !== kind) this.fail(`${column}.${key} is missing or not ${kind}`)
    }
    for (const [key, kind] of Object.entries(shape.optional ?? {})) {
      if (data[key] !== undefined && kindOf(data[key]) !== kind) this.fail(`${column}.${key} is not ${kind}`)
    }
    return data
  }
}

/** JSON for the `data` column: the record minus its scalar-column fields. */
function dataJson(record: object, columns: readonly string[]): string {
  const rest: Record<string, unknown> = { ...record }
  for (const key of columns) delete rest[key]
  return JSON.stringify(rest)
}

/** Copy `value` into `target[key]` only when present (keeps optional fields absent). */
function withOptional<T extends object>(target: T, key: string, value: unknown): T {
  if (value !== undefined) (target as Record<string, unknown>)[key] = value
  return target
}

// Scans ------------------------------------------------------------------------

const SCAN_COLUMNS = [
  'id',
  'workspaceId',
  'status',
  'mode',
  'phase',
  'createdAt',
  'updatedAt',
  'startedAt',
  'finishedAt',
] as const

const SCAN_DATA: DataShape = {
  required: {
    workspaceTitle: 'string',
    workspaceRoot: 'string',
    settings: 'object',
    budget: 'object',
    models: 'object',
    usage: 'object',
    phases: 'array',
    pluginVersion: 'string',
  },
  optional: {
    error: 'object',
    commit: 'string',
    progress: 'object',
    coverage: 'object',
    analyzers: 'array',
    threatModel: 'object',
  },
}

/** Positional parameters for `INSERT INTO scans` / `UPDATE scans` (see sqlite.ts). */
export function scanParams(
  scan: ScanRecord,
): [string, string, string, string, string, string, string, string | null, string | null, string] {
  return [
    scan.id,
    scan.workspaceId,
    scan.status,
    scan.mode,
    scan.phase,
    scan.createdAt,
    scan.updatedAt,
    scan.startedAt ?? null,
    scan.finishedAt ?? null,
    dataJson(scan, SCAN_COLUMNS),
  ]
}

export function decodeScan(row: Row): ScanRecord {
  const r = new RowReader('scans', row)
  const data = r.json('data', SCAN_DATA)
  const scan = {
    ...data,
    id: r.id,
    workspaceId: r.text('workspace_id'),
    status: r.oneOf('status', SCAN_STATUSES),
    mode: r.oneOf('mode', SCAN_MODES),
    phase: r.oneOf('phase', SCAN_PHASES),
    createdAt: r.text('created_at'),
    updatedAt: r.text('updated_at'),
  }
  withOptional(scan, 'startedAt', r.optText('started_at'))
  withOptional(scan, 'finishedAt', r.optText('finished_at'))
  return scan as unknown as ScanRecord
}

// Tasks ------------------------------------------------------------------------

const TASK_COLUMNS = ['id', 'scanId', 'key', 'status', 'priority', 'createdAt'] as const

const TASK_DATA: DataShape = {
  required: { kind: 'string', role: 'string', title: 'string', input: 'object', attempts: 'number' },
  optional: { error: 'object', outcome: 'object', startedAt: 'string', finishedAt: 'string' },
}

export function taskParams(task: TaskRecord): [string, string, string, string, number, string, string] {
  return [task.id, task.scanId, task.key, task.status, task.priority, task.createdAt, dataJson(task, TASK_COLUMNS)]
}

export function decodeTask(row: Row): TaskRecord {
  const r = new RowReader('tasks', row)
  const data = r.json('data', TASK_DATA)
  if (!Object.hasOwn(TASK_KIND, data.kind as string)) r.fail(`data.kind has unknown value ${JSON.stringify(data.kind)}`)
  if (!(ROLE_NAMES as readonly unknown[]).includes(data.role)) {
    r.fail(`data.role has unknown value ${JSON.stringify(data.role)}`)
  }
  return {
    ...data,
    id: r.id,
    scanId: r.text('scan_id'),
    key: r.text('key'),
    status: r.oneOf('status', TASK_STATUS),
    priority: r.num('priority'),
    createdAt: r.text('created_at'),
  } as unknown as TaskRecord
}

// Agent runs -------------------------------------------------------------------

const AGENT_RUN_COLUMNS = ['id', 'scanId', 'status', 'startedAt'] as const

const AGENT_RUN_DATA: DataShape = {
  required: {
    taskId: 'string',
    role: 'string',
    title: 'string',
    provider: 'string',
    model: 'string',
    turns: 'number',
    toolCalls: 'number',
    llmCalls: 'number',
    inputTokens: 'number',
    outputTokens: 'number',
    filesRead: 'array',
  },
  optional: { finishedAt: 'string', stopReason: 'string', error: 'object' },
}

export function agentRunParams(run: AgentRunRecord): [string, string, string, string, string] {
  return [run.id, run.scanId, run.status, run.startedAt, dataJson(run, AGENT_RUN_COLUMNS)]
}

export function decodeAgentRun(row: Row): AgentRunRecord {
  const r = new RowReader('agent_runs', row)
  const data = r.json('data', AGENT_RUN_DATA)
  return {
    ...data,
    id: r.id,
    scanId: r.text('scan_id'),
    status: r.oneOf('status', AGENT_RUN_STATUS),
    startedAt: r.text('started_at'),
  } as unknown as AgentRunRecord
}

// Evidence ---------------------------------------------------------------------

const EVIDENCE_COLUMNS = ['id', 'scanId', 'createdAt'] as const

const EVIDENCE_DATA: DataShape = {
  required: { origin: 'string', kind: 'string', trust: 'string', claim: 'string', quoteCheck: 'string' },
  optional: {
    taskId: 'string',
    agentRunId: 'string',
    location: 'object',
    fileHash: 'string',
    quote: 'string',
    snippet: 'string',
  },
}

export function evidenceParams(evidence: EvidenceRecord): [string, string, string, string] {
  return [evidence.id, evidence.scanId, evidence.createdAt, dataJson(evidence, EVIDENCE_COLUMNS)]
}

export function decodeEvidence(row: Row): EvidenceRecord {
  const r = new RowReader('evidence', row)
  const data = r.json('data', EVIDENCE_DATA)
  return {
    ...data,
    id: r.id,
    scanId: r.text('scan_id'),
    createdAt: r.text('created_at'),
  } as unknown as EvidenceRecord
}

// Findings ---------------------------------------------------------------------

const FINDING_COLUMNS = ['id', 'scanId', 'fingerprint', 'severity', 'verification'] as const

const FINDING_DATA: DataShape = {
  required: {
    title: 'string',
    category: 'string',
    source: 'string',
    summary: 'string',
    impact: 'string',
    preconditions: 'array',
    attackPath: 'array',
    recommendation: 'string',
    limitations: 'array',
    references: 'array',
    createdBy: 'object',
    supportEvidenceIds: 'array',
    counterEvidenceIds: 'array',
    mergedFingerprints: 'array',
    isNew: 'boolean',
    createdAt: 'string',
    updatedAt: 'string',
  },
  optional: { cwe: 'string', ruleId: 'string', location: 'object', review: 'object' },
}

export function findingParams(finding: FindingRecord): [string, string, string, string, string, string] {
  return [
    finding.id,
    finding.scanId,
    finding.fingerprint,
    finding.severity,
    finding.verification,
    dataJson(finding, FINDING_COLUMNS),
  ]
}

export function decodeFinding(row: Row): FindingRecord {
  const r = new RowReader('findings', row)
  const data = r.json('data', FINDING_DATA)
  const merged = data.mergedFingerprints as unknown[]
  if (!merged.every(fp => typeof fp === 'string')) r.fail('data.mergedFingerprints holds a non-string')
  return {
    ...data,
    id: r.id,
    scanId: r.text('scan_id'),
    fingerprint: r.text('fingerprint'),
    severity: r.oneOf('severity', SEVERITIES),
    verification: r.oneOf('verification', VERIFICATIONS),
  } as unknown as FindingRecord
}

// Triage -----------------------------------------------------------------------

export function decodeTriage(row: Row): TriageRecord {
  const r = new RowReader('triage', row, 'fingerprint')
  const record = {
    workspaceId: r.text('workspace_id'),
    fingerprint: r.id,
    state: r.oneOf('state', TRIAGE_STATES),
    updatedAt: r.text('updated_at'),
  }
  return withOptional(record, 'note', r.optText('note'))
}

// Events -----------------------------------------------------------------------

export function decodeEvent(row: Row): EventRecord {
  const r = new RowReader('events', row, 'seq')
  const record = {
    seq: r.num('seq'),
    scanId: r.text('scan_id'),
    at: r.text('at'),
    level: r.oneOf('level', EVENT_LEVEL),
    type: r.text('type'),
    message: r.text('message'),
  }
  return withOptional(record, 'data', r.optJson('data'))
}
