/**
 * SQLite implementation of `SecurityStore` on Node's built-in `node:sqlite`.
 *
 * Behavior notes beyond the interface JSDoc:
 * - Errors: SQLite failures surface as `StoreError` — `corrupt` (malformed
 *   file, unexpected schema, undecodable row), `constraint` (duplicate id,
 *   unknown parent scan), `io` (anything else, including a closed store).
 *   Errors thrown by a `transaction` callback propagate unchanged.
 * - Transactions: the outermost `transaction` runs `BEGIN IMMEDIATE` …
 *   `COMMIT`, and `ROLLBACK` when the callback throws. A nested call opens a
 *   SAVEPOINT instead: when it throws, only the nested part is rolled back and
 *   the error is rethrown — if the caller catches it, the outer transaction
 *   continues and can still commit; if the outer callback throws, everything
 *   (released nested work included) is rolled back. Callbacks must be
 *   synchronous.
 * - Patches: `undefined` values in a patch mean "leave unchanged"; use
 *   `clearError` / `clearProgress` / `clearFinishedAt` to remove those scan fields. Keys outside
 *   the patch type (e.g. `id`) are ignored at runtime.
 * - Status filters: an empty `statuses` array matches nothing; omit it to
 *   match every status.
 * - `getEvidence` returns records in the order of `ids` (duplicates and
 *   unknown ids dropped).
 * - Orderings break remaining ties by id so results are deterministic.
 */

import { chmodSync, mkdirSync, realpathSync } from 'node:fs'
import { dirname } from 'node:path'
import { DatabaseSync, type SQLInputValue, type StatementSync } from 'node:sqlite'
import { gunzipSync, gzipSync } from 'node:zlib'
import type { SeverityCounts } from '../../shared/contracts.ts'
import {
  SEVERITIES,
  type Severity,
  severityRank,
  TRIAGE_STATES,
  type TriageState,
  VERIFICATIONS,
} from '../../shared/domain.ts'
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
import { scanRoot } from '../scan/root.ts'
import {
  agentRunParams,
  decodeAgentRun,
  decodeEvent,
  decodeEvidence,
  decodeFinding,
  decodeScan,
  decodeTask,
  decodeTriage,
  evidenceParams,
  findingParams,
  type Row,
  RowReader,
  scanParams,
  taskParams,
} from './records.ts'
import { migrate } from './schema.ts'
import {
  type AgentRunPatch,
  type FindingPatch,
  type ScanPatch,
  type ScanQuery,
  type SecurityStore,
  StoreError,
  type TaskPatch,
} from './types.ts'

export { SCHEMA_VERSION } from './schema.ts'

/** Serialized event `data` larger than this is replaced by `{ truncated: true }`. */
export const EVENT_DATA_MAX_BYTES = 8 * 1024
/** Event messages are cut to this many UTF-8 bytes (on a character boundary). */
export const EVENT_MESSAGE_MAX_BYTES = 2 * 1024
/** Transcripts whose JSON exceeds this are stored as `{ truncated: true, bytes }`. */
export const TRANSCRIPT_MAX_BYTES = 32 * 1024 * 1024
/** Triage notes are cut to this many UTF-16 code units. */
export const TRIAGE_NOTE_MAX_CHARS = 2000

const SCAN_LIST_DEFAULT = 50
const SCAN_LIST_MAX = 500
const EVENT_LIST_DEFAULT = 200
const EVENT_LIST_MAX = 1000
const DAY_MS = 24 * 60 * 60 * 1000
const BUSY_TIMEOUT_MS = 5000

/** Options for `openSecurityStore`. */
export interface OpenStoreOptions {
  /** Clock for `updatedAt`, event timestamps, and purge cutoffs. Defaults to the system clock. */
  readonly now?: () => Date
}

// Patch allowlists. Typed as exhaustive records so adding a field to a patch
// type without listing it here is a compile error.
type PatchKeys<P> = Readonly<Record<Exclude<keyof P, 'clearError' | 'clearProgress' | 'clearFinishedAt'>, true>>

const SCAN_PATCH_KEYS: PatchKeys<ScanPatch> = {
  status: true,
  phase: true,
  startedAt: true,
  finishedAt: true,
  error: true,
  commit: true,
  usage: true,
  phases: true,
  progress: true,
  coverage: true,
  analyzers: true,
  threatModel: true,
  snapshotDigest: true,
  models: true,
}
const TASK_PATCH_KEYS: PatchKeys<TaskPatch> = {
  status: true,
  attempts: true,
  error: true,
  outcome: true,
  startedAt: true,
  finishedAt: true,
}
const AGENT_RUN_PATCH_KEYS: PatchKeys<AgentRunPatch> = {
  status: true,
  turns: true,
  toolCalls: true,
  llmCalls: true,
  inputTokens: true,
  outputTokens: true,
  finishedAt: true,
  stopReason: true,
  error: true,
  filesRead: true,
}
const FINDING_PATCH_KEYS: PatchKeys<FindingPatch> = {
  title: true,
  severity: true,
  verification: true,
  summary: true,
  impact: true,
  preconditions: true,
  attackPath: true,
  recommendation: true,
  limitations: true,
  references: true,
  review: true,
  supportEvidenceIds: true,
  counterEvidenceIds: true,
  mergedFingerprints: true,
  isNew: true,
  location: true,
}

const SQL = {
  readSettings: 'SELECT id, json, revision FROM settings WHERE id = 1',
  writeSettings: `INSERT INTO settings (id, json, revision) VALUES (1, ?, ?)
    ON CONFLICT (id) DO UPDATE SET json = excluded.json, revision = excluded.revision`,

  insertScan: `INSERT INTO scans
    (id, workspace_id, status, mode, phase, created_at, updated_at, started_at, finished_at, data, root_key)
    VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)`,
  updateScan: `UPDATE scans SET workspace_id = ?2, status = ?3, mode = ?4, phase = ?5, created_at = ?6,
    updated_at = ?7, started_at = ?8, finished_at = ?9, data = ?10, root_key = ?11 WHERE id = ?1`,
  getScan: 'SELECT * FROM scans WHERE id = ?',
  listScans: `SELECT * FROM scans
    WHERE (:statuses IS NULL OR status IN (SELECT value FROM json_each(:statuses)))
    ORDER BY created_at DESC, id DESC LIMIT :limit`,
  listScansByWorkspace: `SELECT * FROM scans
    WHERE (workspace_id = :workspace OR (json_valid(data) AND json_extract(data, '$.workspaceRoot') = :root))
      AND (:statuses IS NULL OR status IN (SELECT value FROM json_each(:statuses)))
    ORDER BY created_at DESC, id DESC LIMIT :limit`,
  previousCompletedScan: `SELECT * FROM scans
    WHERE root_key = ? AND status = 'completed' AND created_at < ?
    ORDER BY created_at DESC, id DESC LIMIT 1`,
  deleteScan: 'DELETE FROM scans WHERE id = ?',
  purgeScans: `DELETE FROM scans WHERE created_at < ? AND status NOT IN ('queued', 'running', 'paused')`,

  insertTask: `INSERT INTO tasks (id, scan_id, key, status, priority, created_at, data)
    VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7) ON CONFLICT (scan_id, key) DO NOTHING`,
  updateTask: `UPDATE tasks SET scan_id = ?2, key = ?3, status = ?4, priority = ?5, created_at = ?6, data = ?7
    WHERE id = ?1`,
  getTask: 'SELECT * FROM tasks WHERE id = ?',
  getTaskByKey: 'SELECT * FROM tasks WHERE scan_id = ? AND key = ?',
  listTasks: `SELECT * FROM tasks
    WHERE scan_id = :scan AND (:statuses IS NULL OR status IN (SELECT value FROM json_each(:statuses)))
    ORDER BY priority DESC, created_at, id`,

  insertAgentRun: 'INSERT INTO agent_runs (id, scan_id, status, started_at, data) VALUES (?1, ?2, ?3, ?4, ?5)',
  updateAgentRun: 'UPDATE agent_runs SET scan_id = ?2, status = ?3, started_at = ?4, data = ?5 WHERE id = ?1',
  getAgentRun: 'SELECT * FROM agent_runs WHERE id = ?',
  listAgentRuns: 'SELECT * FROM agent_runs WHERE scan_id = ? ORDER BY started_at, id',
  saveTranscript: `INSERT INTO transcripts (run_id, gz) VALUES (?, ?)
    ON CONFLICT (run_id) DO UPDATE SET gz = excluded.gz`,
  loadTranscript: 'SELECT run_id, gz FROM transcripts WHERE run_id = ?',

  insertEvidence: 'INSERT INTO evidence (id, scan_id, created_at, data) VALUES (?1, ?2, ?3, ?4)',
  getEvidence: 'SELECT * FROM evidence WHERE scan_id = ? AND id IN (SELECT value FROM json_each(?))',
  listEvidence: 'SELECT * FROM evidence WHERE scan_id = ? ORDER BY created_at, id',

  insertFinding: `INSERT INTO findings (id, scan_id, fingerprint, severity, verification, data)
    VALUES (?1, ?2, ?3, ?4, ?5, ?6)`,
  updateFinding: `UPDATE findings SET scan_id = ?2, fingerprint = ?3, severity = ?4, verification = ?5, data = ?6
    WHERE id = ?1`,
  getFindingById: 'SELECT * FROM findings WHERE id = ?',
  getFinding: 'SELECT * FROM findings WHERE scan_id = ? AND id = ?',
  findFindingByFingerprint: 'SELECT * FROM findings WHERE scan_id = ? AND fingerprint = ? ORDER BY id LIMIT 1',
  listFindings: 'SELECT * FROM findings WHERE scan_id = ?',
  deleteFinding: 'DELETE FROM findings WHERE id = ?',
  countOpenFindings: `SELECT f.severity AS severity, f.verification AS verification, COUNT(*) AS n
    FROM findings f
    LEFT JOIN triage t ON t.root_key_base = ?2 AND t.fingerprint = (
      SELECT candidate.fingerprint FROM triage candidate
      WHERE candidate.root_key_base = ?2 AND (
        candidate.fingerprint = f.fingerprint OR candidate.fingerprint IN (
          SELECT value FROM json_each(f.data, '$.mergedFingerprints')
        )
      )
      ORDER BY candidate.updated_at DESC, (candidate.state = 'open') DESC, candidate.fingerprint ASC
      LIMIT 1
    )
    WHERE f.scan_id = ?1 AND f.verification <> 'refuted' AND (t.state IS NULL OR t.state = 'open')
    GROUP BY f.severity, f.verification`,

  getTriage: `SELECT * FROM triage
    WHERE root_key_base = ? AND fingerprint IN (SELECT value FROM json_each(?))`,
  setTriage: `INSERT INTO triage (root_key_base, fingerprint, state, note, updated_at) VALUES (?, ?, ?, ?, ?)
    ON CONFLICT (root_key_base, fingerprint)
    DO UPDATE SET state = excluded.state, note = excluded.note, updated_at = excluded.updated_at`,

  appendEvent: 'INSERT INTO events (scan_id, at, level, type, message, data) VALUES (?, ?, ?, ?, ?, ?)',
  listEvents: 'SELECT * FROM events WHERE scan_id = ? AND seq > ? ORDER BY seq LIMIT ?',
} as const

/**
 * Bind a positional argument list to `?1`, `?2`, … by name.
 *
 * Node.js 22.19.0 gives `?NNN` a name and then skips every named parameter when
 * applying a positional list, so `statement.run(a, b)` on `VALUES (?1, ?2)`
 * throws `ERR_SQLITE_ERROR` (errcode 25, column index out of range). Node.js
 * 22.20.0 and later bind that list by position. Passing the names explicitly
 * works on both, including statements whose indexes are not in textual order
 * (`UPDATE … SET col = ?2 WHERE id = ?1`). Anonymous `?` placeholders stay
 * positional: they have no name for this map to address.
 */
function numbered(values: readonly SQLInputValue[]): Record<string, SQLInputValue> {
  const params: Record<string, SQLInputValue> = Object.create(null)
  for (let index = 0; index < values.length; index++) {
    const value = values[index]
    if (value === undefined) throw new TypeError(`SQLite parameter ?${index + 1} is undefined`)
    params[`?${index + 1}`] = value
  }
  return params
}

/**
 * Open (creating and migrating as needed) the security database at `path`.
 * Use `':memory:'` for a throwaway database. Throws `StoreError` with code
 * `schema-too-new`, `corrupt`, or `io` when the file cannot be used.
 */
export function openSecurityStore(path: string, options: OpenStoreOptions = {}): SecurityStore {
  const inMemory = path === ':memory:' || path === ''
  let db: DatabaseSync | undefined
  try {
    if (!inMemory) mkdirSync(dirname(path), { recursive: true, mode: 0o700 })
    db = new DatabaseSync(path, { enableForeignKeyConstraints: true, timeout: BUSY_TIMEOUT_MS })
    if (!inMemory && process.platform !== 'win32') chmodSync(path, 0o600)
    configure(db)
    migrate(db)
  } catch (error) {
    try {
      db?.close()
    } catch {
      // Already failing; keep the original error.
    }
    throw toStoreError(error, `open ${path}`, 'io')
  }
  return new SqliteSecurityStore(db, options.now ?? (() => new Date()))
}

function configure(db: DatabaseSync): void {
  // Touch the schema first so a non-database file fails as `corrupt` here
  // rather than being mistaken for "WAL unsupported" below.
  db.prepare('SELECT count(*) AS n FROM sqlite_master').get()
  db.exec(`PRAGMA busy_timeout = ${BUSY_TIMEOUT_MS}`) // constant, not a value: no injection surface
  db.exec('PRAGMA foreign_keys = ON')
  try {
    db.prepare('PRAGMA journal_mode = WAL').get()
  } catch (error) {
    const code = sqliteErrcode(error)
    if (code !== undefined && storeCodeFor(code) === 'corrupt') throw error
    // WAL unsupported (e.g. some network filesystems): keep the default journal.
  }
  db.exec('PRAGMA synchronous = NORMAL')
}

class SqliteSecurityStore implements SecurityStore {
  private readonly statements = new Map<string, StatementSync>()
  private depth = 0
  private closed = false

  constructor(
    private readonly db: DatabaseSync,
    private readonly now: () => Date,
  ) {}

  close(): void {
    if (this.closed) return
    this.closed = true
    this.statements.clear()
    try {
      if (!this.db.isTransaction) this.db.exec('PRAGMA optimize')
    } catch {
      // Best effort only.
    }
    try {
      this.db.close()
    } catch (error) {
      throw toStoreError(error, 'close')
    }
  }

  transaction<T>(fn: () => T): T {
    return this.guard('transaction', () => (this.depth === 0 ? this.outer(fn) : this.nested(fn)))
  }

  // Settings -----------------------------------------------------------------

  readSettings(): { readonly value: unknown; readonly revision: number } {
    return this.guard('readSettings', () => {
      const row = this.stmt(SQL.readSettings).get()
      if (row === undefined) return { value: undefined, revision: 0 }
      const r = new RowReader('settings', row)
      return { value: r.anyJson('json'), revision: r.num('revision') }
    })
  }

  writeSettings(value: SecuritySettings, expectedRevision: number): number | undefined {
    return this.guard('writeSettings', () =>
      this.atomic(() => {
        const row = this.stmt(SQL.readSettings).get()
        const current = row === undefined ? 0 : new RowReader('settings', row).num('revision')
        if (current !== expectedRevision) return undefined
        const next = current + 1
        this.stmt(SQL.writeSettings).run(JSON.stringify(value), next)
        return next
      }),
    )
  }

  // Scans --------------------------------------------------------------------

  insertScan(scan: ScanRecord): void {
    this.guard('insertScan', () => {
      this.stmt(SQL.insertScan).run(numbered(scanParams(scan)))
    })
  }

  updateScan(id: string, patch: ScanPatch): ScanRecord {
    return this.guard('updateScan', () =>
      this.atomic(() => {
        const current = this.getScan(id)
        if (current === undefined) throw notFound('scan', id)
        const next = mergePatch(current, patch, SCAN_PATCH_KEYS)
        if (patch.clearError) delete next.error
        if (patch.clearProgress) delete next.progress
        if (patch.clearFinishedAt) delete next.finishedAt
        next.updatedAt = this.stamp()
        const record = next as unknown as ScanRecord
        this.stmt(SQL.updateScan).run(numbered(scanParams(record)))
        return record
      }),
    )
  }

  getScan(id: string): ScanRecord | undefined {
    return this.guard('getScan', () => mapOne(this.stmt(SQL.getScan).get(id), decodeScan))
  }

  listScans(query: ScanQuery = {}): ScanRecord[] {
    return this.guard('listScans', () => {
      const params: Record<string, SQLInputValue> = {
        statuses: query.statuses === undefined ? null : JSON.stringify(query.statuses),
        limit: clampLimit(query.limit, SCAN_LIST_DEFAULT, SCAN_LIST_MAX),
      }
      if (query.workspaceId === undefined) return this.stmt(SQL.listScans).all(params).map(decodeScan)
      params.workspace = query.workspaceId
      params.root = query.workspaceRoot ?? null
      return this.stmt(SQL.listScansByWorkspace).all(params).map(decodeScan)
    })
  }

  scansNeedingRecovery(): ScanRecord[] {
    return this.guard('scansNeedingRecovery', () =>
      this.stmt(`SELECT * FROM scans
      WHERE status = 'running' OR (status = 'interrupted' AND (
        EXISTS (SELECT 1 FROM agent_runs r WHERE r.scan_id = scans.id AND r.status = 'running')
        OR EXISTS (SELECT 1 FROM tasks t WHERE t.scan_id = scans.id AND t.status = 'running')
      )) ORDER BY created_at, id`)
        .all()
        .map(decodeScan),
    )
  }

  previousCompletedScan(rootKey: string, before: string): ScanRecord | undefined {
    return this.guard('previousCompletedScan', () =>
      mapOne(this.stmt(SQL.previousCompletedScan).get(rootKey, before), decodeScan),
    )
  }

  deleteScan(id: string): boolean {
    return this.guard('deleteScan', () => Number(this.stmt(SQL.deleteScan).run(id).changes) > 0)
  }

  purgeScansOlderThan(days: number, now: Date = this.now()): number {
    return this.guard('purgeScansOlderThan', () => {
      if (!(days > 0) || !Number.isFinite(days)) return 0
      const cutoff = new Date(now.getTime() - days * DAY_MS)
      if (Number.isNaN(cutoff.getTime())) return 0
      return this.atomic(() => Number(this.stmt(SQL.purgeScans).run(cutoff.toISOString()).changes))
    })
  }

  // Tasks --------------------------------------------------------------------

  ensureTask(task: TaskRecord): TaskRecord {
    return this.guard('ensureTask', () =>
      this.atomic(() => {
        this.stmt(SQL.insertTask).run(numbered(taskParams(task)))
        const row = this.stmt(SQL.getTaskByKey).get(task.scanId, task.key)
        if (row === undefined) throw new StoreError('io', `ensureTask: task ${task.key} vanished after insert`)
        return decodeTask(row)
      }),
    )
  }

  updateTask(id: string, patch: TaskPatch): TaskRecord {
    return this.guard('updateTask', () =>
      this.atomic(() => {
        const current = mapOne(this.stmt(SQL.getTask).get(id), decodeTask)
        if (current === undefined) throw notFound('task', id)
        const record = mergePatch(current, patch, TASK_PATCH_KEYS) as unknown as TaskRecord
        this.stmt(SQL.updateTask).run(numbered(taskParams(record)))
        return record
      }),
    )
  }

  getTask(id: string): TaskRecord | undefined {
    return this.guard('getTask', () => mapOne(this.stmt(SQL.getTask).get(id), decodeTask))
  }

  listTasks(scanId: string, statuses?: readonly TaskStatus[]): TaskRecord[] {
    return this.guard('listTasks', () =>
      this.stmt(SQL.listTasks)
        .all({ scan: scanId, statuses: statuses === undefined ? null : JSON.stringify(statuses) })
        .map(decodeTask),
    )
  }

  // Agent runs -----------------------------------------------------------------

  insertAgentRun(run: AgentRunRecord): void {
    this.guard('insertAgentRun', () => {
      this.stmt(SQL.insertAgentRun).run(numbered(agentRunParams(run)))
    })
  }

  updateAgentRun(id: string, patch: AgentRunPatch): AgentRunRecord {
    return this.guard('updateAgentRun', () =>
      this.atomic(() => {
        const current = mapOne(this.stmt(SQL.getAgentRun).get(id), decodeAgentRun)
        if (current === undefined) throw notFound('agent run', id)
        const record = mergePatch(current, patch, AGENT_RUN_PATCH_KEYS) as unknown as AgentRunRecord
        this.stmt(SQL.updateAgentRun).run(numbered(agentRunParams(record)))
        return record
      }),
    )
  }

  listAgentRuns(scanId: string): AgentRunRecord[] {
    return this.guard('listAgentRuns', () => this.stmt(SQL.listAgentRuns).all(scanId).map(decodeAgentRun))
  }

  saveTranscript(runId: string, transcript: unknown): void {
    this.guard('saveTranscript', () => {
      let json = JSON.stringify(transcript) ?? 'null'
      const bytes = Buffer.byteLength(json, 'utf8')
      if (bytes > TRANSCRIPT_MAX_BYTES) json = JSON.stringify({ truncated: true, bytes })
      this.stmt(SQL.saveTranscript).run(runId, gzipSync(json))
    })
  }

  loadTranscript(runId: string): unknown {
    return this.guard('loadTranscript', () => {
      const row = this.stmt(SQL.loadTranscript).get(runId)
      if (row === undefined) return undefined
      const r: RowReader = new RowReader('transcripts', row, 'run_id')
      let text: string
      try {
        text = gunzipSync(r.blob('gz'), { maxOutputLength: TRANSCRIPT_MAX_BYTES + 1024 }).toString('utf8')
      } catch (error) {
        if (error instanceof StoreError) throw error
        return r.fail('column gz is not valid gzip', error)
      }
      try {
        return JSON.parse(text) as unknown
      } catch (error) {
        return r.fail('column gz does not hold valid JSON', error)
      }
    })
  }

  // Evidence -------------------------------------------------------------------

  insertEvidence(evidence: EvidenceRecord): void {
    this.guard('insertEvidence', () => {
      this.stmt(SQL.insertEvidence).run(numbered(evidenceParams(evidence)))
    })
  }

  getEvidence(scanId: string, ids: readonly string[]): EvidenceRecord[] {
    return this.guard('getEvidence', () => {
      if (ids.length === 0) return []
      const byId = new Map<string, EvidenceRecord>()
      for (const row of this.stmt(SQL.getEvidence).all(scanId, JSON.stringify(ids))) {
        const record = decodeEvidence(row)
        byId.set(record.id, record)
      }
      const out: EvidenceRecord[] = []
      for (const id of new Set(ids)) {
        const record = byId.get(id)
        if (record !== undefined) out.push(record)
      }
      return out
    })
  }

  listEvidence(scanId: string): EvidenceRecord[] {
    return this.guard('listEvidence', () => this.stmt(SQL.listEvidence).all(scanId).map(decodeEvidence))
  }

  // Findings -------------------------------------------------------------------

  insertFinding(finding: FindingRecord): void {
    this.guard('insertFinding', () => {
      this.stmt(SQL.insertFinding).run(numbered(findingParams(finding)))
    })
  }

  updateFinding(id: string, patch: FindingPatch): FindingRecord {
    return this.guard('updateFinding', () =>
      this.atomic(() => {
        const current = mapOne(this.stmt(SQL.getFindingById).get(id), decodeFinding)
        if (current === undefined) throw notFound('finding', id)
        const next = mergePatch(current, patch, FINDING_PATCH_KEYS)
        next.updatedAt = this.stamp()
        const record = next as unknown as FindingRecord
        this.stmt(SQL.updateFinding).run(numbered(findingParams(record)))
        return record
      }),
    )
  }

  getFinding(scanId: string, id: string): FindingRecord | undefined {
    return this.guard('getFinding', () => mapOne(this.stmt(SQL.getFinding).get(scanId, id), decodeFinding))
  }

  findFindingByFingerprint(scanId: string, fingerprint: string): FindingRecord | undefined {
    return this.guard('findFindingByFingerprint', () =>
      mapOne(this.stmt(SQL.findFindingByFingerprint).get(scanId, fingerprint), decodeFinding),
    )
  }

  listFindings(scanId: string): FindingRecord[] {
    return this.guard('listFindings', () =>
      this.stmt(SQL.listFindings).all(scanId).map(decodeFinding).sort(compareFindings),
    )
  }

  deleteFinding(id: string): void {
    this.guard('deleteFinding', () => {
      this.stmt(SQL.deleteFinding).run(id)
    })
  }

  scanFingerprints(scanId: string): Set<string> {
    return this.guard('scanFingerprints', () => {
      const out = new Set<string>()
      for (const row of this.stmt(SQL.listFindings).all(scanId)) {
        const finding = decodeFinding(row)
        out.add(finding.fingerprint)
        for (const merged of finding.mergedFingerprints) out.add(merged)
      }
      return out
    })
  }

  countOpenFindings(
    scanId: string,
    rootKeyBase: string,
  ): { readonly counts: SeverityCounts; readonly confirmed: number } {
    return this.guard('countOpenFindings', () => {
      const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
      let confirmed = 0
      for (const row of this.stmt(SQL.countOpenFindings).all(numbered([scanId, rootKeyBase]))) {
        const { severity, verification, n } = row
        if (typeof n !== 'number' || !isSeverity(severity) || typeof verification !== 'string') {
          throw new StoreError('corrupt', `findings of scan ${scanId}: unexpected severity ${String(severity)}`)
        }
        counts[severity] += n
        if (verification === 'strong_static_evidence' || verification === 'proven_dynamic') confirmed += n
      }
      return { counts, confirmed }
    })
  }

  // Triage ---------------------------------------------------------------------

  reconcileTriageRoot(workspaceId: string, rootKeyBase: string): void {
    this.guard('reconcileTriageRoot', () =>
      this.atomic(() => {
        // v2 copied legacy paths verbatim. Reconcile on registration as well as
        // startup, including databases already migrated by 0.2.0/0.2.1. A path
        // that cannot currently be resolved is retained, never guessed.
        const aliases = new Set([workspaceId])
        for (const row of this.stmt(`SELECT json_extract(data, '$.workspaceRoot') AS root FROM scans
          UNION SELECT root_key_base AS root FROM triage`).all()) {
          if (typeof row.root !== 'string' || row.root === rootKeyBase) continue
          try {
            if (realpathSync(row.root) === rootKeyBase) aliases.add(row.root)
          } catch {
            // Offline or removed roots can be reconciled after they become available.
          }
        }
        aliases.delete(rootKeyBase)
        // Latest decision wins. Equal timestamps keep the canonical row, then
        // the lexically first alias; ordering makes retries deterministic.
        for (const alias of [...aliases].sort()) {
          this.stmt(`INSERT INTO triage (root_key_base, fingerprint, state, note, updated_at)
          SELECT ?, fingerprint, state, note, updated_at FROM triage WHERE root_key_base = ?
          ON CONFLICT (root_key_base, fingerprint) DO UPDATE SET
            state = excluded.state, note = excluded.note, updated_at = excluded.updated_at
          WHERE excluded.updated_at > triage.updated_at`).run(rootKeyBase, alias)
          this.stmt('DELETE FROM triage WHERE root_key_base = ?').run(alias)
          for (const row of this.stmt("SELECT * FROM scans WHERE json_extract(data, '$.workspaceRoot') = ?").all(
            alias,
          )) {
            const scan = decodeScan(row)
            // Change only identity: preserve timestamps, status, and scoped history.
            this.stmt("UPDATE scans SET root_key = ?, data = json_set(data, '$.workspaceRoot', ?) WHERE id = ?").run(
              scanRoot({ ...scan, workspaceRoot: rootKeyBase }),
              rootKeyBase,
              scan.id,
            )
          }
        }
      }),
    )
  }

  getTriage(rootKeyBase: string, fingerprints: readonly string[]): Map<string, TriageRecord> {
    return this.guard('getTriage', () => {
      const out = new Map<string, TriageRecord>()
      if (fingerprints.length === 0) return out
      for (const row of this.stmt(SQL.getTriage).all(rootKeyBase, JSON.stringify(fingerprints))) {
        const record = decodeTriage(row)
        out.set(record.fingerprint, record)
      }
      return out
    })
  }

  setTriage(rootKeyBase: string, fingerprint: string, state: TriageState, note: string | undefined): TriageRecord {
    return this.guard('setTriage', () => {
      if (!(TRIAGE_STATES as readonly string[]).includes(state)) {
        throw new StoreError('constraint', `setTriage: unknown triage state ${JSON.stringify(state)}`)
      }
      const capped = note === undefined ? undefined : truncateChars(note, TRIAGE_NOTE_MAX_CHARS)
      const updatedAt = this.stamp()
      this.stmt(SQL.setTriage).run(rootKeyBase, fingerprint, state, capped ?? null, updatedAt)
      const record: TriageRecord = { rootKeyBase, fingerprint, state, updatedAt }
      return capped === undefined ? record : { ...record, note: capped }
    })
  }

  // Events ---------------------------------------------------------------------

  appendEvent(
    scanId: string,
    level: EventLevel,
    type: string,
    message: string,
    data?: Readonly<Record<string, unknown>>,
  ): number {
    return this.guard('appendEvent', () => {
      const result = this.stmt(SQL.appendEvent).run(
        scanId,
        this.stamp(),
        level,
        type,
        truncateUtf8(message, EVENT_MESSAGE_MAX_BYTES),
        encodeEventData(data),
      )
      return Number(result.lastInsertRowid)
    })
  }

  listEvents(scanId: string, afterSeq = 0, limit?: number): EventRecord[] {
    return this.guard('listEvents', () => {
      const after = Number.isFinite(afterSeq) ? Math.floor(afterSeq) : 0
      const count = clampLimit(limit, EVENT_LIST_DEFAULT, EVENT_LIST_MAX)
      return this.stmt(SQL.listEvents).all(scanId, after, count).map(decodeEvent)
    })
  }

  // Internals ------------------------------------------------------------------

  /** Check the store is open and translate SQLite errors into `StoreError`. */
  private guard<T>(operation: string, fn: () => T): T {
    if (this.closed) throw new StoreError('io', 'store is closed')
    try {
      return fn()
    } catch (error) {
      throw toStoreError(error, operation)
    }
  }

  /**
   * Run a single-write read-modify-write step atomically. Inside an open
   * transaction it simply joins it (a single statement is atomic on its own,
   * so no savepoint is needed); otherwise it opens one.
   */
  private atomic<T>(fn: () => T): T {
    return this.depth > 0 ? fn() : this.outer(fn)
  }

  private outer<T>(fn: () => T): T {
    this.db.exec('BEGIN IMMEDIATE')
    this.depth++
    let result: T
    try {
      result = fn()
      assertSync(result)
    } catch (error) {
      this.depth--
      this.rollback('ROLLBACK')
      throw error
    }
    this.depth--
    if (!this.db.isTransaction) {
      // SQLite aborted the whole transaction (e.g. disk full) inside a nested
      // call whose error the callback caught; nothing was committed.
      throw new StoreError('io', 'transaction was rolled back by SQLite before it could commit')
    }
    try {
      this.db.exec('COMMIT')
    } catch (error) {
      this.rollback('ROLLBACK')
      throw error
    }
    return result
  }

  private nested<T>(fn: () => T): T {
    this.db.exec('SAVEPOINT store_nested')
    this.depth++
    try {
      const result = fn()
      assertSync(result)
      this.db.exec('RELEASE store_nested')
      return result
    } catch (error) {
      this.rollback('ROLLBACK TO store_nested; RELEASE store_nested')
      throw error
    } finally {
      this.depth--
    }
  }

  private rollback(sql: string): void {
    if (!this.db.isTransaction) return // SQLite already rolled back (e.g. disk full).
    try {
      this.db.exec(sql)
    } catch {
      // Keep the error that caused the rollback.
    }
  }

  private stmt(sql: string): StatementSync {
    let statement = this.statements.get(sql)
    if (statement === undefined) {
      statement = this.db.prepare(sql)
      this.statements.set(sql, statement)
    }
    return statement
  }

  private stamp(): string {
    return this.now().toISOString()
  }
}

// Helpers ----------------------------------------------------------------------

function notFound(kind: string, id: string): StoreError {
  return new StoreError('not-found', `${kind} ${id} not found`)
}

function mapOne<T>(row: Row | undefined, decode: (row: Row) => T): T | undefined {
  return row === undefined ? undefined : decode(row)
}

/** Copy the defined, allowlisted fields of `patch` over `current`. */
function mergePatch(current: object, patch: object, keys: Readonly<Record<string, true>>): Record<string, unknown> {
  const next: Record<string, unknown> = { ...current }
  for (const [key, value] of Object.entries(patch)) {
    if (value !== undefined && Object.hasOwn(keys, key)) next[key] = value
  }
  return next
}

function assertSync(result: unknown): void {
  if (typeof result === 'object' && result !== null && typeof (result as { then?: unknown }).then === 'function') {
    throw new TypeError('SecurityStore.transaction callback must be synchronous')
  }
}

function clampLimit(value: number | undefined, fallback: number, max: number): number {
  if (value === undefined || !Number.isFinite(value)) return fallback
  return Math.min(max, Math.max(0, Math.floor(value)))
}

function isSeverity(value: unknown): value is Severity {
  return typeof value === 'string' && (SEVERITIES as readonly string[]).includes(value)
}

const VERIFICATION_RANK = new Map<string, number>(VERIFICATIONS.map((v, i) => [v, i]))

function compareText(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0
}

function compareFindings(a: FindingRecord, b: FindingRecord): number {
  return (
    severityRank(a.severity) - severityRank(b.severity) ||
    (VERIFICATION_RANK.get(a.verification) ?? 0) - (VERIFICATION_RANK.get(b.verification) ?? 0) ||
    compareText(a.title, b.title) ||
    compareText(a.id, b.id)
  )
}

const utf8 = new TextEncoder()

/** Cut `text` to at most `maxBytes` UTF-8 bytes without splitting a character. */
function truncateUtf8(text: string, maxBytes: number): string {
  // A UTF-16 code unit never needs more than 3 UTF-8 bytes.
  if (text.length * 3 <= maxBytes || Buffer.byteLength(text, 'utf8') <= maxBytes) return text
  const { read } = utf8.encodeInto(text, new Uint8Array(maxBytes))
  return text.slice(0, read)
}

/** Cut `text` to at most `max` UTF-16 code units without splitting a surrogate pair. */
function truncateChars(text: string, max: number): string {
  if (text.length <= max) return text
  const last = text.charCodeAt(max - 1)
  return text.slice(0, last >= 0xd800 && last <= 0xdbff ? max - 1 : max)
}

const TRUNCATED_DATA = JSON.stringify({ truncated: true })

function encodeEventData(data: Readonly<Record<string, unknown>> | undefined): string | null {
  if (data === undefined) return null
  let json: string | undefined
  try {
    json = JSON.stringify(data)
  } catch {
    return JSON.stringify({ unserializable: true })
  }
  if (json === undefined) return null
  if (json.length * 3 > EVENT_DATA_MAX_BYTES && Buffer.byteLength(json, 'utf8') > EVENT_DATA_MAX_BYTES) {
    return TRUNCATED_DATA
  }
  return json
}

// Error mapping ----------------------------------------------------------------

function sqliteErrcode(error: unknown): number | undefined {
  if (typeof error !== 'object' || error === null) return undefined
  const { code, errcode } = error as { code?: unknown; errcode?: unknown }
  return code === 'ERR_SQLITE_ERROR' && typeof errcode === 'number' ? errcode : undefined
}

/** Map a (possibly extended) SQLite result code to a `StoreError` code. */
function storeCodeFor(errcode: number): StoreError['code'] {
  switch (errcode & 0xff) {
    case 11: // SQLITE_CORRUPT
    case 26: // SQLITE_NOTADB
      return 'corrupt'
    case 19: // SQLITE_CONSTRAINT
      return 'constraint'
    // Generic SQLITE_ERROR is deliberately not `corrupt`: it also covers SQL
    // bugs, and `corrupt` may prompt a user to discard their history.
    default: // ERROR, IOERR, CANTOPEN, FULL, BUSY, LOCKED, READONLY, PERM, NOMEM, ...
      return 'io'
  }
}

/**
 * Translate `error` into a `StoreError`. `StoreError`s pass through; SQLite
 * errors are mapped by result code; anything else passes through unchanged
 * unless `fallback` is given (used while opening, where fs errors are I/O).
 */
function toStoreError(error: unknown, context: string, fallback?: StoreError['code']): unknown {
  if (error instanceof StoreError) return error
  const errcode = sqliteErrcode(error)
  const message = error instanceof Error ? error.message : String(error)
  if (errcode !== undefined) return new StoreError(storeCodeFor(errcode), `${context}: ${message}`, { cause: error })
  if (fallback !== undefined) return new StoreError(fallback, `${context}: ${message}`, { cause: error })
  return error
}
