/**
 * SQLite schema and migrations for the security store.
 *
 * `MIGRATIONS[i]` upgrades a database from version `i` to `i + 1`. Shipped
 * steps are never edited: append a new step instead. The current version is
 * kept in `meta` under `schema_version`; a database written by a newer plugin
 * is refused rather than silently downgraded.
 */

import type { DatabaseSync } from 'node:sqlite'
import { StoreError } from './types.ts'

const VERSION_KEY = 'schema_version'

/**
 * Ordered migration steps. Conventions:
 * - Scalar columns hold what queries filter or sort on; `data` holds the rest
 *   of the record as JSON (see `records.ts`).
 * - Every per-scan table cascades from `scans`; `transcripts` cascades from
 *   `agent_runs`. `triage` is per workspace and survives scan deletion.
 * - Enum columns carry no CHECK constraint so new values need no table rebuild;
 *   they are validated when read.
 * - Timestamps are ISO-8601 UTC strings as produced by `Date#toISOString`, so
 *   text order is chronological order.
 */
export const MIGRATIONS: readonly (readonly string[])[] = [
  // v1 — initial schema.
  [
    `CREATE TABLE settings (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      json TEXT NOT NULL,
      revision INTEGER NOT NULL
    ) STRICT`,
    `CREATE TABLE scans (
      id TEXT PRIMARY KEY,
      workspace_id TEXT NOT NULL,
      status TEXT NOT NULL,
      mode TEXT NOT NULL,
      phase TEXT NOT NULL,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      started_at TEXT,
      finished_at TEXT,
      data TEXT NOT NULL
    ) STRICT`,
    'CREATE INDEX scans_created ON scans (created_at DESC, id DESC)',
    'CREATE INDEX scans_workspace_created ON scans (workspace_id, created_at DESC, id DESC)',
    `CREATE TABLE tasks (
      id TEXT PRIMARY KEY,
      scan_id TEXT NOT NULL REFERENCES scans (id) ON DELETE CASCADE,
      key TEXT NOT NULL,
      status TEXT NOT NULL,
      priority REAL NOT NULL,
      created_at TEXT NOT NULL,
      data TEXT NOT NULL,
      UNIQUE (scan_id, key)
    ) STRICT`,
    'CREATE INDEX tasks_order ON tasks (scan_id, priority DESC, created_at, id)',
    `CREATE TABLE agent_runs (
      id TEXT PRIMARY KEY,
      scan_id TEXT NOT NULL REFERENCES scans (id) ON DELETE CASCADE,
      status TEXT NOT NULL,
      started_at TEXT NOT NULL,
      data TEXT NOT NULL
    ) STRICT`,
    'CREATE INDEX agent_runs_scan ON agent_runs (scan_id, started_at, id)',
    `CREATE TABLE transcripts (
      run_id TEXT PRIMARY KEY REFERENCES agent_runs (id) ON DELETE CASCADE,
      gz BLOB NOT NULL
    ) STRICT`,
    // Evidence is only ever addressed within a scan, so ids need only be
    // unique per scan (short, model-citable ids work).
    `CREATE TABLE evidence (
      scan_id TEXT NOT NULL REFERENCES scans (id) ON DELETE CASCADE,
      id TEXT NOT NULL,
      created_at TEXT NOT NULL,
      data TEXT NOT NULL,
      PRIMARY KEY (scan_id, id)
    ) STRICT`,
    'CREATE INDEX evidence_scan ON evidence (scan_id, created_at, id)',
    `CREATE TABLE findings (
      id TEXT PRIMARY KEY,
      scan_id TEXT NOT NULL REFERENCES scans (id) ON DELETE CASCADE,
      fingerprint TEXT NOT NULL,
      severity TEXT NOT NULL,
      verification TEXT NOT NULL,
      data TEXT NOT NULL
    ) STRICT`,
    'CREATE INDEX findings_scan_fingerprint ON findings (scan_id, fingerprint)',
    `CREATE TABLE triage (
      workspace_id TEXT NOT NULL,
      fingerprint TEXT NOT NULL,
      state TEXT NOT NULL,
      note TEXT,
      updated_at TEXT NOT NULL,
      PRIMARY KEY (workspace_id, fingerprint)
    ) STRICT, WITHOUT ROWID`,
    `CREATE TABLE events (
      seq INTEGER PRIMARY KEY AUTOINCREMENT,
      scan_id TEXT NOT NULL REFERENCES scans (id) ON DELETE CASCADE,
      at TEXT NOT NULL,
      level TEXT NOT NULL,
      type TEXT NOT NULL,
      message TEXT NOT NULL,
      data TEXT
    ) STRICT`,
    'CREATE INDEX events_scan_seq ON events (scan_id, seq)',
  ],
  // v2 — durable filesystem identity, independent of DSH's workspace UUID.
  [
    "ALTER TABLE scans ADD COLUMN root_key TEXT NOT NULL DEFAULT ''",
    "UPDATE scans SET root_key = json_extract(data, '$.workspaceRoot')",
    'CREATE INDEX scans_root_created ON scans (root_key, created_at DESC, id DESC)',
    "CREATE INDEX scans_base_created ON scans (json_extract(data, '$.workspaceRoot'), created_at DESC, id DESC) WHERE json_valid(data)",
    `CREATE TABLE triage_v2 (
      root_key_base TEXT NOT NULL,
      fingerprint TEXT NOT NULL,
      state TEXT NOT NULL,
      note TEXT,
      updated_at TEXT NOT NULL,
      PRIMARY KEY (root_key_base, fingerprint)
    ) STRICT, WITHOUT ROWID`,
    // One UUID can have scans at several roots. Preserve each association;
    // when re-registered UUIDs collide, the latest decision wins deterministically.
    `INSERT INTO triage_v2 (root_key_base, fingerprint, state, note, updated_at)
      SELECT root_key_base, fingerprint, state, note, updated_at FROM (
        SELECT COALESCE(json_extract(s.data, '$.workspaceRoot'), t.workspace_id) AS root_key_base,
          t.fingerprint, t.state, t.note, t.updated_at,
          ROW_NUMBER() OVER (
            PARTITION BY COALESCE(json_extract(s.data, '$.workspaceRoot'), t.workspace_id), t.fingerprint
            ORDER BY t.updated_at DESC, t.workspace_id DESC, s.id DESC
          ) AS rank
        FROM triage t LEFT JOIN scans s ON s.workspace_id = t.workspace_id
      ) WHERE rank = 1`,
    'DROP TABLE triage',
    'ALTER TABLE triage_v2 RENAME TO triage',
  ],
]

/** Schema version this build writes. Monotonic; equals the number of migrations. */
export const SCHEMA_VERSION = MIGRATIONS.length

/** Read the stored schema version (0 for a fresh database). */
export function readSchemaVersion(db: DatabaseSync): number {
  const row = db.prepare('SELECT value FROM meta WHERE key = ?').get(VERSION_KEY)
  if (row === undefined) return 0
  const version = typeof row.value === 'string' || typeof row.value === 'number' ? Number(row.value) : Number.NaN
  if (!Number.isSafeInteger(version) || version < 0) {
    throw new StoreError('corrupt', `meta row ${VERSION_KEY}: invalid schema version ${String(row.value)}`)
  }
  return version
}

/**
 * Bring `db` to `SCHEMA_VERSION` inside one immediate transaction. Throws
 * `StoreError('schema-too-new')` (leaving the file untouched) when the
 * database was written by a newer schema.
 */
export function migrate(db: DatabaseSync): void {
  db.exec('BEGIN IMMEDIATE')
  try {
    db.exec('CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL) STRICT')
    const current = readSchemaVersion(db)
    if (current > SCHEMA_VERSION) {
      throw new StoreError(
        'schema-too-new',
        `database schema version ${current} is newer than this plugin supports (${SCHEMA_VERSION}); update the plugin`,
      )
    }
    for (let version = current; version < SCHEMA_VERSION; version++) {
      for (const step of MIGRATIONS[version] ?? []) db.exec(step)
    }
    if (current !== SCHEMA_VERSION) {
      db.prepare(
        'INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value',
      ).run(VERSION_KEY, String(SCHEMA_VERSION))
    }
    db.exec('COMMIT')
  } catch (error) {
    if (db.isTransaction) db.exec('ROLLBACK')
    throw error
  }
}
