// INTENTIONALLY VULNERABLE TEST FIXTURE — do not deploy
// @ts-nocheck fixture: framework packages are not installed
import Database from 'better-sqlite3'
import { config } from './config'

const sqlite = new Database(config.databaseFile)
sqlite.pragma('journal_mode = WAL')
sqlite.pragma('foreign_keys = ON')

export type SqlParam = string | number | null

/** Thin wrapper so route code never touches prepared statements directly. */
export const db = {
  /** Every row produced by `sql`. */
  query<T = Record<string, unknown>>(sql: string, params: SqlParam[] = []): T[] {
    return sqlite.prepare(sql).all(...params) as T[]
  },

  /** The first row produced by `sql`, or `undefined`. */
  one<T = Record<string, unknown>>(sql: string, params: SqlParam[] = []): T | undefined {
    return sqlite.prepare(sql).get(...params) as T | undefined
  },

  /** INSERT / UPDATE / DELETE. */
  run(sql: string, params: SqlParam[] = []): { changes: number; lastInsertRowid: number } {
    const info = sqlite.prepare(sql).run(...params)
    return { changes: info.changes, lastInsertRowid: Number(info.lastInsertRowid) }
  },

  transaction<T>(fn: () => T): T {
    return sqlite.transaction(fn)()
  },
}
