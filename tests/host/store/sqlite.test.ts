import { mkdtempSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import {
  EVENT_DATA_MAX_BYTES,
  EVENT_MESSAGE_MAX_BYTES,
  openSecurityStore,
  SCHEMA_VERSION,
  TRANSCRIPT_MAX_BYTES,
  TRIAGE_NOTE_MAX_CHARS,
} from '../../../src/host/store/sqlite.ts'
import { type ScanPatch, type SecurityStore, StoreError } from '../../../src/host/store/types.ts'
import type { Severity, Verification } from '../../../src/shared/domain.ts'
import { DEFAULT_SETTINGS } from '../../../src/shared/settings.ts'
import {
  evidenceOf,
  findingOf,
  fullEvidenceOf,
  fullFindingOf,
  fullRunOf,
  fullScanOf,
  fullTaskOf,
  runOf,
  scanOf,
  taskOf,
} from './fixtures.ts'

const NOW = new Date('2026-10-13T12:00:00.000Z')
const DAY = 24 * 60 * 60 * 1000

function daysAgo(days: number): string {
  return new Date(NOW.getTime() - days * DAY).toISOString()
}

/** Run `fn` and return the `StoreError` it throws (fails the test otherwise). */
function storeErrorOf(fn: () => unknown): StoreError {
  try {
    fn()
  } catch (error) {
    expect(error).toBeInstanceOf(StoreError)
    return error as StoreError
  }
  throw new Error('expected a StoreError')
}

describe('openSecurityStore (in memory)', () => {
  let store: SecurityStore
  let clock: Date

  beforeEach(() => {
    clock = NOW
    store = openSecurityStore(':memory:', { now: () => clock })
  })

  afterEach(() => {
    store.close()
  })

  describe('round trips', () => {
    it('round-trips minimal and full scans', () => {
      const minimal = scanOf({ id: 'scan_min' })
      const full = fullScanOf({ id: 'scan_full' })
      store.insertScan(minimal)
      store.insertScan(full)
      expect(store.getScan('scan_min')).toStrictEqual(minimal)
      expect(store.getScan('scan_full')).toStrictEqual(full)
      expect(store.getScan('nope')).toBeUndefined()
    })

    it('round-trips tasks, agent runs, evidence, and findings', () => {
      store.insertScan(scanOf())
      const tasks = [taskOf({ id: 't_min', key: 'k1' }), fullTaskOf({ id: 't_full', key: 'k2' })]
      for (const task of tasks) expect(store.ensureTask(task)).toStrictEqual(task)
      for (const task of tasks) expect(store.getTask(task.id)).toStrictEqual(task)

      const runs = [runOf({ id: 'r_min' }), fullRunOf({ id: 'r_full', startedAt: '2026-10-01T10:02:01.000Z' })]
      for (const run of runs) store.insertAgentRun(run)
      expect(store.listAgentRuns('scan_1')).toStrictEqual(runs)

      const evidence = [
        evidenceOf({ id: 'e_min' }),
        fullEvidenceOf({ id: 'e_full', createdAt: '2026-10-01T10:03:01.000Z' }),
      ]
      for (const ev of evidence) store.insertEvidence(ev)
      expect(store.listEvidence('scan_1')).toStrictEqual(evidence)

      const minimal = findingOf({ id: 'f_min', fingerprint: 'fp_min' })
      const full = fullFindingOf({ id: 'f_full', fingerprint: 'fp_full' })
      store.insertFinding(minimal)
      store.insertFinding(full)
      expect(store.getFinding('scan_1', 'f_min')).toStrictEqual(minimal)
      expect(store.getFinding('scan_1', 'f_full')).toStrictEqual(full)
      expect(store.getFinding('other_scan', 'f_full')).toBeUndefined()
      expect(store.findFindingByFingerprint('scan_1', 'fp_full')).toStrictEqual(full)
      expect(store.findFindingByFingerprint('scan_1', 'fp_dup')).toBeUndefined()
    })

    it('round-trips triage with and without a note', () => {
      const withNote = store.setTriage('ws_1', 'fp_a', 'accepted_risk', 'internal only')
      const without = store.setTriage('ws_1', 'fp_b', 'fixed', undefined)
      expect(withNote).toStrictEqual({
        workspaceId: 'ws_1',
        fingerprint: 'fp_a',
        state: 'accepted_risk',
        note: 'internal only',
        updatedAt: NOW.toISOString(),
      })
      expect(without).toStrictEqual({
        workspaceId: 'ws_1',
        fingerprint: 'fp_b',
        state: 'fixed',
        updatedAt: NOW.toISOString(),
      })
      const map = store.getTriage('ws_1', ['fp_a', 'fp_b', 'fp_missing'])
      expect([...map.keys()].sort()).toEqual(['fp_a', 'fp_b'])
      expect(map.get('fp_a')).toStrictEqual(withNote)
      expect(map.get('fp_b')).toStrictEqual(without)
      expect(store.getTriage('ws_2', ['fp_a']).size).toBe(0)
      expect(store.getTriage('ws_1', []).size).toBe(0)
    })

    it('upserts triage and caps the note', () => {
      store.setTriage('ws_1', 'fp', 'false_positive', 'first')
      clock = new Date(NOW.getTime() + 1000)
      const long = 'n'.repeat(TRIAGE_NOTE_MAX_CHARS + 50)
      const updated = store.setTriage('ws_1', 'fp', 'open', long)
      expect(updated.state).toBe('open')
      expect(updated.note).toHaveLength(TRIAGE_NOTE_MAX_CHARS)
      expect(updated.updatedAt).toBe(clock.toISOString())
      expect(store.getTriage('ws_1', ['fp']).get('fp')).toStrictEqual(updated)
      // Clearing the note.
      expect(store.setTriage('ws_1', 'fp', 'open', undefined)).not.toHaveProperty('note')
      expect(store.getTriage('ws_1', ['fp']).get('fp')).not.toHaveProperty('note')
    })

    it('returns evidence in the requested order, scoped to the scan', () => {
      store.insertScan(scanOf())
      store.insertScan(scanOf({ id: 'scan_2' }))
      store.insertEvidence(evidenceOf({ id: 'a' }))
      store.insertEvidence(evidenceOf({ id: 'b' }))
      store.insertEvidence(evidenceOf({ id: 'c', scanId: 'scan_2' }))
      expect(store.getEvidence('scan_1', ['b', 'missing', 'a', 'c', 'b']).map(e => e.id)).toEqual(['b', 'a'])
      expect(store.getEvidence('scan_1', [])).toEqual([])
    })

    it('scopes evidence ids to their scan', () => {
      store.insertScan(scanOf())
      store.insertScan(scanOf({ id: 'scan_2' }))
      store.insertEvidence(evidenceOf({ id: 'E1', claim: 'one' }))
      store.insertEvidence(evidenceOf({ id: 'E1', scanId: 'scan_2', claim: 'two' }))
      expect(store.getEvidence('scan_1', ['E1']).map(e => e.claim)).toEqual(['one'])
      expect(store.getEvidence('scan_2', ['E1']).map(e => e.claim)).toEqual(['two'])
      expect(storeErrorOf(() => store.insertEvidence(evidenceOf({ id: 'E1' }))).code).toBe('constraint')
    })
  })

  describe('scan updates', () => {
    beforeEach(() => {
      store.insertScan(scanOf())
    })

    it('merges patches, bumps updatedAt, and honors clear flags', () => {
      clock = new Date('2026-10-13T12:00:01.000Z')
      const running = store.updateScan('scan_1', {
        status: 'running',
        phase: 'hunt',
        startedAt: '2026-10-13T12:00:00.500Z',
        progress: { done: 1, total: 4, unit: 'tasks' },
        error: { code: 'x', message: 'transient' },
      })
      expect(running).toStrictEqual({
        ...scanOf(),
        status: 'running',
        phase: 'hunt',
        startedAt: '2026-10-13T12:00:00.500Z',
        progress: { done: 1, total: 4, unit: 'tasks' },
        error: { code: 'x', message: 'transient' },
        updatedAt: '2026-10-13T12:00:01.000Z',
      })
      expect(store.getScan('scan_1')).toStrictEqual(running)

      // `undefined` leaves fields unchanged.
      const same = store.updateScan('scan_1', { error: undefined, progress: undefined })
      expect(same.error).toEqual({ code: 'x', message: 'transient' })
      expect(same.progress).toEqual({ done: 1, total: 4, unit: 'tasks' })

      clock = new Date('2026-10-13T12:00:02.000Z')
      const cleared = store.updateScan('scan_1', { clearError: true, clearProgress: true, status: 'completed' })
      expect(cleared).not.toHaveProperty('error')
      expect(cleared).not.toHaveProperty('progress')
      expect(cleared).not.toHaveProperty('clearError')
      expect(cleared.status).toBe('completed')
      expect(cleared.updatedAt).toBe('2026-10-13T12:00:02.000Z')
      expect(store.getScan('scan_1')).toStrictEqual(cleared)
    })

    it('ignores keys outside the patch type', () => {
      const patch = { id: 'hijack', workspaceId: 'ws_9', status: 'paused' } as unknown as ScanPatch
      const updated = store.updateScan('scan_1', patch)
      expect(updated.id).toBe('scan_1')
      expect(updated.workspaceId).toBe('ws_1')
      expect(updated.status).toBe('paused')
      expect(store.getScan('hijack')).toBeUndefined()
    })

    it('throws not-found for unknown ids', () => {
      expect(storeErrorOf(() => store.updateScan('nope', { status: 'running' })).code).toBe('not-found')
      expect(storeErrorOf(() => store.updateTask('nope', { status: 'done' })).code).toBe('not-found')
      expect(storeErrorOf(() => store.updateAgentRun('nope', { turns: 1 })).code).toBe('not-found')
      expect(storeErrorOf(() => store.updateFinding('nope', { title: 'x' })).code).toBe('not-found')
    })

    it('rejects duplicate ids and orphans as constraint errors', () => {
      expect(storeErrorOf(() => store.insertScan(scanOf())).code).toBe('constraint')
      expect(storeErrorOf(() => store.insertFinding(findingOf({ scanId: 'ghost' }))).code).toBe('constraint')
      expect(storeErrorOf(() => store.ensureTask(taskOf({ scanId: 'ghost' }))).code).toBe('constraint')
    })
  })

  describe('scan queries', () => {
    it('lists newest first with workspace/status filters and limits', () => {
      store.transaction(() => {
        for (let i = 0; i < 60; i++) {
          store.insertScan(
            scanOf({
              id: `s_${String(i).padStart(3, '0')}`,
              workspaceId: i % 2 === 0 ? 'ws_even' : 'ws_odd',
              status: i % 3 === 0 ? 'completed' : 'failed',
              createdAt: new Date(NOW.getTime() + i * 1000).toISOString(),
            }),
          )
        }
        // Same createdAt as s_059: tie broken by id (descending, like createdAt).
        store.insertScan(scanOf({ id: 's_tie', createdAt: new Date(NOW.getTime() + 59_000).toISOString() }))
      })
      const all = store.listScans()
      expect(all).toHaveLength(50)
      expect(all.slice(0, 3).map(s => s.id)).toEqual(['s_tie', 's_059', 's_058'])
      expect(store.listScans({ limit: 5 }).map(s => s.id)).toEqual(['s_tie', 's_059', 's_058', 's_057', 's_056'])
      expect(store.listScans({ workspaceId: 'ws_even', limit: 3 }).map(s => s.id)).toEqual(['s_058', 's_056', 's_054'])
      expect(store.listScans({ workspaceId: 'ws_odd', statuses: ['completed'], limit: 2 }).map(s => s.id)).toEqual([
        's_057',
        's_051',
      ])
      expect(store.listScans({ statuses: ['completed', 'queued'], limit: 3 }).map(s => s.id)).toEqual([
        's_tie',
        's_057',
        's_054',
      ])
      expect(store.listScans({ statuses: [] })).toEqual([])
      expect(store.listScans({ workspaceId: 'ws_none' })).toEqual([])
    })

    it('caps the list limit at 500', () => {
      store.transaction(() => {
        for (let i = 0; i < 510; i++) {
          store.insertScan(scanOf({ id: `s_${i}`, createdAt: new Date(NOW.getTime() + i).toISOString() }))
        }
      })
      expect(store.listScans({ limit: 10_000 })).toHaveLength(500)
    })

    it('finds the previous completed scan of a workspace (exclusive bound)', () => {
      store.insertScan(scanOf({ id: 'a', status: 'completed', createdAt: '2026-10-01T00:00:00.000Z' }))
      store.insertScan(scanOf({ id: 'b', status: 'completed', createdAt: '2026-10-03T00:00:00.000Z' }))
      store.insertScan(scanOf({ id: 'c', status: 'failed', createdAt: '2026-10-04T00:00:00.000Z' }))
      store.insertScan(
        scanOf({ id: 'other', workspaceId: 'ws_2', status: 'completed', createdAt: '2026-10-03T12:00:00.000Z' }),
      )
      expect(store.previousCompletedScan('ws_1', '2026-10-05T00:00:00.000Z')?.id).toBe('b')
      expect(store.previousCompletedScan('ws_1', '2026-10-03T00:00:00.000Z')?.id).toBe('a')
      expect(store.previousCompletedScan('ws_1', '2026-10-01T00:00:00.000Z')).toBeUndefined()
      expect(store.previousCompletedScan('ws_2', '2026-10-05T00:00:00.000Z')?.id).toBe('other')
    })

    it('purges old inactive scans only', () => {
      const old = daysAgo(31)
      store.insertScan(scanOf({ id: 'old_completed', status: 'completed', createdAt: old }))
      store.insertScan(scanOf({ id: 'old_failed', status: 'failed', createdAt: old }))
      store.insertScan(scanOf({ id: 'old_cancelled', status: 'cancelled', createdAt: old }))
      store.insertScan(scanOf({ id: 'old_interrupted', status: 'interrupted', createdAt: old }))
      store.insertScan(scanOf({ id: 'old_queued', status: 'queued', createdAt: old }))
      store.insertScan(scanOf({ id: 'old_running', status: 'running', createdAt: old }))
      store.insertScan(scanOf({ id: 'old_paused', status: 'paused', createdAt: old }))
      store.insertScan(scanOf({ id: 'recent', status: 'completed', createdAt: daysAgo(29) }))
      store.insertFinding(findingOf({ scanId: 'old_completed' }))
      store.setTriage('ws_1', 'fp_1', 'fixed', undefined)

      expect(store.purgeScansOlderThan(0)).toBe(0)
      expect(store.purgeScansOlderThan(-5)).toBe(0)
      expect(store.purgeScansOlderThan(Number.NaN)).toBe(0)
      expect(store.listScans()).toHaveLength(8)

      // An explicit `now` far in the past deletes nothing.
      expect(store.purgeScansOlderThan(30, new Date('2026-01-01T00:00:00.000Z'))).toBe(0)

      // Default `now` comes from the injected clock.
      expect(store.purgeScansOlderThan(30)).toBe(4)
      expect(
        store
          .listScans()
          .map(s => s.id)
          .sort(),
      ).toEqual(['old_paused', 'old_queued', 'old_running', 'recent'])
      expect(store.getFinding('old_completed', 'f_1')).toBeUndefined()
      expect(store.getTriage('ws_1', ['fp_1']).size).toBe(1)
    })
  })

  describe('tasks', () => {
    beforeEach(() => {
      store.insertScan(scanOf())
    })

    it('is idempotent on (scanId, key)', () => {
      const first = store.ensureTask(taskOf({ id: 't1', key: 'k' }))
      const second = store.ensureTask(taskOf({ id: 't2', key: 'k', title: 'different', priority: 99 }))
      expect(second).toStrictEqual(first)
      expect(store.getTask('t2')).toBeUndefined()
      expect(store.listTasks('scan_1')).toHaveLength(1)
      // Same key in another scan is a different task.
      store.insertScan(scanOf({ id: 'scan_2' }))
      expect(store.ensureTask(taskOf({ id: 't3', scanId: 'scan_2', key: 'k' })).id).toBe('t3')
    })

    it('orders by priority desc, createdAt, id and filters by status', () => {
      store.ensureTask(taskOf({ id: 'b', key: 'kb', priority: 1, createdAt: '2026-10-01T10:00:00.000Z' }))
      store.ensureTask(taskOf({ id: 'a', key: 'ka', priority: 1, createdAt: '2026-10-01T10:00:00.000Z' }))
      store.ensureTask(taskOf({ id: 'c', key: 'kc', priority: 1, createdAt: '2026-09-30T10:00:00.000Z' }))
      store.ensureTask(taskOf({ id: 'd', key: 'kd', priority: 10, status: 'done' }))
      store.ensureTask(taskOf({ id: 'e', key: 'ke', priority: -2.5, status: 'running' }))
      expect(store.listTasks('scan_1').map(t => t.id)).toEqual(['d', 'c', 'a', 'b', 'e'])
      expect(store.listTasks('scan_1', ['pending']).map(t => t.id)).toEqual(['c', 'a', 'b'])
      expect(store.listTasks('scan_1', ['done', 'running']).map(t => t.id)).toEqual(['d', 'e'])
      expect(store.listTasks('scan_1', [])).toEqual([])
      expect(store.listTasks('scan_x')).toEqual([])
    })

    it('updates tasks', () => {
      store.ensureTask(taskOf())
      const updated = store.updateTask('task_1', {
        status: 'done',
        attempts: 1,
        outcome: { findings: 3 },
        finishedAt: '2026-10-01T10:09:00.000Z',
      })
      expect(updated).toStrictEqual({
        ...taskOf(),
        status: 'done',
        attempts: 1,
        outcome: { findings: 3 },
        finishedAt: '2026-10-01T10:09:00.000Z',
      })
      expect(store.getTask('task_1')).toStrictEqual(updated)
      expect(store.listTasks('scan_1', ['done'])).toStrictEqual([updated])
    })
  })

  describe('agent runs and transcripts', () => {
    beforeEach(() => {
      store.insertScan(scanOf())
      store.insertAgentRun(runOf())
    })

    it('updates runs', () => {
      const updated = store.updateAgentRun('run_1', {
        status: 'submitted',
        turns: 3,
        filesRead: ['a.ts', 'b.ts'],
        finishedAt: '2026-10-01T10:05:00.000Z',
      })
      expect(updated).toStrictEqual({
        ...runOf(),
        status: 'submitted',
        turns: 3,
        filesRead: ['a.ts', 'b.ts'],
        finishedAt: '2026-10-01T10:05:00.000Z',
      })
      expect(store.listAgentRuns('scan_1')).toStrictEqual([updated])
    })

    it('round-trips and replaces transcripts', () => {
      expect(store.loadTranscript('run_1')).toBeUndefined()
      const transcript = {
        messages: [
          { role: 'user', content: 'héllo ✓' },
          { role: 'assistant', content: [1, null, true] },
        ],
      }
      store.saveTranscript('run_1', transcript)
      expect(store.loadTranscript('run_1')).toStrictEqual(transcript)
      store.saveTranscript('run_1', ['replaced'])
      expect(store.loadTranscript('run_1')).toStrictEqual(['replaced'])
    })

    it('stores a marker instead of transcripts over the size cap', () => {
      const huge = 'x'.repeat(TRANSCRIPT_MAX_BYTES)
      store.saveTranscript('run_1', huge)
      expect(store.loadTranscript('run_1')).toStrictEqual({ truncated: true, bytes: TRANSCRIPT_MAX_BYTES + 2 })
    })

    it('rejects transcripts for unknown runs', () => {
      expect(storeErrorOf(() => store.saveTranscript('ghost', {})).code).toBe('constraint')
    })
  })

  describe('findings', () => {
    beforeEach(() => {
      store.insertScan(scanOf())
    })

    it('orders by severity, verification strength, then title', () => {
      const specs = [
        ['1', 'low', 'proven_dynamic', 'A'],
        ['2', 'critical', 'potential', 'Z'],
        ['3', 'critical', 'proven_dynamic', 'M'],
        ['4', 'critical', 'potential', 'B'],
        ['5', 'info', 'refuted', 'A'],
        ['6', 'high', 'refuted', 'A'],
        ['7', 'high', 'strong_static_evidence', 'Q'],
        ['8', 'medium', 'inconclusive', 'A'],
        ['9', 'high', 'inconclusive', 'A'],
      ] as const
      for (const [id, severity, verification, title] of specs) {
        store.insertFinding(findingOf({ id, fingerprint: `fp${id}`, severity, verification, title }))
      }
      expect(store.listFindings('scan_1').map(f => f.id)).toEqual(['3', '4', '2', '7', '9', '6', '8', '1', '5'])
    })

    it('updates findings and bumps updatedAt', () => {
      store.insertFinding(findingOf())
      clock = new Date('2026-10-13T13:00:00.000Z')
      const updated = store.updateFinding('f_1', {
        severity: 'critical',
        verification: 'refuted',
        mergedFingerprints: ['fp_x'],
        review: { verdict: 'refuted', reasoning: 'sanitized', model: 'm' },
      })
      expect(updated).toStrictEqual({
        ...findingOf(),
        severity: 'critical',
        verification: 'refuted',
        mergedFingerprints: ['fp_x'],
        review: { verdict: 'refuted', reasoning: 'sanitized', model: 'm' },
        updatedAt: '2026-10-13T13:00:00.000Z',
      })
      expect(store.getFinding('scan_1', 'f_1')).toStrictEqual(updated)
      expect(store.scanFingerprints('scan_1')).toEqual(new Set(['fp_1', 'fp_x']))
    })

    it('deletes findings', () => {
      store.insertFinding(findingOf())
      store.deleteFinding('f_1')
      store.deleteFinding('f_1')
      expect(store.listFindings('scan_1')).toEqual([])
    })

    it('collects own and merged fingerprints', () => {
      store.insertScan(scanOf({ id: 'scan_2' }))
      store.insertFinding(findingOf({ id: 'a', fingerprint: 'fa', mergedFingerprints: ['m1', 'm2'] }))
      store.insertFinding(findingOf({ id: 'b', fingerprint: 'fb', mergedFingerprints: ['m2', 'fa'] }))
      store.insertFinding(findingOf({ id: 'c', scanId: 'scan_2', fingerprint: 'fc', mergedFingerprints: ['m3'] }))
      expect(store.scanFingerprints('scan_1')).toEqual(new Set(['fa', 'fb', 'm1', 'm2']))
      expect(store.scanFingerprints('scan_none')).toEqual(new Set())
    })

    it('counts open findings excluding refuted and triaged ones', () => {
      const add = (id: string, severity: Severity, verification: Verification) =>
        store.insertFinding(findingOf({ id, fingerprint: `fp_${id}`, severity, verification }))
      add('1', 'critical', 'strong_static_evidence') // counted, confirmed
      add('2', 'high', 'potential') // false_positive → excluded
      add('3', 'high', 'proven_dynamic') // triage open → counted, confirmed
      add('4', 'medium', 'refuted') // refuted → excluded
      add('5', 'low', 'inconclusive') // triaged in another workspace → counted
      add('6', 'info', 'potential') // fixed → excluded
      add('7', 'medium', 'potential') // counted
      add('8', 'critical', 'potential') // accepted_risk → excluded
      store.setTriage('ws_1', 'fp_2', 'false_positive', undefined)
      store.setTriage('ws_1', 'fp_3', 'open', 'looking')
      store.setTriage('ws_2', 'fp_5', 'accepted_risk', undefined)
      store.setTriage('ws_1', 'fp_6', 'fixed', undefined)
      store.setTriage('ws_1', 'fp_8', 'accepted_risk', undefined)

      expect(store.countOpenFindings('scan_1', 'ws_1')).toStrictEqual({
        counts: { critical: 1, high: 1, medium: 1, low: 1, info: 0 },
        confirmed: 2,
      })
      expect(store.countOpenFindings('scan_none', 'ws_1')).toStrictEqual({
        counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
        confirmed: 0,
      })
    })
  })

  describe('deletion', () => {
    it('cascades scan deletion to children but keeps triage and other scans', () => {
      for (const id of ['scan_1', 'scan_2']) {
        store.insertScan(scanOf({ id }))
        store.ensureTask(taskOf({ id: `${id}_t`, scanId: id }))
        store.insertAgentRun(runOf({ id: `${id}_r`, scanId: id, taskId: `${id}_t` }))
        store.saveTranscript(`${id}_r`, { id })
        store.insertEvidence(evidenceOf({ id: `${id}_e`, scanId: id }))
        store.insertFinding(findingOf({ id: `${id}_f`, scanId: id }))
        store.appendEvent(id, 'info', 'phase', 'started')
      }
      store.setTriage('ws_1', 'fp_1', 'false_positive', 'nope')

      expect(store.deleteScan('scan_1')).toBe(true)
      expect(store.deleteScan('scan_1')).toBe(false)
      expect(store.getScan('scan_1')).toBeUndefined()
      expect(store.getTask('scan_1_t')).toBeUndefined()
      expect(store.listTasks('scan_1')).toEqual([])
      expect(store.listAgentRuns('scan_1')).toEqual([])
      expect(store.loadTranscript('scan_1_r')).toBeUndefined()
      expect(store.listEvidence('scan_1')).toEqual([])
      expect(store.listFindings('scan_1')).toEqual([])
      expect(store.listEvents('scan_1')).toEqual([])
      expect(store.getTriage('ws_1', ['fp_1']).get('fp_1')?.state).toBe('false_positive')

      expect(store.getScan('scan_2')).toBeDefined()
      expect(store.listTasks('scan_2')).toHaveLength(1)
      expect(store.listAgentRuns('scan_2')).toHaveLength(1)
      expect(store.loadTranscript('scan_2_r')).toEqual({ id: 'scan_2' })
      expect(store.listEvidence('scan_2')).toHaveLength(1)
      expect(store.listFindings('scan_2')).toHaveLength(1)
      expect(store.listEvents('scan_2')).toHaveLength(1)
    })
  })

  describe('events', () => {
    beforeEach(() => {
      store.insertScan(scanOf())
      store.insertScan(scanOf({ id: 'scan_2' }))
    })

    it('appends with monotonic sequence numbers and round-trips', () => {
      const s1 = store.appendEvent('scan_1', 'info', 'phase', 'entered hunt', { phase: 'hunt', n: 1 })
      clock = new Date(NOW.getTime() + 5)
      const s2 = store.appendEvent('scan_2', 'warn', 'budget', 'almost out')
      const s3 = store.appendEvent('scan_1', 'error', 'worker', 'failed', {})
      expect(s2).toBeGreaterThan(s1)
      expect(s3).toBeGreaterThan(s2)
      expect(store.listEvents('scan_1')).toStrictEqual([
        {
          seq: s1,
          scanId: 'scan_1',
          at: NOW.toISOString(),
          level: 'info',
          type: 'phase',
          message: 'entered hunt',
          data: { phase: 'hunt', n: 1 },
        },
        {
          seq: s3,
          scanId: 'scan_1',
          at: clock.toISOString(),
          level: 'error',
          type: 'worker',
          message: 'failed',
          data: {},
        },
      ])
      expect(store.listEvents('scan_2')).toStrictEqual([
        { seq: s2, scanId: 'scan_2', at: clock.toISOString(), level: 'warn', type: 'budget', message: 'almost out' },
      ])
    })

    it('paginates by sequence and clamps the limit', () => {
      const seqs = store.transaction(() =>
        Array.from({ length: 1205 }, (_, i) => store.appendEvent('scan_1', 'debug', 't', `m${i}`)),
      )
      expect(store.listEvents('scan_1').map(e => e.seq)).toEqual(seqs.slice(0, 200))
      expect(store.listEvents('scan_1', 0, 5000)).toHaveLength(1000)
      expect(store.listEvents('scan_1', seqs[9], 3).map(e => e.message)).toEqual(['m10', 'm11', 'm12'])
      expect(store.listEvents('scan_1', seqs[1203])).toHaveLength(1)
      expect(store.listEvents('scan_1', seqs[1204])).toEqual([])
    })

    it('caps message and data sizes', () => {
      const atCap = 's'.repeat(EVENT_DATA_MAX_BYTES - '{"s":""}'.length)
      store.appendEvent('scan_1', 'info', 'ok', 'm', { s: atCap })
      store.appendEvent('scan_1', 'info', 'big', 'm', { s: `${atCap}x` })
      store.appendEvent('scan_1', 'info', 'long', 'x'.repeat(EVENT_MESSAGE_MAX_BYTES + 100))
      store.appendEvent('scan_1', 'info', 'utf8', '€'.repeat(1000))
      const [ok, big, long, utf8] = store.listEvents('scan_1')
      expect(ok?.data).toStrictEqual({ s: atCap })
      expect(big?.data).toStrictEqual({ truncated: true })
      expect(long?.message).toBe('x'.repeat(EVENT_MESSAGE_MAX_BYTES))
      // '€' is 3 bytes in UTF-8: never split a character.
      expect(utf8?.message).toBe('€'.repeat(Math.floor(EVENT_MESSAGE_MAX_BYTES / 3)))
    })
  })

  describe('settings', () => {
    it('compares and sets by revision', () => {
      expect(store.readSettings()).toStrictEqual({ value: undefined, revision: 0 })
      expect(store.writeSettings(DEFAULT_SETTINGS, 1)).toBeUndefined()
      expect(store.writeSettings(DEFAULT_SETTINGS, 0)).toBe(1)
      expect(store.readSettings()).toStrictEqual({ value: DEFAULT_SETTINGS, revision: 1 })
      const changed = { ...DEFAULT_SETTINGS, ui: { language: 'ja' as const } }
      expect(store.writeSettings(changed, 0)).toBeUndefined()
      expect(store.readSettings().value).toStrictEqual(DEFAULT_SETTINGS)
      expect(store.writeSettings(changed, 1)).toBe(2)
      expect(store.readSettings()).toStrictEqual({ value: changed, revision: 2 })
    })
  })

  describe('transactions', () => {
    beforeEach(() => {
      store.insertScan(scanOf())
    })

    it('commits the outer transaction when an inner failure is caught', () => {
      const inner = new Error('inner')
      const result = store.transaction(() => {
        store.appendEvent('scan_1', 'info', 'outer', 'before')
        let caught: unknown
        try {
          store.transaction(() => {
            store.appendEvent('scan_1', 'info', 'inner', 'rolled back')
            store.updateScan('scan_1', { status: 'running' })
            throw inner
          })
        } catch (error) {
          caught = error
        }
        expect(caught).toBe(inner)
        store.transaction(() => store.appendEvent('scan_1', 'info', 'inner-ok', 'kept'))
        store.appendEvent('scan_1', 'info', 'outer', 'after')
        return 42
      })
      expect(result).toBe(42)
      expect(store.listEvents('scan_1').map(e => e.type)).toEqual(['outer', 'inner-ok', 'outer'])
      expect(store.getScan('scan_1')?.status).toBe('queued')
    })

    it('rolls back everything when the outer transaction throws', () => {
      const boom = new Error('boom')
      expect(() =>
        store.transaction(() => {
          store.appendEvent('scan_1', 'info', 'outer', 'gone')
          store.transaction(() => {
            store.transaction(() => store.insertFinding(findingOf()))
            store.updateScan('scan_1', { status: 'running' })
          })
          throw boom
        }),
      ).toThrow(boom)
      expect(store.listEvents('scan_1')).toEqual([])
      expect(store.listFindings('scan_1')).toEqual([])
      expect(store.getScan('scan_1')?.status).toBe('queued')
      // The store is usable afterwards.
      expect(store.transaction(() => store.appendEvent('scan_1', 'info', 'x', 'y'))).toBeGreaterThan(0)
    })

    it('rolls back a failing store call inside a transaction', () => {
      expect(() =>
        store.transaction(() => {
          store.appendEvent('scan_1', 'info', 'x', 'y')
          store.insertScan(scanOf()) // duplicate id
        }),
      ).toThrow(StoreError)
      expect(store.listEvents('scan_1')).toEqual([])
    })

    it('rejects async callbacks', () => {
      expect(() => store.transaction(async () => store.appendEvent('scan_1', 'info', 'x', 'y'))).toThrow(/synchronous/)
      expect(store.listEvents('scan_1')).toEqual([])
    })
  })

  it('handles a realistic volume quickly', () => {
    const started = performance.now()
    store.transaction(() => {
      store.insertScan(scanOf())
      for (let i = 0; i < 5000; i++) {
        store.insertFinding(
          findingOf({
            id: `f_${i}`,
            fingerprint: `fp_${i}`,
            title: `Finding ${i}`,
            severity: (['critical', 'high', 'medium', 'low', 'info'] as const)[i % 5],
          }),
        )
      }
    })
    store.transaction(() => {
      for (let i = 0; i < 20_000; i++) store.appendEvent('scan_1', 'info', 'tick', `event ${i}`, { i })
    })
    expect(store.listFindings('scan_1')).toHaveLength(5000)
    expect(store.scanFingerprints('scan_1').size).toBe(5000)
    expect(store.countOpenFindings('scan_1', 'ws_1').counts.critical).toBe(1000)
    expect(store.listEvents('scan_1', 19_000, 1000)).toHaveLength(1000)
    expect(performance.now() - started).toBeLessThan(5000)
  })

  it('throws io after close and closes idempotently', () => {
    store.close()
    store.close()
    const error = storeErrorOf(() => store.getScan('scan_1'))
    expect(error.code).toBe('io')
    expect(error.message).toBe('store is closed')
    expect(storeErrorOf(() => store.transaction(() => 1)).code).toBe('io')
    expect(storeErrorOf(() => store.appendEvent('s', 'info', 't', 'm')).code).toBe('io')
  })
})

describe('openSecurityStore (files)', () => {
  let dir: string

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'dsh-store-'))
  })

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true })
  })

  it('persists data across reopen and uses WAL', () => {
    const path = join(dir, 'nested', 'deeper', 'security.db')
    const first = openSecurityStore(path)
    first.insertScan(fullScanOf())
    first.close()

    const second = openSecurityStore(path)
    expect(second.getScan('scan_1')).toStrictEqual(fullScanOf())
    second.close()

    const raw = new DatabaseSync(path)
    try {
      expect(raw.prepare('PRAGMA journal_mode').get()?.journal_mode).toBe('wal')
      expect(raw.prepare("SELECT value FROM meta WHERE key = 'schema_version'").get()?.value).toBe(
        String(SCHEMA_VERSION),
      )
    } finally {
      raw.close()
    }
  })

  it.skipIf(process.platform === 'win32')('creates the file 0600 inside a 0700 directory', () => {
    const parent = join(dir, 'private')
    const path = join(parent, 'security.db')
    openSecurityStore(path).close()
    expect(statSync(path).mode & 0o777).toBe(0o600)
    expect(statSync(parent).mode & 0o777).toBe(0o700)
  })

  it('stores transcripts gzip-compressed', () => {
    const path = join(dir, 'security.db')
    const store = openSecurityStore(path)
    store.insertScan(scanOf())
    store.insertAgentRun(runOf())
    const transcript = { messages: Array.from({ length: 200 }, (_, i) => ({ role: 'user', content: `turn ${i}` })) }
    store.saveTranscript('run_1', transcript)
    store.close()

    const raw = new DatabaseSync(path)
    const gz = raw.prepare('SELECT gz FROM transcripts WHERE run_id = ?').get('run_1')?.gz
    raw.close()
    expect(gz).toBeInstanceOf(Uint8Array)
    const bytes = gz as Uint8Array
    expect([bytes[0], bytes[1]]).toEqual([0x1f, 0x8b])
    expect(bytes.length).toBeLessThan(JSON.stringify(transcript).length / 4)

    const reopened = openSecurityStore(path)
    expect(reopened.loadTranscript('run_1')).toStrictEqual(transcript)
    reopened.close()
  })

  it('refuses a database written by a newer schema', () => {
    const path = join(dir, 'security.db')
    const store = openSecurityStore(path)
    store.insertScan(scanOf())
    store.close()

    const raw = new DatabaseSync(path)
    raw.prepare("UPDATE meta SET value = ? WHERE key = 'schema_version'").run(String(SCHEMA_VERSION + 1))
    raw.close()

    const error = storeErrorOf(() => openSecurityStore(path))
    expect(error.code).toBe('schema-too-new')

    // The file is left untouched.
    const check = new DatabaseSync(path)
    expect(check.prepare("SELECT value FROM meta WHERE key = 'schema_version'").get()?.value).toBe(
      String(SCHEMA_VERSION + 1),
    )
    expect(check.prepare('SELECT count(*) AS n FROM scans').get()?.n).toBe(1)
    check.close()
  })

  it('reports a non-database file as corrupt with the cause attached', () => {
    const path = join(dir, 'security.db')
    writeFileSync(path, 'not a database '.repeat(100))
    const error = storeErrorOf(() => openSecurityStore(path))
    expect(error.code).toBe('corrupt')
    expect(error.cause).toBeInstanceOf(Error)
  })

  it('reports an unusable path as io', () => {
    const blocker = join(dir, 'file')
    writeFileSync(blocker, '')
    const error = storeErrorOf(() => openSecurityStore(join(blocker, 'security.db')))
    expect(error.code).toBe('io')
    expect(error.cause).toBeDefined()
  })

  describe('corrupt rows', () => {
    let path: string

    beforeEach(() => {
      path = join(dir, 'security.db')
      const store = openSecurityStore(path)
      store.insertScan(scanOf())
      store.insertFinding(findingOf())
      store.ensureTask(taskOf())
      store.insertAgentRun(runOf())
      store.saveTranscript('run_1', { ok: true })
      store.appendEvent('scan_1', 'info', 't', 'm', { a: 1 })
      store.writeSettings(DEFAULT_SETTINGS, 0)
      store.close()
    })

    function tamper(sql: string, ...params: (string | Uint8Array)[]): SecurityStore {
      const raw = new DatabaseSync(path)
      raw.prepare(sql).run(...params)
      raw.close()
      return openSecurityStore(path)
    }

    function expectCorrupt(fn: () => unknown, ...fragments: string[]): void {
      const error = storeErrorOf(fn)
      expect(error.code).toBe('corrupt')
      for (const fragment of fragments) expect(error.message).toContain(fragment)
    }

    it('rejects invalid JSON in a scan', () => {
      const store = tamper("UPDATE scans SET data = '{oops' WHERE id = 'scan_1'")
      expectCorrupt(() => store.getScan('scan_1'), 'scans', 'scan_1')
      expectCorrupt(() => store.listScans(), 'scans', 'scan_1')
      store.close()
    })

    it('rejects JSON of the wrong shape', () => {
      const store = tamper("UPDATE scans SET data = '[]' WHERE id = 'scan_1'")
      expectCorrupt(() => store.getScan('scan_1'), 'scans', 'scan_1', 'object')
      store.close()
    })

    it('rejects a missing required field', () => {
      const store = tamper("UPDATE findings SET data = json_remove(data, '$.title') WHERE id = 'f_1'")
      expectCorrupt(() => store.listFindings('scan_1'), 'findings', 'f_1', 'title')
      store.close()
    })

    it('rejects unknown enum values', () => {
      const store = tamper("UPDATE findings SET severity = 'apocalyptic' WHERE id = 'f_1'")
      expectCorrupt(() => store.getFinding('scan_1', 'f_1'), 'findings', 'f_1', 'severity')
      expectCorrupt(() => store.countOpenFindings('scan_1', 'ws_1'), 'apocalyptic')
      store.close()
    })

    it('rejects corrupt tasks, events, transcripts, and settings', () => {
      let store = tamper("UPDATE tasks SET data = json_set(data, '$.kind', 'dance') WHERE id = 'task_1'")
      expectCorrupt(() => store.getTask('task_1'), 'tasks', 'task_1', 'kind')
      store.close()
      store = tamper('UPDATE events SET data = \'"str"\'')
      expectCorrupt(() => store.listEvents('scan_1'), 'events')
      store.close()
      store = tamper("UPDATE transcripts SET gz = ? WHERE run_id = 'run_1'", new Uint8Array([1, 2, 3]))
      expectCorrupt(() => store.loadTranscript('run_1'), 'transcripts', 'run_1', 'gzip')
      store.close()
      store = tamper("UPDATE settings SET json = '{nope'")
      expectCorrupt(() => store.readSettings(), 'settings')
      store.close()
    })
  })
})

describe('numbered ?NNN parameters (Node.js 22.19.0)', () => {
  it('binds ?NNN by name when a positional argument list misses those parameters', () => {
    const db = new DatabaseSync(':memory:')
    db.exec('CREATE TABLE t (id INTEGER PRIMARY KEY, b INTEGER NOT NULL) STRICT')
    db.prepare('INSERT INTO t (id, b) VALUES (?, ?)').run(1, 1)
    const update = db.prepare('UPDATE t SET b = ?2 WHERE id = ?1')
    let positional: 'bound' | 'out-of-range' = 'bound'
    try {
      update.run(1, 7)
    } catch (error) {
      const sqlite = error as { code?: unknown; errcode?: unknown }
      expect(sqlite.code).toBe('ERR_SQLITE_ERROR')
      expect(sqlite.errcode).toBe(25)
      positional = 'out-of-range'
    }
    // 22.19.0 is the engines lower bound and the release that skips named ?NNN.
    if (process.versions.node.startsWith('22.19.')) expect(positional).toBe('out-of-range')
    db.exec('UPDATE t SET b = 1')
    update.run({ '?1': 1, '?2': 9 })
    expect(db.prepare('SELECT id, b FROM t').get()).toEqual({ id: 1, b: 9 })
    db.close()
  })

  it('round-trips rows whose ?NNN indexes are not in textual order', () => {
    const store = openSecurityStore(':memory:', { now: () => NOW })
    try {
      store.insertScan(scanOf({ id: 'scan_n', workspaceId: 'ws_n' }))
      const updated = store.updateScan('scan_n', { status: 'running', phase: 'inventory' })
      expect(updated).toMatchObject({ id: 'scan_n', workspaceId: 'ws_n', status: 'running', phase: 'inventory' })
      expect(store.getScan('scan_n')).toStrictEqual(updated)

      store.insertFinding(findingOf({ id: 'f_n', scanId: 'scan_n', fingerprint: 'fp_n' }))
      const revised = store.updateFinding('f_n', { title: 'Renamed' })
      expect(revised).toMatchObject({ id: 'f_n', scanId: 'scan_n', title: 'Renamed' })
      expect(store.getFinding('scan_n', 'f_n')).toStrictEqual(revised)

      // countOpenFindings binds the scan as ?1 and the workspace as ?2, while the SQL names ?2 first.
      // Triage is joined on ?2, so a dismissal in one workspace must not hide the finding from another.
      const empty = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
      expect(store.countOpenFindings('scan_n', 'ws_n')).toEqual({ counts: { ...empty, high: 1 }, confirmed: 0 })
      store.setTriage('ws_n', 'fp_n', 'fixed', undefined)
      expect(store.countOpenFindings('scan_n', 'ws_n')).toEqual({ counts: empty, confirmed: 0 })
      expect(store.countOpenFindings('scan_n', 'ws_other')).toEqual({ counts: { ...empty, high: 1 }, confirmed: 0 })
      expect(store.countOpenFindings('scan_other', 'ws_n')).toEqual({ counts: empty, confirmed: 0 })
    } finally {
      store.close()
    }
  })
})
