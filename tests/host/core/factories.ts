/** Small builders for analysis records used by the orchestration tests. */

import type { Endpoint, Signal } from '../../../src/host/analysis/types.ts'
import type { FindingRecord, PlanUnitRecord, ScanRecord } from '../../../src/host/core/model.ts'
import { unitId } from '../../../src/host/scan/units.ts'
import type { SecurityStore } from '../../../src/host/store/types.ts'
import { DEFAULT_SETTINGS } from '../../../src/shared/settings.ts'

export function signalOf(overrides: Partial<Signal> = {}): Signal {
  const path = overrides.location?.path ?? 'src/app.ts'
  const line = overrides.location?.startLine ?? 1
  const ruleId = overrides.ruleId ?? 'js.sql-injection'
  return {
    analyzer: 'sast',
    ruleId,
    kind: 'vulnerability',
    title: 'SQL injection',
    category: 'injection',
    severity: 'high',
    confidence: 'medium',
    cwe: 'CWE-89',
    location: { path, startLine: line, endLine: line },
    snippet: 'db.query(sql)',
    message: 'User input reaches a SQL query. It may be injectable.',
    recommendation: 'Use bound parameters.',
    fingerprintParts: [ruleId, path, `line-${line}`],
    ...overrides,
  }
}

/** A validated coverage unit (as reconnaissance would store it). */
export function unitOf(
  title: string,
  targetPaths: readonly string[],
  overrides: Partial<PlanUnitRecord> = {},
): PlanUnitRecord {
  const focus = overrides.focus ?? ['authz']
  return {
    id: unitId(targetPaths, focus),
    title,
    focus,
    targetPaths,
    priority: 'high',
    rationale: `Check ${title}.`,
    origin: 'recon',
    ...overrides,
  }
}

export function endpointOf(
  method: string,
  route: string,
  path: string,
  line: number,
  overrides: Partial<Endpoint> = {},
): Endpoint {
  return {
    id: `${method} ${route} @ ${path}:${line}`,
    framework: 'express',
    method,
    route,
    declaredAt: { path, startLine: line, endLine: line },
    middleware: [],
    authHints: [],
    params: [],
    ...overrides,
  }
}

export function scanRecord(overrides: Partial<ScanRecord> = {}): ScanRecord {
  return {
    id: 'scan-1',
    workspaceId: 'ws-1',
    workspaceTitle: 'Shop',
    workspaceRoot: '/work/shop',
    mode: 'deep',
    status: 'running',
    phase: 'hunt',
    createdAt: '2026-10-01T10:00:00.000Z',
    updatedAt: '2026-10-01T10:00:00.000Z',
    settings: DEFAULT_SETTINGS,
    budget: DEFAULT_SETTINGS.budgets.deep,
    models: {},
    usage: { llmCalls: 0, inputTokens: 0, outputTokens: 0, toolCalls: 0, elapsedMs: 0 },
    phases: [],
    pluginVersion: '0.0.0-test',
    ...overrides,
  }
}

export function findingRecord(overrides: Partial<FindingRecord> = {}): FindingRecord {
  return {
    id: 'f-1',
    scanId: 'scan-1',
    fingerprint: 'fp-1',
    title: 'Issue',
    category: 'injection',
    severity: 'high',
    verification: 'potential',
    source: 'ai',
    location: { path: 'src/app.ts', startLine: 3, endLine: 3 },
    summary: 'Something is wrong.',
    impact: 'Bad things.',
    preconditions: [],
    attackPath: [],
    recommendation: 'Fix it.',
    limitations: [],
    references: [],
    createdBy: { role: 'hunter' },
    supportEvidenceIds: [],
    counterEvidenceIds: [],
    mergedFingerprints: [],
    isNew: false,
    createdAt: '2026-10-01T10:00:00.000Z',
    updatedAt: '2026-10-01T10:00:00.000Z',
    ...overrides,
  }
}

/** Insert a scan row so per-scan records satisfy their foreign keys. */
export function insertScan(store: SecurityStore, overrides: Partial<ScanRecord> = {}): ScanRecord {
  const scan = scanRecord(overrides)
  store.insertScan(scan)
  return scan
}
