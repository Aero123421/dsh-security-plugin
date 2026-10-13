import type { FindingDetail, ScanDetail } from '../../../src/shared/contracts.ts'
import { closureOf } from '../../../src/shared/domain.ts'
import type { ReportInput } from '../../../src/host/report/common.ts'

/** A completed deep scan with coverage, models, and a threat model. */
export function scanDetail(overrides: Partial<ScanDetail['summary']> = {}, rest: Partial<ScanDetail> = {}): ScanDetail {
  return {
    summary: {
      id: 'scan_01',
      workspaceId: 'ws_1',
      workspaceTitle: 'Acme API',
      mode: 'deep',
      status: 'completed',
      phase: 'done',
      createdAt: '2026-10-12T09:00:00.000Z',
      startedAt: '2026-10-12T09:00:05.000Z',
      finishedAt: '2026-10-12T09:41:30.000Z',
      counts: { critical: 1, high: 1, medium: 1, low: 0, info: 0 },
      confirmed: 1,
      commit: '0123456789abcdef0123456789abcdef01234567',
      dirty: true,
      ...overrides,
    },
    phases: [],
    usage: { llmCalls: 123, inputTokens: 1_234_567, outputTokens: 89_012, toolCalls: 456, elapsedMs: 2_485_000 },
    budget: { maxLlmCalls: 300, maxTokens: 3_000_000, maxMinutes: 60 },
    workers: [],
    coverage: {
      files: { total: 420, analyzed: 400, readByAi: 85, excluded: 20 },
      endpoints: { total: 30, reviewed: 24 },
      tasks: { planned: 40, completed: 36, failed: 1, skipped: 3 },
      analyzers: [
        { id: 'secrets', available: true, source: 'builtin' },
        { id: 'semgrep', available: false, source: 'disabled', reason: 'not installed' },
      ],
      discardedUnverifiable: 4,
      gaps: ['Budget exhausted before 3 tasks', 'Templates under views/ were not read'],
    },
    notices: [
      { level: 'warn', key: 'budget', text: 'Token budget 90% used', at: '2026-10-12T09:40:00.000Z' },
      { level: 'info', key: 'phase', text: 'Entered hunt', at: '2026-10-12T09:10:00.000Z' },
    ],
    models: {
      planner: { provider: 'deepseek', model: 'deepseek-reasoner', reasoningEffort: 'high' },
      hunter: { provider: 'deepseek', model: 'deepseek-chat' },
      skeptic: { provider: 'other', model: 'judge-1' },
    },
    threatModel: {
      summary: 'Public REST API backed by Postgres.',
      assets: ['Customer records'],
      actors: ['Anonymous internet user'],
      trustBoundaries: ['HTTP edge'],
    },
    ...rest,
  }
}

let counter = 0

/** A finding with consistent closure; override anything. */
export function finding(overrides: Partial<FindingDetail> = {}): FindingDetail {
  counter++
  const verification = overrides.verification ?? 'potential'
  return {
    id: `f_${counter}`,
    scanId: 'scan_01',
    fingerprint: `fp${counter.toString(16).padStart(8, '0')}`,
    title: `Finding ${counter}`,
    category: 'injection',
    severity: 'medium',
    verification,
    closure: closureOf(verification),
    source: 'ai',
    cwe: 'CWE-89',
    location: { path: 'src/db/users.ts', startLine: 10, endLine: 12 },
    summary: 'User input reaches a SQL query without parameters.',
    triage: 'open',
    isNew: false,
    impact: 'An attacker can read every customer record.',
    preconditions: ['The /users endpoint is reachable without authentication'],
    attackPath: [
      {
        order: 1,
        description: 'Request handler reads `req.query.name`.',
        location: { path: 'src/routes/users.ts', startLine: 4, endLine: 4 },
        snippet: 'const name = req.query.name',
        quoteCheck: 'match',
      },
      {
        order: 2,
        description: 'The value is concatenated into SQL.',
        location: { path: 'src/db/users.ts', startLine: 10, endLine: 12 },
        snippet: 'db.query("SELECT * FROM users WHERE name = \'" + name + "\'")',
        quoteCheck: 'mismatch',
      },
      { order: 3, description: 'The database returns all rows.', quoteCheck: 'unchecked' },
    ],
    recommendation: 'Use a parameterized query.',
    evidence: [
      {
        id: 'e1',
        kind: 'source_span',
        trust: 'observed',
        claim: 'Concatenation into a query string.',
        location: { path: 'src/db/users.ts', startLine: 10, endLine: 12 },
        snippet: 'db.query("SELECT ..." + name)',
        quoteCheck: 'match',
        originRole: 'hunter',
      },
    ],
    counterevidence: [],
    review: {
      verdict: 'inconclusive',
      reasoning: 'No validation found, but the route may be internal.',
      model: 'judge-1',
    },
    limitations: ['Deployment configuration was not available'],
    references: ['https://owasp.org/Top10/A03_2021-Injection/', 'javascript:alert(1)'],
    createdBy: { role: 'hunter', model: 'deepseek-chat' },
    ...overrides,
    ...(overrides.verification !== undefined && overrides.closure === undefined
      ? { closure: closureOf(verification) }
      : {}),
  }
}

/** A report with one finding in each closure group plus extra severities. */
export function reportInput(overrides: Partial<ReportInput> = {}): ReportInput {
  return {
    scan: scanDetail(),
    findings: [
      finding({
        id: 'f_ruled',
        title: 'Refuted XSS',
        category: 'xss',
        cwe: 'CWE-79',
        severity: 'high',
        verification: 'refuted',
      }),
      finding({ id: 'f_low', title: 'Verbose errors', severity: 'low', category: 'data-exposure', cwe: undefined }),
      finding({
        id: 'f_conf',
        title: 'SQL injection in user search',
        severity: 'critical',
        verification: 'strong_static_evidence',
        isNew: true,
      }),
      finding({
        id: 'f_gap',
        title: 'Missing authorization on export',
        category: 'authz',
        cwe: 'CWE-862',
        severity: 'high',
        verification: 'inconclusive',
        triage: 'accepted_risk',
        triageNote: 'Internal-only endpoint behind VPN',
      }),
      finding({
        id: 'f_secret',
        title: 'Hard-coded API key',
        category: 'secrets',
        cwe: 'CWE-798',
        source: 'secret',
        ruleId: 'secrets/generic-api-key',
        severity: 'high',
        verification: 'potential',
        triage: 'false_positive',
        attackPath: [],
        createdBy: { role: 'analyzer', analyzer: 'secrets' },
      }),
    ],
    workspaceTitle: 'Acme API',
    generatedAt: '2026-10-12T09:45:07.000Z',
    pluginVersion: '0.1.0',
    language: 'en',
    ...overrides,
  }
}
