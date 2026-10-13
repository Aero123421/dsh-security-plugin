import type {
  AgentRunRecord,
  EvidenceRecord,
  FindingRecord,
  ScanRecord,
  TaskRecord,
} from '../../../src/host/core/model.ts'
import { DEFAULT_SETTINGS } from '../../../src/shared/settings.ts'

/** A minimal scan: only required fields. */
export function scanOf(overrides: Partial<ScanRecord> = {}): ScanRecord {
  return {
    id: 'scan_1',
    workspaceId: 'ws_1',
    workspaceTitle: 'Acme API',
    workspaceRoot: '/home/dev/acme',
    mode: 'deep',
    status: 'queued',
    phase: 'snapshot',
    createdAt: '2026-10-01T10:00:00.000Z',
    updatedAt: '2026-10-01T10:00:00.000Z',
    settings: DEFAULT_SETTINGS,
    budget: DEFAULT_SETTINGS.budgets.deep,
    models: {},
    usage: { llmCalls: 0, inputTokens: 0, outputTokens: 0, toolCalls: 0, elapsedMs: 0 },
    phases: [{ phase: 'snapshot', state: 'pending' }],
    pluginVersion: '0.1.0',
    ...overrides,
  }
}

/** A scan with every optional field set. */
export function fullScanOf(overrides: Partial<ScanRecord> = {}): ScanRecord {
  return scanOf({
    status: 'completed',
    phase: 'done',
    startedAt: '2026-10-01T10:00:05.000Z',
    finishedAt: '2026-10-01T10:40:00.000Z',
    error: { code: 'budget', message: 'Token budget exhausted' },
    commit: '0123456789abcdef0123456789abcdef01234567',
    models: {
      planner: { provider: 'deepseek', model: 'deepseek-reasoner', reasoningEffort: 'high', maxOutputTokens: 8192 },
      hunter: { provider: 'deepseek', model: 'deepseek-chat' },
    },
    usage: { llmCalls: 12, inputTokens: 123_456, outputTokens: 7_890, toolCalls: 44, elapsedMs: 2_400_000 },
    phases: [
      { phase: 'snapshot', state: 'done' },
      { phase: 'hunt', state: 'skipped' },
    ],
    progress: { done: 3, total: 10, unit: 'tasks' },
    coverage: {
      files: { total: 100, analyzed: 90, readByAi: 20, excluded: 10 },
      endpoints: { total: 5, reviewed: 4 },
      tasks: { planned: 10, completed: 8, failed: 1, skipped: 1 },
      analyzers: [{ id: 'secrets', available: true, source: 'builtin' }],
      discardedUnverifiable: 2,
      gaps: ['templates not read'],
    },
    analyzers: [
      { id: 'semgrep', available: false, source: 'disabled', reason: 'not installed' },
      { id: 'gitleaks', available: true, source: 'managed', version: '8.18.0' },
    ],
    threatModel: {
      summary: 'Public REST API with admin panel',
      assets: ['user data'],
      actors: ['anonymous user', 'admin'],
      trustBoundaries: ['internet → api'],
      priorities: [{ target: 'src/routes/admin.ts', reason: 'privileged' }],
    },
    ...overrides,
  })
}

export function taskOf(overrides: Partial<TaskRecord> = {}): TaskRecord {
  return {
    id: 'task_1',
    scanId: 'scan_1',
    key: 'hunt-file:src/a.ts',
    kind: 'hunt-file',
    role: 'hunter',
    title: 'Hunt src/a.ts',
    status: 'pending',
    priority: 5,
    input: { targetPaths: ['src/a.ts'], focus: ['injection'] },
    attempts: 0,
    createdAt: '2026-10-01T10:01:00.000Z',
    ...overrides,
  }
}

export function fullTaskOf(overrides: Partial<TaskRecord> = {}): TaskRecord {
  return taskOf({
    status: 'failed',
    input: {
      targetPaths: ['src/a.ts', 'src/b.ts'],
      endpointIds: ['ep1'],
      signalFingerprints: ['sig1'],
      findingId: 'f1',
      findingIds: ['f1', 'f2'],
      focus: ['authz', 'injection'],
      hypothesis: 'Admin route lacks auth',
    },
    attempts: 2,
    error: { code: 'timeout', message: 'worker timed out' },
    outcome: { findings: 2, submitted: true, note: 'ok' },
    startedAt: '2026-10-01T10:02:00.000Z',
    finishedAt: '2026-10-01T10:03:00.000Z',
    ...overrides,
  })
}

export function runOf(overrides: Partial<AgentRunRecord> = {}): AgentRunRecord {
  return {
    id: 'run_1',
    scanId: 'scan_1',
    taskId: 'task_1',
    role: 'hunter',
    title: 'Hunt src/a.ts',
    provider: 'deepseek',
    model: 'deepseek-chat',
    status: 'running',
    turns: 0,
    toolCalls: 0,
    llmCalls: 0,
    inputTokens: 0,
    outputTokens: 0,
    startedAt: '2026-10-01T10:02:00.000Z',
    filesRead: [],
    ...overrides,
  }
}

export function fullRunOf(overrides: Partial<AgentRunRecord> = {}): AgentRunRecord {
  return runOf({
    status: 'failed',
    turns: 4,
    toolCalls: 9,
    llmCalls: 4,
    inputTokens: 10_000,
    outputTokens: 900,
    finishedAt: '2026-10-01T10:05:00.000Z',
    stopReason: 'error',
    error: { code: 'provider', message: '429' },
    filesRead: ['src/a.ts'],
    ...overrides,
  })
}

export function evidenceOf(overrides: Partial<EvidenceRecord> = {}): EvidenceRecord {
  return {
    id: 'ev_1',
    scanId: 'scan_1',
    origin: 'analyzer',
    kind: 'tool_observation',
    trust: 'observed',
    claim: 'eval() on request body',
    quoteCheck: 'unchecked',
    createdAt: '2026-10-01T10:03:00.000Z',
    ...overrides,
  }
}

export function fullEvidenceOf(overrides: Partial<EvidenceRecord> = {}): EvidenceRecord {
  return evidenceOf({
    taskId: 'task_1',
    agentRunId: 'run_1',
    origin: 'hunter',
    kind: 'source_span',
    trust: 'inferred',
    location: { path: 'src/a.ts', startLine: 10, endLine: 12 },
    fileHash: 'a'.repeat(64),
    quote: 'eval(req.body.code)',
    snippet: '  eval(req.body.code)\n',
    quoteCheck: 'match',
    ...overrides,
  })
}

export function findingOf(overrides: Partial<FindingRecord> = {}): FindingRecord {
  return {
    id: 'f_1',
    scanId: 'scan_1',
    fingerprint: 'fp_1',
    title: 'Code injection',
    category: 'injection',
    severity: 'high',
    verification: 'potential',
    source: 'ai',
    summary: 'User input reaches eval',
    impact: 'Remote code execution',
    preconditions: [],
    attackPath: [],
    recommendation: 'Remove eval',
    limitations: [],
    references: [],
    createdBy: { role: 'hunter' },
    supportEvidenceIds: [],
    counterEvidenceIds: [],
    mergedFingerprints: [],
    isNew: false,
    createdAt: '2026-10-01T10:04:00.000Z',
    updatedAt: '2026-10-01T10:04:00.000Z',
    ...overrides,
  }
}

export function fullFindingOf(overrides: Partial<FindingRecord> = {}): FindingRecord {
  return findingOf({
    verification: 'strong_static_evidence',
    cwe: 'CWE-94',
    ruleId: 'js.eval',
    location: { path: 'src/a.ts', startLine: 10, endLine: 12 },
    preconditions: ['attacker can POST /run'],
    attackPath: [
      {
        order: 1,
        description: 'POST /run',
        location: { path: 'src/routes.ts', startLine: 3, endLine: 3 },
        quote: "app.post('/run'",
        snippet: "app.post('/run', run)",
        quoteCheck: 'relocated',
      },
      { order: 2, description: 'eval', quoteCheck: 'unchecked' },
    ],
    limitations: ['static only'],
    references: ['https://cwe.mitre.org/data/definitions/94.html'],
    review: {
      verdict: 'confirmed',
      reasoning: 'no sanitizer',
      model: 'deepseek-reasoner',
      severityAdjustment: 'critical',
    },
    createdBy: { role: 'hunter', model: 'deepseek-chat', analyzer: 'sast' },
    supportEvidenceIds: ['ev_1'],
    counterEvidenceIds: ['ev_2'],
    mergedFingerprints: ['fp_dup'],
    isNew: true,
    ...overrides,
  })
}
