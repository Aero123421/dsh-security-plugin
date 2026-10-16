import { beforeEach, describe, expect, it } from 'vitest'
import type { ChainProposal } from '../../../src/host/agents/roles/chain.ts'
import type { VerifiedCitation } from '../../../src/host/agents/roles/common.ts'
import type { HunterFinding, HunterOutput } from '../../../src/host/agents/roles/hunter.ts'
import type { SkepticOutput } from '../../../src/host/agents/roles/skeptic.ts'
import { runSast } from '../../../src/host/analysis/sast/engine.ts'
import { scanSecrets, secretSignals } from '../../../src/host/analysis/secrets.ts'
import type { FindingRecord } from '../../../src/host/core/model.ts'
import {
  applySkepticOutput,
  type HunterRecordContext,
  markNewFindings,
  recordChains,
  recordHunterOutput,
  recordSignalFindings,
  signalFingerprint,
  sourceOfAnalyzer,
} from '../../../src/host/scan/findings.ts'
import { openSecurityStore } from '../../../src/host/store/sqlite.ts'
import type { SecurityStore } from '../../../src/host/store/types.ts'
import type { Severity } from '../../../src/shared/domain.ts'
import { snapshotOf } from '../analysis/helpers.ts'
import { findingRecord, insertScan, signalOf } from './factories.ts'

const SCAN = 'scan-1'
const now = () => '2026-10-01T12:00:00.000Z'

let store: SecurityStore

beforeEach(() => {
  store = openSecurityStore(':memory:')
  insertScan(store, { id: SCAN })
})

function cite(
  path: string,
  line: number,
  quote: string,
  check: VerifiedCitation['quoteCheck'] = 'match',
): VerifiedCitation {
  const verified = check === 'match' || check === 'relocated'
  return {
    description: `step at ${path}:${line}`,
    quote,
    quoteCheck: check,
    ...(verified ? { location: { path, startLine: line, endLine: line }, snippet: quote } : {}),
  }
}

function hunterFinding(overrides: Partial<HunterFinding> = {}): HunterFinding {
  return {
    title: 'Any user can read any order',
    category: 'authz',
    cwe: 'CWE-639',
    severity: 'high',
    confidence: 'high',
    summary: 'Orders are loaded by id only.',
    impact: 'Customers read other customers orders.',
    preconditions: ['attacker has an account'],
    attackPath: [
      cite('src/routes/orders.ts', 24, "router.get('/:id', (req, res) => {"),
      cite('src/routes/orders.ts', 26, "db.one('SELECT * FROM orders WHERE id = ?', [req.params.id])"),
    ],
    defenses: [],
    recommendation: 'Filter by user_id.',
    references: [],
    ...overrides,
  }
}

function hunterOutput(findings: HunterFinding[], assessments: HunterOutput['assessments'] = []): HunterOutput {
  return { findings, assessments, reviewedPaths: [] }
}

function hunterCtx(overrides: Partial<HunterRecordContext> = {}): HunterRecordContext {
  return {
    scanId: SCAN,
    taskId: 'task-1',
    agentRunId: 'run-1',
    model: 'scripted/oracle',
    now,
    signalIds: new Map(),
    willReview: () => true,
    ...overrides,
  }
}

const roleCtx = { scanId: SCAN, taskId: 'task-2', agentRunId: 'run-2', model: 'scripted/oracle', now }

function insertFinding(overrides: Partial<FindingRecord> = {}): FindingRecord {
  const finding = findingRecord({ scanId: SCAN, ...overrides })
  store.insertFinding(finding)
  return finding
}

describe('sourceOfAnalyzer', () => {
  it('maps every analyzer to a finding source', () => {
    expect(sourceOfAnalyzer('secrets')).toBe('secret')
    expect(sourceOfAnalyzer('gitleaks')).toBe('external')
    expect(sourceOfAnalyzer('osv')).toBe('dependency')
    expect(sourceOfAnalyzer('dependencies')).toBe('dependency')
    expect(sourceOfAnalyzer('osv-scanner')).toBe('external')
    expect(sourceOfAnalyzer('sast')).toBe('sast')
    expect(sourceOfAnalyzer('ast-grep')).toBe('sast')
    expect(sourceOfAnalyzer('routes')).toBe('sast')
    expect(sourceOfAnalyzer('semgrep')).toBe('external')
  })
})

describe('recordSignalFindings', () => {
  const signals = [
    signalOf({ location: { path: 'src/db.ts', startLine: 4, endLine: 4 } }),
    signalOf({
      analyzer: 'secrets',
      ruleId: 'github-token',
      kind: 'secret',
      category: 'secrets',
      confidence: 'high',
      title: 'Hard-coded secret: GitHub token',
      location: { path: 'scripts/sync.ts', startLine: 8, endLine: 8 },
      snippet: "const TOKEN = '[REDACTED:github-token]'",
      fingerprintParts: ['github-token', 'scripts/sync.ts', 'abc'],
    }),
    signalOf({
      analyzer: 'secrets',
      ruleId: 'generic-secret',
      kind: 'secret',
      category: 'secrets',
      confidence: 'medium',
      fingerprintParts: ['generic-secret', 'src/config.ts', 'def'],
    }),
    signalOf({
      analyzer: 'osv',
      ruleId: 'GHSA-xxxx',
      kind: 'dependency',
      category: 'dependency',
      title: 'lodash 4.17.15 has known vulnerabilities',
      message: 'Prototype pollution. Command injection via template. Upgrade soon.',
      references: Array.from({ length: 10 }, (_, i) => `https://example.test/${i}`),
      fingerprintParts: ['GHSA-xxxx', 'lodash'],
    }),
    signalOf({ kind: 'sink', fingerprintParts: ['sink'] }),
    signalOf({ kind: 'info', fingerprintParts: ['info'] }),
  ]

  it.each([false, true])('merges a generic secret into the specific SAST finding (reverse=%s)', async reverse => {
    const snapshot = snapshotOf({ 'app/config.py': 'SECRET_KEY = "kR8vN2pQ7xL4mT9wB3zY6cH1jF5gD0sA8eU2iO7q"' })
    const generic = secretSignals(await scanSecrets(snapshot), snapshot)
    const specific = (await runSast(snapshot)).signals
    expect(generic.map(s => s.ruleId)).toEqual(['generic-secret'])
    expect(specific.map(s => s.ruleId)).toEqual(['py.hardcoded-secret-key'])
    const all = reverse ? [...specific, ...generic] : [...generic, ...specific]
    expect(recordSignalFindings(store, SCAN, all, now).created).toBe(1)
    const [finding] = store.listFindings(SCAN)
    expect(finding).toMatchObject({
      ruleId: 'py.hardcoded-secret-key',
      severity: 'high',
      mergedFingerprints: [signalFingerprint(generic[0]!)],
    })
    const evidence = store.getEvidence(SCAN, finding!.supportEvidenceIds)
    expect(evidence.map(e => e.claim.split(':')[0])).toEqual(['py.hardcoded-secret-key', 'generic-secret'])
    expect(recordSignalFindings(store, SCAN, all, now).created).toBe(0)
    expect(store.listFindings(SCAN)).toHaveLength(1)
    const assessment = recordHunterOutput(
      store,
      hunterCtx({ signalIds: new Map([['S1', signalFingerprint(generic[0]!)]]) }),
      hunterOutput([], [{ id: 'S1', verdict: 'true_positive', reason: 'The framework key is embedded in source.' }]),
    )
    expect(assessment.assessed).toBe(1)
  })

  it.each(['\n', '; '])('does not merge different secrets separated by %j', async separator => {
    const snapshot = snapshotOf({
      'app/config.py':
        'SECRET_KEY = "kR8vN2pQ7xL4mT9wB3zY6cH1jF5gD0sA8eU2iO7q"' +
        separator +
        'token = "aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA5"',
    })
    const generic = secretSignals(await scanSecrets(snapshot), snapshot)
    const specific = (await runSast(snapshot)).signals
    expect(generic).toHaveLength(2)
    expect(recordSignalFindings(store, SCAN, [...generic, ...specific], now).created).toBe(2)
    expect(
      store
        .listFindings(SCAN)
        .map(f => f.ruleId)
        .sort(),
    ).toEqual(['generic-secret', 'py.hardcoded-secret-key'])
  })

  it('prefers a specific secrets rule but preserves higher severity and both observations', () => {
    const common = { secretStart: 10, secretEnd: 50 }
    const generic = signalOf({
      analyzer: 'secrets',
      ruleId: 'generic-secret',
      kind: 'secret',
      category: 'secrets',
      severity: 'high',
      metadata: common,
      fingerprintParts: ['generic'],
    })
    const specific = signalOf({
      analyzer: 'secrets',
      ruleId: 'google-api-key',
      kind: 'secret',
      category: 'secrets',
      severity: 'medium',
      metadata: common,
      fingerprintParts: ['specific'],
    })
    expect(recordSignalFindings(store, SCAN, [generic, specific], now).created).toBe(1)
    expect(store.listFindings(SCAN)[0]).toMatchObject({
      ruleId: 'google-api-key',
      severity: 'high',
      mergedFingerprints: [signalFingerprint(generic)],
    })
  })

  it('keeps unrelated categories and dependencies even at the same location', () => {
    const at = { secretStart: 10, secretEnd: 50 }
    const all = [
      signalOf({ metadata: at }),
      signalOf({
        analyzer: 'osv',
        kind: 'dependency',
        category: 'dependency',
        metadata: at,
        fingerprintParts: ['dep'],
      }),
      signalOf({
        analyzer: 'secrets',
        ruleId: 'generic-secret',
        kind: 'secret',
        category: 'secrets',
        metadata: at,
        fingerprintParts: ['generic'],
      }),
    ]
    expect(recordSignalFindings(store, SCAN, all, now).created).toBe(3)
  })

  it('creates one finding with observed evidence per reportable signal', () => {
    const result = recordSignalFindings(store, SCAN, signals, now)
    expect(result.created).toBe(4)
    expect([...result.byFingerprint.keys()]).toEqual(signals.slice(0, 4).map(signalFingerprint))
    const findings = store.listFindings(SCAN)
    expect(findings).toHaveLength(4)

    const sast = store.findFindingByFingerprint(SCAN, signalFingerprint(signals[0]!))
    expect(sast).toMatchObject({
      source: 'sast',
      verification: 'potential',
      ruleId: 'js.sql-injection',
      cwe: 'CWE-89',
      summary: 'User input reaches a SQL query. It may be injectable.',
      recommendation: 'Use bound parameters.',
      createdBy: { role: 'analyzer', analyzer: 'sast' },
      attackPath: [{ order: 1, quoteCheck: 'match', snippet: 'db.query(sql)' }],
      isNew: false,
    })
    expect(sast?.limitations[0]).toMatch(/^Found by a pattern rule/)
    const [evidence] = store.getEvidence(SCAN, sast?.supportEvidenceIds ?? [])
    expect(evidence).toMatchObject({
      origin: 'analyzer',
      kind: 'tool_observation',
      trust: 'observed',
      quoteCheck: 'match',
      claim: 'js.sql-injection: SQL injection',
      location: { path: 'src/db.ts', startLine: 4, endLine: 4 },
    })
  })

  it('treats a high-confidence secret as strong static evidence and a medium one as potential', () => {
    recordSignalFindings(store, SCAN, signals, now)
    const high = store.findFindingByFingerprint(SCAN, signalFingerprint(signals[1]!))
    const medium = store.findFindingByFingerprint(SCAN, signalFingerprint(signals[2]!))
    expect(high).toMatchObject({ source: 'secret', verification: 'strong_static_evidence' })
    expect(high?.limitations).toEqual([
      'Whether the credential is still valid was not checked; the value itself is never shown.',
    ])
    expect(medium?.verification).toBe('potential')
  })

  it('notes that dependency reachability was not analyzed', () => {
    recordSignalFindings(store, SCAN, signals, now)
    const dep = store.findFindingByFingerprint(SCAN, signalFingerprint(signals[3]!))
    expect(dep).toMatchObject({ source: 'dependency' })
    expect(dep?.limitations).toEqual(['Reachability of the vulnerable code in this project was not analyzed.'])
    expect(dep?.summary).toBe('Prototype pollution. Command injection via template.')
    expect(dep?.references).toHaveLength(8)
  })

  it('is idempotent by fingerprint (safe to call again on resume)', () => {
    recordSignalFindings(store, SCAN, signals, now)
    const evidenceBefore = store.listEvidence(SCAN).length
    const again = recordSignalFindings(store, SCAN, signals, now)
    expect(again.created).toBe(0)
    expect(again.byFingerprint.size).toBe(4)
    expect(store.listFindings(SCAN)).toHaveLength(4)
    expect(store.listEvidence(SCAN)).toHaveLength(evidenceBefore)
  })
})

describe('recordHunterOutput', () => {
  it('stores a verified finding as a potential AI finding located at its last verified step', () => {
    const result = recordHunterOutput(store, hunterCtx(), hunterOutput([hunterFinding()]))
    expect(result).toEqual({ created: 1, merged: 0, discarded: 0, assessed: 0, disputed: 0 })
    const [finding] = store.listFindings(SCAN)
    expect(finding).toMatchObject({
      source: 'ai',
      verification: 'potential',
      category: 'authz',
      cwe: 'CWE-639',
      location: { path: 'src/routes/orders.ts', startLine: 26, endLine: 26 },
      createdBy: { role: 'hunter', model: 'scripted/oracle' },
      limitations: [],
      mergedFingerprints: [],
    })
    expect(finding?.attackPath.map(s => s.order)).toEqual([1, 2])
    const evidence = store.getEvidence(SCAN, finding?.supportEvidenceIds ?? [])
    expect(evidence).toHaveLength(2)
    expect(evidence.every(e => e.origin === 'hunter' && e.trust === 'inferred' && e.taskId === 'task-1')).toBe(true)
  })

  it('discards findings without any verified quote and stores nothing for them', () => {
    const fabricated = hunterFinding({
      title: 'Fabricated',
      attackPath: [cite('src/routes/orders.ts', 1, 'eval(req.query.backdoor)', 'mismatch')],
    })
    const result = recordHunterOutput(store, hunterCtx(), hunterOutput([fabricated]))
    expect(result).toMatchObject({ created: 0, discarded: 1 })
    expect(store.listFindings(SCAN)).toEqual([])
    expect(store.listEvidence(SCAN)).toEqual([])
  })

  it('keeps partly verified findings and records the unverified steps as a limitation', () => {
    const partial = hunterFinding({
      attackPath: [
        cite('src/routes/orders.ts', 26, "db.one('SELECT * FROM orders WHERE id = ?', [req.params.id])"),
        cite('src/routes/orders.ts', 40, 'res.json(order.secret)', 'mismatch'),
      ],
    })
    recordHunterOutput(store, hunterCtx(), hunterOutput([partial]))
    const [finding] = store.listFindings(SCAN)
    expect(finding?.location?.startLine).toBe(26)
    expect(finding?.limitations).toEqual([
      '1 of 2 attack-path steps could not be matched to the source and are shown unverified.',
    ])
  })

  it('merges into an overlapping rule finding, enriching its text and recording the merged fingerprint', () => {
    const sast = insertFinding({
      id: 'sast-1',
      fingerprint: 'sast-fp',
      source: 'sast',
      category: 'injection',
      cwe: 'CWE-89',
      severity: 'medium',
      title: 'SQL injection',
      location: { path: 'src/routes/products.ts', startLine: 27, endLine: 29 },
      attackPath: [{ order: 1, description: 'rule hit', quoteCheck: 'match' }],
      limitations: ['Found by a pattern rule; the full data flow has not been traced unless an AI review is attached.'],
      supportEvidenceIds: ['ev-rule'],
    })
    const enriched = hunterFinding({
      title: 'SQL injection in product search',
      category: 'injection',
      cwe: 'CWE-89',
      severity: 'high',
      attackPath: [
        cite('src/routes/products.ts', 24, "router.get('/search', (req, res) => {"),
        cite('src/routes/products.ts', 29, 'name LIKE \'%" + term + "%\''),
      ],
    })
    const result = recordHunterOutput(store, hunterCtx(), hunterOutput([enriched]))
    expect(result).toMatchObject({ created: 0, merged: 1 })
    const merged = store.getFinding(SCAN, sast.id)
    expect(store.listFindings(SCAN)).toHaveLength(1)
    expect(merged).toMatchObject({
      fingerprint: 'sast-fp',
      source: 'sast',
      title: 'SQL injection in product search',
      summary: 'Orders are loaded by id only.',
      severity: 'high',
      limitations: [],
    })
    expect(merged?.attackPath).toHaveLength(2)
    expect(merged?.mergedFingerprints).toHaveLength(1)
    expect(merged?.mergedFingerprints[0]).toMatch(/^[0-9a-f]{32}$/)
    expect(merged?.supportEvidenceIds[0]).toBe('ev-rule')
    expect(merged?.supportEvidenceIds).toHaveLength(3)
  })

  it('does not merge into secret or dependency findings, other categories, or far-away lines', () => {
    const location = { path: 'src/routes/orders.ts', startLine: 26, endLine: 26 }
    insertFinding({ id: 'secret', fingerprint: 'a', source: 'secret', category: 'authz', location })
    insertFinding({ id: 'other', fingerprint: 'b', source: 'sast', category: 'xss', cwe: 'CWE-79', location })
    insertFinding({
      id: 'far',
      fingerprint: 'c',
      source: 'sast',
      category: 'authz',
      location: { ...location, startLine: 30, endLine: 30 },
    })
    const result = recordHunterOutput(store, hunterCtx(), hunterOutput([hunterFinding()]))
    expect(result).toMatchObject({ created: 1, merged: 0 })
    expect(store.listFindings(SCAN)).toHaveLength(4)
  })

  it('merges a repeated AI finding by fingerprint without changing its text', () => {
    recordHunterOutput(store, hunterCtx(), hunterOutput([hunterFinding()]))
    const repeat = hunterFinding({ title: 'Same issue, other words', severity: 'critical' })
    const result = recordHunterOutput(store, hunterCtx({ taskId: 'task-9' }), hunterOutput([repeat]))
    expect(result).toMatchObject({ created: 0, merged: 1 })
    const [finding] = store.listFindings(SCAN)
    expect(store.listFindings(SCAN)).toHaveLength(1)
    expect(finding).toMatchObject({
      title: 'Any user can read any order',
      severity: 'critical',
      mergedFingerprints: [],
    })
    expect(finding?.supportEvidenceIds).toHaveLength(4)
  })

  describe('signal assessments', () => {
    const rule = signalOf({ location: { path: 'src/db.ts', startLine: 4, endLine: 4 }, severity: 'medium' })
    const fingerprint = signalFingerprint(rule)
    const defense = cite('src/db.ts', 4, "db.query('SELECT 1 WHERE id = ?', [id])")

    beforeEach(() => {
      recordSignalFindings(store, SCAN, [rule], now)
    })

    const assess = (
      verdict: 'true_positive' | 'false_positive' | 'uncertain',
      evidence: VerifiedCitation | undefined,
      willReview: (severity: Severity) => boolean,
      id = 'S1',
    ) =>
      recordHunterOutput(
        store,
        hunterCtx({ signalIds: new Map([['S1', fingerprint]]), willReview }),
        hunterOutput([], [{ id, verdict, reason: 'Parameterized.', ...(evidence ? { evidence } : {}) }]),
      )

    it('never refutes without a review: a verified code defense makes the rule hit inconclusive (Quick mode)', () => {
      const result = assess('false_positive', defense, () => false, ' s1 ')
      expect(result).toMatchObject({ assessed: 1, disputed: 1 })
      const finding = store.findFindingByFingerprint(SCAN, fingerprint)
      expect(finding?.verification).toBe('inconclusive')
      expect(finding?.review).toBeUndefined()
      expect(finding?.limitations).toContain(
        'An AI hunter assessed this rule hit as a false positive (Parameterized.), but no independent review confirmed the cited defense, so it stays open.',
      )
      const [counter] = store.getEvidence(SCAN, finding?.counterEvidenceIds ?? [])
      expect(counter).toMatchObject({ kind: 'counterevidence', origin: 'hunter', quoteCheck: 'match' })
      expect(counter?.claim).toMatch(/^Parameterized\. — /)
    })

    it('does not count a comment-only defense, from any file, as counter-evidence', () => {
      const comment = { ...cite('src/other.ts', 2, '// input sanitized upstream'), commentOnly: true }
      expect(assess('false_positive', comment, () => false)).toMatchObject({ assessed: 1, disputed: 0 })
      const finding = store.findFindingByFingerprint(SCAN, fingerprint)
      expect(finding?.verification).toBe('potential')
      // Still shown as context.
      const [counter] = store.getEvidence(SCAN, finding?.counterEvidenceIds ?? [])
      expect(counter).toMatchObject({
        kind: 'counterevidence',
        quote: '// input sanitized upstream',
        quoteCheck: 'match',
      })
    })

    it('leaves the decision to the reviewer when a review will follow', () => {
      const result = assess('false_positive', defense, () => true)
      expect(result).toMatchObject({ assessed: 1 })
      const finding = store.findFindingByFingerprint(SCAN, fingerprint)
      expect(finding?.verification).toBe('potential')
      expect(finding?.review).toBeUndefined()
      expect(finding?.counterEvidenceIds).toHaveLength(1)
    })

    it('never rules out without a verified quote', () => {
      expect(assess('false_positive', undefined, () => false)).toMatchObject({ assessed: 1 })
      expect(assess('false_positive', cite('src/db.ts', 4, 'invented', 'mismatch'), () => false)).toMatchObject({
        disputed: 0,
      })
      const finding = store.findFindingByFingerprint(SCAN, fingerprint)
      expect(finding?.verification).toBe('potential')
      expect(finding?.counterEvidenceIds).toHaveLength(1)
    })

    it('adds supporting evidence for true positives and ignores unknown ids', () => {
      const result = assess('true_positive', defense, () => true)
      expect(result).toMatchObject({ assessed: 1 })
      const finding = store.findFindingByFingerprint(SCAN, fingerprint)
      expect(finding?.supportEvidenceIds).toHaveLength(2)
      expect(store.getEvidence(SCAN, finding?.supportEvidenceIds ?? [])[1]?.kind).toBe('source_span')
      expect(assess('false_positive', defense, () => false, 'S7')).toMatchObject({ assessed: 0 })
    })
  })
})

describe('applySkepticOutput', () => {
  const verifiedStep = { order: 1, description: 'sink', quote: 'q', quoteCheck: 'match' as const }
  const verdict = (overrides: Partial<SkepticOutput> = {}): SkepticOutput => ({
    verdict: 'confirmed',
    reasoning: 'No guard.',
    counterevidence: [],
    supporting: [],
    missingInformation: [],
    ...overrides,
  })

  it('downgrades a refutation without verified counterevidence to inconclusive, keeping the severity', () => {
    const finding = insertFinding({ severity: 'critical', attackPath: [verifiedStep] })
    const updated = applySkepticOutput(
      store,
      finding,
      verdict({
        verdict: 'refuted',
        reasoning: 'There is a guard.',
        counterevidence: [cite('src/app.ts', 1, 'requireAuth()', 'mismatch')],
        severity: 'low',
      }),
      roleCtx,
    )
    expect(updated.verification).toBe('inconclusive')
    expect(updated.review?.verdict).toBe('inconclusive')
    expect(updated.review?.reasoning).toMatch(/^There is a guard\.\n\n\[Host\] The reviewer claimed a defense/)
    // The unverified defense must not lower the severity either; the suggestion is kept in the review.
    expect(updated.severity).toBe('critical')
    expect(updated.review?.severityAdjustment).toBe('low')
    expect(updated.counterEvidenceIds).toHaveLength(1)
  })

  it('refutes with verified counterevidence and does not apply a severity change', () => {
    const finding = insertFinding({ severity: 'high', attackPath: [verifiedStep] })
    const updated = applySkepticOutput(
      store,
      finding,
      verdict({
        verdict: 'refuted',
        reasoning: 'Scoped by user.',
        counterevidence: [cite('src/app.ts', 3, 'WHERE user_id = ?')],
        severity: 'info',
      }),
      roleCtx,
    )
    expect(updated).toMatchObject({
      verification: 'refuted',
      severity: 'high',
      review: {
        verdict: 'refuted',
        reasoning: 'Scoped by user.',
        model: 'scripted/oracle',
        severityAdjustment: 'info',
      },
    })
    const [counter] = store.getEvidence(SCAN, updated.counterEvidenceIds)
    expect(counter).toMatchObject({ origin: 'skeptic', kind: 'counterevidence', taskId: 'task-2' })
  })

  it('confirms to strong static evidence and applies the corrected severity and localized text', () => {
    const finding = insertFinding({
      source: 'sast',
      attackPath: [verifiedStep],
      limitations: ['Found by a pattern rule; the full data flow has not been traced unless an AI review is attached.'],
      supportEvidenceIds: ['ev-0'],
    })
    const updated = applySkepticOutput(
      store,
      finding,
      verdict({
        severity: 'critical',
        supporting: [cite('src/app.ts', 3, 'db.query(sql)')],
        missingInformation: ['deployment', 'deployment'],
        localized: { title: '検証済み', summary: '要約', impact: '影響', recommendation: '推奨' },
      }),
      roleCtx,
    )
    expect(updated).toMatchObject({
      verification: 'strong_static_evidence',
      severity: 'critical',
      title: '検証済み',
      summary: '要約',
      impact: '影響',
      recommendation: '推奨',
      limitations: ['deployment'],
      review: {
        verdict: 'confirmed',
        reasoning: 'No guard.\n\n[Host] Severity changed from high (original) to critical.',
        severityAdjustment: 'critical',
      },
    })
    expect(updated.supportEvidenceIds).toHaveLength(2)
    expect(updated.supportEvidenceIds[0]).toBe('ev-0')
  })

  it('needs a verified excerpt on the attack path to confirm', () => {
    const finding = insertFinding({ attackPath: [{ ...verifiedStep, quoteCheck: 'mismatch' }] })
    const updated = applySkepticOutput(store, finding, verdict(), roleCtx)
    expect(updated.verification).toBe('inconclusive')
    expect(updated.review?.reasoning).toMatch(/\[Host\] Confirmation requires at least one verified code excerpt/)

    // A verified supporting citation from the reviewer is enough.
    const second = insertFinding({ id: 'f-2', fingerprint: 'fp-2', attackPath: [] })
    expect(
      applySkepticOutput(store, second, verdict({ supporting: [cite('src/app.ts', 3, 'db.query(sql)')] }), roleCtx)
        .verification,
    ).toBe('strong_static_evidence')
  })

  it('does not accept comment-only counter-evidence for a refutation', () => {
    const finding = insertFinding({ attackPath: [verifiedStep] })
    const comment = { ...cite('src/app.ts', 2, '// sanitized by the gateway'), commentOnly: true }
    const updated = applySkepticOutput(
      store,
      finding,
      verdict({ verdict: 'refuted', reasoning: 'Sanitized upstream.', counterevidence: [comment] }),
      roleCtx,
    )
    expect(updated.verification).toBe('inconclusive')
    expect(updated.review?.verdict).toBe('inconclusive')
    expect(updated.review?.reasoning).toMatch(/\[Host\] The reviewer's matching counter-evidence is non-code evidence/)
    expect(store.getEvidence(SCAN, updated.counterEvidenceIds)[0]).toMatchObject({ quoteCheck: 'match' })

    // One verified code quote next to the comment is enough.
    const second = insertFinding({ id: 'f-2', fingerprint: 'fp-2', attackPath: [verifiedStep] })
    const code = cite('src/app.ts', 3, 'if (!isAdmin(req.user)) return res.status(403).end()')
    expect(
      applySkepticOutput(store, second, verdict({ verdict: 'refuted', counterevidence: [comment, code] }), roleCtx)
        .verification,
    ).toBe('refuted')
  })

  describe('severity corrections', () => {
    const support = [cite('src/app.ts', 3, 'db.query(sql)')]
    const review = (overrides: Partial<FindingRecord>, output: Partial<SkepticOutput>) =>
      applySkepticOutput(store, insertFinding({ attackPath: [verifiedStep], ...overrides }), verdict(output), roleCtx)

    it('ignores a severity change on an inconclusive verdict and notes it', () => {
      const updated = review({ severity: 'high' }, { verdict: 'inconclusive', severity: 'low', supporting: support })
      expect(updated.severity).toBe('high')
      expect(updated.review?.severityAdjustment).toBe('low')
      expect(updated.review?.reasoning).toBe(
        'No guard.\n\n[Host] The suggested severity (low) was not applied: a severity change needs a confirmed verdict with verified supporting code. Severity stays high.',
      )
    })

    it('ignores a severity change on a confirmation without verified supporting code', () => {
      // The attack path is verified, so the confirmation stands, but the new severity has no evidence.
      const unverified = review({ severity: 'high' }, { severity: 'critical' })
      expect(unverified).toMatchObject({ verification: 'strong_static_evidence', severity: 'high' })
      expect(unverified.review?.reasoning).toMatch(/The suggested severity \(critical\) was not applied/)

      const mismatched = review(
        { id: 'f-2', fingerprint: 'fp-2', severity: 'high' },
        { severity: 'low', supporting: [cite('src/app.ts', 3, 'db.raw(x)', 'mismatch')] },
      )
      expect(mismatched.severity).toBe('high')

      const commentOnly = review(
        { id: 'f-3', fingerprint: 'fp-3', severity: 'high' },
        { severity: 'low', supporting: [{ ...cite('src/app.ts', 3, '// low impact'), commentOnly: true }] },
      )
      expect(commentOnly.severity).toBe('high')
    })

    it('lowers a deterministic critical/high rule hit by at most one level per review', () => {
      const sast = review({ source: 'sast', severity: 'critical' }, { severity: 'low', supporting: support })
      expect(sast.severity).toBe('high')
      expect(sast.review?.severityAdjustment).toBe('low')
      expect(sast.review?.reasoning).toBe(
        'No guard.\n\n[Host] Severity changed from critical (original) to high; the reviewer suggested low, but a deterministic critical rule hit is lowered by at most one level per review.',
      )
      const secret = review(
        { id: 'f-2', fingerprint: 'fp-2', source: 'secret', severity: 'high' },
        { severity: 'info', supporting: support },
      )
      expect(secret.severity).toBe('medium')
      const dependency = review(
        { id: 'f-3', fingerprint: 'fp-3', source: 'dependency', severity: 'high' },
        { severity: 'medium', supporting: support },
      )
      expect(dependency.severity).toBe('medium')
      expect(dependency.review?.reasoning).toBe('No guard.\n\n[Host] Severity changed from high (original) to medium.')
    })

    it('applies other confirmed, evidenced changes as proposed', () => {
      const ai = review({ source: 'ai', severity: 'critical' }, { severity: 'low', supporting: support })
      expect(ai.severity).toBe('low')
      const medium = review(
        { id: 'f-2', fingerprint: 'fp-2', source: 'sast', severity: 'medium' },
        { severity: 'info', supporting: support },
      )
      expect(medium.severity).toBe('info')
      const raised = review(
        { id: 'f-3', fingerprint: 'fp-3', source: 'sast', severity: 'low' },
        { severity: 'critical', supporting: support },
      )
      expect(raised.severity).toBe('critical')
      const same = review(
        { id: 'f-4', fingerprint: 'fp-4', severity: 'high' },
        { severity: 'high', supporting: support },
      )
      expect(same.review?.reasoning).toBe('No guard.')
    })
  })

  it('records inconclusive verdicts with the missing information', () => {
    const finding = insertFinding({ attackPath: [verifiedStep] })
    const updated = applySkepticOutput(
      store,
      finding,
      verdict({ verdict: 'inconclusive', missingInformation: ['proxy configuration'] }),
      roleCtx,
    )
    expect(updated).toMatchObject({ verification: 'inconclusive', limitations: ['proxy configuration'] })
  })
})

describe('recordChains', () => {
  const chain = (overrides: Partial<ChainProposal> = {}): ChainProposal => ({
    title: 'Leak then IDOR',
    findingIds: ['F1', 'f2'],
    category: 'authz',
    severity: 'critical',
    summary: 'Combined.',
    impact: 'Full takeover.',
    attackPath: [cite('src/app.ts', 3, 'db.query(sql)')],
    recommendation: 'Fix both.',
    ...overrides,
  })

  it('stores verified chains that combine at least two findings, once', () => {
    const a = insertFinding({ id: 'a', fingerprint: 'fp-a', title: 'Leak' })
    const b = insertFinding({ id: 'b', fingerprint: 'fp-b', title: 'IDOR' })
    const ids = new Map([
      ['F1', a],
      ['F2', b],
    ])
    expect(recordChains(store, [chain()], ids, roleCtx)).toEqual({ created: 1, discarded: 0 })
    const stored = store.listFindings(SCAN).find(f => f.createdBy.role === 'chain')
    expect(stored).toMatchObject({
      source: 'ai',
      verification: 'potential',
      severity: 'critical',
      location: { path: 'src/app.ts', startLine: 3, endLine: 3 },
      limitations: ['Combines: Leak + IDOR'],
    })
    // The same combination is not stored twice.
    expect(recordChains(store, [chain({ findingIds: ['F2', 'F1'] })], ids, roleCtx)).toEqual({
      created: 0,
      discarded: 0,
    })
    expect(store.listFindings(SCAN)).toHaveLength(3)
  })

  it('discards chains with unknown or repeated parts and chains without verified code', () => {
    const a = insertFinding({ id: 'a', fingerprint: 'fp-a' })
    const ids = new Map([['F1', a]])
    const result = recordChains(
      store,
      [
        chain({ findingIds: ['F1', 'F9'] }),
        chain({ findingIds: ['F1', 'F1'] }),
        chain({ findingIds: ['F1', 'F1'], attackPath: [cite('src/app.ts', 3, 'x', 'mismatch')] }),
      ],
      ids,
      roleCtx,
    )
    expect(result).toEqual({ created: 0, discarded: 3 })
    expect(store.listFindings(SCAN)).toHaveLength(1)
  })
})

describe('markNewFindings', () => {
  it('marks nothing new without a previous scan', () => {
    insertFinding({ id: 'x', fingerprint: 'fp-x', isNew: true })
    markNewFindings(store, SCAN, undefined)
    expect(store.getFinding(SCAN, 'x')?.isNew).toBe(false)
  })

  it('marks only fingerprints absent from the previous scan, counting merged duplicates', () => {
    insertFinding({ id: 'old', fingerprint: 'fp-old' })
    insertFinding({ id: 'merged', fingerprint: 'fp-sast', mergedFingerprints: ['fp-ai-before'] })
    insertFinding({ id: 'fresh', fingerprint: 'fp-fresh' })
    insertFinding({ id: 'was-new', fingerprint: 'fp-again', isNew: true })
    markNewFindings(store, SCAN, new Set(['fp-old', 'fp-ai-before', 'fp-again']))
    const isNew = Object.fromEntries(store.listFindings(SCAN).map(f => [f.id, f.isNew]))
    expect(isNew).toEqual({ old: false, merged: false, fresh: true, 'was-new': false })
  })
})
