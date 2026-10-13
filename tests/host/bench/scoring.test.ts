import { describe, expect, it } from 'vitest'
import type { FixtureManifest } from '../../../bench/fixtures.ts'
import {
  activeDetectorsOf,
  detectorsOf,
  type FindingProvenance,
  type ReportedFinding,
  scoreApp,
  sumScores,
} from '../../../bench/scoring.ts'
import type { Closure } from '../../../src/shared/domain.ts'

const manifest: Pick<FixtureManifest, 'app' | 'findings' | 'negatives'> = {
  app: 'demo',
  findings: [
    {
      id: 'DM-01',
      title: 'SQL injection',
      category: 'injection',
      cwe: 'CWE-89',
      severity: 'high',
      path: 'src/db.ts',
      line: 20,
      anchor: 'db.query(',
      detectableBy: ['sast', 'ai'],
      notes: 'n',
    },
    {
      id: 'DM-02',
      title: 'IDOR',
      category: 'authz',
      cwe: 'CWE-639',
      severity: 'high',
      path: 'src/orders.ts',
      line: 10,
      anchor: 'findById(',
      detectableBy: ['ai'],
      notes: 'n',
    },
    {
      id: 'DM-03',
      title: 'Hard-coded key',
      category: 'secrets',
      cwe: 'CWE-798',
      severity: 'high',
      path: 'src/config.ts',
      line: 4,
      anchor: "key: '",
      detectableBy: ['secrets'],
      notes: 'n',
    },
    {
      id: 'DM-04',
      title: 'lodash 4.17.15',
      category: 'dependency',
      severity: 'medium',
      path: 'package-lock.json',
      line: 30,
      anchor: '"node_modules/lodash"',
      detectableBy: ['dependency'],
      notes: 'n',
    },
  ],
  negatives: [
    {
      id: 'DM-N1',
      path: 'src/db.ts',
      line: 40,
      anchor: 'db.query(',
      description: 'parameterized',
      category: 'injection',
    },
    {
      id: 'DM-N2',
      path: 'src/orders.ts',
      line: 13,
      anchor: 'findOne(',
      description: 'scoped by owner',
      category: 'authz',
    },
  ],
}

let counter = 0

function report(
  path: string,
  line: number,
  category: string,
  options: {
    readonly cwe?: string
    readonly endLine?: number
    readonly closure?: Closure
    readonly detectors?: ReportedFinding['detectors']
  } = {},
): ReportedFinding {
  counter++
  const closure = options.closure ?? 'open_proof_gap'
  return {
    id: `r${counter}`,
    title: `report ${counter}`,
    category,
    ...(options.cwe ? { cwe: options.cwe } : {}),
    location: { path, startLine: line, endLine: options.endLine ?? line },
    verification:
      closure === 'confirmed' ? 'strong_static_evidence' : closure === 'ruled_out' ? 'refuted' : 'potential',
    closure,
    detectors: options.detectors ?? ['sast'],
  }
}

describe('scoreApp', () => {
  it('counts true positives, false negatives and recall over planted findings', () => {
    const score = scoreApp(manifest, [
      report('src/db.ts', 20, 'injection'),
      report('src/config.ts', 4, 'secrets', { detectors: ['secrets'] }),
    ])
    expect(score.totals).toMatchObject({
      planted: 4,
      truePositives: 2,
      falseNegatives: 2,
      recall: 0.5,
      reports: 2,
      matchedReports: 2,
      falsePositives: 0,
      precision: 1,
    })
    expect(score.expected.map(row => [row.id, row.status])).toEqual([
      ['DM-01', 'detected'],
      ['DM-02', 'missed'],
      ['DM-03', 'detected'],
      ['DM-04', 'missed'],
    ])
  })

  it('counts unmatched reports and reports on negative controls as false positives', () => {
    const score = scoreApp(manifest, [
      report('src/db.ts', 20, 'injection'),
      report('src/db.ts', 41, 'injection'),
      report('src/other.ts', 5, 'xss'),
    ])
    expect(score.totals).toMatchObject({ reports: 3, matchedReports: 1, falsePositives: 2, negativeHits: 1 })
    expect(score.totals.precision).toBeCloseTo(1 / 3)
    expect(score.negatives.find(n => n.id === 'DM-N1')?.hits).toBe(1)
    expect(score.reports.map(row => row.outcome)).toEqual(['true-positive', 'negative', 'false-positive'])
  })

  it('applies the line tolerance and accepts an expected line inside the reported range', () => {
    expect(scoreApp(manifest, [report('src/db.ts', 23, 'injection')]).totals.truePositives).toBe(1)
    expect(scoreApp(manifest, [report('src/db.ts', 24, 'injection')]).totals.truePositives).toBe(0)
    expect(scoreApp(manifest, [report('src/db.ts', 24, 'injection')], { tolerance: 4 }).totals.truePositives).toBe(1)
    expect(scoreApp(manifest, [report('src/db.ts', 12, 'injection', { endLine: 25 })]).totals.truePositives).toBe(1)
  })

  it('matches on category or CWE', () => {
    const byCwe = scoreApp(manifest, [report('src/db.ts', 20, 'command-execution', { cwe: 'cwe-89' })])
    expect(byCwe.totals.truePositives).toBe(1)
    const neither = scoreApp(manifest, [report('src/db.ts', 20, 'xss', { cwe: 'CWE-79' })])
    expect(neither.totals).toMatchObject({ truePositives: 0, falsePositives: 1 })
    const wrongPath = scoreApp(manifest, [report('src/db2.ts', 20, 'injection')])
    expect(wrongPath.totals.truePositives).toBe(0)
  })

  it('assigns a report to the nearest entry, planted findings first on ties', () => {
    // DM-02 (line 10) and DM-N2 (line 13) are both within tolerance of line 12.
    const nearNegative = scoreApp(manifest, [report('src/orders.ts', 12, 'authz', { detectors: ['ai'] })])
    expect(nearNegative.reports[0]).toMatchObject({ outcome: 'negative', matchedId: 'DM-N2' })
    // A range covering both lines is a tie (distance 0 to each).
    const tie = scoreApp(manifest, [report('src/orders.ts', 10, 'authz', { endLine: 13, detectors: ['ai'] })])
    expect(tie.reports[0]).toMatchObject({ outcome: 'true-positive', matchedId: 'DM-02' })
  })

  it('counts extra reports of a detected finding as duplicates, not as recall', () => {
    const score = scoreApp(manifest, [
      report('src/db.ts', 20, 'injection'),
      report('src/db.ts', 21, 'injection', { cwe: 'CWE-89', detectors: ['ai'] }),
    ])
    expect(score.totals).toMatchObject({ truePositives: 1, matchedReports: 2, duplicates: 1, falsePositives: 0 })
    expect(score.totals.precision).toBe(1)
    expect(score.expected[0]?.reports).toBe(2)
  })

  it('excludes ruled-out reports from false positives and detections but reports them', () => {
    const score = scoreApp(manifest, [
      report('src/db.ts', 40, 'injection', { closure: 'ruled_out' }),
      report('src/orders.ts', 10, 'authz', { closure: 'ruled_out', detectors: ['ai'] }),
      report('src/nowhere.ts', 1, 'xss', { closure: 'ruled_out' }),
    ])
    expect(score.totals).toMatchObject({
      reports: 0,
      falsePositives: 0,
      negativeHits: 0,
      truePositives: 0,
      precision: null,
      ruledOut: { total: 3, onNegatives: 1, onPlanted: 1, unmatched: 1 },
      verification: { confirmed: 0, needsProof: 0, ruledOut: 3 },
    })
    expect(score.expected.find(row => row.id === 'DM-02')?.status).toBe('ruled-out')
    expect(score.negatives.find(row => row.id === 'DM-N1')).toMatchObject({ hits: 0, ruledOut: 1 })
  })

  it('prefers a live report over a ruled-out one for the same entry', () => {
    const score = scoreApp(manifest, [
      report('src/db.ts', 20, 'injection', { closure: 'ruled_out' }),
      report('src/db.ts', 20, 'injection', { closure: 'confirmed' }),
    ])
    expect(score.expected[0]).toMatchObject({ status: 'detected', reports: 1 })
    expect(score.expected[0]?.match?.closure).toBe('confirmed')
    expect(score.totals.confirmedTruePositives).toBe(1)
  })

  it('ignores reports without a location for matching', () => {
    const { location: _location, ...rest } = report('src/db.ts', 20, 'injection')
    const score = scoreApp(manifest, [rest])
    expect(score.totals).toMatchObject({ truePositives: 0, falsePositives: 1 })
  })

  it('scores each detector against the findings the manifest attributes to it', () => {
    const score = scoreApp(
      manifest,
      [
        report('src/db.ts', 20, 'injection', { detectors: ['sast', 'ai'] }),
        report('src/config.ts', 4, 'secrets', { detectors: ['secrets', 'ai'] }),
        report('src/other.ts', 1, 'xss', { detectors: ['sast'] }),
      ],
      { activeDetectors: ['sast', 'secrets', 'ai'] },
    )
    const by = Object.fromEntries(score.detectors.map(d => [d.detector, d]))
    expect(by.sast).toMatchObject({ active: true, planted: 1, truePositives: 1, reports: 2, falsePositives: 1 })
    expect(by.sast?.precision).toBe(0.5)
    expect(by.secrets).toMatchObject({ planted: 1, truePositives: 1, recall: 1, bonus: 0 })
    // DM-03 is attributed to secrets only, so the AI credit on it is a bonus detection.
    expect(by.ai).toMatchObject({ planted: 2, truePositives: 1, falseNegatives: 1, bonus: 1 })
    expect(by.dependency).toMatchObject({ active: false, planted: 1, truePositives: 0, recall: 0, precision: null })
    expect(score.totals).toMatchObject({ inScope: 3, inScopeTruePositives: 2 })
    expect(score.totals.scopedRecall).toBeCloseTo(2 / 3)
  })

  it('sums app scores and recomputes the rates', () => {
    const a = scoreApp(manifest, [report('src/db.ts', 20, 'injection')])
    const b = scoreApp(manifest, [report('src/other.ts', 1, 'xss'), report('src/config.ts', 4, 'secrets')])
    const total = sumScores([a, b])
    expect(total.totals).toMatchObject({ planted: 8, truePositives: 2, reports: 3, falsePositives: 1 })
    expect(total.totals.recall).toBe(0.25)
    expect(total.totals.precision).toBeCloseTo(2 / 3)
    expect(sumScores([]).totals.recall).toBeNull()
  })
})

describe('detector attribution', () => {
  const base: FindingProvenance = { source: 'sast', createdBy: { role: 'analyzer', analyzer: 'sast' }, evidence: [] }

  it('credits the analyzer that created a finding', () => {
    expect(detectorsOf(base)).toEqual(['sast'])
    expect(detectorsOf({ ...base, source: 'secret', createdBy: { role: 'analyzer', analyzer: 'secrets' } })).toEqual([
      'secrets',
    ])
    expect(detectorsOf({ ...base, source: 'external', createdBy: { role: 'analyzer', analyzer: 'gitleaks' } })).toEqual(
      ['secrets'],
    )
    expect(detectorsOf({ ...base, source: 'dependency', createdBy: { role: 'analyzer', analyzer: 'osv' } })).toEqual([
      'dependency',
    ])
  })

  it('credits AI for hunter findings and for hunter evidence merged into a rule hit', () => {
    expect(detectorsOf({ source: 'ai', createdBy: { role: 'hunter' }, evidence: [] })).toEqual(['ai'])
    expect(detectorsOf({ ...base, evidence: [{ originRole: 'hunter', kind: 'source_span' }] })).toEqual(['sast', 'ai'])
    // A skeptic's confirmation or a hunter's counterevidence is review, not detection.
    expect(
      detectorsOf({
        ...base,
        evidence: [
          { originRole: 'skeptic', kind: 'source_span' },
          { originRole: 'hunter', kind: 'counterevidence' },
        ],
      }),
    ).toEqual(['sast'])
  })

  it('derives the detectors that ran from analyzer statuses', () => {
    const analyzers = [
      { id: 'secrets', available: true },
      { id: 'sast', available: true },
      { id: 'routes', available: true },
      { id: 'osv', available: false },
      { id: 'semgrep', available: false },
    ]
    expect(activeDetectorsOf(analyzers, false)).toEqual(['sast', 'secrets'])
    expect(activeDetectorsOf(analyzers, true)).toEqual(['sast', 'secrets', 'routes', 'ai'])
    expect(activeDetectorsOf([...analyzers, { id: 'osv', available: true }], false)).toEqual([
      'sast',
      'secrets',
      'dependency',
    ])
  })
})
