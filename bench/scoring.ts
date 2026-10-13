/**
 * Scoring of reported findings against fixture ground truth. Pure functions
 * only: `bench/run.ts` feeds them the JSON report of an in-process scan and
 * `bench/score.ts` the JSON report a maintainer exported from DSH, so both
 * paths measure exactly the same thing.
 *
 * Rules (see `bench/README.md` for how to read the numbers):
 * - A report matches a ground-truth entry with {@link matchesExpected}: same
 *   path, the line within the tolerance or inside the reported range, and the
 *   same category or CWE. Each report counts toward at most one entry, the
 *   nearest one (planted findings win ties over negative controls).
 * - Ruled-out reports (refuted by an independent review) are never false
 *   positives and never detections; they are counted on their own.
 * - A planted finding is detected when at least one live report matched it.
 *   Further reports matched to the same entry are duplicates: they are true
 *   reports for precision but add nothing to recall.
 */

import type { Closure } from '../src/shared/domain.ts'
import {
  FIXTURE_DETECTORS,
  type FixtureDetector,
  type FixtureFinding,
  type FixtureManifest,
  type FixtureNegative,
  matchesExpected,
} from './fixtures.ts'

/** One reported finding, reduced to what scoring needs. */
export interface ReportedFinding {
  readonly id: string
  readonly title: string
  readonly category: string
  readonly cwe?: string
  readonly location?: { readonly path: string; readonly startLine: number; readonly endLine: number }
  readonly verification: string
  readonly closure: Closure
  /** Detectors credited with this report (see {@link detectorsOf}). */
  readonly detectors: readonly FixtureDetector[]
}

/** The provenance fields of an exported finding (`FindingDetail`) that decide detector credit. */
export interface FindingProvenance {
  readonly source: string
  readonly createdBy: { readonly role: string; readonly analyzer?: string }
  readonly evidence: readonly { readonly originRole: string; readonly kind: string }[]
}

const ANALYZER_DETECTORS: Readonly<Record<string, FixtureDetector>> = {
  secrets: 'secrets',
  gitleaks: 'secrets',
  sast: 'sast',
  'ast-grep': 'sast',
  semgrep: 'sast',
  routes: 'routes',
  osv: 'dependency',
  'osv-scanner': 'dependency',
}

const SOURCE_DETECTORS: Readonly<Record<string, FixtureDetector>> = {
  secret: 'secrets',
  dependency: 'dependency',
  sast: 'sast',
  ai: 'ai',
}

/**
 * Detectors credited with one report: the analyzer that created it, plus
 * `ai` when an AI hunter or chain researcher cited source evidence for it
 * (an AI finding merged into a rule hit, or a hunter confirming the hit).
 */
export function detectorsOf(finding: FindingProvenance): FixtureDetector[] {
  const out = new Set<FixtureDetector>()
  const byAnalyzer = finding.createdBy.analyzer ? ANALYZER_DETECTORS[finding.createdBy.analyzer] : undefined
  const bySource = SOURCE_DETECTORS[finding.source]
  if (byAnalyzer) out.add(byAnalyzer)
  else if (bySource) out.add(bySource)
  if (finding.createdBy.role === 'hunter' || finding.createdBy.role === 'chain') out.add('ai')
  if (finding.evidence.some(e => (e.originRole === 'hunter' || e.originRole === 'chain') && e.kind === 'source_span'))
    out.add('ai')
  return FIXTURE_DETECTORS.filter(d => out.has(d))
}

/**
 * Detectors that ran in a scan, from its analyzer statuses and whether an AI
 * hunter model was configured. The `dependencies` parser alone finds nothing;
 * dependency findings need OSV. The route extractor creates no findings by
 * itself (it hands endpoints and their auth hints to AI hunters), so `routes`
 * only counts as active when AI review ran.
 */
export function activeDetectorsOf(
  analyzers: readonly { readonly id: string; readonly available: boolean }[],
  aiReview: boolean,
): FixtureDetector[] {
  const out = new Set<FixtureDetector>()
  for (const analyzer of analyzers) {
    const detector = ANALYZER_DETECTORS[analyzer.id]
    if (analyzer.available && detector && (detector !== 'routes' || aiReview)) out.add(detector)
  }
  if (aiReview) out.add('ai')
  return FIXTURE_DETECTORS.filter(d => out.has(d))
}

// ---------------------------------------------------------------------------
// Results
// ---------------------------------------------------------------------------

export type ReportOutcome = 'true-positive' | 'duplicate' | 'negative' | 'false-positive' | 'ruled-out'

export interface ReportRow {
  readonly finding: ReportedFinding
  readonly outcome: ReportOutcome
  /** The ground-truth entry (planted or negative) the report was matched to. */
  readonly matchedId?: string
}

export type ExpectedStatus = 'detected' | 'missed' | 'ruled-out'

export interface ExpectedRow {
  readonly id: string
  readonly title: string
  readonly category: string
  readonly cwe?: string
  readonly path: string
  readonly line: number
  readonly detectableBy: readonly FixtureDetector[]
  readonly status: ExpectedStatus
  /** The strongest live report matched to this entry, or the ruled-out one when no live report matched. */
  readonly match?: ReportedFinding
  /** Live reports matched to this entry. */
  readonly reports: number
}

export interface NegativeRow {
  readonly id: string
  readonly path: string
  readonly line: number
  readonly category: string
  /** Live reports on this negative control (false positives). */
  readonly hits: number
  /** Reports on it that a review correctly ruled out. */
  readonly ruledOut: number
}

export interface DetectorScore {
  readonly detector: FixtureDetector
  /** Whether this detector ran in the scored scan. */
  readonly active: boolean
  /** Planted findings whose manifest lists this detector. */
  readonly planted: number
  /** Of those, detected by a live report credited to this detector. */
  readonly truePositives: number
  readonly falseNegatives: number
  readonly recall: number | null
  /** Live reports credited to this detector. */
  readonly reports: number
  /** Of those, reports matched to a planted finding (duplicates included). */
  readonly matchedReports: number
  readonly falsePositives: number
  readonly negativeHits: number
  readonly precision: number | null
  /** Planted findings the manifest does not attribute to this detector that it detected anyway. */
  readonly bonus: number
}

export interface VerificationBreakdown {
  readonly confirmed: number
  readonly needsProof: number
  readonly ruledOut: number
}

export interface ScoreTotals {
  readonly planted: number
  /** Planted findings at least one active detector is expected to catch. */
  readonly inScope: number
  readonly truePositives: number
  readonly inScopeTruePositives: number
  readonly falseNegatives: number
  /** Detected / planted. */
  readonly recall: number | null
  /** Detected in scope / in scope. */
  readonly scopedRecall: number | null
  /** Reports that were not ruled out. */
  readonly reports: number
  readonly matchedReports: number
  readonly duplicates: number
  /** Live reports matching no planted finding, including those on negative controls. */
  readonly falsePositives: number
  readonly negativeHits: number
  readonly precision: number | null
  /** Every report, ruled-out ones included. */
  readonly verification: VerificationBreakdown
  /** Planted findings detected by at least one confirmed report. */
  readonly confirmedTruePositives: number
  readonly ruledOut: {
    readonly total: number
    /** Correct: the review refuted a report on a negative control. */
    readonly onNegatives: number
    /** Verification loss: the review refuted a report of a real planted finding. */
    readonly onPlanted: number
    readonly unmatched: number
  }
}

export interface ScoreSummary {
  readonly totals: ScoreTotals
  readonly detectors: readonly DetectorScore[]
}

export interface AppScore extends ScoreSummary {
  readonly app: string
  readonly activeDetectors: readonly FixtureDetector[]
  readonly expected: readonly ExpectedRow[]
  readonly negatives: readonly NegativeRow[]
  readonly reports: readonly ReportRow[]
}

export interface ScoreOptions {
  /** Line tolerance for {@link matchesExpected}; default 3. */
  readonly tolerance?: number
  /** Detectors that ran; default all. Only affects `inScope`/`scopedRecall` and the `active` flags. */
  readonly activeDetectors?: readonly FixtureDetector[]
}

// ---------------------------------------------------------------------------
// Scoring
// ---------------------------------------------------------------------------

type Candidate =
  | { readonly kind: 'planted'; readonly entry: FixtureFinding }
  | { readonly kind: 'negative'; readonly entry: FixtureNegative }

const CLOSURE_STRENGTH: Readonly<Record<Closure, number>> = { confirmed: 0, open_proof_gap: 1, ruled_out: 2 }

/** Score one app's reports against its manifest. */
export function scoreApp(
  manifest: Pick<FixtureManifest, 'app' | 'findings' | 'negatives'>,
  findings: readonly ReportedFinding[],
  options: ScoreOptions = {},
): AppScore {
  const tolerance = options.tolerance ?? 3
  const active = new Set(options.activeDetectors ?? FIXTURE_DETECTORS)

  const rows: ReportRow[] = []
  const livePerPlanted = new Map<string, ReportedFinding[]>()
  const ruledOutPerEntry = new Map<string, ReportedFinding[]>()
  const liveNegativeHits = new Map<string, number>()
  for (const finding of findings) {
    const candidate = nearestCandidate(manifest, finding, tolerance)
    const id = candidate?.entry.id
    if (finding.closure === 'ruled_out') {
      if (id) push(ruledOutPerEntry, id, finding)
      rows.push({ finding, outcome: 'ruled-out', ...(id ? { matchedId: id } : {}) })
      continue
    }
    if (candidate?.kind === 'planted') {
      const previous = livePerPlanted.get(candidate.entry.id)
      push(livePerPlanted, candidate.entry.id, finding)
      rows.push({ finding, outcome: previous ? 'duplicate' : 'true-positive', matchedId: candidate.entry.id })
    } else if (candidate?.kind === 'negative') {
      liveNegativeHits.set(candidate.entry.id, (liveNegativeHits.get(candidate.entry.id) ?? 0) + 1)
      rows.push({ finding, outcome: 'negative', matchedId: candidate.entry.id })
    } else {
      rows.push({ finding, outcome: 'false-positive' })
    }
  }

  const expected = manifest.findings.map((entry): ExpectedRow => {
    const live = livePerPlanted.get(entry.id) ?? []
    const refuted = ruledOutPerEntry.get(entry.id) ?? []
    const match = strongest(live) ?? refuted[0]
    return {
      id: entry.id,
      title: entry.title,
      category: entry.category,
      ...(entry.cwe ? { cwe: entry.cwe } : {}),
      path: entry.path,
      line: entry.line,
      detectableBy: entry.detectableBy,
      status: live.length > 0 ? 'detected' : refuted.length > 0 ? 'ruled-out' : 'missed',
      ...(match ? { match } : {}),
      reports: live.length,
    }
  })

  const negatives = manifest.negatives.map(
    (entry): NegativeRow => ({
      id: entry.id,
      path: entry.path,
      line: entry.line,
      category: entry.category,
      hits: liveNegativeHits.get(entry.id) ?? 0,
      ruledOut: ruledOutPerEntry.get(entry.id)?.length ?? 0,
    }),
  )

  const detectors = FIXTURE_DETECTORS.map(detector =>
    detectorScore(detector, active.has(detector), manifest.findings, rows, livePerPlanted),
  )

  const planted = manifest.findings.length
  const inScope = manifest.findings.filter(f => f.detectableBy.some(d => active.has(d)))
  const detected = new Set(expected.filter(row => row.status === 'detected').map(row => row.id))
  const live = rows.filter(row => row.outcome !== 'ruled-out')
  const matchedReports = live.filter(row => row.outcome === 'true-positive' || row.outcome === 'duplicate').length
  const falsePositives = live.length - matchedReports
  const ruledOutRows = rows.filter(row => row.outcome === 'ruled-out')
  const negativeIds = new Set(manifest.negatives.map(n => n.id))
  const onNegatives = ruledOutRows.filter(row => row.matchedId && negativeIds.has(row.matchedId)).length
  const unmatchedRuledOut = ruledOutRows.filter(row => !row.matchedId).length

  const totals: ScoreTotals = {
    planted,
    inScope: inScope.length,
    truePositives: detected.size,
    inScopeTruePositives: inScope.filter(f => detected.has(f.id)).length,
    falseNegatives: planted - detected.size,
    recall: ratio(detected.size, planted),
    scopedRecall: ratio(inScope.filter(f => detected.has(f.id)).length, inScope.length),
    reports: live.length,
    matchedReports,
    duplicates: live.filter(row => row.outcome === 'duplicate').length,
    falsePositives,
    negativeHits: live.filter(row => row.outcome === 'negative').length,
    precision: ratio(matchedReports, live.length),
    verification: verificationOf(findings),
    confirmedTruePositives: [...livePerPlanted.values()].filter(list => list.some(f => f.closure === 'confirmed'))
      .length,
    ruledOut: {
      total: ruledOutRows.length,
      onNegatives,
      onPlanted: ruledOutRows.length - onNegatives - unmatchedRuledOut,
      unmatched: unmatchedRuledOut,
    },
  }

  return {
    app: manifest.app,
    activeDetectors: FIXTURE_DETECTORS.filter(d => active.has(d)),
    totals,
    detectors,
    expected,
    negatives,
    reports: rows,
  }
}

/** Sum several app scores (e.g. every app of one configuration) and recompute the rates. */
export function sumScores(scores: readonly ScoreSummary[]): ScoreSummary {
  const t = (pick: (totals: ScoreTotals) => number) => scores.reduce((n, s) => n + pick(s.totals), 0)
  const planted = t(s => s.planted)
  const inScope = t(s => s.inScope)
  const truePositives = t(s => s.truePositives)
  const inScopeTruePositives = t(s => s.inScopeTruePositives)
  const reports = t(s => s.reports)
  const matchedReports = t(s => s.matchedReports)
  const totals: ScoreTotals = {
    planted,
    inScope,
    truePositives,
    inScopeTruePositives,
    falseNegatives: t(s => s.falseNegatives),
    recall: ratio(truePositives, planted),
    scopedRecall: ratio(inScopeTruePositives, inScope),
    reports,
    matchedReports,
    duplicates: t(s => s.duplicates),
    falsePositives: t(s => s.falsePositives),
    negativeHits: t(s => s.negativeHits),
    precision: ratio(matchedReports, reports),
    verification: {
      confirmed: t(s => s.verification.confirmed),
      needsProof: t(s => s.verification.needsProof),
      ruledOut: t(s => s.verification.ruledOut),
    },
    confirmedTruePositives: t(s => s.confirmedTruePositives),
    ruledOut: {
      total: t(s => s.ruledOut.total),
      onNegatives: t(s => s.ruledOut.onNegatives),
      onPlanted: t(s => s.ruledOut.onPlanted),
      unmatched: t(s => s.ruledOut.unmatched),
    },
  }
  const detectors = FIXTURE_DETECTORS.map((detector): DetectorScore => {
    const parts = scores.map(s => s.detectors.find(d => d.detector === detector)).filter(d => d !== undefined)
    const d = (pick: (score: DetectorScore) => number) => parts.reduce((n, p) => n + pick(p), 0)
    const truePositives = d(p => p.truePositives)
    const planted = d(p => p.planted)
    const detectorReports = d(p => p.reports)
    const matched = d(p => p.matchedReports)
    return {
      detector,
      active: parts.some(p => p.active),
      planted,
      truePositives,
      falseNegatives: d(p => p.falseNegatives),
      recall: ratio(truePositives, planted),
      reports: detectorReports,
      matchedReports: matched,
      falsePositives: d(p => p.falsePositives),
      negativeHits: d(p => p.negativeHits),
      precision: ratio(matched, detectorReports),
      bonus: d(p => p.bonus),
    }
  })
  return { totals, detectors }
}

function detectorScore(
  detector: FixtureDetector,
  active: boolean,
  planted: readonly FixtureFinding[],
  rows: readonly ReportRow[],
  livePerPlanted: ReadonlyMap<string, readonly ReportedFinding[]>,
): DetectorScore {
  const credited = (finding: ReportedFinding) => finding.detectors.includes(detector)
  const claimed = planted.filter(f => f.detectableBy.includes(detector))
  const caught = (f: FixtureFinding) => (livePerPlanted.get(f.id) ?? []).some(credited)
  const truePositives = claimed.filter(caught).length
  const own = rows.filter(row => row.outcome !== 'ruled-out' && credited(row.finding))
  const matchedReports = own.filter(row => row.outcome === 'true-positive' || row.outcome === 'duplicate').length
  return {
    detector,
    active,
    planted: claimed.length,
    truePositives,
    falseNegatives: claimed.length - truePositives,
    recall: ratio(truePositives, claimed.length),
    reports: own.length,
    matchedReports,
    falsePositives: own.length - matchedReports,
    negativeHits: own.filter(row => row.outcome === 'negative').length,
    precision: ratio(matchedReports, own.length),
    bonus: planted.filter(f => !f.detectableBy.includes(detector) && caught(f)).length,
  }
}

/** The matching ground-truth entry nearest to the report, planted findings first on ties. */
function nearestCandidate(
  manifest: Pick<FixtureManifest, 'findings' | 'negatives'>,
  finding: ReportedFinding,
  tolerance: number,
): Candidate | undefined {
  const location = finding.location
  if (!location) return undefined
  const reported = {
    path: location.path,
    startLine: location.startLine,
    endLine: location.endLine,
    category: finding.category,
    ...(finding.cwe ? { cwe: finding.cwe } : {}),
  }
  const candidates: Candidate[] = [
    ...manifest.findings.map(entry => ({ kind: 'planted' as const, entry })),
    ...manifest.negatives.map(entry => ({ kind: 'negative' as const, entry })),
  ].filter(c => matchesExpected(c.entry, reported, tolerance))
  let best: Candidate | undefined
  let bestDistance = Number.POSITIVE_INFINITY
  for (const candidate of candidates) {
    const distance = lineDistance(candidate.entry.line, location.startLine, location.endLine)
    if (distance < bestDistance) {
      best = candidate
      bestDistance = distance
    }
  }
  return best
}

function lineDistance(line: number, startLine: number, endLine: number): number {
  const start = Math.min(startLine, endLine)
  const end = Math.max(startLine, endLine)
  return line >= start && line <= end ? 0 : Math.abs(line - startLine)
}

function verificationOf(findings: readonly ReportedFinding[]): VerificationBreakdown {
  return {
    confirmed: findings.filter(f => f.closure === 'confirmed').length,
    needsProof: findings.filter(f => f.closure === 'open_proof_gap').length,
    ruledOut: findings.filter(f => f.closure === 'ruled_out').length,
  }
}

function strongest(findings: readonly ReportedFinding[]): ReportedFinding | undefined {
  return [...findings].sort((a, b) => CLOSURE_STRENGTH[a.closure] - CLOSURE_STRENGTH[b.closure])[0]
}

function push<T>(map: Map<string, T[]>, key: string, value: T): void {
  const list = map.get(key)
  if (list) list.push(value)
  else map.set(key, [value])
}

/** `part / whole`, or null when `whole` is 0. */
export function ratio(part: number, whole: number): number | null {
  return whole === 0 ? null : part / whole
}
