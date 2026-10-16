/**
 * Turning analyzer signals and verified AI submissions into findings and
 * evidence. Every function here is deterministic given its inputs; the
 * pipeline decides when to call them.
 */

import { randomUUID } from 'node:crypto'
import type { AnalyzerId } from '../../shared/contracts.ts'
import {
  type CodeRef,
  type FindingCategory,
  type FindingSource,
  isQuoteVerified,
  SEVERITIES,
  type Severity,
  severityRank,
  type Verification,
  VERIFICATIONS,
} from '../../shared/domain.ts'
import type { ChainProposal } from '../agents/roles/chain.ts'
import { isVerifiedCode, type VerifiedCitation } from '../agents/roles/common.ts'
import type { HunterFinding, HunterOutput } from '../agents/roles/hunter.ts'
import type { SkepticOutput } from '../agents/roles/skeptic.ts'
import type { Signal } from '../analysis/types.ts'
import type { AttackStepRecord, EvidenceRecord, FindingRecord, FindingReview, Origin } from '../core/model.ts'
import type { SecurityStore } from '../store/types.ts'
import { fingerprintOf, normalizeCode } from './fingerprint.ts'

const MAX_TEXT = 4000

export function newId(): string {
  return randomUUID()
}

export function sourceOfAnalyzer(analyzer: AnalyzerId): FindingSource {
  switch (analyzer) {
    case 'secrets':
      return 'secret'
    case 'osv':
    case 'dependencies':
      return 'dependency'
    case 'sast':
    case 'ast-grep':
    case 'routes':
      return 'sast'
    case 'gitleaks':
    case 'osv-scanner':
    case 'semgrep':
      return 'external'
  }
}

/** Signals that become findings on their own; `sink`/`info` signals only steer AI review. */
export function isReportableSignal(signal: Signal): boolean {
  return signal.kind === 'vulnerability' || signal.kind === 'secret' || signal.kind === 'dependency'
}

export function signalFingerprint(signal: Signal): string {
  return fingerprintOf(['signal', ...signal.fingerprintParts])
}

function initialVerification(signal: Signal): Verification {
  // A high-confidence secret match is directly observed in the source; whether it is live is a limitation.
  return signal.kind === 'secret' && signal.confidence === 'high' ? 'strong_static_evidence' : 'potential'
}

function signalLimitations(signal: Signal): string[] {
  switch (signal.kind) {
    case 'dependency':
      return ['Reachability of the vulnerable code in this project was not analyzed.']
    case 'secret':
      return ['Whether the credential is still valid was not checked; the value itself is never shown.']
    default:
      return ['Found by a pattern rule; the full data flow has not been traced unless an AI review is attached.']
  }
}

/**
 * Merge generic secret hits only when a specific credential rule covers the
 * same sensitive span. Never use the hunter's range-overlap heuristic here:
 * adjacent credentials and unrelated findings must remain independent.
 */
function signalGroups(signals: readonly Signal[]): { primary: Signal; duplicates: Signal[] }[] {
  const reportable = signals.filter(isReportableSignal)
  const groups = new Map(reportable.map(signal => [signal, { primary: signal, duplicates: [] as Signal[] }]))
  const specific = reportable
    .filter(
      signal =>
        (signal.analyzer === 'secrets' && signal.ruleId !== 'generic-secret' && signal.ruleId !== 'env-secret') ||
        (signal.analyzer === 'sast' && signal.cwe === 'CWE-798'),
    )
    .sort((a, b) => severityRank(a.severity) - severityRank(b.severity) || a.ruleId.localeCompare(b.ruleId))
  for (const generic of reportable) {
    if (generic.analyzer !== 'secrets' || generic.ruleId !== 'generic-secret') continue
    const start = generic.metadata?.secretStart
    const end = generic.metadata?.secretEnd
    if (typeof start !== 'number' || typeof end !== 'number' || end <= start) continue
    const primary = specific.find(signal => {
      const from = signal.metadata?.secretStart
      const to = signal.metadata?.secretEnd
      return (
        signal.location.path === generic.location.path &&
        typeof from === 'number' &&
        typeof to === 'number' &&
        from <= start &&
        to >= end
      )
    })
    if (!primary) continue
    groups.get(primary)!.duplicates.push(generic)
    groups.delete(generic)
  }
  return [...groups.values()]
}

/**
 * Insert reportable signals, coalescing generic/specific secret duplicates and
 * skipping fingerprints the scan already has (safe when a scan resumes).
 */
export function recordSignalFindings(
  store: SecurityStore,
  scanId: string,
  signals: readonly Signal[],
  now: () => string,
): { readonly created: number; readonly byFingerprint: Map<string, Signal> } {
  const byFingerprint = new Map(signals.filter(isReportableSignal).map(signal => [signalFingerprint(signal), signal]))
  let created = 0
  store.transaction(() => {
    for (const { primary: signal, duplicates } of signalGroups(signals)) {
      const fingerprint = signalFingerprint(signal)
      if (store.findFindingByFingerprint(scanId, fingerprint)) continue
      const at = now()
      const supporting = [signal, ...duplicates]
      const evidenceIds = supporting.map(observation => {
        const evidence: EvidenceRecord = {
          id: newId(),
          scanId,
          origin: 'analyzer',
          kind: 'tool_observation',
          trust: 'observed',
          claim: clip(`${observation.ruleId}: ${observation.title}`),
          location: observation.location,
          snippet: observation.snippet,
          quoteCheck: 'match',
          createdAt: at,
        }
        store.insertEvidence(evidence)
        return evidence.id
      })
      const finding: FindingRecord = {
        id: newId(),
        scanId,
        fingerprint,
        title: clip(signal.title, 200),
        category: signal.category,
        severity: supporting.reduce(
          (severity, observation) =>
            severityRank(observation.severity) < severityRank(severity) ? observation.severity : severity,
          signal.severity,
        ),
        verification: initialVerification(signal),
        source: sourceOfAnalyzer(signal.analyzer),
        ...(signal.cwe ? { cwe: signal.cwe } : {}),
        ruleId: signal.ruleId,
        location: signal.location,
        summary: clip(firstSentences(signal.message, 2), 700),
        impact: clip(signal.message),
        preconditions: [],
        attackPath: [
          {
            order: 1,
            description: clip(signal.title, 500),
            location: signal.location,
            snippet: signal.snippet,
            quoteCheck: 'match',
          },
        ],
        recommendation: clip(signal.recommendation ?? ''),
        limitations: signalLimitations(signal),
        references: [...(signal.references ?? [])].slice(0, 8),
        createdBy: { role: 'analyzer', analyzer: signal.analyzer },
        supportEvidenceIds: evidenceIds,
        counterEvidenceIds: [],
        mergedFingerprints: [...new Set(duplicates.map(signalFingerprint))],
        isNew: false,
        createdAt: at,
        updatedAt: at,
      }
      store.insertFinding(finding)
      created++
    }
  })
  return { created, byFingerprint }
}

export interface HunterRecordContext {
  readonly scanId: string
  readonly taskId: string
  readonly agentRunId: string
  readonly model: string
  readonly now: () => string
  /** Signal ids shown in the task (`S1` …) → finding fingerprints. */
  readonly signalIds: ReadonlyMap<string, string>
  /** Whether a skeptic will review a finding of this severity later in this scan. */
  readonly willReview: (severity: Severity) => boolean
}

export interface HunterRecordResult {
  readonly created: number
  readonly merged: number
  readonly discarded: number
  readonly assessed: number
  /**
   * Rule hits a hunter called false positives with verified code while no
   * reviewer will follow: they are moved to `inconclusive`, not `refuted`.
   */
  readonly disputed: number
}

/**
 * Persist a hunter's verified output. Findings without any verified code quote are
 * discarded. A `false_positive` verdict on a rule hit never refutes it: the
 * cited defense is attached as counter-evidence and, when no reviewer will
 * follow and the defense is verified code (not only comments), the finding
 * becomes `inconclusive` with the hunter's reason recorded as a limitation.
 */
export function recordHunterOutput(
  store: SecurityStore,
  ctx: HunterRecordContext,
  output: HunterOutput,
): HunterRecordResult {
  let created = 0
  let merged = 0
  let discarded = 0
  let assessed = 0
  let disputed = 0
  store.transaction(() => {
    // Keep a transaction-local, ordered view. Point refreshes after updates preserve
    // same-batch overlap precedence without decoding/sorting the entire table per item.
    const findings = store.listFindings(ctx.scanId)
    const cache = (finding: FindingRecord): void => {
      const old = findings.findIndex(item => item.id === finding.id)
      if (old >= 0) findings.splice(old, 1)
      let low = 0
      let high = findings.length
      while (low < high) {
        const mid = (low + high) >>> 1
        if (compareCachedFindings(findings[mid]!, finding) <= 0) low = mid + 1
        else high = mid
      }
      findings.splice(low, 0, finding)
    }
    for (const finding of output.findings) {
      const verifiedSteps = finding.attackPath.filter(isVerifiedCode)
      const key = keyStep(finding.attackPath)
      if (verifiedSteps.length === 0 || !key?.location) {
        discarded++
        continue
      }
      const evidenceIds = insertCitations(store, ctx, 'hunter', 'source_span', finding.attackPath)
      const defenseIds = insertCitations(store, ctx, 'hunter', 'source_span', finding.defenses, 'Checked defense: ')
      const fingerprint = fingerprintOf([
        'ai',
        finding.category,
        finding.cwe ?? '',
        key.location.path,
        normalizeCode(key.quote),
      ])
      const existing =
        store.findFindingByFingerprint(ctx.scanId, fingerprint) ??
        overlapping(findings, key.location, finding.category, finding.cwe)
      if (existing) {
        mergeHunterFinding(store, existing, finding, fingerprint, [...evidenceIds, ...defenseIds])
        const updated = store.getFinding(ctx.scanId, existing.id)
        if (updated) cache(updated)
        merged++
        continue
      }
      const at = ctx.now()
      const record: FindingRecord = {
        id: newId(),
        scanId: ctx.scanId,
        fingerprint,
        title: clip(finding.title, 200),
        category: finding.category,
        severity: finding.severity,
        verification: 'potential',
        source: 'ai',
        ...(finding.cwe ? { cwe: finding.cwe } : {}),
        location: key.location,
        summary: clip(finding.summary, 700),
        impact: clip(finding.impact),
        preconditions: finding.preconditions.map(p => clip(p, 300)),
        attackPath: toSteps(finding.attackPath),
        recommendation: clip(finding.recommendation),
        limitations: unverifiedNote(finding.attackPath),
        references: [...finding.references],
        createdBy: { role: 'hunter', model: ctx.model },
        supportEvidenceIds: [...evidenceIds, ...defenseIds],
        counterEvidenceIds: [],
        mergedFingerprints: [],
        isNew: false,
        createdAt: at,
        updatedAt: at,
      }
      store.insertFinding(record)
      cache(record)
      created++
    }

    for (const assessment of output.assessments) {
      const fingerprint = ctx.signalIds.get(assessment.id.trim().toUpperCase())
      if (!fingerprint) continue
      const target =
        store.findFindingByFingerprint(ctx.scanId, fingerprint) ??
        findings.find(finding => finding.mergedFingerprints.includes(fingerprint))
      if (!target) continue
      assessed++
      const evidenceIds = assessment.evidence
        ? insertCitations(
            store,
            ctx,
            'hunter',
            assessment.verdict === 'false_positive' ? 'counterevidence' : 'source_span',
            [assessment.evidence],
            `${assessment.reason} — `,
          )
        : []
      if (assessment.verdict === 'false_positive') {
        // A hunter never rules out a rule hit on its own: with a reviewer later, the reviewer decides; without one,
        // a defense backed by verified code leaves the finding open as inconclusive, never refuted.
        const verifiedDefense = assessment.evidence !== undefined && isVerifiedCode(assessment.evidence)
        const dispute = verifiedDefense && !ctx.willReview(target.severity) && target.verification === 'potential'
        store.updateFinding(target.id, {
          counterEvidenceIds: [...target.counterEvidenceIds, ...evidenceIds],
          ...(dispute
            ? {
                verification: 'inconclusive' as const,
                limitations: dedupe([
                  ...target.limitations,
                  clip(
                    `An AI hunter assessed this rule hit as a false positive (${assessment.reason.trim()}), but no independent review confirmed the cited defense, so it stays open.`,
                    600,
                  ),
                ]).slice(0, 10),
              }
            : {}),
        })
        if (dispute) disputed++
      } else if (evidenceIds.length > 0) {
        store.updateFinding(target.id, { supportEvidenceIds: [...target.supportEvidenceIds, ...evidenceIds] })
      }
      const updated = store.getFinding(ctx.scanId, target.id)
      if (updated) cache(updated)
    }
  })
  return { created, merged, discarded, assessed, disputed }
}

/**
 * Apply an independent review. Refutation needs verified counter-evidence
 * that is code, not only comments; confirmation needs verified code. A
 * severity correction applies only to a confirmed verdict with verified
 * supporting code, and lowers a deterministic critical/high rule hit by at
 * most one level; the original severity is noted in the review reasoning.
 */
export function applySkepticOutput(
  store: SecurityStore,
  finding: FindingRecord,
  output: SkepticOutput,
  ctx: {
    readonly scanId: string
    readonly taskId: string
    readonly agentRunId: string
    readonly model: string
    readonly now: () => string
  },
): FindingRecord {
  return store.transaction(() => {
    const counterIds = insertCitations(store, ctx, 'skeptic', 'counterevidence', output.counterevidence)
    const supportIds = insertCitations(store, ctx, 'skeptic', 'source_span', output.supporting)
    const counterVerified = output.counterevidence.some(isVerifiedCode)
    const supportVerified = output.supporting.some(isVerifiedCode)
    const pathVerified = finding.attackPath.some(isVerifiedCode) || supportVerified
    let verdict = output.verdict
    let reasoning = output.reasoning
    if (verdict === 'refuted' && !counterVerified) {
      verdict = 'inconclusive'
      reasoning = output.counterevidence.some(c => isQuoteVerified(c.quoteCheck))
        ? `${reasoning}\n\n[Host] The reviewer's matching counter-evidence is non-code evidence (comments, literal text, punctuation, or comment-led excerpts), which does not prove a defense, so the finding stays open.`
        : `${reasoning}\n\n[Host] The reviewer claimed a defense but none of its quotes matched the source, so the finding stays open.`
    }
    if (verdict === 'confirmed' && !pathVerified) {
      verdict = 'inconclusive'
      reasoning = `${reasoning}\n\n[Host] Confirmation requires at least one verified code excerpt on the attack path.`
    }
    const verification: Verification =
      verdict === 'confirmed' ? 'strong_static_evidence' : verdict === 'refuted' ? 'refuted' : 'inconclusive'
    const severity = reviewedSeverity(finding, output.severity, verdict, supportVerified)
    if (severity.note) reasoning = `${reasoning}\n\n${severity.note}`
    const limitations = [
      ...finding.limitations.filter(l => !l.startsWith('Found by a pattern rule')),
      ...output.missingInformation.map(m => clip(m, 300)),
    ]
    const localized = output.localized
    return store.updateFinding(finding.id, {
      verification,
      ...(severity.applied ? { severity: severity.applied } : {}),
      review: {
        verdict,
        reasoning: clip(reasoning),
        model: ctx.model,
        ...(output.severity ? { severityAdjustment: output.severity } : {}),
      },
      supportEvidenceIds: [...finding.supportEvidenceIds, ...supportIds],
      counterEvidenceIds: [...finding.counterEvidenceIds, ...counterIds],
      limitations: dedupe(limitations).slice(0, 10),
      ...(localized
        ? {
            title: clip(localized.title, 200),
            summary: clip(localized.summary, 700),
            impact: clip(localized.impact),
            recommendation: clip(localized.recommendation),
          }
        : {}),
    })
  })
}

/** Store verified chains as new AI findings that reference their parts. */
export function recordChains(
  store: SecurityStore,
  chains: readonly ChainProposal[],
  ids: ReadonlyMap<string, FindingRecord>,
  ctx: {
    readonly scanId: string
    readonly taskId: string
    readonly agentRunId: string
    readonly model: string
    readonly now: () => string
  },
): { readonly created: number; readonly discarded: number } {
  let created = 0
  let discarded = 0
  store.transaction(() => {
    for (const chain of chains) {
      // Distinct parts only: citing one finding twice is not a chain.
      const parts = [
        ...new Set(chain.findingIds.map(id => ids.get(id.trim().toUpperCase())).filter(f => f !== undefined)),
      ]
      const key = keyStep(chain.attackPath)
      if (parts.length < 2 || !key?.location || !chain.attackPath.some(isVerifiedCode)) {
        discarded++
        continue
      }
      const fingerprint = fingerprintOf(['chain', ...parts.map(p => p.fingerprint).sort()])
      if (store.findFindingByFingerprint(ctx.scanId, fingerprint)) continue
      const evidenceIds = insertCitations(store, ctx, 'chain', 'source_span', chain.attackPath)
      const at = ctx.now()
      store.insertFinding({
        id: newId(),
        scanId: ctx.scanId,
        fingerprint,
        title: clip(chain.title, 200),
        category: chain.category,
        severity: chain.severity,
        verification: 'potential',
        source: 'ai',
        ...(chain.cwe ? { cwe: chain.cwe } : {}),
        location: key.location,
        summary: clip(chain.summary, 700),
        impact: clip(chain.impact),
        preconditions: [],
        attackPath: toSteps(chain.attackPath),
        recommendation: clip(chain.recommendation),
        limitations: [`Combines: ${parts.map(p => p.title).join(' + ')}`, ...unverifiedNote(chain.attackPath)].map(l =>
          clip(l, 600),
        ),
        references: [],
        createdBy: { role: 'chain', model: ctx.model },
        supportEvidenceIds: evidenceIds,
        counterEvidenceIds: [],
        mergedFingerprints: [],
        isNew: false,
        createdAt: at,
        updatedAt: at,
      })
      created++
    }
  })
  return { created, discarded }
}

/** Mark findings whose fingerprints were absent from the previous completed scan. */
export function markNewFindings(store: SecurityStore, scanId: string, previous: ReadonlySet<string> | undefined): void {
  store.transaction(() => {
    for (const finding of store.listFindings(scanId)) {
      const isNew =
        previous !== undefined &&
        !previous.has(finding.fingerprint) &&
        !finding.mergedFingerprints.some(fp => previous.has(fp))
      if (finding.isNew !== isNew) store.updateFinding(finding.id, { isNew })
    }
  })
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Rule-hit sources: their severity comes from a deterministic rule, not a model. */
const DETERMINISTIC_SOURCES: ReadonlySet<FindingSource> = new Set(['secret', 'dependency', 'sast', 'external'])

/**
 * The severity a review may set, with a host note for the reasoning. Nothing
 * changes unless the final verdict is `confirmed` with verified supporting
 * code. A deterministic critical/high rule hit drops one level at most. A
 * refuted finding's severity is moot, so it gets no note.
 */
function reviewedSeverity(
  finding: FindingRecord,
  proposed: Severity | undefined,
  verdict: FindingReview['verdict'],
  supportVerified: boolean,
): { readonly applied?: Severity; readonly note?: string } {
  if (proposed === undefined || proposed === finding.severity || verdict === 'refuted') return {}
  if (verdict !== 'confirmed' || !supportVerified) {
    return {
      note: `[Host] The suggested severity (${proposed}) was not applied: a severity change needs a confirmed verdict with verified supporting code. Severity stays ${finding.severity}.`,
    }
  }
  const from = severityRank(finding.severity)
  const capped =
    DETERMINISTIC_SOURCES.has(finding.source) && from <= severityRank('high') && severityRank(proposed) > from + 1
  const applied = capped ? (SEVERITIES[from + 1] ?? proposed) : proposed
  return {
    applied,
    note: `[Host] Severity changed from ${finding.severity} (original) to ${applied}${capped ? `; the reviewer suggested ${proposed}, but a deterministic ${finding.severity} rule hit is lowered by at most one level per review` : ''}.`,
  }
}

/** The step that best identifies the issue: the last verified code step (usually the sink). */
function keyStep(steps: readonly VerifiedCitation[]): VerifiedCitation | undefined {
  for (let i = steps.length - 1; i >= 0; i--) {
    const step = steps[i]
    if (step && isVerifiedCode(step) && step.location) return step
  }
  return undefined
}

function toSteps(steps: readonly VerifiedCitation[]): AttackStepRecord[] {
  return steps.map((step, index) => ({
    order: index + 1,
    description: clip(step.description, 600),
    ...(step.location ? { location: step.location } : {}),
    quote: clip(step.quote, 1200),
    ...(step.snippet ? { snippet: step.snippet } : {}),
    quoteCheck: step.quoteCheck,
    ...(step.commentOnly ? { commentOnly: true } : {}),
  }))
}

function unverifiedNote(steps: readonly VerifiedCitation[]): string[] {
  const unverified = steps.filter(step => !isQuoteVerified(step.quoteCheck)).length
  return unverified === 0
    ? []
    : [
        `${unverified} of ${steps.length} attack-path steps could not be matched to the source and are shown unverified.`,
      ]
}

function insertCitations(
  store: SecurityStore,
  ctx: { readonly scanId: string; readonly taskId: string; readonly agentRunId: string; readonly now: () => string },
  origin: Origin,
  kind: EvidenceRecord['kind'],
  citations: readonly VerifiedCitation[],
  prefix = '',
): string[] {
  const ids: string[] = []
  for (const citation of citations) {
    const record: EvidenceRecord = {
      id: newId(),
      scanId: ctx.scanId,
      taskId: ctx.taskId,
      agentRunId: ctx.agentRunId,
      origin,
      kind,
      trust: 'inferred',
      claim: clip(prefix + citation.description, 1200),
      ...(citation.location ? { location: citation.location } : {}),
      quote: clip(citation.quote, 1200),
      ...(citation.snippet ? { snippet: citation.snippet } : {}),
      quoteCheck: citation.quoteCheck,
      createdAt: ctx.now(),
    }
    store.insertEvidence(record)
    ids.push(record.id)
  }
  return ids
}

/** Same order as SecurityStore.listFindings: overlap ties must keep their existing precedence. */
function compareCachedFindings(a: FindingRecord, b: FindingRecord): number {
  const text = (x: string, y: string) => (x < y ? -1 : x > y ? 1 : 0)
  return (
    severityRank(a.severity) - severityRank(b.severity) ||
    VERIFICATIONS.indexOf(a.verification) - VERIFICATIONS.indexOf(b.verification) ||
    text(a.title, b.title) ||
    text(a.id, b.id)
  )
}

/** An existing finding for the same place and kind of issue. */
function overlapping(
  findings: readonly FindingRecord[],
  location: CodeRef,
  category: FindingCategory,
  cwe: string | undefined,
): FindingRecord | undefined {
  return findings.find(
    f =>
      f.location !== undefined &&
      f.location.path === location.path &&
      f.source !== 'dependency' &&
      f.source !== 'secret' &&
      f.location.startLine <= location.endLine &&
      location.startLine <= f.location.endLine &&
      (f.category === category || (cwe !== undefined && f.cwe === cwe)),
  )
}

function mergeHunterFinding(
  store: SecurityStore,
  existing: FindingRecord,
  finding: HunterFinding,
  fingerprint: string,
  evidenceIds: readonly string[],
): void {
  const mergedFingerprints =
    fingerprint === existing.fingerprint || existing.mergedFingerprints.includes(fingerprint)
      ? existing.mergedFingerprints
      : [...existing.mergedFingerprints, fingerprint]
  // A rule hit gains the hunter's narrative and attack path; an AI finding keeps its own text.
  const enrich = existing.source !== 'ai' && existing.attackPath.length <= 1
  store.updateFinding(existing.id, {
    mergedFingerprints,
    supportEvidenceIds: [...existing.supportEvidenceIds, ...evidenceIds],
    ...(severityRank(finding.severity) < severityRank(existing.severity) ? { severity: finding.severity } : {}),
    ...(enrich
      ? {
          title: clip(finding.title, 200),
          summary: clip(finding.summary, 700),
          impact: clip(finding.impact),
          preconditions: finding.preconditions.map(p => clip(p, 300)),
          attackPath: toSteps(finding.attackPath),
          recommendation: clip(finding.recommendation),
          limitations: existing.limitations.filter(l => !l.startsWith('Found by a pattern rule')),
        }
      : {}),
  })
}

function firstSentences(text: string, count: number): string {
  const parts = text.split(/(?<=[.!?。])\s+/)
  return parts.slice(0, count).join(' ')
}

function clip(text: string, max = MAX_TEXT): string {
  return text.length <= max ? text : `${text.slice(0, max - 1)}…`
}

function dedupe(items: readonly string[]): string[] {
  return [...new Set(items)]
}
