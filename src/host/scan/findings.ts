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
  type Severity,
  severityRank,
  type Verification,
} from '../../shared/domain.ts'
import type { ChainProposal } from '../agents/roles/chain.ts'
import type { VerifiedCitation } from '../agents/roles/common.ts'
import type { HunterFinding, HunterOutput } from '../agents/roles/hunter.ts'
import type { SkepticOutput } from '../agents/roles/skeptic.ts'
import type { Signal } from '../analysis/types.ts'
import type { AttackStepRecord, EvidenceRecord, FindingRecord, Origin } from '../core/model.ts'
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
 * Insert one finding per reportable signal, skipping fingerprints the scan
 * already has (safe to call again when a scan resumes).
 */
export function recordSignalFindings(
  store: SecurityStore,
  scanId: string,
  signals: readonly Signal[],
  now: () => string,
): { readonly created: number; readonly byFingerprint: Map<string, Signal> } {
  const byFingerprint = new Map<string, Signal>()
  let created = 0
  store.transaction(() => {
    for (const signal of signals) {
      if (!isReportableSignal(signal)) continue
      const fingerprint = signalFingerprint(signal)
      byFingerprint.set(fingerprint, signal)
      if (store.findFindingByFingerprint(scanId, fingerprint)) continue
      const at = now()
      const evidence: EvidenceRecord = {
        id: newId(),
        scanId,
        origin: 'analyzer',
        kind: 'tool_observation',
        trust: 'observed',
        claim: clip(`${signal.ruleId}: ${signal.title}`),
        location: signal.location,
        snippet: signal.snippet,
        quoteCheck: 'match',
        createdAt: at,
      }
      store.insertEvidence(evidence)
      const finding: FindingRecord = {
        id: newId(),
        scanId,
        fingerprint,
        title: clip(signal.title, 200),
        category: signal.category,
        severity: signal.severity,
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
        supportEvidenceIds: [evidence.id],
        counterEvidenceIds: [],
        mergedFingerprints: [],
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
  readonly ruledOut: number
}

/** Persist a hunter's verified output. Findings without any verified quote are discarded. */
export function recordHunterOutput(
  store: SecurityStore,
  ctx: HunterRecordContext,
  output: HunterOutput,
): HunterRecordResult {
  let created = 0
  let merged = 0
  let discarded = 0
  let assessed = 0
  let ruledOut = 0
  store.transaction(() => {
    for (const finding of output.findings) {
      const verifiedSteps = finding.attackPath.filter(step => isQuoteVerified(step.quoteCheck))
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
        overlapping(store.listFindings(ctx.scanId), key.location, finding.category, finding.cwe)
      if (existing) {
        mergeHunterFinding(store, existing, finding, fingerprint, [...evidenceIds, ...defenseIds])
        merged++
        continue
      }
      const at = ctx.now()
      store.insertFinding({
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
      })
      created++
    }

    for (const assessment of output.assessments) {
      const fingerprint = ctx.signalIds.get(assessment.id.trim().toUpperCase())
      if (!fingerprint) continue
      const target = store.findFindingByFingerprint(ctx.scanId, fingerprint)
      if (!target) continue
      assessed++
      const verified = assessment.evidence && isQuoteVerified(assessment.evidence.quoteCheck)
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
        // Without a skeptic later, a hunter's cited defense is the strongest review this finding gets.
        const ruleOut = verified === true && !ctx.willReview(target.severity) && target.verification === 'potential'
        store.updateFinding(target.id, {
          counterEvidenceIds: [...target.counterEvidenceIds, ...evidenceIds],
          ...(ruleOut
            ? {
                verification: 'refuted' as const,
                review: { verdict: 'refuted' as const, reasoning: clip(assessment.reason), model: ctx.model },
              }
            : {}),
        })
        if (ruleOut) ruledOut++
      } else if (evidenceIds.length > 0) {
        store.updateFinding(target.id, { supportEvidenceIds: [...target.supportEvidenceIds, ...evidenceIds] })
      }
    }
  })
  return { created, merged, discarded, assessed, ruledOut }
}

/** Apply an independent review. Refutation and confirmation both need verified code. */
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
    const counterVerified = output.counterevidence.some(c => isQuoteVerified(c.quoteCheck))
    const pathVerified =
      finding.attackPath.some(step => isQuoteVerified(step.quoteCheck)) ||
      output.supporting.some(c => isQuoteVerified(c.quoteCheck))
    let verdict = output.verdict
    let reasoning = output.reasoning
    if (verdict === 'refuted' && !counterVerified) {
      verdict = 'inconclusive'
      reasoning = `${reasoning}\n\n[Host] The reviewer claimed a defense but none of its quotes matched the source, so the finding stays open.`
    }
    if (verdict === 'confirmed' && !pathVerified) {
      verdict = 'inconclusive'
      reasoning = `${reasoning}\n\n[Host] Confirmation requires at least one verified code excerpt on the attack path.`
    }
    const verification: Verification =
      verdict === 'confirmed' ? 'strong_static_evidence' : verdict === 'refuted' ? 'refuted' : 'inconclusive'
    const limitations = [
      ...finding.limitations.filter(l => !l.startsWith('Found by a pattern rule')),
      ...output.missingInformation.map(m => clip(m, 300)),
    ]
    const localized = output.localized
    return store.updateFinding(finding.id, {
      verification,
      ...(output.severity && verdict !== 'refuted' ? { severity: output.severity } : {}),
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
      const parts = chain.findingIds.map(id => ids.get(id.trim().toUpperCase())).filter(f => f !== undefined)
      const key = keyStep(chain.attackPath)
      if (parts.length < 2 || !key?.location || !chain.attackPath.some(s => isQuoteVerified(s.quoteCheck))) {
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

/** The step that best identifies the issue: the last verified one (usually the sink). */
function keyStep(steps: readonly VerifiedCitation[]): VerifiedCitation | undefined {
  for (let i = steps.length - 1; i >= 0; i--) {
    const step = steps[i]
    if (step && isQuoteVerified(step.quoteCheck) && step.location) return step
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
      Math.abs(f.location.startLine - location.startLine) <= 3 &&
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
