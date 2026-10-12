/**
 * Domain vocabulary shared by the Host and the browser. Everything here is
 * plain data and pure functions so both builds can import it.
 */

export const SCAN_MODES = ['quick', 'deep', 'research'] as const
export type ScanMode = (typeof SCAN_MODES)[number]

export const SCAN_STATUSES = ['queued', 'running', 'paused', 'completed', 'failed', 'cancelled', 'interrupted'] as const
export type ScanStatus = (typeof SCAN_STATUSES)[number]

/** Scans that still own work and may be paused, resumed, or cancelled. */
export function isActiveScanStatus(status: ScanStatus): boolean {
  return status === 'queued' || status === 'running' || status === 'paused' || status === 'interrupted'
}

/** Ordered pipeline phases. A scan records the last phase it entered. */
export const SCAN_PHASES = [
  'snapshot',
  'inventory',
  'deterministic',
  'surface',
  'threat-model',
  'hunt',
  'review',
  'chain',
  'reconcile',
  'report',
  'done',
] as const
export type ScanPhase = (typeof SCAN_PHASES)[number]

export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const
export type Severity = (typeof SEVERITIES)[number]

/** Lower rank means more severe; use for sorting. */
export function severityRank(severity: Severity): number {
  return SEVERITIES.indexOf(severity)
}

/** Whether `severity` is at least as severe as `threshold`. */
export function severityAtLeast(severity: Severity, threshold: Severity): boolean {
  return severityRank(severity) <= severityRank(threshold)
}

/**
 * How strongly a finding is established. Severity and verification are
 * independent axes (ADR-11): a critical issue can still be only `potential`.
 *
 * - `proven_dynamic`: reproduced in an isolated environment. Code-only scans
 *   never assign it.
 * - `strong_static_evidence`: a reachable code path and its preconditions were
 *   confirmed against host-verified source quotes, and an independent review
 *   found no effective defense.
 * - `potential`: a hypothesis or a deterministic signal that nobody confirmed.
 * - `inconclusive`: review could neither confirm nor refute it.
 * - `refuted`: an independent review cited a concrete, host-verified defense.
 */
export const VERIFICATIONS = [
  'proven_dynamic',
  'strong_static_evidence',
  'potential',
  'inconclusive',
  'refuted',
] as const
export type Verification = (typeof VERIFICATIONS)[number]

/** Closure is derived from verification so the two can never disagree. */
export type Closure = 'confirmed' | 'open_proof_gap' | 'ruled_out'

export function closureOf(verification: Verification): Closure {
  switch (verification) {
    case 'proven_dynamic':
    case 'strong_static_evidence':
      return 'confirmed'
    case 'refuted':
      return 'ruled_out'
    case 'potential':
    case 'inconclusive':
      return 'open_proof_gap'
  }
}

/** Where a finding came from. */
export const FINDING_SOURCES = ['secret', 'dependency', 'sast', 'ai', 'external'] as const
export type FindingSource = (typeof FINDING_SOURCES)[number]

/** Coarse categories used for grouping and filtering in the UI. */
export const FINDING_CATEGORIES = [
  'injection',
  'authz',
  'authn',
  'secrets',
  'dependency',
  'crypto',
  'ssrf',
  'xss',
  'path-traversal',
  'deserialization',
  'command-execution',
  'business-logic',
  'race-condition',
  'misconfiguration',
  'data-exposure',
  'other',
] as const
export type FindingCategory = (typeof FINDING_CATEGORIES)[number]

/** The user's own disposition of a finding; carried across scans by fingerprint. */
export const TRIAGE_STATES = ['open', 'accepted_risk', 'false_positive', 'fixed'] as const
export type TriageState = (typeof TRIAGE_STATES)[number]

/** LLM worker roles. Each role can use its own model. */
export const ROLE_NAMES = ['planner', 'hunter', 'skeptic', 'chain'] as const
export type RoleName = (typeof ROLE_NAMES)[number]

export const EVIDENCE_KINDS = [
  'tool_observation',
  'source_span',
  'hypothesis',
  'counterevidence',
  'threat_model',
  'test_result',
] as const
export type EvidenceKind = (typeof EVIDENCE_KINDS)[number]

/** `observed`: produced by deterministic code. `inferred`: produced by a model. */
export type EvidenceTrust = 'observed' | 'inferred'

/**
 * Result of the Host checking a model-cited quote against the snapshot.
 * `match`: found at the cited lines. `relocated`: found exactly once elsewhere
 * in the same file and the lines were corrected. `mismatch`: not found.
 * `stale`: the file changed after the snapshot. `unchecked`: nothing to check.
 */
export type QuoteCheck = 'match' | 'relocated' | 'mismatch' | 'stale' | 'unchecked'

export function isQuoteVerified(check: QuoteCheck): boolean {
  return check === 'match' || check === 'relocated'
}

export interface CodeRef {
  /** Workspace-relative POSIX path. */
  readonly path: string
  /** 1-based inclusive line range. */
  readonly startLine: number
  readonly endLine: number
}

export function formatCodeRef(ref: CodeRef): string {
  return ref.startLine === ref.endLine ? `${ref.path}:${ref.startLine}` : `${ref.path}:${ref.startLine}-${ref.endLine}`
}
