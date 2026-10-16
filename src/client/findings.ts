/** Client-side finding filtering and ordering (pure; covered by tests). */

import type { FindingSummary } from '../shared/contracts.ts'
import {
  type Closure,
  FINDING_SOURCES,
  type FindingSource,
  SEVERITIES,
  type Severity,
  severityRank,
  type TriageState,
} from '../shared/domain.ts'

export interface FindingsFilter {
  /** Severities to show. */
  readonly severities: readonly Severity[]
  /** Closures to show. Ruled-out findings are hidden by default. */
  readonly closures: readonly Closure[]
  readonly source: FindingSource | 'all'
  /** Triage states to show. Only `open` by default. */
  readonly triage: readonly TriageState[]
  readonly text: string
}

export const CLOSURES: readonly Closure[] = ['confirmed', 'open_proof_gap', 'ruled_out']

export const DEFAULT_FINDINGS_FILTER: FindingsFilter = {
  severities: SEVERITIES,
  closures: ['confirmed', 'open_proof_gap'],
  source: 'all',
  triage: ['open'],
  text: '',
}

const CLOSURE_ORDER: Readonly<Record<Closure, number>> = { confirmed: 0, open_proof_gap: 1, ruled_out: 2 }

/** Most severe first, then most certain, then new, then title. */
export function compareFindings(a: FindingSummary, b: FindingSummary): number {
  return (
    rankOf(a.severity) - rankOf(b.severity) ||
    (CLOSURE_ORDER[a.closure] ?? 3) - (CLOSURE_ORDER[b.closure] ?? 3) ||
    Number(b.isNew) - Number(a.isNew) ||
    String(a.title).localeCompare(String(b.title))
  )
}

function rankOf(severity: Severity): number {
  const rank = severityRank(severity)
  return rank < 0 ? SEVERITIES.length : rank
}

function searchText(finding: FindingSummary): string {
  return [finding.title, finding.summary, finding.location?.path, finding.cwe, finding.ruleId, finding.category]
    .filter((part): part is string => typeof part === 'string')
    .join('\n')
    .toLowerCase()
}

export function matchesText(finding: FindingSummary, query: string): boolean {
  const words = query.trim().toLowerCase().split(/\s+/).filter(Boolean)
  if (!words.length) return true
  const haystack = searchText(finding)
  return words.every(word => haystack.includes(word))
}

// Findings are immutable store snapshots. Weak keys let replaced scans and their
// lowercased search fields be collected rather than retaining them indefinitely.
const searchIndexes = new WeakMap<readonly FindingSummary[], readonly string[]>()
function searchIndex(findings: readonly FindingSummary[]): readonly string[] {
  let index = searchIndexes.get(findings)
  if (!index) {
    index = findings.map(searchText)
    searchIndexes.set(findings, index)
  }
  return index
}

export function filterFindings(findings: readonly FindingSummary[], filter: FindingsFilter): FindingSummary[] {
  const words = filter.text.trim().toLowerCase().split(/\s+/).filter(Boolean)
  const index = words.length ? searchIndex(findings) : undefined
  return findings
    .filter(
      (f, i) =>
        filter.severities.includes(f.severity) &&
        filter.closures.includes(f.closure) &&
        (filter.source === 'all' || f.source === filter.source) &&
        filter.triage.includes(f.triage) &&
        (!index || words.every(word => index[i]!.includes(word))),
    )
    .sort(compareFindings)
}

export function isDefaultFilter(filter: FindingsFilter): boolean {
  const same = <T>(a: readonly T[], b: readonly T[]) => a.length === b.length && a.every(item => b.includes(item))
  return (
    same(filter.severities, DEFAULT_FINDINGS_FILTER.severities) &&
    same(filter.closures, DEFAULT_FINDINGS_FILTER.closures) &&
    filter.source === 'all' &&
    same(filter.triage, DEFAULT_FINDINGS_FILTER.triage) &&
    filter.text.trim() === ''
  )
}

export function toggleIn<T>(list: readonly T[], item: T, order: readonly T[]): T[] {
  const next = list.includes(item) ? list.filter(x => x !== item) : [...list, item]
  return order.filter(x => next.includes(x))
}

export interface CertaintyCounts {
  readonly confirmed: number
  readonly open_proof_gap: number
  readonly ruled_out: number
  readonly isNew: number
}

/** Counts across all findings of a scan, ignoring triage, for the summary. */
export function certaintyCounts(findings: readonly FindingSummary[]): CertaintyCounts {
  let confirmed = 0
  let gap = 0
  let ruledOut = 0
  let isNew = 0
  for (const f of findings) {
    if (f.closure === 'confirmed') confirmed++
    else if (f.closure === 'ruled_out') ruledOut++
    else gap++
    if (f.isNew && f.closure !== 'ruled_out' && f.triage === 'open') isNew++
  }
  return { confirmed, open_proof_gap: gap, ruled_out: ruledOut, isNew }
}

/** Open (untriaged, not ruled out) findings, most important first. */
export function topOpenFindings(findings: readonly FindingSummary[], limit = 5): FindingSummary[] {
  return findings
    .filter(f => f.closure !== 'ruled_out' && f.triage === 'open')
    .sort(compareFindings)
    .slice(0, limit)
}

export { FINDING_SOURCES }
