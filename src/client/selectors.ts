/** Pure derivations over controller state. Components memoize these. */

import type { ScanDetail, ScanSummary } from '../shared/contracts.ts'
import type { ScanStatus } from '../shared/domain.ts'
import { parseDate } from './format.ts'

/** Statuses that change on their own and are worth polling. */
export function isPollableStatus(status: ScanStatus | undefined): boolean {
  return status === 'queued' || status === 'running' || status === 'paused'
}

export function isTerminalStatus(status: ScanStatus | undefined): boolean {
  return status === 'completed' || status === 'failed' || status === 'cancelled'
}

function time(value: string | undefined): number {
  return parseDate(value)?.getTime() ?? 0
}

/** Newest first, tolerating missing dates. */
export function sortScans(scans: readonly ScanSummary[] | undefined): ScanSummary[] {
  if (!Array.isArray(scans)) return []
  return [...scans].sort((a, b) => time(b.createdAt) - time(a.createdAt))
}

/** The scan that should be polled: a running one first, then paused, then queued. */
export function pollableScan(scans: readonly ScanSummary[]): ScanSummary | undefined {
  return (
    scans.find(s => s.status === 'running') ??
    scans.find(s => s.status === 'paused') ??
    scans.find(s => s.status === 'queued')
  )
}

export function latestCompleted(scans: readonly ScanSummary[]): ScanSummary | undefined {
  return scans.find(s => s.status === 'completed')
}

/**
 * What the Overview should feature for a workspace:
 * - `active`: a queued/running/paused scan (progress card),
 * - `problem`: the newest scan failed, was cancelled or was interrupted,
 * - `results`: the completed scan whose summary to show (may accompany the others).
 */
export interface OverviewFocus {
  readonly active?: ScanSummary
  readonly problem?: ScanSummary
  readonly results?: ScanSummary
}

export function overviewFocus(scans: readonly ScanSummary[], viewScanId: string | undefined): OverviewFocus {
  if (viewScanId) {
    const viewed = scans.find(s => s.id === viewScanId)
    if (!viewed) return {}
    if (isPollableStatus(viewed.status)) return { active: viewed }
    if (viewed.status === 'completed') return { results: viewed }
    return { problem: viewed }
  }
  const newest = scans[0]
  const active = pollableScan(scans)
  const results = latestCompleted(scans)
  const problem =
    newest && !active && newest.status !== 'completed' && !isPollableStatus(newest.status) ? newest : undefined
  return { ...(active ? { active } : {}), ...(problem ? { problem } : {}), ...(results ? { results } : {}) }
}

/** Scan whose findings the Findings tab shows. */
export function resultsScan(scans: readonly ScanSummary[], viewScanId: string | undefined): ScanSummary | undefined {
  if (viewScanId) return scans.find(s => s.id === viewScanId)
  return latestCompleted(scans)
}

/** Prefer the fresher status from a polled detail over the list entry. */
export function mergeSummary(list: readonly ScanSummary[], summary: ScanSummary): readonly ScanSummary[] {
  let found = false
  const next = list.map(s => {
    if (s.id !== summary.id) return s
    found = true
    return summary
  })
  return found ? next : [summary, ...list]
}

export function detailStatus(detail: ScanDetail | undefined): ScanStatus | undefined {
  return detail?.summary?.status
}
