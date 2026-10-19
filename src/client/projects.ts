/** What the project picker says about each project, from its last scan and the active scans of all projects. */

import type { ScanSummary, WorkspaceSummary } from '../shared/contracts.ts'
import { SEVERITIES, type Severity } from '../shared/domain.ts'
import { isFiniteNumber } from './format.ts'
import type { Translator } from './i18n.ts'

export interface ProjectStatus {
  readonly text: string
  /** `active` pulses; `severity` colors the dot by the worst open finding. */
  readonly tone: 'active' | 'idle' | 'warn' | 'error' | 'none'
  readonly severity?: Severity
}

/**
 * One short status per project: its queued/running/paused scan if it has
 * one, otherwise the outcome of its last scan ("2 Critical · 5 High",
 * "No open findings", "Interrupted"), or "Not scanned".
 */
export function projectStatus(
  tr: Translator,
  workspace: WorkspaceSummary,
  active: readonly ScanSummary[],
): ProjectStatus {
  const live = active.find(scan => scan.workspaceId === workspace.id)
  if (live) {
    return {
      text: tr.t(
        live.status === 'running' ? 'project.scanning' : live.status === 'paused' ? 'status.paused' : 'status.queued',
      ),
      tone: live.status === 'running' ? 'active' : 'idle',
    }
  }
  const last = workspace.lastScan
  if (!last) return { text: tr.t('project.notScanned'), tone: 'none' }
  if (last.status === 'failed') return { text: tr.t('status.failed'), tone: 'error' }
  if (last.status === 'interrupted') return { text: tr.t('status.interrupted'), tone: 'warn' }
  if (last.status !== 'completed') return { text: tr.lookup(`status.${last.status}`) ?? last.status, tone: 'idle' }
  const counts = SEVERITIES.map(severity => ({
    severity,
    count: isFiniteNumber(last.counts?.[severity]) ? last.counts[severity] : 0,
  })).filter(entry => entry.count > 0)
  if (!counts.length) return { text: tr.t('project.noOpen'), tone: 'none' }
  return {
    text: counts
      .slice(0, 2)
      .map(entry => tr.t('project.count', { count: entry.count, severity: tr.t(`severity.${entry.severity}`) }))
      .join(' · '),
    tone: 'idle',
    severity: counts[0]?.severity,
  }
}

/** Scans ahead of `scan` in the shared queue, the running ones first. */
export function queueAhead(scan: ScanSummary, active: readonly ScanSummary[]): readonly ScanSummary[] {
  const created = Date.parse(scan.createdAt) || 0
  const running = active.filter(other => other.id !== scan.id && other.status === 'running')
  const queued = active.filter(
    other => other.id !== scan.id && other.status === 'queued' && (Date.parse(other.createdAt) || 0) < created,
  )
  return [...running, ...queued]
}
