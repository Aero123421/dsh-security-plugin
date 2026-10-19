import { useState } from 'react'
import type { ScanSummary } from '../../shared/contracts.ts'
import { SEVERITIES } from '../../shared/domain.ts'
import { StatusLabel } from '../components/Badge.tsx'
import { Button } from '../components/Button.tsx'
import { ConfirmDialog } from '../components/ConfirmDialog.tsx'
import { useController, useSecurity, useT } from '../context.tsx'
import { formatDateTime, formatRelative, isFiniteNumber, shortSha } from '../format.ts'
import { useNow, useWorkspaceScans } from '../hooks.ts'
import { AvailabilityGate, EmptyState, ExportMenu, LoadError, Loading } from './shared.tsx'

export function HistoryView() {
  return (
    <AvailabilityGate>
      <HistoryBody />
    </AvailabilityGate>
  )
}

function HistoryBody() {
  const controller = useController()
  const tr = useT()
  const { entry, scans } = useWorkspaceScans()
  const viewScanId = useSecurity(s => s.viewScanId)
  const workspaceId = useSecurity(s => s.workspaceId)
  const hasMore = useSecurity(s => (workspaceId ? s.scansHasMore[workspaceId] === true : false))
  const now = useNow()
  const [deleting, setDeleting] = useState<ScanSummary | undefined>()

  if (!entry.value && entry.status === 'error' && entry.error) {
    return <LoadError error={entry.error} onRetry={() => void controller.refreshScans()} />
  }
  if (!entry.value) return <Loading />
  if (!scans.length) {
    return (
      <EmptyState
        title={tr.t('history.empty')}
        action={
          <Button variant="primary" onClick={() => controller.openNewScan()}>
            {tr.t('page.newScan')}
          </Button>
        }
      />
    )
  }

  const view = (scan: ScanSummary) => {
    controller.viewScan(scan.id)
    controller.setTab(scan.status === 'completed' ? 'findings' : 'overview')
  }

  return (
    <div className="dshsec-history">
      <div className="dshsec-table-wrap">
        <table className="dshsec-table">
          <thead>
            <tr>
              <th scope="col">{tr.t('history.started')}</th>
              <th scope="col">{tr.t('history.mode')}</th>
              <th scope="col">{tr.t('history.status')}</th>
              <th scope="col">{tr.t('history.open')}</th>
              <th scope="col">{tr.t('history.commit')}</th>
              <th scope="col">
                <span className="dshsec-visually-hidden">{tr.t('history.actions')}</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {scans.map(scan => {
              const viewing = viewScanId === scan.id
              const started = scan.startedAt ?? scan.createdAt
              return (
                <tr key={scan.id} className={viewing ? 'is-viewing' : undefined}>
                  <td data-label={tr.t('history.started')}>
                    <time dateTime={started} title={formatDateTime(started, tr.intlLocale)}>
                      {formatRelative(started, tr.intlLocale, now)}
                    </time>
                  </td>
                  <td data-label={tr.t('history.mode')}>
                    {tr.lookup(`mode.${scan.mode}`) ?? '—'}
                    <div className="dshsec-hint">{scan.subpath ?? tr.t('scan.wholeProject')}</div>
                  </td>
                  <td data-label={tr.t('history.status')}>
                    <StatusLabel status={scan.status} />
                    {scan.status === 'completed' && scan.review ? (
                      <div className="dshsec-hint">{tr.t(`review.${scan.review.state}`)}</div>
                    ) : null}
                  </td>
                  <td data-label={tr.t('history.open')}>
                    <OpenCounts scan={scan} />
                  </td>
                  <td data-label={tr.t('history.commit')}>
                    <span className="dshsec-cell-mono">{shortSha(scan.commit)}</span>
                    {scan.dirty ? (
                      <span className="dshsec-dirty" title={tr.t('history.dirty')}>
                        *<span className="dshsec-visually-hidden"> {tr.t('history.dirty')}</span>
                      </span>
                    ) : null}
                  </td>
                  <td className="dshsec-row-actions">
                    <Button
                      size="sm"
                      variant={viewing ? 'ghost' : 'secondary'}
                      disabled={viewing}
                      onClick={() => view(scan)}
                    >
                      {viewing ? tr.t('history.viewing') : tr.t('history.view')}
                    </Button>
                    {scan.status === 'completed' || scan.status === 'failed' || scan.status === 'cancelled' ? (
                      <ExportMenu scanId={scan.id} />
                    ) : null}
                    <Button size="sm" variant="ghost" onClick={() => setDeleting(scan)}>
                      {tr.t('history.delete')}
                    </Button>
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
      {entry.status === 'error' && entry.error ? (
        <LoadError
          error={entry.error}
          onRetry={() => void (hasMore ? controller.loadMoreScans(workspaceId) : controller.refreshScans(workspaceId))}
        />
      ) : hasMore ? (
        <div className="dshsec-actions">
          <Button busy={entry.status === 'loading'} onClick={() => void controller.loadMoreScans(workspaceId)}>
            {tr.t(entry.status === 'loading' ? 'history.loadingMore' : 'history.loadMore')}
          </Button>
        </div>
      ) : null}
      {deleting ? (
        <ConfirmDialog
          title={tr.t('confirmDelete.title')}
          body={tr.t('confirmDelete.body')}
          confirmLabel={tr.t('confirmDelete.confirm')}
          onConfirm={() => controller.deleteScan(deleting.id)}
          onClose={() => setDeleting(undefined)}
        />
      ) : null}
    </div>
  )
}

function OpenCounts(props: { readonly scan: ScanSummary }) {
  const tr = useT()
  const parts = SEVERITIES.map(severity => ({
    severity,
    count: isFiniteNumber(props.scan.counts?.[severity]) ? props.scan.counts[severity] : 0,
  })).filter(p => p.count > 0)
  if (props.scan.status !== 'completed') return <span className="dshsec-muted">—</span>
  if (!parts.length) return <span className="dshsec-muted">{tr.t('history.noOpen')}</span>
  return (
    <span className="dshsec-counts">
      {parts.map(p => (
        <span key={p.severity} className={`dshsec-count dshsec-sev--${p.severity}`}>
          <span className="dshsec-sev-dot" aria-hidden="true" />
          {tr.t('project.count', { count: p.count, severity: tr.t(`severity.${p.severity}`) })}
        </span>
      ))}
    </span>
  )
}
