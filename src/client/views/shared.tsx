/** Small view pieces shared by several tabs. */

import { type KeyboardEvent, memo, type ReactNode, useState } from 'react'
import type { FindingSummary, ReportFormat, ScanSummary } from '../../shared/contracts.ts'
import { Badge, SeverityLabel, TriageBadge, VerificationLabel } from '../components/Badge.tsx'
import { Button } from '../components/Button.tsx'
import { Callout } from '../components/Callout.tsx'
import { MenuButton } from '../components/Menu.tsx'
import { formatLocation } from '../components/Text.tsx'
import { useController, useSecurity, useT } from '../context.tsx'
import { DASH, formatDateTime } from '../format.ts'
import { useScanAvailability } from '../hooks.ts'
import { errorText } from '../i18n.ts'
import { IconDownload, IconPlus, IconRefresh, IconShield } from '../icons.tsx'
import { AddProjectFolder } from './AddProjectFolder.tsx'

export const REPORT_FORMATS: readonly ReportFormat[] = ['markdown', 'json', 'sarif']

/** "Viewing the scan from <date>" with a way back, when History picked a scan. */
export function ViewingBanner(props: { readonly scan: ScanSummary | undefined }) {
  const controller = useController()
  const tr = useT()
  const viewScanId = useSecurity(s => s.viewScanId)
  if (!viewScanId) return null
  return (
    <Callout
      tone="info"
      className="dshsec-viewing"
      action={
        <Button size="sm" onClick={() => controller.viewScan(undefined)}>
          {tr.t('banner.backToLatest')}
        </Button>
      }
    >
      {tr.t('banner.viewingOld', { date: formatDateTime(props.scan?.createdAt, tr.intlLocale) })}
    </Callout>
  )
}

/** Explains why scanning is impossible, or renders children when it is possible. */
export function AvailabilityGate(props: { readonly children: ReactNode }) {
  const controller = useController()
  const tr = useT()
  const availability = useScanAvailability()
  if (availability === 'unsupported') {
    return <EmptyState title={tr.t('state.noWorkspacesTitle')} body={tr.t('state.noWorkspaceSupport')} />
  }
  if (availability === 'no-workspaces') {
    return (
      <EmptyState
        title={tr.t('state.noWorkspacesTitle')}
        body={tr.t('state.noWorkspacesBody')}
        action={<AddProjectFolder variant="button" onAdded={controller.selectWorkspace} />}
      />
    )
  }
  if (availability === 'loading') return <Loading />
  return <>{props.children}</>
}

/** Centered placeholder in DSH's style: a glyph, one line, at most one sentence and one action. */
export function EmptyState(props: {
  readonly title: string
  readonly body?: ReactNode
  readonly action?: ReactNode
  readonly icon?: ReactNode
}) {
  return (
    <div className="dshsec-empty">
      <span className="dshsec-empty-icon">{props.icon ?? <IconShield size={24} />}</span>
      <h2 className="dshsec-empty-title">{props.title}</h2>
      {props.body ? <p className="dshsec-empty-body">{props.body}</p> : null}
      {props.action ? <div className="dshsec-empty-action">{props.action}</div> : null}
    </div>
  )
}

export function Loading(props: { readonly label?: string }) {
  const tr = useT()
  return (
    <div className="dshsec-loading" role="status">
      <span className="dshsec-spinner" aria-hidden="true" />
      {props.label ?? tr.t('common.loading')}
    </div>
  )
}

export function LoadError(props: {
  readonly error: { code: string; message: string }
  readonly onRetry: () => void
  readonly title?: string
}) {
  const tr = useT()
  return (
    <Callout
      tone="error"
      title={props.title}
      action={
        <Button size="sm" onClick={props.onRetry}>
          {tr.t('common.retry')}
        </Button>
      }
    >
      {errorText(tr, props.error)}
    </Callout>
  )
}

/** A project that has never been scanned. */
export function FirstRun(props: { readonly workspaceId: string | undefined }) {
  const controller = useController()
  const tr = useT()
  const title = useSecurity(s => s.workspaces.value?.find(w => w.id === props.workspaceId)?.title)
  return (
    <EmptyState
      title={tr.t('intro.title')}
      body={tr.t('intro.body', { project: title || tr.t('intro.thisProject') })}
      action={
        <Button
          variant="primary"
          icon={<IconPlus size={16} />}
          onClick={() => controller.openNewScan({ ...(props.workspaceId ? { workspaceId: props.workspaceId } : {}) })}
        >
          {tr.t('page.newScan')}
        </Button>
      }
    />
  )
}

/** One finding in a list: severity, title, then certainty, location and tags on one quiet line. */
export const FindingRow = memo(function FindingRow(props: {
  readonly finding: FindingSummary
  readonly selected?: boolean
  readonly onSelect: (finding: FindingSummary) => void
  /** Roving tabindex: only the active row is in the Tab order. */
  readonly tabIndex?: number
  readonly onKeyDown?: (event: KeyboardEvent<HTMLButtonElement>, finding: FindingSummary) => void
}) {
  const tr = useT()
  const f = props.finding
  const location = formatLocation(f.location)
  return (
    <button
      type="button"
      className={`dshsec-frow${props.selected ? ' is-selected' : ''}${f.closure === 'ruled_out' ? ' is-ruled-out' : ''}`}
      aria-current={props.selected ? 'true' : undefined}
      data-finding-row={f.id}
      tabIndex={props.tabIndex}
      onClick={() => props.onSelect(f)}
      onKeyDown={event => props.onKeyDown?.(event, f)}
    >
      <span className="dshsec-frow-sev">
        <SeverityLabel severity={f.severity} />
      </span>
      <span className="dshsec-frow-main">
        <span className="dshsec-frow-title" title={typeof f.title === 'string' ? f.title : undefined}>
          {typeof f.title === 'string' && f.title ? f.title : DASH}
        </span>
        <span className="dshsec-frow-meta">
          <VerificationLabel verification={f.verification} withTitle={false} />
          <span className="dshsec-frow-loc" title={location}>
            <bdi>{location}</bdi>
          </span>
          {f.isNew ? <Badge tone="brand">{tr.t('findings.new')}</Badge> : null}
          <TriageBadge triage={f.triage} />
        </span>
      </span>
    </button>
  )
})

/** Export menu: one button, three formats. Downloads through the controller. */
export function ExportMenu(props: { readonly scanId: string; readonly size?: 'sm' | 'md' }) {
  const controller = useController()
  const tr = useT()
  const [busy, setBusy] = useState(false)
  const run = async (format: ReportFormat) => {
    setBusy(true)
    const result = await controller.exportReport(props.scanId, format)
    setBusy(false)
    if (!result.ok) controller.flash({ tone: 'error', error: result.error })
  }
  return (
    <MenuButton
      size={props.size ?? 'sm'}
      label={tr.t('export.menu')}
      ariaLabel={tr.t('export.title')}
      icon={<IconDownload size={14} />}
      busy={busy}
      items={REPORT_FORMATS.map(format => ({
        id: format,
        label: tr.t(`export.${format}`),
        onSelect: () => void run(format),
      }))}
    />
  )
}

/** Fallback for a view that threw while rendering unexpected data. */
export function RenderFailure(props: { readonly onRetry: () => void; readonly retryLabel?: string }) {
  const tr = useT()
  return (
    <div className="dshsec-failure">
      <Callout
        tone="error"
        title={tr.t('error.renderTitle')}
        action={
          <Button size="sm" icon={props.retryLabel ? undefined : <IconRefresh size={14} />} onClick={props.onRetry}>
            {props.retryLabel ?? tr.t('common.retry')}
          </Button>
        }
      >
        {tr.t('error.renderBody')}
      </Callout>
    </div>
  )
}
