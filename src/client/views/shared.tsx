/** Small view pieces shared by several tabs. */

import { type KeyboardEvent, memo, type ReactNode, useState } from 'react'
import type { FindingSummary, ReportFormat, ScanSummary } from '../../shared/contracts.ts'
import type { ScanMode } from '../../shared/domain.ts'
import { Badge, SeverityBadge, TriageBadge, VerificationBadge } from '../components/Badge.tsx'
import { Button } from '../components/Button.tsx'
import { Callout } from '../components/Callout.tsx'
import { MenuButton } from '../components/Menu.tsx'
import { formatLocation } from '../components/Text.tsx'
import { useController, useSecurity, useT } from '../context.tsx'
import { DASH, formatDateTime } from '../format.ts'
import { useScanAvailability } from '../hooks.ts'
import { errorText } from '../i18n.ts'
import { IconDownload, IconRefresh } from '../icons.tsx'
import { ModeCards } from './NewScanDialog.tsx'

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
  const tr = useT()
  const availability = useScanAvailability()
  if (availability === 'unsupported') {
    return (
      <EmptyState title={tr.t('state.noWorkspacesTitle')}>
        <p>{tr.t('state.noWorkspaceSupport')}</p>
      </EmptyState>
    )
  }
  if (availability === 'no-workspaces') {
    return (
      <EmptyState title={tr.t('state.noWorkspacesTitle')}>
        <p>{tr.t('state.noWorkspacesBody')}</p>
      </EmptyState>
    )
  }
  if (availability === 'loading') return <Loading />
  return <>{props.children}</>
}

export function EmptyState(props: {
  readonly title: string
  readonly children?: ReactNode
  readonly action?: ReactNode
}) {
  return (
    <div className="dshsec-empty">
      <h2 className="dshsec-h2">{props.title}</h2>
      <div className="dshsec-empty-body">{props.children}</div>
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

/** First-run explanation with the three depth choices and a Start button. */
export function FirstRun(props: { readonly workspaceId: string | undefined }) {
  const controller = useController()
  const tr = useT()
  const defaultMode = useSecurity(s => s.bootstrap.value?.settings?.scan?.defaultMode) ?? 'deep'
  const [mode, setMode] = useState<ScanMode>(defaultMode)
  return (
    <section className="dshsec-intro" aria-labelledby="dshsec-intro-title">
      <h2 className="dshsec-intro-title" id="dshsec-intro-title">
        {tr.t('intro.title')}
      </h2>
      <p className="dshsec-intro-body">{tr.t('intro.body')}</p>
      <div className="dshsec-leaves">
        <h3 className="dshsec-h3">{tr.t('intro.leavesTitle')}</h3>
        <ul className="dshsec-list">
          <li>{tr.t('intro.leaves1')}</li>
          <li>{tr.t('intro.leaves2')}</li>
          <li>{tr.t('intro.leaves3')}</li>
        </ul>
      </div>
      <fieldset className="dshsec-fieldset">
        <legend className="dshsec-h3">{tr.t('intro.modesTitle')}</legend>
        <ModeCards value={mode} onChange={setMode} name="dshsec-intro-mode" />
      </fieldset>
      <div>
        <Button
          variant="primary"
          onClick={() =>
            controller.openNewScan({ ...(props.workspaceId ? { workspaceId: props.workspaceId } : {}), mode })
          }
        >
          {tr.t('intro.start')}
        </Button>
      </div>
    </section>
  )
}

/** One finding in a list: severity, title, certainty, location, tags. */
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
        <SeverityBadge severity={f.severity} />
      </span>
      <span className="dshsec-frow-main">
        <span className="dshsec-frow-title" title={typeof f.title === 'string' ? f.title : undefined}>
          {typeof f.title === 'string' && f.title ? f.title : DASH}
        </span>
        <span className="dshsec-frow-meta">
          <VerificationBadge verification={f.verification} withTitle={false} />
          {f.isNew ? <Badge tone="brand">{tr.t('findings.new')}</Badge> : null}
          <TriageBadge triage={f.triage} />
          <span className="dshsec-frow-loc" title={location}>
            <bdi>{location}</bdi>
          </span>
        </span>
      </span>
    </button>
  )
})

/** Export menu (History rows) — downloads through the controller. */
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

/** Inline export buttons (Overview summary). */
export function ExportButtons(props: { readonly scanId: string }) {
  const controller = useController()
  const tr = useT()
  const [busy, setBusy] = useState<ReportFormat | undefined>()
  const [error, setError] = useState<{ code: string; message: string } | undefined>()
  const run = async (format: ReportFormat) => {
    setBusy(format)
    setError(undefined)
    const result = await controller.exportReport(props.scanId, format)
    setBusy(undefined)
    if (!result.ok) setError(result.error)
  }
  return (
    <div className="dshsec-export">
      {/* biome-ignore lint/a11y/useSemanticElements: a labelled button group, not a form fieldset */}
      <div className="dshsec-btn-group" role="group" aria-label={tr.t('export.title')}>
        {REPORT_FORMATS.map(format => (
          <Button
            key={format}
            size="sm"
            icon={<IconDownload size={14} />}
            busy={busy === format}
            disabled={busy !== undefined && busy !== format}
            onClick={() => void run(format)}
          >
            {tr.t(`export.${format}`)}
          </Button>
        ))}
      </div>
      {error ? (
        <Callout tone="error">
          {tr.t('export.failed')} {errorText(tr, error)}
        </Callout>
      ) : null}
    </div>
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
