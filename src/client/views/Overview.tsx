import { useEffect, useMemo, useState } from 'react'
import type {
  AnalyzerStatus,
  Coverage,
  FindingSummary,
  ScanDetail,
  ScanEvent,
  ScanNotice,
  ScanSummary,
} from '../../shared/contracts.ts'
import { SCAN_PHASES, SEVERITIES, type Severity } from '../../shared/domain.ts'
import { severityTone, StatusBadge } from '../components/Badge.tsx'
import { Button } from '../components/Button.tsx'
import { Callout } from '../components/Callout.tsx'
import { ConfirmDialog } from '../components/ConfirmDialog.tsx'
import { useController, useSecurity, useT } from '../context.tsx'
import type { Loadable } from '../controller.ts'
import { DEFAULT_FINDINGS_FILTER, certaintyCounts, topOpenFindings } from '../findings.ts'
import {
  DASH,
  asArray,
  formatCompact,
  formatDateTime,
  formatDuration,
  formatMinutes,
  formatNumber,
  formatRelative,
  formatTime,
  isFiniteNumber,
  ratio,
  text,
} from '../format.ts'
import { useNow, useWatchScan, useWorkspaceScans } from '../hooks.ts'
import { errorText, noticeText, type Translator } from '../i18n.ts'
import { IconPause, IconPlay, IconRefresh, IconStop } from '../icons.tsx'
import { overviewFocus } from '../selectors.ts'
import { AvailabilityGate, ExportButtons, FindingRow, FirstRun, LoadError, Loading, ViewingBanner } from './shared.tsx'

const NO_EVENTS: readonly ScanEvent[] = []
const IDLE_DETAIL: Loadable<ScanDetail> = { status: 'idle' }
const IDLE_FINDINGS: Loadable<readonly FindingSummary[]> = { status: 'idle' }

export function OverviewView() {
  return (
    <AvailabilityGate>
      <OverviewBody />
    </AvailabilityGate>
  )
}

function OverviewBody() {
  const controller = useController()
  const tr = useT()
  const workspaceId = useSecurity(s => s.workspaceId)
  const viewScanId = useSecurity(s => s.viewScanId)
  const { entry, scans } = useWorkspaceScans()
  const focus = useMemo(() => overviewFocus(scans, viewScanId), [scans, viewScanId])

  if (!entry.value && entry.status === 'error' && entry.error) {
    return <LoadError error={entry.error} onRetry={() => void controller.refreshScans()} />
  }
  if (!entry.value) return <Loading />
  if (!scans.length) return <FirstRun workspaceId={workspaceId} />

  const viewed = viewScanId ? scans.find(s => s.id === viewScanId) : undefined
  return (
    <div className="dshsec-stack-lg">
      <ViewingBanner scan={viewed} />
      {focus.active ? <ProgressCard scan={focus.active} /> : null}
      {focus.problem ? <ProblemCard scan={focus.problem} /> : null}
      {focus.results ? (
        <ResultsSummary
          scan={focus.results}
          heading={focus.active || focus.problem ? tr.t('summary.previous') : tr.t('summary.title')}
        />
      ) : null}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Running / paused / queued
// ---------------------------------------------------------------------------

function ProgressCard(props: { readonly scan: ScanSummary }) {
  const controller = useController()
  const tr = useT()
  const { scan } = props
  useWatchScan(scan.id, true)
  const detailEntry = useSecurity(s => s.details[scan.id] ?? IDLE_DETAIL)
  const events = useSecurity(s => s.events[scan.id] ?? NO_EVENTS)
  const detail = detailEntry.value
  const summary = detail?.summary ?? scan
  const status = summary.status
  const [confirming, setConfirming] = useState(false)
  const [busy, setBusy] = useState<'pause' | 'resume' | undefined>()
  const [actionError, setActionError] = useState<{ code: string; message: string } | undefined>()

  const act = async (kind: 'pause' | 'resume') => {
    setBusy(kind)
    setActionError(undefined)
    const result = kind === 'pause' ? await controller.pauseScan(scan.id) : await controller.resumeScan(scan.id)
    setBusy(undefined)
    if (!result.ok) setActionError(result.error)
  }

  const heading =
    status === 'paused'
      ? tr.t('progress.paused')
      : status === 'queued'
        ? tr.t('progress.queued')
        : tr.t('progress.running')
  const phase = summary.phase
  const phaseLabel = tr.lookup(`phase.${phase}`) ?? text(phase)

  return (
    <section className="dshsec-card dshsec-progress" aria-labelledby={`dshsec-progress-${scan.id}`}>
      <header className="dshsec-card-head">
        <div>
          <h2 className="dshsec-h2" id={`dshsec-progress-${scan.id}`}>
            {heading}
          </h2>
          <p className="dshsec-muted dshsec-card-sub">
            <span>{tr.t(`mode.${summary.mode}`)}</span>
            <StatusBadge status={status} />
          </p>
        </div>
        <div className="dshsec-card-actions">
          {status === 'paused' ? (
            <Button icon={<IconPlay size={14} />} busy={busy === 'resume'} onClick={() => void act('resume')}>
              {tr.t('action.resume')}
            </Button>
          ) : status === 'running' ? (
            <Button icon={<IconPause size={14} />} busy={busy === 'pause'} onClick={() => void act('pause')}>
              {tr.t('action.pause')}
            </Button>
          ) : null}
          <Button variant="ghost" icon={<IconStop size={14} />} onClick={() => setConfirming(true)}>
            {tr.t('action.cancelScan')}
          </Button>
        </div>
      </header>

      {actionError ? <Callout tone="error">{errorText(tr, actionError)}</Callout> : null}
      {!detail && detailEntry.status === 'error' && detailEntry.error ? (
        <LoadError error={detailEntry.error} onRetry={() => void controller.loadScanDetail(scan.id, true)} />
      ) : null}

      <PhaseStepper detail={detail} current={phase} />

      <div className="dshsec-live" aria-live="polite" aria-atomic="true">
        <div className="dshsec-live-line">
          <span>{tr.t('progress.phase', { phase: phaseLabel })}</span>
          {detail?.progress ? (
            <span className="dshsec-muted">
              {tr.t('progress.count', {
                done: formatNumber(detail.progress.done, tr.intlLocale),
                total: formatNumber(detail.progress.total, tr.intlLocale),
                unit: tr.lookup(`unit.${detail.progress.unit}`) ?? text(detail.progress.unit),
              })}
            </span>
          ) : null}
        </div>
      </div>
      {detail?.progress ? (
        <Meter
          value={ratio(detail.progress.done, detail.progress.total)}
          label={tr.t('progress.phase', { phase: phaseLabel })}
          strong
        />
      ) : null}

      {detail ? <UsageBlock detail={detail} /> : null}
      {detail ? <WorkersTable detail={detail} /> : null}
      {detail && asArray(detail.notices).length ? <Notices notices={detail.notices} /> : null}
      <ActivityFeed events={events} />

      {confirming ? (
        <ConfirmDialog
          title={tr.t('confirmCancel.title')}
          body={tr.t('confirmCancel.body')}
          confirmLabel={tr.t('confirmCancel.confirm')}
          cancelLabel={tr.t('confirmCancel.keep')}
          onConfirm={() => controller.cancelScan(scan.id)}
          onClose={() => setConfirming(false)}
        />
      ) : null}
    </section>
  )
}

function PhaseStepper(props: { readonly detail: ScanDetail | undefined; readonly current: string }) {
  const tr = useT()
  const phases = asArray(props.detail?.phases)
  const items = phases.length
    ? phases
    : SCAN_PHASES.filter(p => p !== 'done').map(phase => {
        const currentIndex = SCAN_PHASES.indexOf(props.current as (typeof SCAN_PHASES)[number])
        const index = SCAN_PHASES.indexOf(phase)
        const state: 'pending' | 'running' | 'done' =
          index < currentIndex ? 'done' : index === currentIndex ? 'running' : 'pending'
        return { phase, state }
      })
  return (
    <ol className="dshsec-steps" aria-label={tr.t('progress.phases')}>
      {items.map(item => (
        <li
          key={item.phase}
          className={`dshsec-step dshsec-step--${item.state}`}
          aria-current={item.state === 'running' ? 'step' : undefined}
        >
          <span className="dshsec-step-dot" aria-hidden="true" />
          <span className="dshsec-step-label">{tr.lookup(`phase.${item.phase}`) ?? text(item.phase)}</span>
        </li>
      ))}
    </ol>
  )
}

export function Meter(props: {
  readonly value: number
  readonly label: string
  readonly strong?: boolean
  readonly tone?: 'warn'
}) {
  const pct = Math.round(props.value * 100)
  return (
    <div
      className={`dshsec-meter ${props.strong ? 'dshsec-meter--strong' : ''} ${props.tone === 'warn' ? 'dshsec-meter--warn' : ''}`}
      role="progressbar"
      aria-label={props.label}
      aria-valuemin={0}
      aria-valuemax={100}
      aria-valuenow={pct}
    >
      <span style={{ width: `${pct}%` }} />
    </div>
  )
}

function UsageBlock(props: { readonly detail: ScanDetail }) {
  const tr = useT()
  const locale = tr.intlLocale
  const { usage, budget } = props.detail
  const tokens = (usage?.inputTokens ?? 0) + (usage?.outputTokens ?? 0)
  const minutes = formatMinutes(usage?.elapsedMs)
  const rows = [
    {
      key: 'tokens',
      label: tr.t('usage.tokens'),
      used: formatCompact(tokens, locale),
      max: formatCompact(budget?.maxTokens, locale),
      ratio: ratio(tokens, budget?.maxTokens),
    },
    {
      key: 'calls',
      label: tr.t('usage.calls'),
      used: formatNumber(usage?.llmCalls, locale),
      max: formatNumber(budget?.maxLlmCalls, locale),
      ratio: ratio(usage?.llmCalls, budget?.maxLlmCalls),
    },
    {
      key: 'minutes',
      label: tr.t('usage.minutes'),
      used: formatNumber(minutes, locale),
      max: formatNumber(budget?.maxMinutes, locale),
      ratio: ratio(minutes, budget?.maxMinutes),
    },
  ]
  return (
    <section className="dshsec-subsection">
      <h3 className="dshsec-h3">{tr.t('progress.usage')}</h3>
      <dl className="dshsec-usage">
        {rows.map(row => (
          <div key={row.key} className="dshsec-usage-row">
            <dt>{row.label}</dt>
            <dd>
              <span className="dshsec-num">{tr.t('usage.ofBudget', { used: row.used, max: row.max })}</span>
              <Meter value={row.ratio} label={row.label} {...(row.ratio >= 0.9 ? { tone: 'warn' as const } : {})} />
            </dd>
          </div>
        ))}
      </dl>
    </section>
  )
}

function WorkersTable(props: { readonly detail: ScanDetail }) {
  const tr = useT()
  const workers = asArray(props.detail.workers)
  return (
    <section className="dshsec-subsection">
      <h3 className="dshsec-h3">{tr.t('workers.title')}</h3>
      {workers.length ? (
        <div className="dshsec-table-wrap">
          <table className="dshsec-table">
            <thead>
              <tr>
                <th scope="col">{tr.t('workers.role')}</th>
                <th scope="col">{tr.t('workers.task')}</th>
                <th scope="col">{tr.t('workers.model')}</th>
                <th scope="col">{tr.t('workers.state')}</th>
                <th scope="col" className="dshsec-num">
                  {tr.t('workers.turns')}
                </th>
                <th scope="col" className="dshsec-num">
                  {tr.t('workers.toolCalls')}
                </th>
              </tr>
            </thead>
            <tbody>
              {workers.map(w => (
                <tr key={w.id}>
                  <td>{tr.lookup(`role.${w.role}`) ?? text(w.role)}</td>
                  <td className="dshsec-cell-wrap">{text(w.title)}</td>
                  <td className="dshsec-cell-mono">{text(w.model)}</td>
                  <td>
                    <span className={`dshsec-wstate dshsec-wstate--${w.state}`}>
                      {tr.lookup(`workerState.${w.state}`) ?? text(w.state)}
                    </span>
                  </td>
                  <td className="dshsec-num">{formatNumber(w.turns, tr.intlLocale)}</td>
                  <td className="dshsec-num">{formatNumber(w.toolCalls, tr.intlLocale)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <p className="dshsec-muted">{tr.t('workers.empty')}</p>
      )}
    </section>
  )
}

function Notices(props: { readonly notices: readonly ScanNotice[] }) {
  const tr = useT()
  return (
    <section className="dshsec-subsection">
      <h3 className="dshsec-h3">{tr.t('notices.title')}</h3>
      <div className="dshsec-stack-sm">
        {props.notices.map((notice, i) => (
          <Callout
            // biome-ignore lint/suspicious/noArrayIndexKey: notices are append-only
            key={`${notice.key}-${i}`}
            tone={notice.level === 'error' ? 'error' : notice.level === 'warn' ? 'warn' : 'info'}
            live={false}
          >
            {noticeText(tr, notice)}
          </Callout>
        ))}
      </div>
    </section>
  )
}

function ActivityFeed(props: { readonly events: readonly ScanEvent[] }) {
  const tr = useT()
  const [el, setEl] = useState<HTMLOListElement | null>(null)
  const last = props.events[props.events.length - 1]?.seq
  // Keep the newest entry in view (newest at bottom) unless the user scrolled up.
  useEffect(() => {
    if (!el || last === undefined) return
    const nearBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 48
    if (nearBottom || el.dataset.init !== '1') {
      el.scrollTop = el.scrollHeight
      el.dataset.init = '1'
    }
  }, [el, last])
  return (
    <section className="dshsec-subsection">
      <h3 className="dshsec-h3">{tr.t('activity.title')}</h3>
      {props.events.length ? (
        // biome-ignore lint/a11y/noNoninteractiveTabindex: scrollable log must be keyboard-reachable
        <ol className="dshsec-feed" ref={setEl} tabIndex={0} aria-label={tr.t('activity.title')}>
          {props.events.map(event => (
            <li key={event.seq} className={`dshsec-feed-item dshsec-feed-item--${event.level}`}>
              <time className="dshsec-feed-time" dateTime={event.at}>
                {formatTime(event.at, tr.intlLocale)}
              </time>
              <span className="dshsec-feed-msg">{text(event.message)}</span>
            </li>
          ))}
        </ol>
      ) : (
        <p className="dshsec-muted">{tr.t('activity.empty')}</p>
      )}
    </section>
  )
}

// ---------------------------------------------------------------------------
// Failed / cancelled / interrupted
// ---------------------------------------------------------------------------

function ProblemCard(props: { readonly scan: ScanSummary }) {
  const controller = useController()
  const tr = useT()
  const { scan } = props
  const detail = useSecurity(s => s.details[scan.id]?.value)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<{ code: string; message: string } | undefined>()

  useEffect(() => {
    void controller.loadScanDetail(scan.id)
  }, [controller, scan.id])

  const title =
    scan.status === 'failed'
      ? tr.t('problem.failed')
      : scan.status === 'interrupted'
        ? tr.t('problem.interrupted')
        : tr.t('problem.cancelled')
  const resumable = scan.status === 'interrupted'

  const resume = async () => {
    setBusy(true)
    setError(undefined)
    const result = await controller.resumeScan(scan.id)
    setBusy(false)
    if (!result.ok) setError(result.error)
  }

  const notices = asArray(detail?.notices).filter(n => n.level !== 'info')

  return (
    <section
      className={`dshsec-card dshsec-problem dshsec-problem--${scan.status}`}
      aria-labelledby={`dshsec-problem-${scan.id}`}
    >
      <header className="dshsec-card-head">
        <div>
          <h2 className="dshsec-h2" id={`dshsec-problem-${scan.id}`}>
            {title}
          </h2>
          <p className="dshsec-muted dshsec-card-sub">
            <span>{tr.t(`mode.${scan.mode}`)}</span>
            <span>{formatDateTime(scan.createdAt, tr.intlLocale)}</span>
          </p>
        </div>
        <div className="dshsec-card-actions">
          {resumable ? (
            <Button variant="primary" icon={<IconPlay size={14} />} busy={busy} onClick={() => void resume()}>
              {tr.t('action.resume')}
            </Button>
          ) : (
            <Button
              variant="primary"
              icon={<IconRefresh size={14} />}
              onClick={() => controller.openNewScan({ workspaceId: scan.workspaceId, mode: scan.mode })}
            >
              {tr.t('action.scanAgain')}
            </Button>
          )}
        </div>
      </header>
      {resumable ? <p>{tr.t('problem.interruptedBody')}</p> : null}
      {scan.error ? (
        <Callout tone="error" live={false} title={errorText(tr, { code: scan.error.code })}>
          {scan.error.message?.trim() ? scan.error.message : null}
        </Callout>
      ) : null}
      {notices.map((notice, i) => (
        // biome-ignore lint/suspicious/noArrayIndexKey: notices are append-only
        <Callout key={`${notice.key}-${i}`} tone={notice.level === 'error' ? 'error' : 'warn'} live={false}>
          {noticeText(tr, notice)}
        </Callout>
      ))}
      {error ? <Callout tone="error">{errorText(tr, error)}</Callout> : null}
    </section>
  )
}

// ---------------------------------------------------------------------------
// Completed
// ---------------------------------------------------------------------------

function ResultsSummary(props: { readonly scan: ScanSummary; readonly heading: string }) {
  const controller = useController()
  const tr = useT()
  const now = useNow()
  const { scan } = props
  const findingsEntry = useSecurity(s => s.findings[scan.id] ?? IDLE_FINDINGS)
  const detail = useSecurity(s => s.details[scan.id]?.value)

  useEffect(() => {
    void controller.loadFindings(scan.id)
    void controller.loadScanDetail(scan.id)
  }, [controller, scan.id])

  const findings = findingsEntry.value
  const counts = useMemo(() => (findings ? certaintyCounts(findings) : undefined), [findings])
  const top = useMemo(() => (findings ? topOpenFindings(findings, 5) : []), [findings])
  const openTotal = SEVERITIES.reduce(
    (sum, sev) => sum + (isFiniteNumber(scan.counts?.[sev]) ? scan.counts[sev] : 0),
    0,
  )
  const durationMs =
    scan.startedAt && scan.finishedAt ? Date.parse(scan.finishedAt) - Date.parse(scan.startedAt) : undefined

  const showSeverity = (severity: Severity) => {
    controller.setFilter({ ...DEFAULT_FINDINGS_FILTER, severities: [severity] })
    controller.setTab('findings')
  }

  return (
    <section className="dshsec-results" aria-labelledby={`dshsec-results-${scan.id}`}>
      <header className="dshsec-results-head">
        <div>
          <h2 className="dshsec-h2" id={`dshsec-results-${scan.id}`}>
            {props.heading}
          </h2>
          <p className="dshsec-muted dshsec-card-sub">
            <span>{tr.t(`mode.${scan.mode}`)}</span>
            <time
              dateTime={scan.finishedAt ?? scan.createdAt}
              title={formatDateTime(scan.finishedAt ?? scan.createdAt, tr.intlLocale)}
            >
              {tr.t('summary.completed', {
                time: formatRelative(scan.finishedAt ?? scan.createdAt, tr.intlLocale, now),
              })}
            </time>
            {isFiniteNumber(durationMs) && durationMs > 0 ? (
              <span>{tr.t('summary.duration', { duration: formatDuration(durationMs, tr.intlLocale) })}</span>
            ) : null}
          </p>
        </div>
        <ExportButtons scanId={scan.id} />
      </header>

      <div className={`dshsec-notsafe ${openTotal === 0 ? 'dshsec-notsafe--prominent' : ''}`} role="note">
        <strong>{tr.t('summary.notSafeTitle')}</strong>
        <span>{tr.t('summary.notSafeBody')}</span>
      </div>

      <div className="dshsec-subsection">
        <h3 className="dshsec-h3">{tr.t('summary.openBySeverity')}</h3>
        <ul className="dshsec-ledger">
          {SEVERITIES.map(severity => {
            const count = isFiniteNumber(scan.counts?.[severity]) ? scan.counts[severity] : undefined
            return (
              <li key={severity}>
                <button
                  type="button"
                  className={`dshsec-ledger-cell dshsec-ledger-cell--${severityTone(severity)} ${count ? 'has-value' : ''}`}
                  onClick={() => showSeverity(severity)}
                  aria-label={`${tr.t(`severity.${severity}`)}: ${count ?? DASH}`}
                >
                  <span className="dshsec-ledger-num">{count ?? DASH}</span>
                  <span className="dshsec-ledger-label">{tr.t(`severity.${severity}`)}</span>
                </button>
              </li>
            )
          })}
        </ul>
      </div>

      <div className="dshsec-subsection">
        <h3 className="dshsec-h3">{tr.t('summary.certainty')}</h3>
        <dl className="dshsec-certainty-row">
          {(['confirmed', 'open_proof_gap', 'ruled_out'] as const).map(closure => (
            <div key={closure} className={`dshsec-cert dshsec-cert--${closure}`}>
              <dt>{tr.t(`closure.${closure}`)}</dt>
              <dd>
                <span className="dshsec-cert-num">{counts ? counts[closure] : DASH}</span>
                <span className="dshsec-hint">{tr.t(`closure.${closure}.desc`)}</span>
              </dd>
            </div>
          ))}
          <div className="dshsec-cert dshsec-cert--new">
            <dt>{tr.t('summary.new')}</dt>
            <dd>
              <span className="dshsec-cert-num">{counts ? counts.isNew : DASH}</span>
            </dd>
          </div>
        </dl>
      </div>

      <div className="dshsec-subsection">
        <div className="dshsec-subhead">
          <h3 className="dshsec-h3">{tr.t('summary.top')}</h3>
          {findings?.length ? (
            <Button size="sm" variant="link" onClick={() => controller.setTab('findings')}>
              {tr.t('summary.viewAll')}
            </Button>
          ) : null}
        </div>
        {!findings && findingsEntry.status === 'error' && findingsEntry.error ? (
          <LoadError error={findingsEntry.error} onRetry={() => void controller.loadFindings(scan.id, true)} />
        ) : !findings ? (
          <Loading />
        ) : top.length ? (
          <div className="dshsec-flist">
            {top.map(finding => (
              <FindingRow
                key={finding.id}
                finding={finding}
                onSelect={() => controller.openFindingFromOverview(scan.id, finding.id)}
              />
            ))}
          </div>
        ) : (
          <p className="dshsec-muted">{tr.t('summary.topEmpty')}</p>
        )}
      </div>

      <CoverageCard coverage={detail?.coverage} tr={tr} />
    </section>
  )
}

function analyzerLabel(tr: Translator, status: AnalyzerStatus): string {
  return tr.lookup(`analyzer.${status.id}`) ?? text(status.id)
}

function CoverageCard(props: { readonly coverage: Coverage | undefined; readonly tr: Translator }) {
  const { coverage, tr } = props
  const locale = tr.intlLocale
  if (!coverage) {
    return (
      <section className="dshsec-subsection">
        <h3 className="dshsec-h3">{tr.t('coverage.title')}</h3>
        <p className="dshsec-muted">{tr.t('coverage.none')}</p>
      </section>
    )
  }
  const unavailable = asArray(coverage.analyzers).filter(a => a && !a.available)
  const gaps = asArray(coverage.gaps).filter(g => typeof g === 'string' && g.trim())
  const files = coverage.files
  const endpoints = coverage.endpoints
  const tasks = coverage.tasks
  return (
    <section className="dshsec-subsection dshsec-coverage">
      <h3 className="dshsec-h3">{tr.t('coverage.title')}</h3>
      <dl className="dshsec-kv">
        <div className="dshsec-kv-row">
          <dt>{tr.t('coverage.files')}</dt>
          <dd>
            <span className="dshsec-num">
              {tr.t('coverage.filesValue', {
                analyzed: formatNumber(files?.analyzed, locale),
                total: formatNumber(files?.total, locale),
              })}
            </span>
            {isFiniteNumber(files?.excluded) && files.excluded > 0 ? (
              <span className="dshsec-muted">
                {' '}
                ({tr.t('coverage.excluded', { count: formatNumber(files.excluded, locale) })})
              </span>
            ) : null}
            <Meter value={ratio(files?.analyzed, files?.total)} label={tr.t('coverage.files')} />
          </dd>
        </div>
        <div className="dshsec-kv-row">
          <dt>{tr.t('coverage.readByAi')}</dt>
          <dd>
            <span className="dshsec-num">
              {tr.t('coverage.filesValue', {
                analyzed: formatNumber(files?.readByAi, locale),
                total: formatNumber(files?.total, locale),
              })}
            </span>
            <Meter value={ratio(files?.readByAi, files?.total)} label={tr.t('coverage.readByAi')} />
          </dd>
        </div>
        <div className="dshsec-kv-row">
          <dt>{tr.t('coverage.endpoints')}</dt>
          <dd>
            <span className="dshsec-num">
              {tr.t('coverage.filesValue', {
                analyzed: formatNumber(endpoints?.reviewed, locale),
                total: formatNumber(endpoints?.total, locale),
              })}
            </span>
            <Meter value={ratio(endpoints?.reviewed, endpoints?.total)} label={tr.t('coverage.endpoints')} />
          </dd>
        </div>
        <div className="dshsec-kv-row">
          <dt>{tr.t('coverage.tasks')}</dt>
          <dd>
            {tr.t('coverage.tasksValue', {
              completed: formatNumber(tasks?.completed, locale),
              failed: formatNumber(tasks?.failed, locale),
              skipped: formatNumber(tasks?.skipped, locale),
            })}
          </dd>
        </div>
      </dl>
      {unavailable.length ? (
        <div className="dshsec-stack-sm">
          <h4 className="dshsec-h4">{tr.t('coverage.unavailable')}</h4>
          <ul className="dshsec-list">
            {unavailable.map(a => (
              <li key={a.id}>
                <strong>{analyzerLabel(tr, a)}</strong>
                {a.reason ? <span className="dshsec-muted"> — {a.reason}</span> : null}
              </li>
            ))}
          </ul>
        </div>
      ) : null}
      {gaps.length ? (
        <div className="dshsec-stack-sm">
          <h4 className="dshsec-h4">{tr.t('coverage.gaps')}</h4>
          <ul className="dshsec-list">
            {gaps.map(gap => (
              <li key={gap}>{gap}</li>
            ))}
          </ul>
        </div>
      ) : null}
      {isFiniteNumber(coverage.discardedUnverifiable) && coverage.discardedUnverifiable > 0 ? (
        <p className="dshsec-muted">
          {tr.t('coverage.discarded', { count: formatNumber(coverage.discardedUnverifiable, locale) })}
        </p>
      ) : null}
    </section>
  )
}
