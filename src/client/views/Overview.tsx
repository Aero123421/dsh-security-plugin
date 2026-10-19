import { useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react'
import type {
  AnalyzerStatus,
  Coverage,
  FindingSummary,
  RpcFailure,
  ScanDetail,
  ScanEvent,
  ScanNotice,
  ScanSummary,
} from '../../shared/contracts.ts'
import { SCAN_PHASES, SEVERITIES, type Severity, severityAtLeast } from '../../shared/domain.ts'
import { reviewOutcome } from '../../shared/review.ts'
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
  formatNumber,
  formatRelative,
  formatTime,
  isFiniteNumber,
  ratio,
  text,
} from '../format.ts'
import { useNow, useWatchScan, useWorkspaceScans } from '../hooks.ts'
import { activityText, analyzerReasonText, diagnosticText, errorText, noticeText, type Translator } from '../i18n.ts'
import { workerTitle } from '../localized.ts'
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
  const aiOff = isBuiltinOnly(detail)
  const notices = asArray(detail?.notices).filter(n => !(aiOff && n.key === 'ai-disabled'))

  return (
    <section className="dshsec-card dshsec-progress" aria-labelledby={`dshsec-progress-${scan.id}`}>
      <header className="dshsec-card-head">
        <div>
          <h2 className="dshsec-h2" id={`dshsec-progress-${scan.id}`}>
            {heading}
          </h2>
          <p className="dshsec-card-sub">
            <span>{summary.subpath ?? tr.t('scan.wholeProject')}</span>
            <span>{aiOff ? tr.t('newScan.builtin') : tr.t(`mode.${summary.mode}`)}</span>
            {summary.startedAt ? (
              <span>{tr.t('progress.startedAt', { time: formatHourMinute(summary.startedAt, tr.intlLocale) })}</span>
            ) : null}
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

      <div className="dshsec-progress-grid">
        <PhaseStepper detail={detail} current={phase} />
        <div className="dshsec-progress-main">
          <div className="dshsec-now">
            <div className="dshsec-now-line" aria-live="polite" aria-atomic="true">
              <span className="dshsec-now-phase">
                {status === 'running'
                  ? tr.t('progress.phase', { phase: phaseLabel })
                  : status === 'paused'
                    ? tr.t('progress.pausedAt', { phase: phaseLabel })
                    : tr.t('progress.waiting')}
              </span>
              {detail?.progress && status === 'running' ? (
                <span className="dshsec-now-count">
                  {tr.t('progress.count', {
                    done: formatNumber(detail.progress.done, tr.intlLocale),
                    total: formatNumber(detail.progress.total, tr.intlLocale),
                    unit: tr.lookup(`unit.${detail.progress.unit}`) ?? text(detail.progress.unit),
                  })}
                </span>
              ) : null}
            </div>
            <Meter
              value={detail?.progress ? ratio(detail.progress.done, detail.progress.total) : 0}
              label={tr.t('progress.phase', { phase: phaseLabel })}
              strong
              {...(detail?.progress ? {} : { indeterminate: status === 'running' })}
            />
          </div>
          {detail ? <UsageBlock detail={detail} aiOff={aiOff} /> : null}
          {detail && !aiOff ? <WorkersTable detail={detail} /> : null}
        </div>
      </div>

      {notices.length ? <Notices notices={notices} /> : null}
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
          <span className="dshsec-step-tag">
            {item.state === 'skipped' ? (
              tr.t('progress.skipped')
            ) : item.state === 'done' ? (
              <span className="dshsec-visually-hidden">{tr.t('progress.stepDone')}</span>
            ) : item.state === 'running' ? (
              <span className="dshsec-visually-hidden">{tr.t('progress.stepRunning')}</span>
            ) : null}
          </span>
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
  readonly indeterminate?: boolean
}) {
  const pct = Math.round(props.value * 100)
  return (
    <div
      className={`dshsec-meter${props.strong ? ' dshsec-meter--strong' : ''}${props.tone === 'warn' ? ' dshsec-meter--warn' : ''}`}
      role="progressbar"
      aria-label={props.label}
      aria-valuemin={0}
      aria-valuemax={100}
      aria-valuenow={props.indeterminate ? undefined : pct}
    >
      <span style={{ width: `${pct}%` }} />
    </div>
  )
}

function UsageBlock(props: { readonly detail: ScanDetail; readonly aiOff: boolean }) {
  const tr = useT()
  const locale = tr.intlLocale
  const { usage, budget } = props.detail
  const tokens = (usage?.inputTokens ?? 0) + (usage?.outputTokens ?? 0)
  const elapsedMs = isFiniteNumber(usage?.elapsedMs) ? usage.elapsedMs : 0
  const maxMs = isFiniteNumber(budget?.maxMinutes) ? budget.maxMinutes * 60_000 : undefined
  const rows = [
    ...(props.aiOff
      ? []
      : [
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
        ]),
    {
      key: 'time',
      label: tr.t('usage.time'),
      used: formatClock(elapsedMs),
      max: tr.t('usage.minutesLimit', { minutes: formatNumber(budget?.maxMinutes, locale) }),
      ratio: ratio(elapsedMs, maxMs),
    },
  ]
  return (
    <section className="dshsec-subsection" aria-label={tr.t('progress.usage')}>
      <dl className="dshsec-usage">
        {rows.map(row => (
          <div key={row.key} className="dshsec-usage-row">
            <dt>{row.label}</dt>
            <dd>
              <span className="dshsec-usage-value dshsec-num">
                {row.used}
                <span className="dshsec-usage-max"> / {row.max}</span>
              </span>
              <Meter value={row.ratio} label={row.label} {...(row.ratio >= 0.9 ? { tone: 'warn' as const } : {})} />
            </dd>
          </div>
        ))}
      </dl>
    </section>
  )
}

/** `m:ss` or `h:mm:ss` elapsed clock. */
function formatClock(ms: number): string {
  const total = Math.max(0, Math.floor(ms / 1000))
  const h = Math.floor(total / 3600)
  const m = Math.floor((total % 3600) / 60)
  const s = String(total % 60).padStart(2, '0')
  return h > 0 ? `${h}:${String(m).padStart(2, '0')}:${s}` : `${m}:${s}`
}

/**
 * Working reviewers first, then the most recently finished, in a fixed number
 * of rows so the card keeps its height while workers come and go.
 */
const WORKER_ROWS = 5

function WorkersTable(props: { readonly detail: ScanDetail }) {
  const tr = useT()
  const all = asArray(props.detail.workers)
  const active = all.filter(w => w.state === 'running')
  const finished = all.filter(w => w.state !== 'running')
  const shown = [...active, ...finished].slice(0, Math.max(WORKER_ROWS, active.length))
  const hidden = all.length - shown.length
  return (
    <section className="dshsec-subsection dshsec-workers">
      <div className="dshsec-subhead">
        <h3 className="dshsec-h3">{tr.t('workers.title')}</h3>
        {all.length ? (
          <span className="dshsec-hint" title={hidden > 0 ? tr.t('workers.more', { count: hidden }) : undefined}>
            {tr.t('workers.summary', { active: active.length, done: finished.filter(w => w.state === 'done').length })}
          </span>
        ) : null}
      </div>
      {shown.length ? (
        <div className="dshsec-table-wrap">
          <table className="dshsec-table">
            <thead>
              <tr>
                <th scope="col" className="dshsec-w-role">
                  {tr.t('workers.role')}
                </th>
                <th scope="col">{tr.t('workers.task')}</th>
                <th scope="col" className="dshsec-col-opt dshsec-w-model">
                  {tr.t('workers.model')}
                </th>
                <th scope="col" className="dshsec-w-state">
                  {tr.t('workers.state')}
                </th>
                <th scope="col" className="dshsec-num dshsec-col-opt dshsec-w-turns">
                  {tr.t('workers.turns')}
                </th>
              </tr>
            </thead>
            <tbody>
              {shown.map(w => (
                <tr key={w.id}>
                  <td>{tr.lookup(`role.${w.role}`) ?? text(w.role)}</td>
                  <td className="dshsec-cell-wrap" title={workerTitle(tr, w)}>
                    {workerTitle(tr, w)}
                  </td>
                  <td
                    className="dshsec-cell-mono dshsec-col-opt"
                    title={typeof w.model === 'string' ? w.model : undefined}
                  >
                    {text(w.model)}
                  </td>
                  <td>
                    <span className={`dshsec-wstate dshsec-wstate--${w.state}`}>
                      {tr.lookup(`workerState.${w.state}`) ?? text(w.state)}
                    </span>
                  </td>
                  <td className="dshsec-num dshsec-col-opt">{formatNumber(w.turns, tr.intlLocale)}</td>
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
  )
}

function ActivityFeed(props: { readonly events: readonly ScanEvent[] }) {
  const tr = useT()
  const ref = useRef<HTMLOListElement>(null)
  /** Whether the reader is at the bottom (then new lines keep it there); measured before each update. */
  const pinned = useRef(true)
  const last = props.events[props.events.length - 1]?.seq
  useLayoutEffect(() => {
    const el = ref.current
    if (!el || last === undefined) return
    if (pinned.current) el.scrollTop = el.scrollHeight
  }, [last])
  const onScroll = () => {
    const el = ref.current
    if (el) pinned.current = el.scrollHeight - el.scrollTop - el.clientHeight < 24
  }
  return (
    <section className="dshsec-subsection">
      <h3 className="dshsec-h3">{tr.t('activity.title')}</h3>
      {props.events.length ? (
        // biome-ignore lint/a11y/noNoninteractiveTabindex: scrollable log must be keyboard-reachable
        <ol className="dshsec-feed" ref={ref} tabIndex={0} aria-label={tr.t('activity.title')} onScroll={onScroll}>
          {props.events.map(event => (
            <li key={event.seq} className={`dshsec-feed-item dshsec-feed-item--${event.level}`}>
              <time className="dshsec-feed-time" dateTime={event.at}>
                {formatTime(event.at, tr.intlLocale)}
              </time>
              <div className="dshsec-feed-msg">
                <span>{activityText(tr, event)}</span>
                <details>
                  <summary>{tr.t('diagnostic.details')}</summary>
                  <span>{text(event.message)}</span>
                </details>
              </div>
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
            <span>{scan.subpath ?? tr.t('scan.wholeProject')}</span>
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
              onClick={() =>
                controller.openNewScan({ workspaceId: scan.workspaceId, mode: scan.mode, subpath: scan.subpath })
              }
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

/** A scan that ran only the built-in analyzers (the Host notes it, and skips the AI phases). */
function isBuiltinOnly(detail: ScanDetail | undefined): boolean {
  if (!detail) return false
  if (asArray(detail.notices).some(n => n.key === 'ai-disabled')) return true
  const phases = asArray(detail.phases)
  return phases.length > 0 && phases.filter(p => AI_PHASES.has(p.phase)).every(p => p.state === 'skipped')
}

const AI_PHASES: ReadonlySet<string> = new Set(['threat-model', 'hunt', 'review', 'chain'])

function formatHourMinute(value: string, locale: string): string {
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return DASH
  try {
    return new Intl.DateTimeFormat(locale, { hour: 'numeric', minute: '2-digit' }).format(date)
  } catch {
    return date.toISOString().slice(11, 16)
  }
}

/** Add budget to a partially reviewed scan and continue its skipped work in place. */
function ExtendBudgetAction(props: { readonly scan: ScanSummary; readonly detail: ScanDetail }) {
  const controller = useController()
  const tr = useT()
  const [busyPct, setBusyPct] = useState<number | undefined>()
  const [error, setError] = useState<RpcFailure | undefined>()
  const { budget, usage } = props.detail
  const tokensUsed = (usage?.inputTokens ?? 0) + (usage?.outputTokens ?? 0)

  const extend = async (pct: number) => {
    // Grow only the dimensions that actually bound this scan (tokens in
    // practice); fall back to tokens so the request always adds something.
    const extra: { addTokens?: number; addLlmCalls?: number; addMinutes?: number } = {}
    if (isFiniteNumber(budget?.maxTokens) && budget.maxTokens > 0 && tokensUsed >= budget.maxTokens * 0.9) {
      extra.addTokens = Math.max(1, Math.ceil(budget.maxTokens * pct))
    }
    if (
      isFiniteNumber(budget?.maxLlmCalls) &&
      budget.maxLlmCalls > 0 &&
      (usage?.llmCalls ?? 0) >= budget.maxLlmCalls * 0.9
    ) {
      extra.addLlmCalls = Math.max(1, Math.ceil(budget.maxLlmCalls * pct))
    }
    if (
      isFiniteNumber(budget?.maxMinutes) &&
      budget.maxMinutes > 0 &&
      (usage?.elapsedMs ?? 0) >= budget.maxMinutes * 60_000 * 0.9
    ) {
      extra.addMinutes = Math.max(1, Math.ceil(budget.maxMinutes * pct))
    }
    if (!extra.addTokens && !extra.addLlmCalls && !extra.addMinutes && isFiniteNumber(budget?.maxTokens)) {
      extra.addTokens = Math.max(1, Math.ceil(budget.maxTokens * pct))
    }
    setBusyPct(pct)
    setError(undefined)
    const result = await controller.extendScanBudget(props.scan.id, extra)
    setBusyPct(undefined)
    if (!result.ok) setError(result.error)
    // On success the scan is queued again; the overview switches to progress.
  }

  return (
    <div className="dshsec-stack-sm">
      <h3 className="dshsec-h3">{tr.t('budget.extend.title')}</h3>
      <p className="dshsec-hint">{tr.t('budget.extend.body')}</p>
      {isFiniteNumber(budget?.maxTokens) ? (
        <p className="dshsec-hint">
          {tr.t('budget.extend.tokensUsed', {
            used: formatCompact(tokensUsed, tr.intlLocale),
            max: formatCompact(budget.maxTokens, tr.intlLocale),
          })}
        </p>
      ) : null}
      <div className="dshsec-actions">
        {[0.5, 1, 3].map(pct => (
          <Button
            key={pct}
            size="sm"
            busy={busyPct === pct}
            disabled={busyPct !== undefined}
            onClick={() => void extend(pct)}
          >
            {tr.t('budget.extend.add', { percent: pct * 100 })}
          </Button>
        ))}
      </div>
      {error ? <Callout tone="error">{errorText(tr, error)}</Callout> : null}
    </div>
  )
}

function ResultsSummary(props: { readonly scan: ScanSummary; readonly heading: string }) {
  const controller = useController()
  const tr = useT()
  const now = useNow()
  const { scan } = props
  const findingsEntry = useSecurity(s => s.findings[scan.id] ?? IDLE_FINDINGS)
  const detailEntry = useSecurity(s => s.details[scan.id] ?? IDLE_DETAIL)
  const detail = detailEntry.value
  const events = useSecurity(s => s.events[scan.id] ?? NO_EVENTS)
  const eventsError = useSecurity(s => s.eventsErrors[scan.id])
  const eventsLoading = useSecurity(s => s.eventsLoading[scan.id])

  useEffect(() => {
    void controller.loadFindings(scan.id)
    void controller.loadScanDetail(scan.id)
    void controller.loadScanEvents(scan.id)
  }, [controller, scan.id])

  // A cached detail without coverage (loaded while the scan was running)
  // must not shadow the fresher host-computed outcome from the list.
  const review = detail?.coverage
    ? reviewOutcome(detail)
    : (scan.review ?? (detail ? reviewOutcome(detail) : undefined))
  // Mirror the Host's skeptic eligibility as closely as the wire allows:
  // only potential findings at or above the mode's severity floor are ever
  // scheduled for independent review, so only those can be missing one.
  const reviewFloor: Severity = scan.mode === 'research' ? 'low' : 'medium'
  const noSecondOpinion =
    scan.mode !== 'quick' &&
    findingsEntry.value?.some(
      f =>
        f.verification === 'potential' &&
        f.closure !== 'ruled_out' &&
        (f.source === 'ai' || f.source === 'sast' || f.source === 'external') &&
        severityAtLeast(f.severity, reviewFloor) &&
        f.independentlyReviewed !== true,
    )

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
            <span>{scan.subpath ?? tr.t('scan.wholeProject')}</span>
            <span>{isBuiltinOnly(detail) ? tr.t('newScan.builtin') : tr.t(`mode.${scan.mode}`)}</span>
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

      <section aria-label={tr.t('review.title')} className="dshsec-stack-sm">
        <Callout
          tone={
            review?.state === 'failed'
              ? 'error'
              : review?.state === 'complete' || review?.state === 'builtin'
                ? 'info'
                : 'warn'
          }
        >
          <strong>{tr.lookup(`review.${review?.state ?? 'unknown'}`)}</strong>
          {review && review.state !== 'builtin' && review.state !== 'unknown' ? (
            <p>{tr.t('review.count', { completed: review.completed, planned: review.planned })}</p>
          ) : null}
          {review?.state === 'not-run' ? <p>{tr.t('review.notRunBody')}</p> : null}
          {review?.state === 'partial' || review?.state === 'failed' ? <p>{tr.t('review.partialBody')}</p> : null}
          {review?.state === 'complete' ? <p>{tr.t('review.completeBody')}</p> : null}
        </Callout>
        {detailEntry.error ? (
          <LoadError error={detailEntry.error} onRetry={() => void controller.loadScanDetail(scan.id, true)} />
        ) : null}
        {(review?.state === 'partial' || review?.state === 'failed') && detail ? (
          <ExtendBudgetAction scan={scan} detail={detail} />
        ) : null}
        {noSecondOpinion ? <Callout tone="warn">{tr.t('review.secondOpinionMissing')}</Callout> : null}
        {detail?.notices.length ? <Notices notices={detail.notices} /> : null}
      </section>
      <CoverageCard coverage={detail?.coverage} tr={tr} />

      <div className="dshsec-subsection">
        <div className="dshsec-subhead">
          <h3 className="dshsec-h3">{tr.t('summary.openBySeverity')}</h3>
          <span className="dshsec-hint">
            <strong className="dshsec-num dshsec-sevrow-total">{formatNumber(openTotal, tr.intlLocale)}</strong>{' '}
            {tr.t('summary.openTotal')}
          </span>
        </div>
        <ul className="dshsec-sevrows">
          {SEVERITIES.map(severity => {
            const count = isFiniteNumber(scan.counts?.[severity]) ? scan.counts[severity] : undefined
            return (
              <li key={severity}>
                <button
                  type="button"
                  className={`dshsec-sevrow ${count ? 'has-value' : ''}`}
                  onClick={() => showSeverity(severity)}
                  aria-label={`${tr.t(`severity.${severity}`)}: ${count ?? DASH}`}
                >
                  <span className={`dshsec-dist-dot dshsec-dist-dot--${severity}`} aria-hidden="true" />
                  <span className="dshsec-sevrow-label">{tr.t(`severity.${severity}`)}</span>
                  <span className="dshsec-sevrow-count dshsec-num">{count ?? DASH}</span>
                </button>
              </li>
            )
          })}
        </ul>
        <dl className="dshsec-kv">
          <div className="dshsec-kv-row">
            <dt>{tr.t('summary.certainty')}</dt>
            <dd>
              {(['confirmed', 'open_proof_gap', 'ruled_out'] as const).map((closure, index) => (
                <span key={closure} title={tr.t(`closure.${closure}.desc`)}>
                  {index > 0 ? <span aria-hidden="true"> · </span> : null}
                  {tr.t(`closure.${closure}`)} <strong className="dshsec-num">{counts ? counts[closure] : DASH}</strong>
                </span>
              ))}
              <span>
                <span aria-hidden="true"> · </span>
                {tr.t('summary.new')} <strong className="dshsec-num">{counts ? counts.isNew : DASH}</strong>
              </span>
            </dd>
          </div>
        </dl>
        <p className="dshsec-hint dshsec-notsafe" role="note">
          <strong>{tr.t(openTotal === 0 ? 'summary.notSafeTitle' : 'summary.notCompleteTitle')}</strong>{' '}
          {tr.t('summary.notSafeBody')}
        </p>
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

      <details className="dshsec-subsection">
        <summary>{tr.t('review.diagnostics')}</summary>
        {detail ? (
          <>
            <UsageBlock detail={detail} aiOff={isBuiltinOnly(detail)} />
            <WorkersTable detail={detail} />
          </>
        ) : null}
        {eventsError ? (
          <LoadError error={eventsError} onRetry={() => void controller.loadScanEvents(scan.id, true)} />
        ) : null}
        {eventsLoading && events.length === 0 ? <Loading /> : <ActivityFeed events={events} />}
      </details>
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
  // Primary copy only carries diagnostics with a localized sentence; raw
  // Host text is collected once under a single technical-details disclosure.
  const knownGaps = (coverage.gapDetails ?? []).filter(gap => tr.lookup(`diagnostic.gap.${gap.code}`) !== undefined)
  const unknownGapCount = (coverage.gapDetails?.length ?? 0) - knownGaps.length
  const technical = [
    ...unavailable.filter(a => a.reason).map(a => `${analyzerLabel(tr, a)}: ${a.reason}`),
    ...(coverage.gapDetails ?? []).map(gap => gap.fallback),
  ]
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
                <span className="dshsec-muted"> — {analyzerReasonText(tr, a)}</span>
              </li>
            ))}
          </ul>
        </div>
      ) : null}
      {gaps.length ? (
        <div className="dshsec-stack-sm">
          <h4 className="dshsec-h4">{tr.t('coverage.gaps')}</h4>
          {coverage.gapDetails?.length ? (
            <ul className="dshsec-list">
              {knownGaps.map((gap, index) => (
                // biome-ignore lint/suspicious/noArrayIndexKey: immutable diagnostic order, codes may repeat for analyzers
                <li key={`${gap.code}:${index}`}>{diagnosticText(tr, gap)}</li>
              ))}
              {unknownGapCount > 0 ? <li>{tr.t('diagnostic.otherGaps', { count: unknownGapCount })}</li> : null}
            </ul>
          ) : (
            <details>
              <summary>{tr.t('diagnostic.legacy')}</summary>
              <ul className="dshsec-list">
                {gaps.map(gap => (
                  <li key={gap}>{gap}</li>
                ))}
              </ul>
            </details>
          )}
        </div>
      ) : null}
      {technical.length ? (
        <details>
          <summary>{tr.t('diagnostic.details')}</summary>
          <ul className="dshsec-list">
            {technical.map((line, index) => (
              // biome-ignore lint/suspicious/noArrayIndexKey: immutable technical order
              <li key={index}>{line}</li>
            ))}
          </ul>
        </details>
      ) : null}
      {isFiniteNumber(coverage.discardedUnverifiable) && coverage.discardedUnverifiable > 0 ? (
        <p className="dshsec-muted">
          {tr.t('coverage.discarded', { count: formatNumber(coverage.discardedUnverifiable, locale) })}
        </p>
      ) : null}
    </section>
  )
}
