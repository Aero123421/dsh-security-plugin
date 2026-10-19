import { type ReactNode, useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react'
import type {
  AnalyzerStatus,
  Coverage,
  Diagnostic,
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
import { IconPause, IconPlay, IconRefresh, IconStop, IconWarn } from '../icons.tsx'
import { queueAhead } from '../projects.ts'
import { overviewFocus } from '../selectors.ts'
import { LedgerList, LedgerRows } from './CoverageLedger.tsx'
import { AvailabilityGate, ExportMenu, FindingRow, FirstRun, LoadError, Loading, ViewingBanner } from './shared.tsx'

const NO_EVENTS: readonly ScanEvent[] = []
const IDLE_DETAIL: Loadable<ScanDetail> = { status: 'idle' }
const IDLE_FINDINGS: Loadable<readonly FindingSummary[]> = { status: 'idle' }
/** Open findings listed on the Overview; the Findings tab has the rest. */
const TOP_FINDINGS = 5

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

/** "Whole project · Deep · …" — the quiet line under a scan heading. */
function ScanMeta(props: { readonly items: readonly ReactNode[] }) {
  return (
    <p className="dshsec-meta">
      {props.items.filter(Boolean).map((item, i) => (
        // biome-ignore lint/suspicious/noArrayIndexKey: fixed positional items
        <span key={i}>{item}</span>
      ))}
    </p>
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
          <ScanMeta
            items={[
              summary.subpath ?? tr.t('scan.wholeProject'),
              aiOff ? tr.t('newScan.builtin') : tr.t(`mode.${summary.mode}`),
              summary.startedAt
                ? tr.t('progress.startedAt', { time: formatHourMinute(summary.startedAt, tr.intlLocale) })
                : undefined,
            ]}
          />
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
      {status === 'queued' ? <QueueLine scan={summary} /> : null}

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

/**
 * Scans run one after another across projects. A queued scan names the scan
 * it waits for — usually another project's — and offers to switch to it.
 */
function QueueLine(props: { readonly scan: ScanSummary }) {
  const controller = useController()
  const tr = useT()
  const active = useSecurity(s => s.activeScans)
  const ahead = queueAhead(props.scan, active)
  const running = ahead.find(scan => scan.status === 'running')
  if (!running) return null
  const project = running.workspaceTitle || tr.t('intro.thisProject')
  return (
    <p className="dshsec-queue" aria-live="polite">
      <span>
        {ahead.length > 1
          ? tr.t('queue.behindMany', { project, count: ahead.length })
          : tr.t('queue.behindOne', { project })}
      </span>
      {running.workspaceId !== props.scan.workspaceId ? (
        <Button size="sm" variant="link" onClick={() => controller.selectWorkspace(running.workspaceId)}>
          {tr.t('queue.show', { project })}
        </Button>
      ) : null}
    </p>
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
                  <td className="dshsec-cell-wrap" title={typeof w.title === 'string' ? w.title : undefined}>
                    {text(w.title)}
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

/**
 * Event types whose Host message carries the information (which reviewer,
 * which file, which error). The others are fully described by their
 * localized label.
 */
const DETAILED_EVENTS: ReadonlySet<string> = new Set([
  'worker-start',
  'worker-end',
  'worker-retry',
  'worker-wrap-up',
  'hunter-dismissals-applied',
  'analysis-warning',
  'analyzer-unavailable',
  'run-failed',
  'notice',
  'evidence-discarded',
  'review-plan',
  'coverage-critic',
])

/**
 * A feed line: the localized label, plus the Host's own sentence for events
 * whose message names the task, file or error. The Host writes English, so
 * an English UI shows that sentence alone.
 */
function eventParts(tr: Translator, event: ScanEvent): { readonly label: string; readonly detail?: string } {
  const message = typeof event.message === 'string' ? event.message.trim() : ''
  const detailed = message && (DETAILED_EVENTS.has(event.type) || !tr.lookup(`activity.event.${event.type}`))
  if (!detailed) return { label: activityText(tr, event) }
  if (tr.lang === 'en') return { label: message }
  return { label: activityText(tr, event), detail: message }
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
          {props.events.map(event => {
            const { label, detail } = eventParts(tr, event)
            return (
              <li key={event.seq} className={`dshsec-feed-item dshsec-feed-item--${event.level}`}>
                <time className="dshsec-feed-time" dateTime={event.at}>
                  {formatTime(event.at, tr.intlLocale)}
                </time>
                <span className="dshsec-feed-msg" title={detail ? `${label} ${detail}` : label}>
                  {label}
                  {detail ? <span className="dshsec-feed-detail">{detail}</span> : null}
                </span>
              </li>
            )
          })}
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
          <ScanMeta
            items={[
              scan.subpath ?? tr.t('scan.wholeProject'),
              tr.t(`mode.${scan.mode}`),
              formatDateTime(scan.createdAt, tr.intlLocale),
            ]}
          />
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
      {resumable ? <p className="dshsec-muted">{tr.t('problem.interruptedBody')}</p> : null}
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
/**
 * Notices that mean a budget limit stopped scheduled AI work; only these offer
 * more budget. The Host continues exactly that work (tasks skipped with a
 * budget code) when the scan's budget grows.
 */
const BUDGET_NOTICES: ReadonlySet<string> = new Set([
  'budget-tokens',
  'budget-calls',
  'budget-time',
  'budget-exhausted',
  'hunt-budget-reserved',
  'review-skipped',
])

function formatHourMinute(value: string, locale: string): string {
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return DASH
  try {
    return new Intl.DateTimeFormat(locale, { hour: 'numeric', minute: '2-digit' }).format(date)
  } catch {
    return date.toISOString().slice(11, 16)
  }
}

/** A budget stopped scheduled AI work: say which, and continue the same scan with more of it. */
function ExtendBudgetAction(props: {
  readonly scan: ScanSummary
  readonly detail: ScanDetail
  readonly notice: ScanNotice
}) {
  const controller = useController()
  const tr = useT()
  const [busyPct, setBusyPct] = useState<number | undefined>()
  const [error, setError] = useState<RpcFailure | undefined>()
  const { budget, usage } = props.detail
  const tokensUsed = (usage?.inputTokens ?? 0) + (usage?.outputTokens ?? 0)

  const extend = async (pct: number) => {
    // Grow only the dimensions that actually bound this scan (tokens in
    // practice), so the request never raises a limit that was not reached.
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
    // No dimension ran out (work was skipped to keep a phase reserve): grow
    // tokens and AI requests together, since either can bound the next phase.
    if (!extra.addTokens && !extra.addLlmCalls && !extra.addMinutes) {
      if (isFiniteNumber(budget?.maxTokens)) extra.addTokens = Math.max(1, Math.ceil(budget.maxTokens * pct))
      if (isFiniteNumber(budget?.maxLlmCalls)) extra.addLlmCalls = Math.max(1, Math.ceil(budget.maxLlmCalls * pct))
    }
    setBusyPct(pct)
    setError(undefined)
    const result = await controller.extendScanBudget(props.scan.id, extra)
    setBusyPct(undefined)
    if (!result.ok) setError(result.error)
    // On success the scan is queued again; the overview switches to progress.
  }

  return (
    <div className="dshsec-budget-stop">
      <Callout tone="warn" live={false}>
        {noticeText(tr, props.notice)} {tr.t('budget.extend.body')}
      </Callout>
      <div className="dshsec-actions">
        <span className="dshsec-muted">{tr.t('budget.extend.title')}</span>
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
  const top = useMemo(() => (findings ? topOpenFindings(findings, TOP_FINDINGS) : []), [findings])
  const openTotal = SEVERITIES.reduce(
    (sum, sev) => sum + (isFiniteNumber(scan.counts?.[sev]) ? scan.counts[sev] : 0),
    0,
  )
  const durationMs =
    scan.startedAt && scan.finishedAt ? Date.parse(scan.finishedAt) - Date.parse(scan.startedAt) : undefined
  const notices = asArray(detail?.notices)
  const budgetStop = notices.find(n => BUDGET_NOTICES.has(n.key))
  const warnings = notices.filter(n => n !== budgetStop && n.level !== 'info')
  const infos = notices.filter(n => n !== budgetStop && n.level === 'info')

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
          <ScanMeta
            items={[
              scan.subpath ?? tr.t('scan.wholeProject'),
              isBuiltinOnly(detail) ? tr.t('newScan.builtin') : tr.t(`mode.${scan.mode}`),
              <time
                key="time"
                dateTime={scan.finishedAt ?? scan.createdAt}
                title={formatDateTime(scan.finishedAt ?? scan.createdAt, tr.intlLocale)}
              >
                {tr.t('summary.completed', {
                  time: formatRelative(scan.finishedAt ?? scan.createdAt, tr.intlLocale, now),
                })}
              </time>,
              isFiniteNumber(durationMs) && durationMs > 0
                ? tr.t('summary.duration', { duration: formatDuration(durationMs, tr.intlLocale) })
                : undefined,
            ]}
          />
          <ReviewLine review={review} />
        </div>
        <ExportMenu scanId={scan.id} />
      </header>

      {detailEntry.error ? (
        <LoadError error={detailEntry.error} onRetry={() => void controller.loadScanDetail(scan.id, true)} />
      ) : null}
      {budgetStop && detail ? <ExtendBudgetAction scan={scan} detail={detail} notice={budgetStop} /> : null}
      {noSecondOpinion ? <Callout tone="warn">{tr.t('review.secondOpinionMissing')}</Callout> : null}
      {warnings.length ? <Notices notices={warnings} /> : null}

      <SeveritySummary scan={scan} counts={counts} onSelect={showSeverity} />

      <section className="dshsec-subsection" aria-labelledby={`dshsec-top-${scan.id}`}>
        <div className="dshsec-subhead">
          <h3 className="dshsec-h3" id={`dshsec-top-${scan.id}`}>
            {tr.t('summary.top')}
          </h3>
          {findings?.length ? (
            <Button size="sm" variant="link" onClick={() => controller.setTab('findings')}>
              {tr.t('summary.viewAll', { count: formatNumber(findings.length, tr.intlLocale) })}
            </Button>
          ) : null}
        </div>
        {!findings && findingsEntry.status === 'error' && findingsEntry.error ? (
          <LoadError error={findingsEntry.error} onRetry={() => void controller.loadFindings(scan.id, true)} />
        ) : !findings ? (
          <Loading />
        ) : top.length ? (
          <ul className="dshsec-flist">
            {top.map(finding => (
              <li key={finding.id}>
                <FindingRow
                  finding={finding}
                  onSelect={() => controller.openFindingFromOverview(scan.id, finding.id)}
                />
              </li>
            ))}
          </ul>
        ) : (
          <div className="dshsec-stack-sm">
            <p>{tr.t('summary.topEmpty')}</p>
            {openTotal === 0 ? (
              <p className="dshsec-hint" role="note">
                {tr.t('summary.notSafeBody')}
              </p>
            ) : null}
          </div>
        )}
      </section>

      <CoverageSection coverage={detail?.coverage} infos={infos} tr={tr} />

      <details className="dshsec-subsection dshsec-disclosure">
        <summary>{tr.t('review.diagnostics')}</summary>
        <div className="dshsec-disclosure-body">
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
        </div>
      </details>
    </section>
  )
}

/** One line on how much of the scheduled AI review ran. Quiet when complete, a warning when not. */
function ReviewLine(props: { readonly review: ReturnType<typeof reviewOutcome> | undefined }) {
  const tr = useT()
  const { review } = props
  if (!review || review.state === 'unknown') return null
  const tone = review.state === 'failed' ? 'error' : review.state === 'partial' ? 'warn' : 'quiet'
  return (
    <p className={`dshsec-review-line is-${tone}`}>
      {tone !== 'quiet' ? <IconWarn size={14} /> : null}
      <span>
        {tr.t(`review.line.${review.state}`, {
          completed: formatNumber(review.completed, tr.intlLocale),
          planned: formatNumber(review.planned, tr.intlLocale),
        })}
      </span>
    </p>
  )
}

/** Open findings per severity as one row of counts (each opens the filtered list), and certainty underneath. */
function SeveritySummary(props: {
  readonly scan: ScanSummary
  readonly counts: ReturnType<typeof certaintyCounts> | undefined
  readonly onSelect: (severity: Severity) => void
}) {
  const tr = useT()
  const { scan, counts } = props
  return (
    <section className="dshsec-sevsum" aria-label={tr.t('summary.openBySeverity')}>
      <ul className="dshsec-sevsum-row">
        {SEVERITIES.map(severity => {
          const count = isFiniteNumber(scan.counts?.[severity]) ? scan.counts[severity] : undefined
          return (
            <li key={severity}>
              <button
                type="button"
                className={`dshsec-sevsum-item dshsec-sev--${severity}${count ? ' has-value' : ''}`}
                onClick={() => props.onSelect(severity)}
                aria-label={`${tr.t(`severity.${severity}`)}: ${count ?? DASH}`}
              >
                <span className="dshsec-sev-dot" aria-hidden="true" />
                <span className="dshsec-sevsum-count">{count ?? DASH}</span>
                <span>{tr.t(`severity.${severity}`)}</span>
              </button>
            </li>
          )
        })}
      </ul>
      <p className="dshsec-meta">
        {(['confirmed', 'open_proof_gap', 'ruled_out'] as const).map(closure => (
          <span key={closure} title={tr.t(`closure.${closure}.desc`)}>
            {tr.t(`summary.closure.${closure}`, { count: counts ? counts[closure] : DASH })}
          </span>
        ))}
        <span>{tr.t('summary.newCount', { count: counts ? counts.isNew : DASH })}</span>
      </p>
    </section>
  )
}

function analyzerLabel(tr: Translator, status: AnalyzerStatus): string {
  return tr.lookup(`analyzer.${status.id}`) ?? text(status.id)
}

/** Unavailable analyzers grouped by their localized reason: "Gitleaks, OSV-Scanner — not installed". */
function groupUnavailable(tr: Translator, analyzers: readonly AnalyzerStatus[]): string[] {
  const groups = new Map<string, string[]>()
  for (const analyzer of analyzers) {
    const reason = analyzerReasonText(tr, analyzer)
    groups.set(reason, [...(groups.get(reason) ?? []), analyzerLabel(tr, analyzer)])
  }
  return [...groups].map(([reason, names]) => tr.t('coverage.notRunItem', { names: names.join(', '), reason }))
}

/** What the scan looked at, as plain rows, then what it could not do. */
function CoverageSection(props: {
  readonly coverage: Coverage | undefined
  readonly infos: readonly ScanNotice[]
  readonly tr: Translator
}) {
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
  // The "Unassigned files" row already says how many source files were in no part (and why), so that gap is not repeated.
  const shownElsewhere = (gap: Diagnostic) =>
    gap.code === 'analyzer-unavailable' ||
    (gap.code === 'unassigned-files' && isFiniteNumber(coverage.unassignedFiles) && coverage.unassignedFiles > 0)
  const knownGaps = (coverage.gapDetails ?? []).filter(
    gap => !shownElsewhere(gap) && tr.lookup(`diagnostic.gap.${gap.code}`) !== undefined,
  )
  const unknownGapCount = (coverage.gapDetails ?? []).filter(
    gap => !shownElsewhere(gap) && tr.lookup(`diagnostic.gap.${gap.code}`) === undefined,
  ).length
  const technical = [
    ...unavailable.filter(a => a.reason).map(a => `${analyzerLabel(tr, a)}: ${a.reason}`),
    ...(coverage.gapDetails ?? []).filter(gap => !shownElsewhere(gap)).map(gap => gap.fallback),
  ]
  const files = coverage.files
  const endpoints = coverage.endpoints
  const tasks = coverage.tasks
  const aiUsed = (files?.readByAi ?? 0) > 0 || (tasks?.planned ?? 0) > 0
  return (
    <section className="dshsec-subsection dshsec-coverage" aria-labelledby="dshsec-coverage-title">
      <h3 className="dshsec-h3" id="dshsec-coverage-title">
        {tr.t('coverage.title')}
      </h3>
      <dl className="dshsec-kv">
        <div className="dshsec-kv-row">
          <dt>{tr.t('coverage.files')}</dt>
          <dd className="dshsec-num">
            {tr.t(aiUsed ? 'coverage.filesValue' : 'coverage.filesValueBuiltin', {
              analyzed: formatNumber(files?.analyzed, locale),
              read: formatNumber(files?.readByAi, locale),
              total: formatNumber(files?.total, locale),
            })}
            {isFiniteNumber(files?.excluded) && files.excluded > 0 ? (
              <span className="dshsec-muted">
                {' · '}
                {tr.t('coverage.excluded', { count: formatNumber(files.excluded, locale) })}
              </span>
            ) : null}
          </dd>
        </div>
        <div className="dshsec-kv-row">
          <dt>{tr.t('coverage.endpoints')}</dt>
          <dd className="dshsec-num">
            {tr.t(aiUsed ? 'coverage.endpointsValue' : 'coverage.endpointsFound', {
              reviewed: formatNumber(endpoints?.reviewed, locale),
              total: formatNumber(endpoints?.total, locale),
            })}
          </dd>
        </div>
        {aiUsed ? (
          <div className="dshsec-kv-row">
            <dt>{tr.t('coverage.tasks')}</dt>
            <dd className="dshsec-num">
              {tr.t('coverage.tasksValue', {
                completed: formatNumber(tasks?.completed, locale),
                failed: formatNumber(tasks?.failed, locale),
                skipped: formatNumber(tasks?.skipped, locale),
              })}
            </dd>
          </div>
        ) : null}
        <LedgerRows coverage={coverage} tr={tr} />
        {unavailable.length ? (
          <div className="dshsec-kv-row">
            <dt>{tr.t('coverage.unavailable')}</dt>
            <dd>
              <ul className="dshsec-plain-list">
                {groupUnavailable(tr, unavailable).map(line => (
                  <li key={line}>{line}</li>
                ))}
              </ul>
            </dd>
          </div>
        ) : null}
        {isFiniteNumber(coverage.discardedUnverifiable) && coverage.discardedUnverifiable > 0 ? (
          <div className="dshsec-kv-row">
            <dt>{tr.t('coverage.dropped')}</dt>
            <dd>{tr.t('coverage.discarded', { count: formatNumber(coverage.discardedUnverifiable, locale) })}</dd>
          </div>
        ) : null}
      </dl>
      <LedgerList coverage={coverage} tr={tr} />
      {knownGaps.length || unknownGapCount || props.infos.length ? (
        <div className="dshsec-stack-sm">
          <h4 className="dshsec-h4">{tr.t('coverage.gaps')}</h4>
          <ul className="dshsec-list">
            {knownGaps.map((gap, index) => (
              // biome-ignore lint/suspicious/noArrayIndexKey: immutable diagnostic order, codes may repeat
              <li key={`${gap.code}:${index}`}>{diagnosticText(tr, gap)}</li>
            ))}
            {props.infos.map((notice, index) => (
              // biome-ignore lint/suspicious/noArrayIndexKey: notices are append-only
              <li key={`notice-${notice.key}-${index}`}>{noticeText(tr, notice)}</li>
            ))}
            {unknownGapCount > 0 ? <li>{tr.t('diagnostic.otherGaps', { count: unknownGapCount })}</li> : null}
          </ul>
        </div>
      ) : null}
      {!coverage.gapDetails?.length && gaps.length ? (
        // Scans from older versions carry only English gap text: keep it out of localized primary copy.
        <div className="dshsec-stack-sm">
          <h4 className="dshsec-h4">{tr.t('coverage.gaps')}</h4>
          <details className="dshsec-disclosure">
            <summary>{tr.t('diagnostic.legacy')}</summary>
            <ul className="dshsec-list dshsec-technical">
              {gaps.map(gap => (
                <li key={gap}>{gap}</li>
              ))}
            </ul>
          </details>
        </div>
      ) : null}
      {technical.length ? (
        <details className="dshsec-disclosure">
          <summary>{tr.t('diagnostic.details')}</summary>
          <ul className="dshsec-list dshsec-technical">
            {technical.map((line, index) => (
              // biome-ignore lint/suspicious/noArrayIndexKey: immutable technical order
              <li key={index}>{line}</li>
            ))}
          </ul>
        </details>
      ) : null}
    </section>
  )
}
