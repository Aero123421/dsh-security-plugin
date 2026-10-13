import { type ReactNode, useEffect, useId, useMemo, useRef } from 'react'
import type { FindingSummary, ScanSummary } from '../../shared/contracts.ts'
import { FINDING_SOURCES, type FindingSource, SEVERITIES, TRIAGE_STATES } from '../../shared/domain.ts'
import { Button } from '../components/Button.tsx'
import { Select } from '../components/Field.tsx'
import { useController, usePageWidth, useSecurity, useT } from '../context.tsx'
import type { Loadable } from '../controller.ts'
import { CLOSURES, DEFAULT_FINDINGS_FILTER, filterFindings, isDefaultFilter, toggleIn } from '../findings.ts'
import { useWorkspaceScans } from '../hooks.ts'
import { IconSearch } from '../icons.tsx'
import { pollableScan, resultsScan } from '../selectors.ts'
import { FindingDetailView } from './FindingDetail.tsx'
import { AvailabilityGate, EmptyState, FindingRow, LoadError, Loading, ViewingBanner } from './shared.tsx'

const IDLE: Loadable<readonly FindingSummary[]> = { status: 'idle' }
/** Main-area width at which list and detail sit side by side. */
export const SPLIT_MIN_WIDTH = 1100

export function FindingsView() {
  return (
    <AvailabilityGate>
      <FindingsBody />
    </AvailabilityGate>
  )
}

function FindingsBody() {
  const controller = useController()
  const tr = useT()
  const viewScanId = useSecurity(s => s.viewScanId)
  const { entry, scans } = useWorkspaceScans()
  const scan = useMemo(() => resultsScan(scans, viewScanId), [scans, viewScanId])
  const running = !viewScanId && pollableScan(scans) !== undefined

  if (!entry.value && entry.status === 'error' && entry.error) {
    return <LoadError error={entry.error} onRetry={() => void controller.refreshScans()} />
  }
  if (!entry.value) return <Loading />
  if (!scan) {
    return (
      <EmptyState
        title={tr.t('findings.noScan')}
        action={
          <Button variant="primary" onClick={() => controller.setTab('overview')}>
            {tr.t('tab.overview')}
          </Button>
        }
      />
    )
  }
  return (
    <div className="dshsec-stack">
      <ViewingBanner scan={scan} />
      {running ? <p className="dshsec-muted">{tr.t('findings.running')}</p> : null}
      <ScanFindings scan={scan} />
    </div>
  )
}

function ScanFindings(props: { readonly scan: ScanSummary }) {
  const controller = useController()
  const tr = useT()
  const { scan } = props
  const entry = useSecurity(s => s.findings[scan.id] ?? IDLE)
  const filter = useSecurity(s => s.filter)
  const selectedId = useSecurity(s => s.selectedFindingId)
  const split = usePageWidth() >= SPLIT_MIN_WIDTH
  const listRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    void controller.loadFindings(scan.id)
  }, [controller, scan.id])

  const all = entry.value
  const visible = useMemo(() => (all ? filterFindings(all, filter) : []), [all, filter])

  const back = () => {
    const id = selectedId
    controller.selectFinding(undefined)
    // Return focus to the row that opened the detail.
    requestAnimationFrame(() => {
      const rows = listRef.current?.querySelectorAll<HTMLElement>('[data-finding-id]') ?? []
      for (const row of rows) {
        if (row.dataset.findingId === id) row.querySelector<HTMLElement>('button')?.focus()
      }
    })
  }

  if (!all && entry.status === 'error' && entry.error) {
    return <LoadError error={entry.error} onRetry={() => void controller.loadFindings(scan.id, true)} />
  }
  if (!all) return <Loading />

  const showDetail = Boolean(selectedId)
  const listHidden = showDetail && !split

  return (
    <div className={`dshsec-findings ${split ? 'is-split' : ''}`}>
      {!listHidden ? (
        <div className="dshsec-findings-list" ref={listRef}>
          <FilterBar total={all.length} shown={visible.length} />
          {all.length === 0 ? (
            <p className="dshsec-muted">{tr.t('findings.emptyScan')}</p>
          ) : visible.length === 0 ? (
            <div className="dshsec-stack-sm">
              <p className="dshsec-muted">{tr.t('findings.empty')}</p>
              <div>
                <Button size="sm" onClick={() => controller.setFilter(DEFAULT_FINDINGS_FILTER)}>
                  {tr.t('findings.reset')}
                </Button>
              </div>
            </div>
          ) : (
            <ul className="dshsec-flist" aria-label={tr.t('findings.list')}>
              {visible.map(finding => (
                <li key={finding.id} data-finding-id={finding.id}>
                  <FindingRow
                    finding={finding}
                    selected={finding.id === selectedId}
                    onSelect={() => controller.selectFinding(finding.id)}
                  />
                </li>
              ))}
            </ul>
          )}
        </div>
      ) : null}
      {showDetail && selectedId ? (
        <div className="dshsec-findings-detail">
          {!split ? (
            <Button variant="ghost" size="sm" className="dshsec-back" onClick={back}>
              ← {tr.t('detail.back')}
            </Button>
          ) : null}
          <FindingDetailView scan={scan} findingId={selectedId} focusOnOpen={!split} />
        </div>
      ) : split ? (
        <div className="dshsec-findings-detail dshsec-findings-detail--empty">
          <p className="dshsec-muted">{tr.t('findings.selectHint')}</p>
        </div>
      ) : null}
    </div>
  )
}

function FilterBar(props: { readonly total: number; readonly shown: number }) {
  const controller = useController()
  const tr = useT()
  const filter = useSecurity(s => s.filter)
  const searchId = useId()

  const sourceOptions = [
    { value: 'all' as const, label: tr.t('findings.allSources') },
    ...FINDING_SOURCES.map(source => ({ value: source, label: tr.t(`source.${source}`) })),
  ]

  return (
    <div className="dshsec-filters">
      <div className="dshsec-search">
        <label htmlFor={searchId} className="dshsec-visually-hidden">
          {tr.t('findings.search')}
        </label>
        <IconSearch size={16} />
        <input
          id={searchId}
          type="search"
          value={filter.text}
          placeholder={tr.t('findings.searchPlaceholder')}
          onChange={event => {
            const textValue = event.target.value
            controller.setFilter(f => ({ ...f, text: textValue }))
          }}
        />
      </div>
      <ChipGroup label={tr.t('findings.severity')}>
        {SEVERITIES.map(severity => (
          <Chip
            key={severity}
            pressed={filter.severities.includes(severity)}
            tone={severity}
            onToggle={() =>
              controller.setFilter(f => ({ ...f, severities: toggleIn(f.severities, severity, SEVERITIES) }))
            }
          >
            {tr.t(`severity.${severity}`)}
          </Chip>
        ))}
      </ChipGroup>
      <ChipGroup label={tr.t('findings.closure')}>
        {CLOSURES.map(closure => (
          <Chip
            key={closure}
            pressed={filter.closures.includes(closure)}
            onToggle={() => controller.setFilter(f => ({ ...f, closures: toggleIn(f.closures, closure, CLOSURES) }))}
          >
            {tr.t(`closure.${closure}`)}
          </Chip>
        ))}
      </ChipGroup>
      <ChipGroup label={tr.t('findings.triage')}>
        {TRIAGE_STATES.map(triage => (
          <Chip
            key={triage}
            pressed={filter.triage.includes(triage)}
            onToggle={() => controller.setFilter(f => ({ ...f, triage: toggleIn(f.triage, triage, TRIAGE_STATES) }))}
          >
            {tr.t(`triage.${triage}`)}
          </Chip>
        ))}
      </ChipGroup>
      <div className="dshsec-filters-foot">
        <Select<FindingSource | 'all'>
          ariaLabel={tr.t('findings.source')}
          value={filter.source}
          options={sourceOptions}
          onChange={source => controller.setFilter(f => ({ ...f, source }))}
        />
        <span className="dshsec-muted dshsec-count" aria-live="polite">
          {tr.t('findings.count', { shown: props.shown, total: props.total })}
        </span>
        {!isDefaultFilter(filter) ? (
          <Button size="sm" variant="link" onClick={() => controller.setFilter(DEFAULT_FINDINGS_FILTER)}>
            {tr.t('findings.reset')}
          </Button>
        ) : null}
      </div>
    </div>
  )
}

function ChipGroup(props: { readonly label: string; readonly children: ReactNode }) {
  const id = useId()
  return (
    <div className="dshsec-chipgroup">
      <span className="dshsec-chipgroup-label" id={id}>
        {props.label}
      </span>
      {/* biome-ignore lint/a11y/useSemanticElements: toggle buttons grouped under a visible label */}
      <div className="dshsec-chips" role="group" aria-labelledby={id}>
        {props.children}
      </div>
    </div>
  )
}

function Chip(props: {
  readonly pressed: boolean
  readonly onToggle: () => void
  readonly tone?: string
  readonly children: ReactNode
}) {
  return (
    <button
      type="button"
      className={`dshsec-chip ${props.tone ? `dshsec-chip--${props.tone}` : ''}`}
      aria-pressed={props.pressed}
      onClick={props.onToggle}
    >
      {props.children}
    </button>
  )
}
