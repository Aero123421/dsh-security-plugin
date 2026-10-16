import { type KeyboardEvent, type ReactNode, useCallback, useEffect, useId, useMemo, useRef, useState } from 'react'
import type { FindingSummary, ScanSummary } from '../../shared/contracts.ts'
import { FINDING_SOURCES, type FindingSource, SEVERITIES, TRIAGE_STATES } from '../../shared/domain.ts'
import { Button } from '../components/Button.tsx'
import { Select } from '../components/Field.tsx'
import { useController, usePageWidth, useSecurity, useT } from '../context.tsx'
import type { Loadable } from '../controller.ts'
import { CLOSURES, DEFAULT_FINDINGS_FILTER, filterFindings, isDefaultFilter, toggleIn } from '../findings.ts'
import { useWorkspaceScans } from '../hooks.ts'
import { IconArrowLeft, IconSearch } from '../icons.tsx'
import { pollableScan, resultsScan } from '../selectors.ts'
import { FindingDetailView } from './FindingDetail.tsx'
import { AvailabilityGate, EmptyState, FindingRow, LoadError, Loading, ViewingBanner } from './shared.tsx'

const IDLE: Loadable<readonly FindingSummary[]> = { status: 'idle' }
/** Main-area width at which list and detail sit side by side, each scrolling on its own. */
export const SPLIT_MIN_WIDTH = 960
export const FINDINGS_PAGE_SIZE = 200

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
    <div className="dshsec-stack dshsec-findings-body">
      <ViewingBanner scan={scan} />
      {running ? <p className="dshsec-hint">{tr.t('findings.running')}</p> : null}
      <ScanFindings scan={scan} />
    </div>
  )
}

function rowsOf(list: HTMLElement | null): HTMLButtonElement[] {
  return list ? [...list.querySelectorAll<HTMLButtonElement>('[data-finding-row]')] : []
}

function ScanFindings(props: { readonly scan: ScanSummary }) {
  const controller = useController()
  const tr = useT()
  const { scan } = props
  const entry = useSecurity(s => s.findings[scan.id] ?? IDLE)
  const filter = useSecurity(s => s.filter)
  const selection = useSecurity(s => s.selectedFinding)
  const selectedId = selection?.scanId === scan.id ? selection.findingId : undefined
  const split = usePageWidth() >= SPLIT_MIN_WIDTH
  const listRef = useRef<HTMLUListElement>(null)
  const detailRef = useRef<HTMLDivElement>(null)
  /** Keyboard cursor in the list (narrow layout: focus only; split layout: follows selection). */
  const [cursorId, setCursorId] = useState<string | undefined>(selectedId)
  /** Bumped by Enter so the detail heading takes focus once it has loaded (split layout). */
  const [focusToken, setFocusToken] = useState(0)

  useEffect(() => {
    void controller.loadFindings(scan.id)
  }, [controller, scan.id])

  const all = entry.value
  const visible = useMemo(() => (all ? filterFindings(all, filter) : []), [all, filter])
  const [page, setPage] = useState({ findings: visible, limit: FINDINGS_PAGE_SIZE })
  const limit = page.findings === visible ? page.limit : FINDINGS_PAGE_SIZE
  const rendered = useMemo(() => visible.slice(0, limit), [visible, limit])

  useEffect(() => {
    if (selection && (selection.scanId !== scan.id || (all && !all.some(f => f.id === selection.findingId)))) {
      controller.selectFinding(undefined)
    }
  }, [controller, selection, scan.id, all])

  const activeId =
    (cursorId && rendered.some(f => f.id === cursorId) && cursorId) ||
    (selectedId && rendered.some(f => f.id === selectedId) && selectedId) ||
    rendered[0]?.id

  // Keep the selected row in view, and start the detail pane at its top, when the selection changes.
  useEffect(() => {
    if (!selectedId) return
    const row = rowsOf(listRef.current).find(el => el.dataset.findingRow === selectedId)
    row?.scrollIntoView?.({ block: 'nearest' })
    if (split) detailRef.current?.scrollTo?.({ top: 0 })
  }, [selectedId, split])

  const focusRow = useCallback((id: string | undefined) => {
    requestAnimationFrame(() => {
      const row = rowsOf(listRef.current).find(el => el.dataset.findingRow === id)
      row?.focus()
      row?.scrollIntoView?.({ block: 'nearest' })
    })
  }, [])

  const back = () => {
    const id = selectedId
    controller.selectFinding(undefined)
    setCursorId(id)
    // Return focus to the row that opened the detail.
    focusRow(id)
  }

  /** Show a finding. From the keyboard (Enter) focus moves into the detail; a click keeps it on the list. */
  const open = useCallback(
    (id: string, moveFocus: boolean) => {
      setCursorId(id)
      controller.selectFinding(id, scan.id)
      setFocusToken(moveFocus ? t => t + 1 : 0)
    },
    [controller, scan.id],
  )

  const selectRow = useCallback((finding: FindingSummary) => open(finding.id, !split), [open, split])

  /** Esc inside the detail pane returns to the list row (split layout). */
  const onDetailKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    if (!split || event.key !== 'Escape' || event.defaultPrevented) return
    event.preventDefault()
    focusRow(activeId)
  }

  const onRowKeyDown = useCallback(
    (event: KeyboardEvent<HTMLButtonElement>, finding: FindingSummary) => {
      const index = rendered.findIndex(f => f.id === finding.id)
      let next = -1
      if (event.key === 'ArrowDown') next = Math.min(rendered.length - 1, index + 1)
      else if (event.key === 'ArrowUp') next = Math.max(0, index - 1)
      else if (event.key === 'Home') next = 0
      else if (event.key === 'End') next = rendered.length - 1
      else if (event.key === 'Enter' || event.key === ' ') {
        event.preventDefault()
        open(finding.id, true)
        return
      } else if (event.key === 'Escape' && split && controller.store.getState().selectedFinding) {
        event.preventDefault()
        controller.selectFinding(undefined)
        return
      }
      if (next < 0) return
      event.preventDefault()
      const target = rendered[next]
      if (!target) return
      setCursorId(target.id)
      // Side by side, the detail follows the keyboard like a mail list.
      if (split) {
        controller.selectFinding(target.id, scan.id)
        setFocusToken(0)
      }
      focusRow(target.id)
    },
    [controller, rendered, split, open, focusRow, scan.id],
  )

  if (!all && entry.status === 'error' && entry.error) {
    return <LoadError error={entry.error} onRetry={() => void controller.loadFindings(scan.id, true)} />
  }
  if (!all) return <Loading />

  const showDetail = Boolean(selectedId)
  const listHidden = showDetail && !split

  return (
    <div className={`dshsec-findings${split ? ' is-split' : ''}`}>
      {!listHidden ? (
        <div className="dshsec-findings-list">
          <FilterBar total={all.length} shown={rendered.length} />
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
            <>
              <ul
                className="dshsec-flist"
                aria-label={tr.t('findings.list')}
                aria-describedby={`${scan.id}-kbd`}
                ref={listRef}
              >
                {rendered.map(finding => (
                  <li key={finding.id} data-finding-id={finding.id}>
                    <FindingRow
                      finding={finding}
                      selected={split && finding.id === selectedId}
                      tabIndex={finding.id === activeId ? 0 : -1}
                      onSelect={selectRow}
                      onKeyDown={onRowKeyDown}
                    />
                  </li>
                ))}
              </ul>
              {rendered.length < visible.length ? (
                <Button size="sm" onClick={() => setPage({ findings: visible, limit: limit + FINDINGS_PAGE_SIZE })}>
                  {tr.t('findings.showMore')}
                </Button>
              ) : null}
              <p className="dshsec-visually-hidden" id={`${scan.id}-kbd`}>
                {tr.t('findings.keyboardHint')}
              </p>
            </>
          )}
        </div>
      ) : null}
      {showDetail && selectedId ? (
        // biome-ignore lint/a11y/noStaticElementInteractions: Esc returns keyboard users to the list
        <div className="dshsec-findings-detail" ref={detailRef} onKeyDown={onDetailKeyDown}>
          {!split ? (
            <Button variant="ghost" size="sm" className="dshsec-back" icon={<IconArrowLeft size={16} />} onClick={back}>
              {tr.t('detail.back')}
            </Button>
          ) : null}
          <FindingDetailView scan={scan} findingId={selectedId} focusOnOpen={split ? focusToken : 1} />
        </div>
      ) : split ? (
        <div className="dshsec-findings-detail dshsec-findings-detail--empty">
          <p>{visible.length ? tr.t('findings.selectHint') : DASH_SPACE}</p>
        </div>
      ) : null}
    </div>
  )
}

const DASH_SPACE = ' '

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
