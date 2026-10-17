/**
 * The browser half's single source of truth. Components read slices of
 * `controller.store` with `useStoreSelector` and call actions; every Host
 * call, cache, timer, and DSH service interaction lives here.
 */

import {
  type Bootstrap,
  type FindingDetail,
  type FindingSummary,
  type ProviderOption,
  type ReportFormat,
  type RpcFailure,
  type RpcResult,
  type ScanDetail,
  type ScanEstimate,
  type ScanEvent,
  type ScanSummary,
  type ToolkitEntry,
  type WorkspaceSummary,
  CONTRACT_VERSION,
} from '../shared/contracts.ts'
import type { ScanMode, TriageState } from '../shared/domain.ts'
import type { ModelRef, SecuritySettings, SettingsPatch } from '../shared/settings.ts'
import { ABORTED_ERROR, failure, type SecurityApi } from './api.ts'
import { copyText, downloadFile } from './download.ts'
import { type DshLayout, type DshUiWorkspace, type DshWorkspaces, SECURITY_SLOT_ID } from './dsh.ts'
import { DEFAULT_FINDINGS_FILTER, type FindingsFilter } from './findings.ts'
import { type Language, type MessageKey, resolveLanguage } from './i18n.ts'
import { isPollableStatus, mergeSummary, resultsScan, sortScans } from './selectors.ts'
import {
  buildPatch,
  draftFromSettings,
  enforceHighRisk,
  isDraftDirty,
  isPatchEmpty,
  rebaseDraft,
  type SettingsDraft,
  validateDraft,
} from './settingsForm.ts'
import { createStore, type Store } from './store.ts'

export type TabId = 'overview' | 'findings' | 'history' | 'settings'
export const TAB_IDS: readonly TabId[] = ['overview', 'findings', 'history', 'settings']

export interface Loadable<T> {
  readonly status: 'idle' | 'loading' | 'ready' | 'error'
  readonly value?: T
  readonly error?: RpcFailure
}

export type Tone = 'info' | 'success' | 'warn' | 'error'

export type FlashMessage =
  | { readonly id: number; readonly tone: Tone; readonly key: MessageKey }
  | { readonly id: number; readonly tone: Tone; readonly error: RpcFailure }

export interface NewScanRequest {
  readonly subpath?: string
  readonly workspaceId?: string
  readonly mode?: ScanMode
}

export interface StartScanInput {
  readonly subpath?: string
  readonly workspaceId: string
  readonly mode: ScanMode
  /** Grant `privacy.sendCodeToModel` first (the user ticked the consent box). */
  readonly consent?: boolean
  /** `false` runs only the built-in analyzers: no model, no consent. */
  readonly aiReview?: boolean
  /** Save this route as `models.default` first (picked inline in the dialog). */
  readonly model?: ModelRef
}

export interface SettingsFormState {
  readonly base: SettingsDraft
  readonly draft: SettingsDraft
  readonly revision: number
  readonly saving: boolean
  /** Outcome of the last save attempt. */
  readonly result?:
    | { readonly tone: Tone; readonly key: MessageKey }
    | { readonly tone: Tone; readonly error: RpcFailure }
}

export interface SecurityState {
  readonly bootstrap: Loadable<Bootstrap>
  readonly workspaces: Loadable<readonly WorkspaceSummary[]>
  readonly workspaceId: string | undefined
  readonly addingProject: boolean
  /** Scan lists by workspace id, newest first. */
  readonly scans: Readonly<Record<string, Loadable<readonly ScanSummary[]>>>
  readonly scansHasMore: Readonly<Record<string, boolean>>
  /** A scan picked in History; undefined follows the latest scan. */
  readonly viewScanId: string | undefined
  readonly details: Readonly<Record<string, Loadable<ScanDetail>>>
  readonly events: Readonly<Record<string, readonly ScanEvent[]>>
  readonly eventsErrors: Readonly<Record<string, RpcFailure>>
  readonly eventsLoading: Readonly<Record<string, boolean>>
  readonly findings: Readonly<Record<string, Loadable<readonly FindingSummary[]>>>
  /** Keyed by `findingKey(scanId, findingId)`. */
  readonly findingDetails: Readonly<Record<string, Loadable<FindingDetail>>>
  readonly selectedFinding: { readonly scanId: string; readonly findingId: string } | undefined
  readonly filter: FindingsFilter
  readonly tab: TabId
  readonly newScan: NewScanRequest | undefined
  readonly models: Loadable<readonly ProviderOption[]>
  readonly toolkit: Loadable<readonly ToolkitEntry[]>
  readonly form: SettingsFormState | undefined
  readonly dshLocale: string
  readonly language: Language
  readonly flash: FlashMessage | undefined
}

export interface ControllerHost {
  layout(): DshLayout | undefined
  uiWorkspace(): DshUiWorkspace | undefined
  workspaces(): DshWorkspaces | undefined
  readonly isLoopback: boolean
}

export type AddProjectResult =
  | { readonly workspaceId: string }
  | { readonly error: 'project.addFailed' | 'project.refreshFailed' }
  | undefined

export interface ControllerOptions {
  readonly api: SecurityApi
  readonly host?: Partial<ControllerHost>
  readonly dshLocale?: string
  /** Defaults to the global document (visibility, downloads). */
  readonly doc?: Document
  /** Per-viewer convenience storage; defaults to `localStorage` when usable. */
  readonly storage?: Pick<Storage, 'getItem' | 'setItem'> | null
}

/** Poll intervals for an active scan. */
export const POLL_VISIBLE_MS = 1500
export const POLL_HIDDEN_MS = 10_000
export const SCAN_PAGE_SIZE = 50
export const MAX_EVENTS = 200
const FLASH_MS = 6000
export const ESTIMATE_TTL_MS = 30_000
/** Showing the page again refreshes scans at most this often. */
export const REVALIDATE_MS = 3000
const WORKSPACE_KEY = 'dsh-security:workspace'

export function findingKey(scanId: string, findingId: string): string {
  return `${scanId}\u0000${findingId}`
}

const IDLE: Loadable<never> = { status: 'idle' }

function loading<T>(prev: Loadable<T> | undefined): Loadable<T> {
  return prev?.value !== undefined ? { status: 'loading', value: prev.value } : { status: 'loading' }
}

function errored<T>(prev: Loadable<T> | undefined, error: RpcFailure): Loadable<T> {
  return prev?.value !== undefined ? { status: 'error', value: prev.value, error } : { status: 'error', error }
}

function settleLoadable<T>(prev: Loadable<T> | undefined, result: RpcResult<T>): Loadable<T> {
  return result.ok ? { status: 'ready', value: result.value } : errored(prev, result.error)
}

function asList<T>(value: unknown): readonly T[] {
  return Array.isArray(value) ? (value as T[]) : []
}

interface Watcher {
  refs: number
  timer: ReturnType<typeof setTimeout> | undefined
  abort: AbortController | undefined
  stopped: boolean
}

export interface SecurityController {
  readonly store: Store<SecurityState>
  readonly api: SecurityApi
  readonly host: ControllerHost

  /** Load bootstrap and workspaces once (idempotent). */
  ensureLoaded(): void
  /**
   * Re-fetch everything visible (after a reconnect or on Retry). Starts a new
   * request generation: responses to requests issued before it are discarded.
   */
  reload(): Promise<void>
  /** Refresh workspaces and scans when the page is shown again (throttled). */
  revalidate(): void
  /**
   * Fetch the bootstrap. Plain calls join an in-flight request; `force` starts
   * a new one that supersedes it (use after a reconnect, conflict or change).
   */
  reloadBootstrap(options?: { readonly force?: boolean }): Promise<RpcResult<Bootstrap>>
  refreshWorkspaces(force?: boolean): Promise<void>
  refreshScans(workspaceId?: string, force?: boolean): Promise<void>
  loadMoreScans(workspaceId?: string): Promise<void>
  setDshLocale(locale: string): void
  contractMismatch(): boolean

  canAddProject(): boolean
  addProjectFolder(signal?: AbortSignal): Promise<AddProjectResult>
  selectWorkspace(workspaceId: string): void
  setTab(tab: TabId): void
  viewScan(scanId: string | undefined): void
  selectFinding(findingId: string | undefined, scanId?: string): void
  setFilter(update: FindingsFilter | ((prev: FindingsFilter) => FindingsFilter)): void
  openFindingFromOverview(scanId: string, findingId: string): void

  openNewScan(request?: NewScanRequest): void
  closeNewScan(): void
  estimate(
    workspaceId: string,
    mode: ScanMode,
    signal?: AbortSignal,
    subpath?: string,
  ): Promise<RpcResult<ScanEstimate>>
  startScan(input: StartScanInput): Promise<RpcResult<{ scanId: string }>>
  quickRescan(
    workspaceId: string,
    subpath?: string,
    mode?: ScanMode,
  ): Promise<RpcResult<{ scanId: string }> | undefined>

  loadScanDetail(scanId: string, force?: boolean): Promise<void>
  loadScanEvents(scanId: string, force?: boolean): Promise<void>
  watchScan(scanId: string): () => void
  pauseScan(scanId: string): Promise<RpcResult<ScanSummary>>
  resumeScan(scanId: string): Promise<RpcResult<ScanSummary>>
  extendScanBudget(
    scanId: string,
    add: { addTokens?: number; addLlmCalls?: number; addMinutes?: number },
  ): Promise<RpcResult<ScanSummary>>
  cancelScan(scanId: string): Promise<RpcResult<ScanSummary>>
  deleteScan(scanId: string): Promise<RpcResult<{ deleted: boolean }>>
  exportReport(scanId: string, format: ReportFormat): Promise<RpcResult<unknown>>

  loadFindings(scanId: string, force?: boolean): Promise<void>
  loadFinding(scanId: string, findingId: string, force?: boolean): Promise<void>
  setTriage(input: {
    scanId: string
    findingId: string
    triage: TriageState
    note?: string
  }): Promise<RpcResult<FindingSummary>>
  canFixInChat(): boolean
  fixInChat(input: { workspaceId: string; scanId: string; findingId: string }): Promise<RpcResult<unknown>>
  copyFixPrompt(scanId: string, findingId: string): Promise<RpcResult<unknown>>

  loadModels(force?: boolean): Promise<void>
  loadToolkit(force?: boolean): Promise<void>
  installTool(toolId: ToolkitEntry['id']): Promise<RpcResult<ToolkitEntry>>
  updateDraft(update: (draft: SettingsDraft) => SettingsDraft): void
  discardDraft(): void
  saveSettings(): Promise<RpcResult<unknown> | undefined>
  updateSettings(patch: SettingsPatch): Promise<RpcResult<{ settings: SecuritySettings; revision: number }>>

  canOpenPage(): boolean
  openSecurityPage(close?: () => void): void
  flash(message: { tone: Tone; key: MessageKey } | { tone: Tone; error: RpcFailure }): void
  dismissFlash(): void
  dispose(): void
}

export function createController(options: ControllerOptions): SecurityController {
  const { api } = options
  const doc: Document | undefined = options.doc ?? (typeof document !== 'undefined' ? document : undefined)
  const storage = options.storage === undefined ? defaultStorage() : options.storage
  const host: ControllerHost = {
    layout: () => options.host?.layout?.(),
    uiWorkspace: () => options.host?.uiWorkspace?.(),
    workspaces: () => options.host?.workspaces?.(),
    isLoopback: options.host?.isLoopback ?? true,
  }
  const dshLocale = options.dshLocale ?? 'en'

  const store = createStore<SecurityState>({
    bootstrap: IDLE,
    workspaces: IDLE,
    workspaceId: readStorage(storage, WORKSPACE_KEY),
    addingProject: false,
    scans: {},
    scansHasMore: {},
    viewScanId: undefined,
    details: {},
    events: {},
    eventsErrors: {},
    eventsLoading: {},
    findings: {},
    findingDetails: {},
    selectedFinding: undefined,
    filter: DEFAULT_FINDINGS_FILTER,
    tab: 'overview',
    newScan: undefined,
    models: IDLE,
    toolkit: IDLE,
    form: undefined,
    dshLocale,
    language: resolveLanguage(undefined, dshLocale),
    flash: undefined,
  })
  const get = store.getState
  const set = store.setState

  let loaded = false
  let lastRevalidate = 0
  let disposed = false
  let flashSeq = 0
  let flashTimer: ReturnType<typeof setTimeout> | undefined
  const watchers = new Map<string, Watcher>()
  const estimateCache = new Map<string, { readonly value: ScanEstimate; readonly at: number }>()
  let estimateGeneration = 0
  function invalidateEstimates(): void {
    estimateGeneration++
    estimateCache.clear()
  }
  const inflight = new Map<string, { readonly gen: number; readonly promise: Promise<unknown> }>()
  const generations = new Map<string, number>()
  const deletedScans = new Set<string>()
  const loadedEvents = new Set<string>()

  function invalidateRead(key: string): void {
    generations.set(key, (generations.get(key) ?? 0) + 1)
    inflight.delete(key)
  }

  function activeScan(scanId: string): boolean {
    return !disposed && !deletedScans.has(scanId)
  }

  function abortedResult(): RpcResult<never> {
    return { ok: false, error: failure(ABORTED_ERROR, 'This view is no longer active.') }
  }
  /**
   * Highest settings revision this page has applied. Bootstraps and save
   * results carrying an older revision never replace newer settings.
   */
  let knownRevision = Number.NEGATIVE_INFINITY

  /**
   * Coalesce identical concurrent loads. `force` starts a new generation for
   * `key` instead of joining the in-flight request; `run` checks `isCurrent()`
   * after every await and drops its result once a newer generation (or
   * dispose) has superseded it.
   */
  function once<T>(key: string, run: (isCurrent: () => boolean) => Promise<T>, force = false): Promise<T> {
    const pending = inflight.get(key)
    if (pending && !force) return pending.promise as Promise<T>
    const gen = (generations.get(key) ?? 0) + 1
    generations.set(key, gen)
    const isCurrent = () => !disposed && generations.get(key) === gen
    const promise = run(isCurrent).finally(() => {
      if (inflight.get(key)?.gen === gen) inflight.delete(key)
    })
    inflight.set(key, { gen, promise })
    return promise
  }

  // -------------------------------------------------------------------------
  // Bootstrap, settings form, language
  // -------------------------------------------------------------------------

  function revisionOf(value: unknown): number {
    return typeof value === 'number' && Number.isFinite(value) ? value : 0
  }

  function applyBootstrap(incoming: Bootstrap): void {
    let bootstrap = incoming
    const current = get().bootstrap.value
    if (current && revisionOf(incoming.settingsRevision) < knownRevision) {
      // A response read before a newer save: keep its other fields, not its settings.
      bootstrap = { ...incoming, settings: current.settings, settingsRevision: current.settingsRevision }
    }
    knownRevision = Math.max(knownRevision, revisionOf(bootstrap.settingsRevision))
    set(s => {
      const settings = bootstrap.settings
      const revision = revisionOf(bootstrap.settingsRevision)
      const base = draftFromSettings(settings)
      let form: SettingsFormState
      if (!s.form) form = { base, draft: base, revision, saving: false }
      else if (s.form.revision === revision && JSON.stringify(s.form.base) === JSON.stringify(base)) form = s.form
      else form = { ...s.form, base, draft: rebaseDraft(s.form.base, base, s.form.draft), revision }
      return {
        ...s,
        bootstrap: { status: 'ready', value: bootstrap },
        form,
        language: resolveLanguage(settings?.ui?.language, s.dshLocale),
      }
    })
  }

  function applySettings(settings: SecuritySettings, revision: number): void {
    const current = get().bootstrap.value
    if (!current) return
    applyBootstrap({ ...current, settings, settingsRevision: revision })
  }

  /**
   * A conflict reports the server's revision. One below ours means the Host's
   * store was reset (not that our copy is newer), so accept it from now on.
   */
  function noteServerRevision(error: RpcFailure): void {
    const revision = error.details?.revision
    if (typeof revision === 'number' && Number.isFinite(revision) && revision < knownRevision) knownRevision = revision
  }

  /** What a superseded bootstrap request resolves to: the newer request's outcome. */
  function supersededBootstrap(): Promise<RpcResult<Bootstrap>> | RpcResult<Bootstrap> {
    const pending = inflight.get('bootstrap')
    if (!disposed && pending) return pending.promise as Promise<RpcResult<Bootstrap>>
    const value = get().bootstrap.value
    if (!disposed && value) return { ok: true, value }
    return { ok: false, error: failure(ABORTED_ERROR, 'The request was superseded.') }
  }

  async function reloadBootstrap(options: { readonly force?: boolean } = {}): Promise<RpcResult<Bootstrap>> {
    return once(
      'bootstrap',
      async isCurrent => {
        set(s => ({ ...s, bootstrap: loading(s.bootstrap) }))
        const result = await api.call('getBootstrap', {})
        if (!isCurrent()) return supersededBootstrap()
        if (result.ok && isBootstrap(result.value)) applyBootstrap(result.value)
        else {
          const error = result.ok ? failure('security/internal', 'Malformed bootstrap.') : result.error
          set(s => ({ ...s, bootstrap: errored(s.bootstrap, error) }))
          return { ok: false, error } as const
        }
        return { ok: true, value: get().bootstrap.value ?? result.value }
      },
      options.force === true,
    )
  }

  async function refreshWorkspaces(force = false): Promise<void> {
    await once(
      'workspaces',
      async isCurrent => {
        invalidateEstimates()
        set(s => ({ ...s, workspaces: loading(s.workspaces) }))
        const result = await api.call('listWorkspaces', {})
        if (!isCurrent()) return
        const list = result.ok ? asList<WorkspaceSummary>(result.value).filter(w => w && typeof w.id === 'string') : []
        set(s => {
          const workspaces: Loadable<readonly WorkspaceSummary[]> = result.ok
            ? { status: 'ready', value: list }
            : errored(s.workspaces, result.error)
          const known = workspaces.value ?? []
          let workspaceId = s.workspaceId
          if (!workspaceId || (result.ok && !known.some(w => w.id === workspaceId))) workspaceId = pickWorkspace(known)
          return { ...s, workspaces, workspaceId }
        })
        const workspaceId = get().workspaceId
        if (workspaceId) await refreshScans(workspaceId, force)
      },
      force,
    )
  }

  async function refreshScans(workspaceId = get().workspaceId, force = false): Promise<void> {
    if (!workspaceId || disposed) return
    const desired = Math.max(SCAN_PAGE_SIZE, get().scans[workspaceId]?.value?.length ?? 0)
    await once(
      `scans:${workspaceId}`,
      async isCurrent => {
        set(s => ({ ...s, scans: { ...s.scans, [workspaceId]: loading(s.scans[workspaceId]) } }))
        const scans: ScanSummary[] = []
        let hasMore = false
        do {
          const result = await api.call('listScans', {
            workspaceId,
            limit: SCAN_PAGE_SIZE,
            ...(scans.length ? { offset: scans.length } : {}),
          })
          if (!isCurrent()) return
          if (!result.ok) {
            set(s => ({ ...s, scans: { ...s.scans, [workspaceId]: errored(s.scans[workspaceId], result.error) } }))
            return
          }
          const page = asList<ScanSummary>(result.value)
          scans.push(...page)
          hasMore = page.length === SCAN_PAGE_SIZE
        } while (hasMore && scans.length < desired)
        const value = sortScans([
          ...new Map(scans.filter(scan => !deletedScans.has(scan.id)).map(scan => [scan.id, scan])).values(),
        ])
        set(s => {
          const viewScanId =
            s.workspaceId === workspaceId && s.viewScanId && !value.some(scan => scan.id === s.viewScanId)
              ? undefined
              : s.viewScanId
          return {
            ...s,
            scans: { ...s.scans, [workspaceId]: { status: 'ready', value } },
            scansHasMore: { ...s.scansHasMore, [workspaceId]: hasMore },
            viewScanId,
          }
        })
      },
      force,
    )
  }

  async function loadMoreScans(workspaceId = get().workspaceId): Promise<void> {
    if (!workspaceId || disposed || !get().scansHasMore[workspaceId] || get().scans[workspaceId]?.status === 'loading')
      return
    await once(`scans:${workspaceId}`, async isCurrent => {
      const previous = get().scans[workspaceId]?.value ?? []
      set(s => ({ ...s, scans: { ...s.scans, [workspaceId]: loading(s.scans[workspaceId]) } }))
      const result = await api.call('listScans', { workspaceId, limit: SCAN_PAGE_SIZE, offset: previous.length })
      if (!isCurrent()) return
      if (!result.ok) {
        set(s => ({ ...s, scans: { ...s.scans, [workspaceId]: errored(s.scans[workspaceId], result.error) } }))
        return
      }
      const page = asList<ScanSummary>(result.value)
      const value = sortScans([
        ...new Map(
          [...previous, ...page].filter(scan => !deletedScans.has(scan.id)).map(scan => [scan.id, scan]),
        ).values(),
      ])
      set(s => ({
        ...s,
        scans: { ...s.scans, [workspaceId]: { status: 'ready', value } },
        scansHasMore: { ...s.scansHasMore, [workspaceId]: page.length === SCAN_PAGE_SIZE },
      }))
    })
  }

  function ensureLoaded(): void {
    if (loaded) return
    loaded = true
    lastRevalidate = Date.now()
    void reloadBootstrap()
    void refreshWorkspaces()
  }

  function revalidate(): void {
    if (!loaded) {
      ensureLoaded()
      return
    }
    const now = Date.now()
    if (now - lastRevalidate < REVALIDATE_MS) return
    lastRevalidate = now
    void reloadBootstrap()
    void refreshWorkspaces()
  }

  async function reload(): Promise<void> {
    if (disposed) return
    loaded = true
    // A picker/create response from the previous connection must not navigate this one.
    generations.set('add-project', (generations.get('add-project') ?? 0) + 1)
    set(s => ({ ...s, addingProject: false }))
    const tasks: Promise<unknown>[] = [reloadBootstrap({ force: true }), refreshWorkspaces(true)]
    const s = get()
    if (s.models.status !== 'idle') tasks.push(loadModels(true))
    if (s.toolkit.status !== 'idle') tasks.push(loadToolkit(true))
    for (const scanId of Object.keys(s.details)) tasks.push(loadScanDetail(scanId, true))
    for (const scanId of Object.keys(s.findings)) tasks.push(loadFindings(scanId, true))
    for (const scanId of loadedEvents) tasks.push(loadScanEvents(scanId, true))
    for (const key of Object.keys(s.findingDetails)) {
      const [scanId, findingId] = key.split('\u0000')
      if (scanId && findingId) tasks.push(loadFinding(scanId, findingId, true))
    }
    await Promise.all(tasks)
    // Watchers keep running; nudge them so the UI catches up immediately.
    for (const [scanId, watcher] of watchers) {
      if (!watcher.stopped) schedulePoll(scanId, 0)
    }
  }

  function setDshLocale(locale: string): void {
    set(s =>
      s.dshLocale === locale
        ? s
        : {
            ...s,
            dshLocale: locale,
            language: resolveLanguage(s.bootstrap.value?.settings?.ui?.language, locale),
          },
    )
  }

  // -------------------------------------------------------------------------
  // Navigation
  // -------------------------------------------------------------------------

  function canAddProject(): boolean {
    return typeof host.uiWorkspace()?.pickDirectory === 'function' && typeof host.workspaces()?.create === 'function'
  }

  async function addProjectFolder(signal?: AbortSignal): Promise<AddProjectResult> {
    if (disposed || signal?.aborted || get().addingProject || !canAddProject()) return undefined
    return once<AddProjectResult>(
      'add-project',
      async isCurrent => {
        const active = () => isCurrent() && !signal?.aborted
        set(s => ({ ...s, addingProject: true }))
        try {
          const path = await host.uiWorkspace()?.pickDirectory?.()
          if (!path || !active()) return undefined
          const workspace = await host.workspaces()?.create?.({ path })
          if (!workspace || !active()) return undefined
          await refreshWorkspaces(true)
          if (!active()) return undefined
          const list = get().workspaces
          if (list.status !== 'ready' || !list.value?.some(w => w.id === workspace.workspaceId)) {
            // Registration may already have committed. Do not select an unlisted project or claim rollback.
            return { error: 'project.refreshFailed' }
          }
          selectWorkspace(workspace.workspaceId)
          return { workspaceId: workspace.workspaceId }
        } catch {
          return active() ? { error: 'project.addFailed' } : undefined
        } finally {
          if (isCurrent()) set(s => ({ ...s, addingProject: false }))
        }
      },
      true,
    )
  }

  function selectWorkspace(workspaceId: string): void {
    if (get().workspaceId === workspaceId) return
    writeStorage(storage, WORKSPACE_KEY, workspaceId)
    set(s => ({ ...s, workspaceId, viewScanId: undefined, selectedFinding: undefined }))
    void refreshScans(workspaceId)
  }

  function setTab(tab: TabId): void {
    set(s => (s.tab === tab ? s : { ...s, tab }))
  }

  function viewScan(scanId: string | undefined): void {
    set(s => ({ ...s, viewScanId: scanId, selectedFinding: undefined }))
  }

  function selectFinding(findingId: string | undefined, scanId?: string): void {
    set(s => {
      const list = s.workspaceId ? (s.scans[s.workspaceId]?.value ?? []) : []
      const selectedScanId = scanId ?? resultsScan(list, s.viewScanId)?.id
      const selectedFinding = findingId && selectedScanId ? { scanId: selectedScanId, findingId } : undefined
      return { ...s, selectedFinding }
    })
  }

  function setFilter(update: FindingsFilter | ((prev: FindingsFilter) => FindingsFilter)): void {
    set(s => ({ ...s, filter: typeof update === 'function' ? update(s.filter) : update }))
  }

  function openFindingFromOverview(scanId: string, findingId: string): void {
    set(s => {
      const list = s.workspaceId ? (s.scans[s.workspaceId]?.value ?? []) : []
      const latestCompleted = list.find(scan => scan.status === 'completed')
      const viewScanId = s.viewScanId ?? (latestCompleted?.id === scanId ? undefined : scanId)
      return { ...s, tab: 'findings', selectedFinding: { scanId, findingId }, viewScanId }
    })
  }

  // -------------------------------------------------------------------------
  // New scan
  // -------------------------------------------------------------------------

  function openNewScan(request: NewScanRequest = {}): void {
    set(s => ({ ...s, newScan: request }))
  }

  function closeNewScan(): void {
    set(s => (s.newScan ? { ...s, newScan: undefined } : s))
  }

  async function estimate(workspaceId: string, mode: ScanMode, signal?: AbortSignal, subpath?: string) {
    const key = `${workspaceId}\u0000${mode}\u0000${subpath ?? ''}`
    const cached = estimateCache.get(key)
    if (cached && Date.now() - cached.at <= ESTIMATE_TTL_MS) return { ok: true, value: cached.value } as const
    const generation = estimateGeneration
    const result = await api.call('estimateScan', { workspaceId, mode, ...(subpath ? { subpath } : {}) }, signal)
    if (result.ok && !disposed && !signal?.aborted && generation === estimateGeneration) {
      estimateCache.set(key, { value: result.value, at: Date.now() })
    }
    return result
  }

  async function updateSettings(patch: SettingsPatch) {
    if (disposed) return abortedResult()
    const revision = get().bootstrap.value?.settingsRevision ?? 0
    const result = await api.call('updateSettings', { patch, expectedRevision: revision })
    if (disposed) return abortedResult()
    if (result.ok) applySettings(result.value.settings, result.value.revision)
    return result
  }

  /**
   * Apply a settings patch the New Scan dialog needs before creating a scan,
   * retrying once after a revision conflict. `done` says whether the server
   * copy already satisfies the patch (so a retry after reload can be skipped).
   */
  async function patchBeforeScan(
    patch: SettingsPatch,
    done: () => boolean,
    onPatched?: (revision: number) => void,
  ): Promise<RpcResult<unknown>> {
    if (disposed) return abortedResult()
    if (done()) return { ok: true, value: undefined }
    let result = await updateSettings(patch)
    if (!result.ok && result.error.code === 'security/conflict') {
      noteServerRevision(result.error)
      const reloaded = await reloadBootstrap({ force: true })
      if (!reloaded.ok) return reloaded
      if (disposed) return abortedResult()
      if (done()) return { ok: true, value: undefined }
      result = await updateSettings(patch)
    }
    if (result.ok) onPatched?.(result.value.revision)
    return result
  }

  async function startScan(input: StartScanInput) {
    if (disposed) return abortedResult()
    const aiReview = input.aiReview !== false
    const settings = () => get().bootstrap.value?.settings
    if (aiReview && input.model) {
      const model = input.model
      const saved = await patchBeforeScan({ models: { default: model } }, () => {
        const current = settings()?.models?.default
        return current?.provider === model.provider && current?.model === model.model
      })
      if (!saved.ok) return saved
    }
    let consentRevision: number | undefined
    if (aiReview && input.consent) {
      const granted = await patchBeforeScan(
        { privacy: { sendCodeToModel: true } },
        () => settings()?.privacy?.sendCodeToModel === true,
        revision => {
          consentRevision = revision
        },
      )
      if (!granted.ok) return granted
    }
    if (disposed) return abortedResult()
    const result = await api.call('createScan', {
      workspaceId: input.workspaceId,
      mode: input.mode,
      ...(input.subpath ? { subpath: input.subpath } : {}),
      language: get().language,
      ...(aiReview ? {} : { aiReview: false }),
    })
    // Once sent, a create may have committed even if its response was lost.
    // Never roll back consent or automatically resend an uncertain creation.
    if (disposed) return result
    const rejectedBeforeCreation =
      !result.ok &&
      [
        'security/bad-request',
        'security/no-model',
        'security/consent-required',
        'security/not-found',
        'security/workspace-unavailable',
        'security/busy',
        'security/invalid-state',
      ].includes(result.error.code)
    if (!result.ok && !rejectedBeforeCreation) {
      invalidateEstimates()
      await refreshScans(input.workspaceId, true)
      return {
        ok: false,
        error: failure(
          'security/result-unknown',
          'The scan may have been created. Check scan history before trying again.',
          {
            workspaceId: input.workspaceId,
            causeCode: result.error.code,
            reconciled: get().scans[input.workspaceId]?.status === 'ready',
          },
        ),
      } as const
    }
    if (!result.ok && rejectedBeforeCreation && consentRevision !== undefined) {
      // Only undo our own grant. A concurrent settings write makes this CAS fail
      // rather than overwriting another viewer's newer privacy decision.
      const restored = await api.call('updateSettings', {
        patch: { privacy: { sendCodeToModel: false } },
        expectedRevision: consentRevision,
      })
      if (disposed) return result
      if (restored.ok) applySettings(restored.value.settings, restored.value.revision)
    }
    if (result.ok || result.error.code === 'security/busy') {
      invalidateEstimates()
      set(s => ({
        ...s,
        workspaceId: input.workspaceId,
        viewScanId: undefined,
        selectedFinding: s.workspaceId === input.workspaceId ? s.selectedFinding : undefined,
      }))
      writeStorage(storage, WORKSPACE_KEY, input.workspaceId)
      await refreshScans(input.workspaceId)
    }
    return result
  }

  async function quickRescan(workspaceId: string, subpath?: string, mode: ScanMode = 'quick') {
    if (disposed) return abortedResult()
    if (get().bootstrap.value?.settings?.privacy?.sendCodeToModel !== true) {
      openNewScan({ workspaceId, mode, ...(subpath ? { subpath } : {}) })
      return undefined
    }
    const result = await startScan({ workspaceId, mode, ...(subpath ? { subpath } : {}) })
    if (disposed) return result
    if (result.ok) flash({ tone: 'success', key: 'detail.recheckStarted' })
    else if (result.error.code === 'security/consent-required' || result.error.code === 'security/no-model') {
      openNewScan({ workspaceId, mode, ...(subpath ? { subpath } : {}) })
    } else flash({ tone: result.error.code === 'security/busy' ? 'info' : 'error', error: result.error })
    return result
  }

  // -------------------------------------------------------------------------
  // Scan detail and polling
  // -------------------------------------------------------------------------

  function storeDetail(scanId: string, detail: ScanDetail): void {
    if (!activeScan(scanId)) return
    set(s => {
      const summary = detail.summary
      let scans = s.scans
      if (summary && typeof summary.workspaceId === 'string' && s.scans[summary.workspaceId]?.value) {
        const entry = s.scans[summary.workspaceId]!
        scans = {
          ...s.scans,
          [summary.workspaceId]: { ...entry, value: mergeSummary(entry.value ?? [], summary) },
        }
      }
      return { ...s, details: { ...s.details, [scanId]: { status: 'ready', value: detail } }, scans }
    })
  }

  async function loadScanDetail(scanId: string, force = false): Promise<void> {
    if (!activeScan(scanId)) return
    const prev = get().details[scanId]
    // A cached detail from before a status change (completed in another
    // window, resumed, extended) must not shadow the fresher list summary.
    const listed = Object.values(get().scans)
      .flatMap(entry => entry.value ?? [])
      .find(scan => scan.id === scanId)
    if (!force && listed && prev?.value && prev.value.summary?.status !== listed.status) force = true
    if (!force && prev && prev.status !== 'error' && prev.status !== 'idle') return
    await once(
      `detail:${scanId}`,
      async isCurrent => {
        set(s => ({ ...s, details: { ...s.details, [scanId]: loading(s.details[scanId]) } }))
        const result = await api.call('getScan', { scanId })
        if (!isCurrent()) return
        if (result.ok && result.value && typeof result.value === 'object') storeDetail(scanId, result.value)
        else if (!result.ok) {
          set(s => ({ ...s, details: { ...s.details, [scanId]: errored(s.details[scanId], result.error) } }))
        }
      },
      force,
    )
  }

  /** Fetch all event pages, retaining only the newest bounded activity window. */
  async function loadScanEvents(scanId: string, force = false): Promise<void> {
    if (!activeScan(scanId) || (!force && loadedEvents.has(scanId))) return
    await once(
      `events:${scanId}`,
      async isCurrent => {
        set(s => {
          const { [scanId]: _error, ...eventsErrors } = s.eventsErrors
          return { ...s, eventsErrors, eventsLoading: { ...s.eventsLoading, [scanId]: true } }
        })
        let afterSeq: number | undefined
        let latest: readonly ScanEvent[] = []
        for (;;) {
          const result = await api.call('listEvents', {
            scanId,
            limit: MAX_EVENTS,
            ...(afterSeq === undefined ? {} : { afterSeq }),
          })
          if (!isCurrent() || !activeScan(scanId)) return
          if (!result.ok) {
            set(s => ({
              ...s,
              eventsErrors: { ...s.eventsErrors, [scanId]: result.error },
              eventsLoading: { ...s.eventsLoading, [scanId]: false },
            }))
            return
          }
          const page = asList<ScanEvent>(result.value)
          const ordered = page
            .filter(event => Number.isSafeInteger(event.seq) && (afterSeq === undefined || event.seq > afterSeq))
            .sort((a, b) => a.seq - b.seq)
          if (page.length && !ordered.length) {
            set(s => ({
              ...s,
              eventsErrors: {
                ...s.eventsErrors,
                [scanId]: failure('security/internal', 'Activity pagination did not advance.'),
              },
              eventsLoading: { ...s.eventsLoading, [scanId]: false },
            }))
            return
          }
          latest = [...latest, ...ordered].slice(-MAX_EVENTS)
          afterSeq = ordered.at(-1)?.seq ?? afterSeq
          if (page.length < MAX_EVENTS) break
        }
        loadedEvents.add(scanId)
        set(s => ({
          ...s,
          events: {
            ...s.events,
            [scanId]: [...new Map([...latest, ...(s.events[scanId] ?? [])].map(event => [event.seq, event])).values()]
              .sort((a, b) => a.seq - b.seq)
              .slice(-MAX_EVENTS),
          },
          eventsLoading: { ...s.eventsLoading, [scanId]: false },
        }))
      },
      force,
    )
  }

  async function pollEvents(scanId: string, signal: AbortSignal): Promise<void> {
    const existing = get().events[scanId] ?? []
    const afterSeq = existing.length ? existing[existing.length - 1]!.seq : undefined
    const result = await api.call(
      'listEvents',
      { scanId, ...(afterSeq !== undefined ? { afterSeq } : {}), limit: MAX_EVENTS },
      signal,
    )
    if (!result.ok || signal.aborted || !activeScan(scanId)) return
    const incoming = asList<ScanEvent>(result.value).filter(e => e && typeof e.seq === 'number')
    if (!incoming.length) return
    set(s => {
      const current = s.events[scanId] ?? []
      const last = current.length ? current[current.length - 1]!.seq : Number.NEGATIVE_INFINITY
      const fresh = incoming.filter(e => e.seq > last).sort((a, b) => a.seq - b.seq)
      if (!fresh.length) return s
      return { ...s, events: { ...s.events, [scanId]: [...current, ...fresh].slice(-MAX_EVENTS) } }
    })
  }

  function pollDelay(): number {
    return doc?.visibilityState === 'hidden' ? POLL_HIDDEN_MS : POLL_VISIBLE_MS
  }

  function schedulePoll(scanId: string, delay: number): void {
    const watcher = watchers.get(scanId)
    if (!watcher || watcher.stopped) return
    if (watcher.timer !== undefined) clearTimeout(watcher.timer)
    watcher.timer = setTimeout(() => {
      watcher.timer = undefined
      void poll(scanId)
    }, delay)
  }

  function stopWatcher(scanId: string): void {
    const watcher = watchers.get(scanId)
    if (!watcher) return
    watcher.stopped = true
    if (watcher.timer !== undefined) clearTimeout(watcher.timer)
    watcher.abort?.abort()
    watchers.delete(scanId)
  }

  async function poll(scanId: string): Promise<void> {
    const watcher = watchers.get(scanId)
    if (!watcher || watcher.stopped || watcher.abort) return
    const abort = new AbortController()
    watcher.abort = abort
    let next = pollDelay()
    try {
      const generation = generations.get(`detail:${scanId}`)
      const result = await api.call('getScan', { scanId }, abort.signal)
      if (watcher.stopped || generation !== generations.get(`detail:${scanId}`)) return
      if (!result.ok) {
        if (result.error.code === 'security/not-found') {
          stopWatcher(scanId)
          void refreshScans()
          return
        }
        next = POLL_HIDDEN_MS
        return
      }
      storeDetail(scanId, result.value)
      await pollEvents(scanId, abort.signal)
      if (watcher.stopped) return
      const status = result.value.summary?.status
      if (!isPollableStatus(status)) {
        stopWatcher(scanId)
        void onScanSettled(result.value.summary)
      }
    } finally {
      watcher.abort = undefined
      if (!watcher.stopped) schedulePoll(scanId, next)
    }
  }

  async function onScanSettled(summary: ScanSummary | undefined): Promise<void> {
    if (!summary) return
    const tasks: Promise<unknown>[] = [refreshScans(summary.workspaceId), refreshWorkspaces()]
    if (summary.status === 'completed') tasks.push(loadFindings(summary.id, true))
    await Promise.all(tasks)
  }

  function watchScan(scanId: string): () => void {
    if (!activeScan(scanId)) return () => undefined
    let watcher = watchers.get(scanId)
    if (!watcher) {
      watcher = { refs: 0, timer: undefined, abort: undefined, stopped: false }
      watchers.set(scanId, watcher)
      schedulePoll(scanId, 0)
    }
    watcher.refs++
    const owned = watcher
    let released = false
    return () => {
      if (released) return
      released = true
      owned.refs--
      if (owned.refs <= 0 && watchers.get(scanId) === owned) stopWatcher(scanId)
    }
  }

  const onVisibility = () => {
    if (doc?.visibilityState !== 'visible') return
    for (const [scanId, watcher] of watchers) {
      if (!watcher.stopped && !watcher.abort) schedulePoll(scanId, 0)
    }
  }
  doc?.addEventListener('visibilitychange', onVisibility)

  async function scanAction(
    method: 'pauseScan' | 'resumeScan' | 'cancelScan' | 'extendScanBudget',
    scanId: string,
    extra: { addTokens?: number; addLlmCalls?: number; addMinutes?: number } = {},
  ): Promise<RpcResult<ScanSummary>> {
    if (!activeScan(scanId)) return abortedResult()
    const result = await api.call(method, { scanId, ...extra })
    if (result.ok && result.value && activeScan(scanId)) {
      const summary = result.value
      set(s => {
        const entry = s.scans[summary.workspaceId]
        if (!entry?.value) return s
        return {
          ...s,
          scans: { ...s.scans, [summary.workspaceId]: { ...entry, value: mergeSummary(entry.value, summary) } },
        }
      })
      await loadScanDetail(scanId, true)
      // A resumed scan becomes pollable again; the page re-attaches its watcher.
      if (!isPollableStatus(summary.status)) void onScanSettled(summary)
    }
    return result
  }

  async function deleteScan(scanId: string) {
    if (!activeScan(scanId)) return abortedResult()
    const result = await api.call('deleteScan', { scanId })
    if (result.ok && result.value.deleted && !disposed) {
      deletedScans.add(scanId)
      loadedEvents.delete(scanId)
      stopWatcher(scanId)
      // A late list/detail response must not resurrect a deleted scan.
      for (const key of [...generations.keys()]) {
        if (
          key === `detail:${scanId}` ||
          key === `findings:${scanId}` ||
          key === `events:${scanId}` ||
          key.startsWith(`finding:${scanId}\u0000`) ||
          key.startsWith('scans:') ||
          key === 'workspaces'
        )
          invalidateRead(key)
      }
      set(s => {
        const { [scanId]: _detail, ...details } = s.details
        const { [scanId]: _findings, ...findings } = s.findings
        const { [scanId]: _events, ...events } = s.events
        const { [scanId]: _eventsError, ...eventsErrors } = s.eventsErrors
        const { [scanId]: _eventsLoading, ...eventsLoading } = s.eventsLoading
        const findingDetails = Object.fromEntries(
          Object.entries(s.findingDetails).filter(([key]) => !key.startsWith(`${scanId}\u0000`)),
        )
        const scans: Record<string, Loadable<readonly ScanSummary[]>> = {}
        for (const [id, entry] of Object.entries(s.scans)) {
          scans[id] = entry.value ? { ...entry, value: entry.value.filter(scan => scan.id !== scanId) } : entry
        }
        return {
          ...s,
          details,
          findings,
          findingDetails,
          events,
          eventsErrors,
          eventsLoading,
          scans,
          viewScanId: s.viewScanId === scanId ? undefined : s.viewScanId,
          selectedFinding: s.selectedFinding?.scanId === scanId ? undefined : s.selectedFinding,
        }
      })
      void refreshWorkspaces(true)
    }
    return result
  }

  async function exportReport(scanId: string, format: ReportFormat): Promise<RpcResult<unknown>> {
    const result = await api.call('exportReport', { scanId, format })
    if (!result.ok) return result
    if (!result.value || typeof result.value.content !== 'string') {
      return { ok: false, error: failure('security/internal', 'The report was empty.') }
    }
    try {
      downloadFile(result.value, doc)
    } catch (error) {
      return {
        ok: false,
        error: failure('security/internal', error instanceof Error ? error.message : 'Download failed.'),
      }
    }
    return { ok: true, value: undefined }
  }

  // -------------------------------------------------------------------------
  // Findings
  // -------------------------------------------------------------------------

  async function loadFindings(scanId: string, force = false): Promise<void> {
    if (!activeScan(scanId)) return
    const prev = get().findings[scanId]
    if (!force && prev && prev.status !== 'error' && prev.status !== 'idle') return
    await once(
      `findings:${scanId}`,
      async isCurrent => {
        set(s => ({ ...s, findings: { ...s.findings, [scanId]: loading(s.findings[scanId]) } }))
        const result = await api.call('listFindings', { scanId })
        if (!isCurrent()) return
        set(s => ({
          ...s,
          findings: {
            ...s.findings,
            [scanId]: settleLoadable(
              s.findings[scanId],
              result.ok ? { ok: true, value: asList<FindingSummary>(result.value) } : result,
            ),
          },
        }))
      },
      force,
    )
  }

  async function loadFinding(scanId: string, findingId: string, force = false): Promise<void> {
    if (!activeScan(scanId)) return
    const key = findingKey(scanId, findingId)
    const prev = get().findingDetails[key]
    if (!force && prev && prev.status !== 'error' && prev.status !== 'idle') return
    await once(
      `finding:${key}`,
      async isCurrent => {
        set(s => ({ ...s, findingDetails: { ...s.findingDetails, [key]: loading(s.findingDetails[key]) } }))
        const result = await api.call('getFinding', { scanId, findingId })
        if (!isCurrent()) return
        set(s => ({
          ...s,
          findingDetails: { ...s.findingDetails, [key]: settleLoadable(s.findingDetails[key], result) },
        }))
      },
      force,
    )
  }

  async function setTriage(input: { scanId: string; findingId: string; triage: TriageState; note?: string }) {
    if (!activeScan(input.scanId)) return abortedResult()
    const result = await api.call('setTriage', {
      scanId: input.scanId,
      findingId: input.findingId,
      triage: input.triage,
      ...(input.note?.trim() ? { note: input.note.trim() } : {}),
    })
    if (result.ok && result.value && activeScan(input.scanId)) {
      const updated = result.value
      const key = findingKey(input.scanId, input.findingId)
      invalidateRead(`findings:${input.scanId}`)
      invalidateRead(`finding:${key}`)
      set(s => {
        const list = s.findings[input.scanId]
        const detail = s.findingDetails[key]
        return {
          ...s,
          findings: list?.value
            ? {
                ...s.findings,
                [input.scanId]: { status: 'ready', value: list.value.map(f => (f.id === updated.id ? updated : f)) },
              }
            : s.findings,
          findingDetails: detail?.value
            ? {
                ...s.findingDetails,
                [key]: {
                  status: 'ready',
                  value: {
                    ...detail.value,
                    ...updated,
                    ...(input.note?.trim() ? { triageNote: input.note.trim() } : { triageNote: undefined }),
                  },
                },
              }
            : s.findingDetails,
        }
      })
      if (get().findings[input.scanId]?.status === 'loading') void loadFindings(input.scanId, true)
      if (get().findingDetails[key]?.status === 'loading') void loadFinding(input.scanId, input.findingId, true)
      void refreshScans()
    }
    return result
  }

  function canFixInChat(): boolean {
    return typeof host.uiWorkspace()?.startSession === 'function'
  }

  async function fixInChat(input: { workspaceId: string; scanId: string; findingId: string }) {
    const ui = host.uiWorkspace()
    if (!ui?.startSession)
      return { ok: false, error: failure('security/invalid-state', 'DSH chat is not available.') } as const
    const result = await api.call('getFixPrompt', { scanId: input.scanId, findingId: input.findingId })
    if (!result.ok) return result
    try {
      if (disposed) return abortedResult()
      // DSH may reuse a blank session. Preserve its existing unsent input.
      // startSession can return void; success here means requested, not opened.
      await ui.startSession(input.workspaceId, { prompt: result.value.prompt, clearPreviousDraft: false })
    } catch (error) {
      return {
        ok: false,
        error: failure('security/internal', error instanceof Error ? error.message : 'Could not open a chat.'),
      } as const
    }
    return { ok: true, value: undefined } as const
  }

  async function copyFixPrompt(scanId: string, findingId: string): Promise<RpcResult<unknown>> {
    const result = await api.call('getFixPrompt', { scanId, findingId })
    if (!result.ok) return result
    const copied = doc ? await copyText(result.value.prompt, doc) : false
    return copied
      ? { ok: true, value: undefined }
      : { ok: false, error: failure('security/clipboard', 'Could not copy to the clipboard.') }
  }

  // -------------------------------------------------------------------------
  // Settings
  // -------------------------------------------------------------------------

  async function loadModels(force = false): Promise<void> {
    if (!force && get().models.status !== 'idle' && get().models.status !== 'error') return
    await once(
      'models',
      async isCurrent => {
        set(s => ({ ...s, models: loading(s.models) }))
        const result = await api.call('listModels', {})
        if (!isCurrent()) return
        set(s => ({
          ...s,
          models: settleLoadable(
            s.models,
            result.ok ? { ok: true, value: asList<ProviderOption>(result.value) } : result,
          ),
        }))
      },
      force,
    )
  }

  async function loadToolkit(force = false): Promise<void> {
    if (!force && get().toolkit.status !== 'idle' && get().toolkit.status !== 'error') return
    await once(
      'toolkit',
      async isCurrent => {
        set(s => ({ ...s, toolkit: loading(s.toolkit) }))
        const result = await api.call('listToolkit', {})
        if (!isCurrent()) return
        set(s => ({
          ...s,
          toolkit: settleLoadable(
            s.toolkit,
            result.ok ? { ok: true, value: asList<ToolkitEntry>(result.value) } : result,
          ),
        }))
      },
      force,
    )
  }

  async function installTool(toolId: ToolkitEntry['id']) {
    const result = await api.call('installTool', { toolId, acceptLicense: true })
    if (result.ok) {
      const entry = result.value
      set(s => ({
        ...s,
        toolkit: s.toolkit.value
          ? { ...s.toolkit, value: s.toolkit.value.map(t => (t.id === entry.id ? entry : t)) }
          : s.toolkit,
      }))
      // The install changed the Host's analyzer list; a bootstrap already in flight predates it.
      void reloadBootstrap({ force: true })
    }
    return result
  }

  function updateDraft(update: (draft: SettingsDraft) => SettingsDraft): void {
    set(s => {
      if (!s.form) return s
      const draft = update(s.form.draft)
      const { result: _result, ...rest } = s.form
      return { ...s, form: { ...rest, draft } }
    })
  }

  function discardDraft(): void {
    set(s =>
      s.form ? { ...s, form: { base: s.form.base, draft: s.form.base, revision: s.form.revision, saving: false } } : s,
    )
  }

  function setFormResult(result: SettingsFormState['result'], saving = false): void {
    set(s => (s.form ? { ...s, form: { ...s.form, saving, ...(result ? { result } : {}) } } : s))
  }

  async function saveSettings(): Promise<RpcResult<unknown> | undefined> {
    if (disposed) return abortedResult()
    const s = get()
    const form = s.form
    const bootstrap = s.bootstrap.value
    if (!form || !bootstrap || form.saving) return undefined
    const errors = validateDraft(form.draft, form.base, bootstrap.limits)
    if (Object.keys(errors).length) {
      setFormResult({ tone: 'error', key: 'settings.invalid' })
      return { ok: false, error: failure('security/bad-request', 'Invalid settings.') }
    }
    const draft = enforceHighRisk(form.base, form.draft, bootstrap.canEditHighRiskSettings === true)
    const patch = buildPatch(form.base, draft)
    if (isPatchEmpty(patch)) {
      discardDraft()
      return { ok: true, value: undefined }
    }
    set(st => (st.form ? { ...st, form: { ...st.form, saving: true } } : st))
    const result = await api.call('updateSettings', { patch, expectedRevision: form.revision })
    if (disposed) return abortedResult()
    if (result.ok) {
      const fresh = result.value.revision >= knownRevision
      if (fresh) knownRevision = result.value.revision
      set(st => {
        const current = st.bootstrap.value
        if (!current) return st
        const base = draftFromSettings(fresh ? result.value.settings : current.settings)
        // Only edits made since submission survive; unchanged fields take the
        // saved server value. A newer bootstrap may have rebased the draft too.
        const nextDraft = rebaseDraft(form.draft, base, st.form?.draft ?? form.draft)
        const savedForm: SettingsFormState = {
          base,
          draft: nextDraft,
          revision: fresh ? result.value.revision : current.settingsRevision,
          saving: false,
          ...(!isDraftDirty(base, nextDraft) ? { result: { tone: 'success', key: 'settings.saved' } as const } : {}),
        }
        // A newer revision arrived while saving: keep it rather than our older write.
        if (!fresh) return { ...st, form: savedForm }
        return {
          ...st,
          bootstrap: {
            status: 'ready',
            value: { ...current, settings: result.value.settings, settingsRevision: result.value.revision },
          },
          form: savedForm,
          language: resolveLanguage(result.value.settings?.ui?.language, st.dshLocale),
        }
      })
      invalidateEstimates()
      return result
    }
    if (result.error.code === 'security/conflict') {
      setFormResult(undefined, true)
      noteServerRevision(result.error)
      await reloadBootstrap({ force: true })
      if (disposed) return abortedResult()
      setFormResult({ tone: 'warn', key: 'settings.conflict' })
      return result
    }
    setFormResult({ tone: 'error', error: result.error })
    return result
  }

  // -------------------------------------------------------------------------
  // Misc
  // -------------------------------------------------------------------------

  function canOpenPage(): boolean {
    return host.layout() !== undefined
  }

  function openSecurityPage(close?: () => void): void {
    close?.()
    host.layout()?.selectPanel(SECURITY_SLOT_ID)
  }

  function flash(message: { tone: Tone; key: MessageKey } | { tone: Tone; error: RpcFailure }): void {
    const id = ++flashSeq
    set(s => ({ ...s, flash: { ...message, id } }))
    if (flashTimer !== undefined) clearTimeout(flashTimer)
    flashTimer = setTimeout(() => {
      flashTimer = undefined
      set(s => (s.flash?.id === id ? { ...s, flash: undefined } : s))
    }, FLASH_MS)
  }

  function dismissFlash(): void {
    if (flashTimer !== undefined) clearTimeout(flashTimer)
    flashTimer = undefined
    set(s => (s.flash ? { ...s, flash: undefined } : s))
  }

  function contractMismatch(): boolean {
    const version = get().bootstrap.value?.contractVersion
    return version !== undefined && version !== CONTRACT_VERSION
  }

  function dispose(): void {
    if (disposed) return
    disposed = true
    for (const scanId of [...watchers.keys()]) stopWatcher(scanId)
    if (flashTimer !== undefined) clearTimeout(flashTimer)
    doc?.removeEventListener('visibilitychange', onVisibility)
  }

  return {
    store,
    api,
    host,
    ensureLoaded,
    reload,
    revalidate,
    reloadBootstrap,
    refreshWorkspaces,
    refreshScans,
    loadMoreScans,
    setDshLocale,
    contractMismatch,
    canAddProject,
    addProjectFolder,
    selectWorkspace,
    setTab,
    viewScan,
    selectFinding,
    setFilter,
    openFindingFromOverview,
    openNewScan,
    closeNewScan,
    estimate,
    startScan,
    quickRescan,
    loadScanDetail,
    loadScanEvents,
    watchScan,
    pauseScan: scanId => scanAction('pauseScan', scanId),
    resumeScan: scanId => scanAction('resumeScan', scanId),
    extendScanBudget: (scanId, add) => scanAction('extendScanBudget', scanId, add),
    cancelScan: scanId => scanAction('cancelScan', scanId),
    deleteScan,
    exportReport,
    loadFindings,
    loadFinding,
    setTriage,
    canFixInChat,
    fixInChat,
    copyFixPrompt,
    loadModels,
    loadToolkit,
    installTool,
    updateDraft,
    discardDraft,
    saveSettings,
    updateSettings,
    canOpenPage,
    openSecurityPage,
    flash,
    dismissFlash,
    dispose,
  }
}

function isBootstrap(value: unknown): value is Bootstrap {
  return typeof value === 'object' && value !== null && 'settings' in value
}

/** Prefer the workspace scanned most recently, else the first listed. */
function pickWorkspace(workspaces: readonly WorkspaceSummary[]): string | undefined {
  let best: WorkspaceSummary | undefined
  let bestTime = Number.NEGATIVE_INFINITY
  for (const w of workspaces) {
    const t = Date.parse(w.lastScan?.createdAt ?? '')
    if (Number.isFinite(t) && t > bestTime) {
      best = w
      bestTime = t
    }
  }
  return (best ?? workspaces[0])?.id
}

function defaultStorage(): Pick<Storage, 'getItem' | 'setItem'> | null {
  try {
    return typeof localStorage !== 'undefined' ? localStorage : null
  } catch {
    return null
  }
}

function readStorage(storage: Pick<Storage, 'getItem'> | null, key: string): string | undefined {
  try {
    return storage?.getItem(key) ?? undefined
  } catch {
    return undefined
  }
}

function writeStorage(storage: Pick<Storage, 'setItem'> | null, key: string, value: string): void {
  try {
    storage?.setItem(key, value)
  } catch {
    // Private mode or blocked storage: the selection just isn't remembered.
  }
}
