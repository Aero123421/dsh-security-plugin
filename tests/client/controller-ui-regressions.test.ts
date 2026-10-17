import { afterEach, describe, expect, it, vi } from 'vitest'
import { createController, MAX_EVENTS, SCAN_PAGE_SIZE, type SecurityController } from '../../src/client/controller.ts'
import type {
  FindingDetail,
  FindingSummary,
  RpcResult,
  ScanDetail,
  ScanEvent,
  ScanSummary,
} from '../../src/shared/contracts.ts'
import {
  fail,
  fakeApi,
  makeBootstrap,
  makeDetail,
  makeFinding,
  makeFindingDetail,
  makeScan,
  makeSettings,
  ok,
} from './helpers.tsx'

function deferred<T>() {
  let resolve!: (value: T) => void
  const promise = new Promise<T>(done => {
    resolve = done
  })
  return { promise, resolve }
}

let controller: SecurityController | undefined
afterEach(() => {
  controller?.dispose()
})

function workspace(id = 'ws-1') {
  return { id, title: id, displayPath: `~/${id}` }
}

function page(count: number) {
  return Array.from({ length: count }, (_, i) =>
    makeScan({ id: `scan-${i}`, createdAt: new Date(Date.UTC(2026, 9, 17, 0, 0, count - i)).toISOString() }),
  )
}

describe('history request ownership', () => {
  it('does not clear workspace B history selection when workspace A finishes late', async () => {
    const old = deferred<RpcResult<readonly ScanSummary[]>>()
    const api = fakeApi({
      listScans: p =>
        p.workspaceId === 'a'
          ? old.promise
          : ok([makeScan({ id: 'b-new', workspaceId: 'b' }), makeScan({ id: 'b-old', workspaceId: 'b' })]),
    })
    controller = createController({ api, storage: null })
    controller.selectWorkspace('a')
    controller.selectWorkspace('b')
    await controller.refreshScans('b')
    controller.viewScan('b-old')
    old.resolve(ok([makeScan({ id: 'a-old', workspaceId: 'a' })]))
    // Join the in-flight refresh so the late A response has actually landed
    // before asserting; a single microtask tick is not enough to reach it.
    await controller.refreshScans('a')
    expect(controller.store.getState()).toMatchObject({ workspaceId: 'b', viewScanId: 'b-old' })
    expect(controller.store.getState().scans['a']?.value?.map(scan => scan.id)).toEqual(['a-old'])
  })

  it('loads older history and preserves the loaded range when refreshed', async () => {
    const all = page(101)
    const api = fakeApi({ listScans: p => ok(all.slice(p.offset ?? 0, (p.offset ?? 0) + (p.limit ?? 50))) })
    controller = createController({ api, storage: null })
    await controller.refreshScans('ws-1')
    expect(controller.store.getState().scans['ws-1']?.value).toHaveLength(SCAN_PAGE_SIZE)
    expect(controller.store.getState().scansHasMore['ws-1']).toBe(true)
    await controller.loadMoreScans('ws-1')
    expect(controller.store.getState().scans['ws-1']?.value).toHaveLength(100)
    await controller.loadMoreScans('ws-1')
    expect(controller.store.getState().scans['ws-1']?.value).toHaveLength(101)
    expect(controller.store.getState().scansHasMore['ws-1']).toBe(false)
    await controller.refreshScans('ws-1', true)
    expect(controller.store.getState().scans['ws-1']?.value).toHaveLength(101)
    expect(api.callsOf('listScans')).toContainEqual({ workspaceId: 'ws-1', limit: 50, offset: 100 })
  })

  it('deduplicates overlapping pages and rejects an append superseded by refresh', async () => {
    const all = page(51)
    const append = deferred<RpcResult<readonly ScanSummary[]>>()
    let calls = 0
    const api = fakeApi({ listScans: () => (++calls === 2 ? append.promise : ok(all.slice(0, 50))) })
    controller = createController({ api, storage: null })
    await controller.refreshScans('ws-1')
    const late = controller.loadMoreScans('ws-1')
    await controller.refreshScans('ws-1', true)
    append.resolve(ok([all[49]!, all[50]!]))
    await late
    expect(controller.store.getState().scans['ws-1']?.value).toHaveLength(50)
    api.handlers.listScans = () => ok([all[49]!, all[50]!])
    await controller.loadMoreScans('ws-1')
    const ids = controller.store.getState().scans['ws-1']?.value?.map(scan => scan.id)
    expect(ids).toHaveLength(51)
    expect(new Set(ids).size).toBe(51)
  })

  it('retains the previous page and retry affordance after loading more fails', async () => {
    const api = fakeApi({ listScans: () => ok(page(50)) })
    controller = createController({ api, storage: null })
    await controller.refreshScans('ws-1')
    api.handlers.listScans = () => fail('security/transport')
    await controller.loadMoreScans('ws-1')
    expect(controller.store.getState().scans['ws-1']).toMatchObject({ status: 'error' })
    expect(controller.store.getState().scans['ws-1']?.value).toHaveLength(50)
    expect(controller.store.getState().scansHasMore['ws-1']).toBe(true)
    api.handlers.listScans = () => ok([])
    await controller.loadMoreScans('ws-1')
    expect(controller.store.getState().scansHasMore['ws-1']).toBe(false)
  })

  it('deletion invalidates pending scan, finding, and list reads and clears selection', async () => {
    const detail = deferred<RpcResult<ScanDetail>>()
    const findings = deferred<RpcResult<readonly FindingSummary[]>>()
    const finding = deferred<RpcResult<FindingDetail>>()
    const scans = deferred<RpcResult<readonly ScanSummary[]>>()
    let listCalls = 0
    const api = fakeApi({
      getScan: () => detail.promise,
      listFindings: () => findings.promise,
      getFinding: () => finding.promise,
      listScans: () => (++listCalls === 1 ? scans.promise : ok([])),
      listWorkspaces: () => ok([workspace()]),
      deleteScan: () => ok({ deleted: true }),
    })
    controller = createController({ api, storage: null })
    controller.store.setState(s => ({
      ...s,
      workspaceId: 'ws-1',
      viewScanId: 'scan-1',
      selectedFinding: { scanId: 'scan-1', findingId: 'f-1' },
      scans: { 'ws-1': { status: 'ready', value: [makeScan()] } },
    }))
    const pending = [
      controller.refreshScans('ws-1'),
      controller.loadScanDetail('scan-1'),
      controller.loadFindings('scan-1'),
      controller.loadFinding('scan-1', 'f-1'),
    ]
    await controller.deleteScan('scan-1')
    detail.resolve(ok(makeDetail()))
    findings.resolve(ok([makeFinding()]))
    finding.resolve(ok(makeFindingDetail()))
    scans.resolve(ok([makeScan()]))
    await Promise.all(pending)
    const state = controller.store.getState()
    expect(state.scans['ws-1']?.value).toEqual([])
    expect(state.details['scan-1']).toBeUndefined()
    expect(state.findings['scan-1']).toBeUndefined()
    expect(state.findingDetails['scan-1\u0000f-1']).toBeUndefined()
    expect(state.selectedFinding).toBeUndefined()
    expect(state.viewScanId).toBeUndefined()
    await controller.loadScanDetail('scan-1', true)
    expect(api.callsOf('getScan')).toHaveLength(1)
  })
})

describe('result cache revalidation', () => {
  it('reload refreshes completed scan data and finding details without discarding settings drafts', async () => {
    let triage: FindingSummary['triage'] = 'open'
    const api = fakeApi({
      getBootstrap: () => ok(makeBootstrap()),
      listWorkspaces: () => ok([workspace()]),
      listScans: () => ok([makeScan()]),
      getScan: () => ok(makeDetail()),
      listFindings: () => ok([makeFinding({ triage })]),
      getFinding: () => ok(makeFindingDetail({ triage, recommendation: triage })),
    })
    controller = createController({ api, storage: null })
    await controller.reloadBootstrap()
    await Promise.all([
      controller.loadScanDetail('scan-1'),
      controller.loadFindings('scan-1'),
      controller.loadFinding('scan-1', 'f-1'),
    ])
    controller.updateDraft(d => ({ ...d, storage: { ...d.storage, retentionDays: '45' } }))
    triage = 'false_positive'
    await controller.reload()
    expect(api.callsOf('getScan')).toHaveLength(2)
    expect(api.callsOf('listFindings')).toHaveLength(2)
    expect(api.callsOf('getFinding')).toHaveLength(2)
    expect(controller.store.getState().findings['scan-1']?.value?.[0]?.triage).toBe('false_positive')
    expect(controller.store.getState().findingDetails['scan-1\u0000f-1']?.value?.recommendation).toBe('false_positive')
    expect(controller.store.getState().form?.draft.storage.retentionDays).toBe('45')
  })

  it('saving triage supersedes older list and detail reads', async () => {
    const list = deferred<RpcResult<readonly FindingSummary[]>>()
    const detail = deferred<RpcResult<FindingDetail>>()
    const api = fakeApi({
      listFindings: () => list.promise,
      getFinding: () => detail.promise,
      setTriage: () => ok(makeFinding({ triage: 'false_positive' })),
    })
    controller = createController({ api, storage: null })
    controller.store.setState(s => ({
      ...s,
      findings: { 'scan-1': { status: 'ready', value: [makeFinding()] } },
      findingDetails: { 'scan-1\u0000f-1': { status: 'ready', value: makeFindingDetail() } },
    }))
    const pending = [controller.loadFindings('scan-1', true), controller.loadFinding('scan-1', 'f-1', true)]
    await controller.setTriage({ scanId: 'scan-1', findingId: 'f-1', triage: 'false_positive', note: 'saved note' })
    list.resolve(ok([makeFinding()]))
    detail.resolve(ok(makeFindingDetail()))
    await Promise.all(pending)
    expect(controller.store.getState().findings['scan-1']).toMatchObject({
      status: 'ready',
      value: [{ triage: 'false_positive' }],
    })
    expect(controller.store.getState().findingDetails['scan-1\u0000f-1']).toMatchObject({
      status: 'ready',
      value: { triage: 'false_positive', triageNote: 'saved note' },
    })
  })
})

describe('completed scan activity', () => {
  function event(seq: number): ScanEvent {
    return { seq, level: 'info', type: 'test', message: `event ${seq}`, at: '2026-10-17T00:00:00Z' }
  }

  it('reads through old event pages and retains the newest bounded window', async () => {
    const all = Array.from({ length: MAX_EVENTS * 2 + 13 }, (_, i) => event(i + 1))
    const api = fakeApi({ listEvents: p => ok(all.filter(e => e.seq > (p.afterSeq ?? 0)).slice(0, p.limit)) })
    controller = createController({ api, storage: null })
    await controller.loadScanEvents('scan-1')
    const latest = controller.store.getState().events['scan-1']!
    expect(api.callsOf('listEvents')).toHaveLength(3)
    expect(latest).toHaveLength(MAX_EVENTS)
    expect(latest.at(-1)?.seq).toBe(all.length)
    expect(latest[0]?.seq).toBe(all.length - MAX_EVENTS + 1)
    expect(controller.store.getState().eventsLoading['scan-1']).toBe(false)
    await controller.loadScanEvents('scan-1')
    expect(api.callsOf('listEvents')).toHaveLength(3)
  })

  it('keeps prior events on failure and supports an explicit retry', async () => {
    const api = fakeApi({ listEvents: () => fail('security/transport') })
    controller = createController({ api, storage: null })
    controller.store.setState(s => ({ ...s, events: { 'scan-1': [event(1)] } }))
    await controller.loadScanEvents('scan-1')
    expect(controller.store.getState().eventsErrors['scan-1']?.code).toBe('security/transport')
    expect(controller.store.getState().events['scan-1']).toHaveLength(1)
    api.handlers.listEvents = () => ok([event(1), event(2)])
    await controller.loadScanEvents('scan-1', true)
    expect(controller.store.getState().eventsErrors['scan-1']).toBeUndefined()
    expect(controller.store.getState().events['scan-1']).toHaveLength(2)
  })

  it.each(['delete', 'dispose'] as const)('does not continue event pagination after %s', async operation => {
    const gate = deferred<RpcResult<readonly ScanEvent[]>>()
    const api = fakeApi({ listEvents: () => gate.promise, deleteScan: () => ok({ deleted: true }) })
    controller = createController({ api, storage: null })
    const pending = controller.loadScanEvents('scan-1')
    if (operation === 'delete') await controller.deleteScan('scan-1')
    else controller.dispose()
    gate.resolve(ok(Array.from({ length: MAX_EVENTS }, (_, i) => event(i + 1))))
    await pending
    expect(api.callsOf('listEvents')).toHaveLength(1)
    expect(controller.store.getState().events['scan-1']).toBeUndefined()
    if (operation === 'delete') expect(controller.store.getState().eventsLoading['scan-1']).toBeUndefined()
  })
})

describe('scan creation outcomes and ownership', () => {
  it.each(['security/transport', 'security/aborted', 'security/internal'])(
    'keeps consent and reconciles history without guessing success after %s',
    async code => {
      let settings = makeSettings()
      const api = fakeApi({
        getBootstrap: () => ok(makeBootstrap()),
        updateSettings: p => {
          settings = { ...settings, privacy: { ...settings.privacy, ...p.patch.privacy } }
          return ok({ settings, revision: 2 })
        },
        createScan: () => fail(code),
        listScans: () => ok([makeScan({ id: 'maybe-created' })]),
      })
      controller = createController({ api, storage: null })
      await controller.reloadBootstrap()
      expect(await controller.startScan({ workspaceId: 'ws-1', mode: 'deep', consent: true })).toMatchObject({
        ok: false,
        error: { code: 'security/result-unknown', details: { reconciled: true } },
      })
      expect(settings.privacy.sendCodeToModel).toBe(true)
      expect(api.callsOf('updateSettings')).toHaveLength(1)
      expect(api.callsOf('createScan')).toHaveLength(1)
      expect(api.callsOf('listScans')).toHaveLength(1)
      expect(controller.store.getState().scans['ws-1']?.value?.[0]?.id).toBe('maybe-created')
    },
  )

  it('still reports an unknown outcome if history reconciliation also fails', async () => {
    const api = fakeApi({ createScan: () => fail('security/transport'), listScans: () => fail('security/transport') })
    controller = createController({ api, storage: null })
    expect(await controller.startScan({ workspaceId: 'ws-1', mode: 'deep' })).toMatchObject({
      ok: false,
      error: { code: 'security/result-unknown', details: { reconciled: false } },
    })
    expect(api.callsOf('createScan')).toHaveLength(1)
    expect(api.callsOf('updateSettings')).toHaveLength(0)
  })

  it.each(['model', 'consent'] as const)('does not advance after disposal while saving %s', async stage => {
    const gate = deferred<RpcResult<{ settings: ReturnType<typeof makeSettings>; revision: number }>>()
    const api = fakeApi({ getBootstrap: () => ok(makeBootstrap()), updateSettings: () => gate.promise })
    controller = createController({ api, storage: null })
    await controller.reloadBootstrap()
    const pending = controller.startScan({
      workspaceId: 'ws-1',
      mode: 'deep',
      consent: true,
      ...(stage === 'model' ? { model: { provider: 'p', model: 'm' } } : {}),
    })
    controller.dispose()
    gate.resolve(
      ok({ settings: makeSettings({ privacy: { ...makeSettings().privacy, sendCodeToModel: true } }), revision: 2 }),
    )
    expect(await pending).toMatchObject({ ok: false, error: { code: 'security/aborted' } })
    expect(api.callsOf('createScan')).toHaveLength(0)
    expect(api.callsOf('updateSettings')).toHaveLength(1)
    expect(controller.store.getState().bootstrap.value?.settingsRevision).toBe(1)
  })

  it('does not retry a settings conflict or write settings after disposal', async () => {
    const gate = deferred<RpcResult<never>>()
    const api = fakeApi({ getBootstrap: () => ok(makeBootstrap()), updateSettings: () => gate.promise })
    controller = createController({ api, storage: null })
    await controller.reloadBootstrap()
    const pending = controller.startScan({ workspaceId: 'ws-1', mode: 'deep', consent: true })
    controller.dispose()
    gate.resolve(fail('security/conflict'))
    await pending
    await controller.updateSettings({ ui: { language: 'ja' } })
    expect(api.callsOf('getBootstrap')).toHaveLength(1)
    expect(api.callsOf('updateSettings')).toHaveLength(1)
    expect(api.callsOf('createScan')).toHaveLength(0)
  })

  it('does not undo an accepted scan when its controller is disposed before the response', async () => {
    const gate = deferred<RpcResult<{ scanId: string }>>()
    const api = fakeApi({ createScan: () => gate.promise })
    controller = createController({ api, storage: null })
    const pending = controller.startScan({ workspaceId: 'ws-1', mode: 'deep' })
    controller.dispose()
    gate.resolve(ok({ scanId: 'accepted' }))
    expect(await pending).toEqual(ok({ scanId: 'accepted' }))
    expect(api.callsOf('cancelScan')).toHaveLength(0)
    expect(api.callsOf('updateSettings')).toHaveLength(0)
    expect(api.callsOf('listScans')).toHaveLength(0)
  })
})

describe('recheck and chat handoff', () => {
  it('can preserve the previous scan depth and subfolder for a recheck', async () => {
    const settings = makeSettings({ privacy: { ...makeSettings().privacy, sendCodeToModel: true } })
    const api = fakeApi({
      getBootstrap: () => ok(makeBootstrap({ settings })),
      createScan: () => ok({ scanId: 'new' }),
      listScans: () => ok([]),
    })
    controller = createController({ api, storage: null })
    await controller.reloadBootstrap()
    await controller.quickRescan('ws-1', 'packages/api', 'research')
    expect(api.callsOf('createScan')).toEqual([
      { workspaceId: 'ws-1', mode: 'research', subpath: 'packages/api', language: 'en' },
    ])
  })

  it('opens the consent dialog using the original depth', async () => {
    controller = createController({ api: fakeApi(), storage: null })
    await controller.quickRescan('ws-1', undefined, 'deep')
    expect(controller.store.getState().newScan).toEqual({ workspaceId: 'ws-1', mode: 'deep' })
  })

  it('requests chat preparation without authorizing the replacement of existing input', async () => {
    let draft = 'unsent user input'
    const startSession = vi.fn((_workspaceId: string, options: { prompt: string; clearPreviousDraft?: boolean }) => {
      if (!draft || options.clearPreviousDraft) draft = options.prompt
    })
    const api = fakeApi({ getFixPrompt: () => ok({ prompt: 'fix prompt', language: 'en' }) })
    controller = createController({ api, storage: null, host: { uiWorkspace: () => ({ startSession }) } })
    expect(await controller.fixInChat({ workspaceId: 'ws-1', scanId: 'scan-1', findingId: 'f-1' })).toMatchObject({
      ok: true,
    })
    expect(startSession).toHaveBeenCalledWith('ws-1', { prompt: 'fix prompt', clearPreviousDraft: false })
    expect(draft).toBe('unsent user input')
  })
})

describe('disposed settings recovery', () => {
  it('does not update a disposed form after a conflict recovery read finishes', async () => {
    const recovery = deferred<RpcResult<ReturnType<typeof makeBootstrap>>>()
    const started = deferred<void>()
    const api = fakeApi({ getBootstrap: () => ok(makeBootstrap()), updateSettings: () => fail('security/conflict') })
    controller = createController({ api, storage: null })
    await controller.reloadBootstrap()
    controller.updateDraft(d => ({ ...d, storage: { ...d.storage, retentionDays: '45' } }))
    api.handlers.getBootstrap = () => {
      started.resolve()
      return recovery.promise
    }
    const saving = controller.saveSettings()
    await started.promise
    controller.dispose()
    const disposedState = controller.store.getState()
    recovery.resolve(ok(makeBootstrap({ settingsRevision: 2 })))
    expect(await saving).toMatchObject({ ok: false, error: { code: 'security/aborted' } })
    expect(controller.store.getState()).toBe(disposedState)
    expect(api.callsOf('updateSettings')).toHaveLength(1)
  })
})
