import { afterEach, describe, expect, it, vi } from 'vitest'
import { createController, type SecurityController } from '../../src/client/controller.ts'
import { buildPatch, isPatchEmpty } from '../../src/client/settingsForm.ts'
import type { RpcResult, ScanDetail } from '../../src/shared/contracts.ts'
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
  vi.useRealTimers()
})

describe('B6 client races', () => {
  it('keeps edits made during a settings save as a dirty draft after success', async () => {
    const gate = deferred<RpcResult<{ settings: ReturnType<typeof makeSettings>; revision: number }>>()
    const api = fakeApi({ getBootstrap: () => ok(makeBootstrap()), updateSettings: () => gate.promise })
    controller = createController({ api, storage: null })
    await controller.reloadBootstrap()
    controller.updateDraft(d => ({ ...d, storage: { ...d.storage, retentionDays: '30' } }))
    const save = controller.saveSettings()
    controller.updateDraft(d => ({ ...d, storage: { ...d.storage, retentionDays: '45' } }))
    gate.resolve(ok({ settings: makeSettings({ storage: { retentionDays: 30, keepTranscripts: true } }), revision: 2 }))
    await save
    const form = controller.store.getState().form!
    expect(form.base.storage.retentionDays).toBe('30')
    expect(form.draft.storage.retentionDays).toBe('45')
    expect(isPatchEmpty(buildPatch(form.base, form.draft))).toBe(false)
    expect(form.saving).toBe(false)
    expect(form.result).toBeUndefined()
  })

  it('resume supersedes a slow detail load and finishes in running state', async () => {
    const gate = deferred<RpcResult<ScanDetail>>()
    let requests = 0
    const api = fakeApi({
      getScan: () => (++requests === 1 ? gate.promise : ok(makeDetail({ status: 'running' }))),
      resumeScan: () => ok(makeScan({ status: 'running' })),
    })
    controller = createController({ api, storage: null })
    controller.store.setState(s => ({
      ...s,
      scans: { 'ws-1': { status: 'ready', value: [makeScan({ status: 'paused' })] } },
    }))
    const slow = controller.loadScanDetail('scan-1')
    const resumed = controller.resumeScan('scan-1')
    await resumed
    gate.resolve(ok(makeDetail({ status: 'paused' })))
    await Promise.all([slow, resumed])
    expect(api.callsOf('getScan')).toHaveLength(2)
    expect(controller.store.getState().details['scan-1']?.value?.summary.status).toBe('running')
    expect(controller.store.getState().scans['ws-1']?.value?.[0]?.status).toBe('running')
  })

  it.each(['list', 'detail'] as const)('forced finding %s load supersedes an older response', async kind => {
    const gate = deferred<RpcResult<never>>()
    let calls = 0
    const api = fakeApi({
      listFindings: () => (++calls === 1 ? gate.promise : ok([makeFinding({ title: 'new' })])),
      getFinding: () => (++calls === 1 ? gate.promise : ok(makeFindingDetail({ title: 'new' }))),
    })
    controller = createController({ api, storage: null })
    const load = (force = false) =>
      kind === 'list' ? controller!.loadFindings('scan-1', force) : controller!.loadFinding('scan-1', 'f-1', force)
    const slow = load()
    const fresh = load(true)
    await fresh
    gate.resolve(fail('security/transport'))
    await Promise.all([slow, fresh])
    const state = controller.store.getState()
    const entry = kind === 'list' ? state.findings['scan-1'] : state.findingDetails['scan-1\u0000f-1']
    expect(calls).toBe(2)
    expect(entry?.status).toBe('ready')
  })

  it('reuses estimates on reopen within TTL but refetches after 30 seconds', async () => {
    vi.useFakeTimers()
    const estimate = {
      files: 1,
      bytes: 1,
      excluded: 0,
      languages: [],
      frameworks: [],
      endpoints: 0,
      plannedTasks: 0,
      tokens: { min: 0, max: 0 },
      truncated: false,
    }
    const api = fakeApi({ estimateScan: () => ok(estimate) })
    controller = createController({ api, storage: null })
    controller.openNewScan()
    await controller.estimate('ws-1', 'quick')
    controller.closeNewScan()
    await vi.advanceTimersByTimeAsync(29_000)
    controller.openNewScan()
    await controller.estimate('ws-1', 'quick')
    expect(api.callsOf('estimateScan')).toHaveLength(1)
    controller.closeNewScan()
    await vi.advanceTimersByTimeAsync(1001)
    controller.openNewScan()
    await controller.estimate('ws-1', 'quick')
    expect(api.callsOf('estimateScan')).toHaveLength(2)
  })

  it('invalidates estimates when the workspace list refreshes, including an in-flight estimate', async () => {
    const gate = deferred<RpcResult<never>>()
    let calls = 0
    const estimate = {
      files: 1,
      bytes: 1,
      excluded: 0,
      languages: [],
      frameworks: [],
      endpoints: 0,
      plannedTasks: 0,
      tokens: { min: 0, max: 0 },
      truncated: false,
    }
    const api = fakeApi({
      estimateScan: () => (++calls === 1 ? gate.promise : ok(estimate)),
      listWorkspaces: () => ok([]),
    })
    controller = createController({ api, storage: null })
    const slow = controller.estimate('ws-1', 'quick')
    await controller.refreshWorkspaces()
    gate.resolve(ok(estimate) as never)
    await slow
    await controller.estimate('ws-1', 'quick')
    await controller.refreshWorkspaces()
    await controller.estimate('ws-1', 'quick')
    expect(calls).toBe(3)
  })

  it.each([false, true])(
    'failed create restores only consent granted by this flow (previously on: %s)',
    async alreadyOn => {
      let settings = makeSettings({ privacy: { ...makeSettings().privacy, sendCodeToModel: alreadyOn } })
      let revision = 1
      const api = fakeApi({
        getBootstrap: () => ok(makeBootstrap({ settings })),
        updateSettings: p => {
          settings = { ...settings, privacy: { ...settings.privacy, ...p.patch.privacy } }
          return ok({ settings, revision: ++revision })
        },
        createScan: () => fail('security/no-model'),
      })
      controller = createController({ api, storage: null })
      await controller.reloadBootstrap()
      expect(await controller.startScan({ workspaceId: 'ws-1', mode: 'deep', consent: true })).toMatchObject({
        ok: false,
        error: { code: 'security/no-model' },
      })
      expect(settings.privacy.sendCodeToModel).toBe(alreadyOn)
      expect(controller.store.getState().bootstrap.value?.settings.privacy.sendCodeToModel).toBe(alreadyOn)
      expect(api.callsOf('updateSettings')).toHaveLength(alreadyOn ? 0 : 2)
    },
  )

  it('successful create keeps the persisted consent', async () => {
    let settings = makeSettings()
    const api = fakeApi({
      getBootstrap: () => ok(makeBootstrap()),
      updateSettings: p => {
        settings = { ...settings, privacy: { ...settings.privacy, ...p.patch.privacy } }
        return ok({ settings, revision: 2 })
      },
      createScan: () => ok({ scanId: 'new' }),
      listScans: () => ok([]),
    })
    controller = createController({ api, storage: null })
    await controller.reloadBootstrap()
    await controller.startScan({ workspaceId: 'ws-1', mode: 'deep', consent: true })
    expect(settings.privacy.sendCodeToModel).toBe(true)
    expect(api.callsOf('updateSettings')).toHaveLength(1)
  })
})

it('does not claim consent enabled by another viewer after a conflict as its own grant', async () => {
  let revision = 1
  const settings = makeSettings({ privacy: { ...makeSettings().privacy, sendCodeToModel: true } })
  const api = fakeApi({
    getBootstrap: () => ok(makeBootstrap({ settingsRevision: revision, ...(revision > 1 ? { settings } : {}) })),
    updateSettings: () => {
      revision = 2
      return fail('security/conflict')
    },
    createScan: () => fail('security/no-model'),
  })
  controller = createController({ api, storage: null })
  await controller.reloadBootstrap()
  await controller.startScan({ workspaceId: 'ws-1', mode: 'deep', consent: true })
  expect(api.callsOf('updateSettings')).toHaveLength(1)
  expect(controller.store.getState().bootstrap.value?.settings.privacy.sendCodeToModel).toBe(true)
})

it('uses the actual consent write revision for best-effort rollback and preserves the create failure', async () => {
  const consent = deferred<RpcResult<{ settings: ReturnType<typeof makeSettings>; revision: number }>>()
  let boot = makeBootstrap()
  const api = fakeApi({
    getBootstrap: () => ok(boot),
    updateSettings: p => (p.patch.privacy?.sendCodeToModel === true ? consent.promise : fail('security/conflict')),
    createScan: () => fail('security/no-model'),
  })
  controller = createController({ api, storage: null })
  await controller.reloadBootstrap()
  const start = controller.startScan({ workspaceId: 'ws-1', mode: 'deep', consent: true })
  boot = makeBootstrap({
    settingsRevision: 3,
    settings: makeSettings({ privacy: { ...makeSettings().privacy, sendCodeToModel: true } }),
  })
  await controller.reloadBootstrap({ force: true })
  consent.resolve(ok({ settings: boot.settings, revision: 2 }))
  expect(await start).toMatchObject({ ok: false, error: { code: 'security/no-model' } })
  expect(api.callsOf('updateSettings').at(-1)).toEqual({
    patch: { privacy: { sendCodeToModel: false } },
    expectedRevision: 2,
  })
  expect(controller.store.getState().bootstrap.value?.settingsRevision).toBe(3)
  expect(controller.store.getState().bootstrap.value?.settings.privacy.sendCodeToModel).toBe(true)
})

it('drops detail and finding responses after controller disposal', async () => {
  const detail = deferred<RpcResult<ScanDetail>>()
  const findings = deferred<RpcResult<never>>()
  const finding = deferred<RpcResult<never>>()
  const api = fakeApi({
    getScan: () => detail.promise,
    listFindings: () => findings.promise,
    getFinding: () => finding.promise,
  })
  controller = createController({ api, storage: null })
  const pending = [
    controller.loadScanDetail('scan-1'),
    controller.loadFindings('scan-1'),
    controller.loadFinding('scan-1', 'f-1'),
  ]
  controller.dispose()
  detail.resolve(ok(makeDetail()))
  findings.resolve(fail('security/transport'))
  finding.resolve(fail('security/transport'))
  await Promise.all(pending)
  const state = controller.store.getState()
  expect(state.details['scan-1']?.status).toBe('loading')
  expect(state.findings['scan-1']?.status).toBe('loading')
  expect(state.findingDetails['scan-1\u0000f-1']?.status).toBe('loading')
})

it('preserves in-flight edits when a newer bootstrap supersedes the save response', async () => {
  const gate = deferred<RpcResult<{ settings: ReturnType<typeof makeSettings>; revision: number }>>()
  let boot = makeBootstrap()
  const api = fakeApi({ getBootstrap: () => ok(boot), updateSettings: () => gate.promise })
  controller = createController({ api, storage: null })
  await controller.reloadBootstrap()
  controller.updateDraft(d => ({ ...d, storage: { ...d.storage, retentionDays: '30' } }))
  const save = controller.saveSettings()
  controller.updateDraft(d => ({ ...d, storage: { ...d.storage, retentionDays: '45' } }))
  boot = makeBootstrap({ settingsRevision: 3, settings: makeSettings({ ui: { language: 'ja' } }) })
  await controller.reloadBootstrap({ force: true })
  gate.resolve(ok({ settings: makeSettings({ storage: { retentionDays: 30, keepTranscripts: true } }), revision: 2 }))
  await save
  const form = controller.store.getState().form!
  expect(form.revision).toBe(3)
  expect(form.draft.ui.language).toBe('ja')
  expect(form.draft.storage.retentionDays).toBe('45')
  expect(form.result).toBeUndefined()
})

it('a poll started before resume cannot replace the running summary with paused state', async () => {
  vi.useFakeTimers()
  const gate = deferred<RpcResult<ScanDetail>>()
  let requests = 0
  const api = fakeApi({
    getScan: () => (++requests === 1 ? gate.promise : ok(makeDetail({ status: 'running' }))),
    resumeScan: () => ok(makeScan({ status: 'running' })),
    listEvents: () => ok([]),
  })
  controller = createController({ api, storage: null })
  controller.store.setState(s => ({
    ...s,
    scans: { 'ws-1': { status: 'ready', value: [makeScan({ status: 'paused' })] } },
  }))
  controller.watchScan('scan-1')
  await vi.advanceTimersByTimeAsync(0)
  await controller.resumeScan('scan-1')
  gate.resolve(ok(makeDetail({ status: 'paused' })))
  await vi.advanceTimersByTimeAsync(0)
  expect(controller.store.getState().details['scan-1']?.value?.summary.status).toBe('running')
  expect(controller.store.getState().scans['ws-1']?.value?.[0]?.status).toBe('running')
})
