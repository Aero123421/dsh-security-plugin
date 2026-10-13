import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createController, MAX_EVENTS, POLL_HIDDEN_MS, POLL_VISIBLE_MS } from '../../src/client/controller.ts'
import type { ScanEvent } from '../../src/shared/contracts.ts'
import { fail, fakeApi, makeBootstrap, makeDetail, makeFinding, makeScan, makeSettings, ok } from './helpers.tsx'

function setVisibility(state: 'visible' | 'hidden') {
  Object.defineProperty(document, 'visibilityState', { configurable: true, get: () => state })
  document.dispatchEvent(new Event('visibilitychange'))
}

async function tick(ms: number) {
  await vi.advanceTimersByTimeAsync(ms)
}

describe('controller polling', () => {
  beforeEach(() => {
    vi.useFakeTimers()
    setVisibility('visible')
  })
  afterEach(() => {
    vi.useRealTimers()
  })

  function setup(statuses: string[]) {
    let i = 0
    const api = fakeApi({
      getScan: () => {
        const status = (statuses[Math.min(i, statuses.length - 1)] ?? 'running') as 'running'
        i++
        return ok(makeDetail({ id: 's1', status }))
      },
      listEvents: () => ok([]),
      listScans: () => ok([makeScan({ id: 's1', status: 'completed' })]),
      listWorkspaces: () => ok([]),
      listFindings: () => ok([makeFinding({ scanId: 's1' })]),
    })
    const controller = createController({ api, storage: null })
    return { api, controller }
  }

  it('polls getScan every 1.5 s while visible and stops on release', async () => {
    const { api, controller } = setup(['running'])
    const release = controller.watchScan('s1')
    await tick(0)
    expect(api.callsOf('getScan')).toHaveLength(1)
    await tick(POLL_VISIBLE_MS)
    expect(api.callsOf('getScan')).toHaveLength(2)
    await tick(POLL_VISIBLE_MS * 2)
    expect(api.callsOf('getScan')).toHaveLength(4)
    release()
    await tick(POLL_HIDDEN_MS * 3)
    expect(api.callsOf('getScan')).toHaveLength(4)
    controller.dispose()
  })

  it('backs off to 10 s while the document is hidden and resumes immediately when visible', async () => {
    const { api, controller } = setup(['running'])
    controller.watchScan('s1')
    await tick(0)
    expect(api.callsOf('getScan')).toHaveLength(1)
    setVisibility('hidden')
    await tick(POLL_VISIBLE_MS)
    expect(api.callsOf('getScan')).toHaveLength(2) // already scheduled at the visible rate
    await tick(POLL_VISIBLE_MS * 3)
    expect(api.callsOf('getScan')).toHaveLength(2)
    await tick(POLL_HIDDEN_MS)
    expect(api.callsOf('getScan')).toHaveLength(3)
    setVisibility('visible')
    await tick(0)
    expect(api.callsOf('getScan')).toHaveLength(4)
    controller.dispose()
  })

  it('stops when the scan reaches a terminal status and refreshes findings', async () => {
    const { api, controller } = setup(['running', 'completed'])
    controller.watchScan('s1')
    await tick(0)
    await tick(POLL_VISIBLE_MS)
    expect(api.callsOf('getScan')).toHaveLength(2)
    await tick(POLL_VISIBLE_MS * 4)
    expect(api.callsOf('getScan')).toHaveLength(2)
    expect(api.callsOf('listFindings')).toEqual([{ scanId: 's1' }])
    expect(controller.store.getState().findings.s1?.status).toBe('ready')
    controller.dispose()
  })

  it('shares one poller between watchers and stops after the last release', async () => {
    const { api, controller } = setup(['running'])
    const a = controller.watchScan('s1')
    const b = controller.watchScan('s1')
    await tick(0)
    expect(api.callsOf('getScan')).toHaveLength(1)
    a()
    await tick(POLL_VISIBLE_MS)
    expect(api.callsOf('getScan')).toHaveLength(2)
    b()
    await tick(POLL_VISIBLE_MS * 2)
    expect(api.callsOf('getScan')).toHaveLength(2)
    controller.dispose()
  })

  it('dispose stops every poller', async () => {
    const { api, controller } = setup(['running'])
    controller.watchScan('s1')
    await tick(0)
    controller.dispose()
    await tick(POLL_HIDDEN_MS * 2)
    expect(api.callsOf('getScan')).toHaveLength(1)
  })

  it('appends events incrementally by afterSeq and keeps at most 200', async () => {
    let next = 1
    const api = fakeApi({
      getScan: () => ok(makeDetail({ id: 's1', status: 'running' })),
      listEvents: payload => {
        const after = payload.afterSeq ?? 0
        expect(after).toBe(next - 1)
        const batch: ScanEvent[] = Array.from({ length: 150 }, (_, i) => ({
          seq: next + i,
          at: '2026-10-01T10:00:00Z',
          level: 'info',
          type: 'x',
          message: `event ${next + i}`,
        }))
        next += 150
        return ok(batch)
      },
    })
    const controller = createController({ api, storage: null })
    controller.watchScan('s1')
    await tick(0)
    await tick(POLL_VISIBLE_MS)
    const events = controller.store.getState().events.s1 ?? []
    expect(events).toHaveLength(MAX_EVENTS)
    expect(events[0]?.seq).toBe(101)
    expect(events.at(-1)?.seq).toBe(300)
    expect(api.callsOf('listEvents')[1]).toMatchObject({ scanId: 's1', afterSeq: 150 })
    controller.dispose()
  })
})

describe('controller new-scan consent flow', () => {
  function setup(handlers: Parameters<typeof fakeApi>[0] = {}) {
    const api = fakeApi({
      getBootstrap: () => ok(makeBootstrap()),
      listWorkspaces: () => ok([{ id: 'ws-1', title: 'Demo', displayPath: '~/demo' }]),
      listScans: () => ok([]),
      createScan: () => ok({ scanId: 'new-scan' }),
      ...handlers,
    })
    const controller = createController({ api, storage: null })
    return { api, controller }
  }

  it('enables sendCodeToModel with expectedRevision, then creates the scan', async () => {
    const { api, controller } = setup({
      updateSettings: payload =>
        ok({
          settings: makeSettings({ privacy: { ...makeSettings().privacy, ...payload.patch.privacy } }),
          revision: 2,
        }),
    })
    await controller.reloadBootstrap()
    const result = await controller.startScan({ workspaceId: 'ws-1', mode: 'deep', consent: true })
    expect(result.ok).toBe(true)
    const order = api.calls.map(c => c.method).filter(m => m === 'updateSettings' || m === 'createScan')
    expect(order).toEqual(['updateSettings', 'createScan'])
    expect(api.callsOf('updateSettings')[0]).toEqual({
      patch: { privacy: { sendCodeToModel: true } },
      expectedRevision: 1,
    })
    expect(api.callsOf('createScan')[0]).toEqual({ workspaceId: 'ws-1', mode: 'deep', language: 'en' })
    expect(controller.store.getState().bootstrap.value?.settingsRevision).toBe(2)
  })

  it('does not create a scan when consent is refused as forbidden-remote', async () => {
    const { api, controller } = setup({ updateSettings: () => fail('security/forbidden-remote') })
    await controller.reloadBootstrap()
    const result = await controller.startScan({ workspaceId: 'ws-1', mode: 'deep', consent: true })
    expect(result).toMatchObject({ ok: false, error: { code: 'security/forbidden-remote' } })
    expect(api.callsOf('createScan')).toHaveLength(0)
  })

  it('reloads settings and retries once after a revision conflict', async () => {
    let attempts = 0
    let bootRevision = 1
    const { api, controller } = setup({
      getBootstrap: () => ok(makeBootstrap({ settingsRevision: bootRevision })),
      updateSettings: payload => {
        attempts++
        if (attempts === 1) {
          bootRevision = 5
          return fail('security/conflict')
        }
        return ok({
          settings: makeSettings({ privacy: { ...makeSettings().privacy, sendCodeToModel: true } }),
          revision: payload.expectedRevision + 1,
        })
      },
    })
    await controller.reloadBootstrap()
    const result = await controller.startScan({ workspaceId: 'ws-1', mode: 'quick', consent: true })
    expect(result.ok).toBe(true)
    const updates = api.callsOf('updateSettings') as { expectedRevision: number }[]
    expect(updates.map(u => u.expectedRevision)).toEqual([1, 5])
    expect(api.callsOf('createScan')).toHaveLength(1)
  })

  it('keeps no-model failures for the dialog to explain', async () => {
    const { controller } = setup({ createScan: () => fail('security/no-model') })
    await controller.reloadBootstrap()
    const result = await controller.startScan({ workspaceId: 'ws-1', mode: 'deep' })
    expect(result).toMatchObject({ ok: false, error: { code: 'security/no-model' } })
  })
})

describe('controller settings save', () => {
  it('sends a minimal patch with expectedRevision', async () => {
    const api = fakeApi({
      getBootstrap: () => ok(makeBootstrap({ settingsRevision: 7 })),
      updateSettings: () =>
        ok({ settings: makeSettings({ storage: { retentionDays: 30, keepTranscripts: true } }), revision: 8 }),
    })
    const controller = createController({ api, storage: null })
    await controller.reloadBootstrap()
    controller.updateDraft(d => ({ ...d, storage: { ...d.storage, retentionDays: '30' } }))
    await controller.saveSettings()
    expect(api.callsOf('updateSettings')).toEqual([{ patch: { storage: { retentionDays: 30 } }, expectedRevision: 7 }])
    const form = controller.store.getState().form
    expect(form?.revision).toBe(8)
    expect(form?.draft.storage.retentionDays).toBe('30')
    expect(form?.result).toEqual({ tone: 'success', key: 'settings.saved' })
  })

  it('reloads on conflict, keeps the user edit and reports it', async () => {
    let revision = 1
    const api = fakeApi({
      getBootstrap: () =>
        ok(
          makeBootstrap({
            settingsRevision: revision,
            settings: makeSettings({ ui: { language: revision > 1 ? 'ja' : 'auto' } }),
          }),
        ),
      updateSettings: () => {
        revision = 2
        return fail('security/conflict')
      },
    })
    const controller = createController({ api, storage: null })
    await controller.reloadBootstrap()
    controller.updateDraft(d => ({ ...d, storage: { ...d.storage, retentionDays: '30' } }))
    await controller.saveSettings()
    const form = controller.store.getState().form
    expect(form?.revision).toBe(2)
    expect(form?.base.ui.language).toBe('ja')
    expect(form?.draft.ui.language).toBe('ja')
    expect(form?.draft.storage.retentionDays).toBe('30')
    expect(form?.result).toEqual({ tone: 'warn', key: 'settings.conflict' })
  })

  it('refuses to save invalid values', async () => {
    const api = fakeApi({ getBootstrap: () => ok(makeBootstrap()) })
    const controller = createController({ api, storage: null })
    await controller.reloadBootstrap()
    controller.updateDraft(d => ({ ...d, scan: { ...d.scan, parallelWorkers: '99' } }))
    await controller.saveSettings()
    expect(api.callsOf('updateSettings')).toHaveLength(0)
    expect(controller.store.getState().form?.result).toEqual({ tone: 'error', key: 'settings.invalid' })
  })
})

describe('controller language', () => {
  it('follows DSH locale under auto and the explicit setting otherwise', async () => {
    const api = fakeApi({ getBootstrap: () => ok(makeBootstrap()) })
    const controller = createController({ api, storage: null, dshLocale: 'en-US' })
    await controller.reloadBootstrap()
    expect(controller.store.getState().language).toBe('en')
    controller.setDshLocale('ja-JP')
    expect(controller.store.getState().language).toBe('ja')
    api.handlers.getBootstrap = () => ok(makeBootstrap({ settings: makeSettings({ ui: { language: 'zh' } }) }))
    await controller.reloadBootstrap()
    expect(controller.store.getState().language).toBe('zh')
  })
})
