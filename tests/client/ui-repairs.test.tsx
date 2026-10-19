import { act } from 'react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { RpcResult } from '../../src/shared/contracts.ts'
import type { ScanMode } from '../../src/shared/domain.ts'
import { ControllerProvider, useSecurity } from '../../src/client/context.tsx'
import { createController, type SecurityController } from '../../src/client/controller.ts'
import { FindingDetailView } from '../../src/client/views/FindingDetail.tsx'
import { NewScanDialog } from '../../src/client/views/NewScanDialog.tsx'
import { SettingsSection } from '../../src/client/views/Settings.tsx'
import {
  byText,
  click,
  fail,
  fakeApi,
  flush,
  type Handlers,
  makeBootstrap,
  makeFinding,
  makeFindingDetail,
  makeScan,
  makeSettings,
  type Mounted,
  mount,
  ok,
} from './helpers.tsx'

let mounted: Mounted | undefined
let controller: SecurityController | undefined

afterEach(() => {
  mounted?.unmount()
  mounted = undefined
  controller?.dispose()
  controller = undefined
  document.body.innerHTML = ''
})

function deferred<T>() {
  let resolve!: (value: T) => void
  const promise = new Promise<T>(done => {
    resolve = done
  })
  return { promise, resolve }
}

const PROVIDERS = [{ id: 'p', name: 'Provider', models: [{ id: 'm', name: 'Model' }] }]
const SETTINGS = makeSettings({
  models: { default: { provider: 'p', model: 'm' } },
  privacy: { ...makeSettings().privacy, sendCodeToModel: true },
})

async function setup(extra: Handlers = {}, host: Parameters<typeof createController>[0]['host'] = {}) {
  const api = fakeApi({
    getBootstrap: () => ok(makeBootstrap({ settings: SETTINGS })),
    listWorkspaces: () => ok([{ id: 'ws-1', title: 'Demo', displayPath: '~/demo' }]),
    listScans: () => ok([]),
    listModels: () => ok(PROVIDERS),
    getFinding: () => ok(makeFindingDetail()),
    ...extra,
  })
  controller = createController({ api, storage: null, host, dshLocale: 'en' })
  controller.ensureLoaded()
  await flush(10)
  return { api, c: controller }
}

async function inputNote(textarea: HTMLTextAreaElement, value: string) {
  await act(async () => {
    Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value')!.set!.call(textarea, value)
    textarea.dispatchEvent(new Event('input', { bubbles: true }))
  })
}

async function renderFinding(extra: Handlers = {}, mode: ScanMode = 'deep') {
  const result = await setup(extra)
  mounted = mount(
    <ControllerProvider controller={result.c}>
      <FindingDetailView scan={makeScan({ mode })} findingId="f-1" />
    </ControllerProvider>,
  )
  await flush(10)
  return { ...result, root: mounted.container }
}

function DialogHost() {
  const request = useSecurity(s => s.newScan)
  return request ? <NewScanDialog request={request} /> : null
}

async function renderDialog(extra: Handlers = {}) {
  const result = await setup(extra)
  result.c.openNewScan({ workspaceId: 'ws-1' })
  mounted = mount(
    <ControllerProvider controller={result.c}>
      <DialogHost />
    </ControllerProvider>,
  )
  await flush(10)
  return { ...result, dialog: document.querySelector<HTMLElement>('[role="dialog"]')! }
}

describe('triage draft repair', () => {
  it('keeps additional note and decision edits made while saving and marks them unsaved', async () => {
    const save = deferred<RpcResult<ReturnType<typeof makeFinding>>>()
    const { api, root } = await renderFinding({ setTriage: () => save.promise })
    const note = root.querySelector<HTMLTextAreaElement>('textarea')!
    await inputNote(note, 'Submitted note')
    await click(byText(root, 'button', 'Save decision'))
    await inputNote(note, 'Newer unsaved note')
    await click(byText(root, 'label.dshsec-seg', 'Accepted risk').querySelector('input'))
    await act(async () => save.resolve(ok(makeFinding({ triage: 'open' }))))
    await flush(10)
    expect(note.value).toBe('Newer unsaved note')
    expect(root.querySelector<HTMLInputElement>('input[value="accepted_risk"]')?.checked).toBe(true)
    expect(root.textContent).toContain('Your newer changes are not saved yet')
    expect(root.textContent).toContain('You have unsaved changes')
    expect(api.callsOf('setTriage')).toEqual([
      { scanId: 'scan-1', findingId: 'f-1', triage: 'open', note: 'Submitted note' },
    ])
    expect((byText(root, 'button', 'Save decision') as HTMLButtonElement).disabled).toBe(false)
  })

  it('leaves a clean saved draft clean and still adopts later external changes', async () => {
    const { api, c, root } = await renderFinding({
      setTriage: payload => ok(makeFinding({ triage: payload.triage })),
    })
    await inputNote(root.querySelector('textarea')!, 'Saved note')
    await click(byText(root, 'button', 'Save decision'))
    expect(root.textContent).toContain('Decision saved.')
    expect(root.textContent).not.toContain('You have unsaved changes')
    expect((byText(root, 'button', 'Save decision') as HTMLButtonElement).disabled).toBe(true)
    api.handlers.getFinding = () => ok(makeFindingDetail({ triage: 'false_positive', triageNote: 'External note' }))
    await act(async () => c.loadFinding('scan-1', 'f-1', true))
    await flush()
    expect(root.querySelector<HTMLTextAreaElement>('textarea')?.value).toBe('External note')
    expect(root.querySelector<HTMLInputElement>('input[value="false_positive"]')?.checked).toBe(true)
  })

  it('retains the latest input after a save failure', async () => {
    const save = deferred<RpcResult<ReturnType<typeof makeFinding>>>()
    const { root } = await renderFinding({ setTriage: () => save.promise })
    const note = root.querySelector<HTMLTextAreaElement>('textarea')!
    await inputNote(note, 'First note')
    await click(byText(root, 'button', 'Save decision'))
    await inputNote(note, 'Keep this draft')
    await act(async () => save.resolve(fail('security/internal', 'Save failed')))
    await flush()
    expect(note.value).toBe('Keep this draft')
    expect(root.textContent).toContain('You have unsaved changes')
    expect((byText(root, 'button', 'Save decision') as HTMLButtonElement).disabled).toBe(false)
  })
})

describe('scan start dismissal repair', () => {
  it('blocks cancel, close, Escape and backdrop while starting, then unlocks after failure', async () => {
    const start = deferred<RpcResult<{ scanId: string }>>()
    const { api, c, dialog } = await renderDialog({ createScan: () => start.promise })
    await click(byText(dialog, 'button', 'Start scan'))
    const cancel = byText<HTMLButtonElement>(dialog, 'button', 'Cancel')
    const close = dialog.querySelector<HTMLButtonElement>('.dshsec-modal-x')!
    expect(cancel.disabled).toBe(true)
    expect(close.disabled).toBe(true)
    expect(dialog.textContent).toContain('closing is temporarily disabled')
    expect(dialog.querySelector('form')?.getAttribute('aria-busy')).toBe('true')
    await click(cancel)
    await click(close)
    await act(async () => {
      dialog.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }))
      dialog.parentElement!.dispatchEvent(new MouseEvent('mousedown', { bubbles: true }))
    })
    expect(c.store.getState().newScan).toBeDefined()
    expect(api.callsOf('createScan')).toHaveLength(1)
    await act(async () => start.resolve(fail('security/internal', 'Start failed')))
    await flush(10)
    expect(close.disabled).toBe(false)
    expect(cancel.disabled).toBe(false)
    await click(cancel)
    expect(document.querySelector('[role="dialog"]')).toBeNull()
  })

  it('closes only after a successful start response', async () => {
    const start = deferred<RpcResult<{ scanId: string }>>()
    const { c, dialog } = await renderDialog({ createScan: () => start.promise })
    await click(byText(dialog, 'button', 'Start scan'))
    expect(document.querySelector('[role="dialog"]')).not.toBeNull()
    await act(async () => start.resolve(ok({ scanId: 'new-scan' })))
    await flush(10)
    expect(c.store.getState().newScan).toBeUndefined()
    expect(document.querySelector('[role="dialog"]')).toBeNull()
  })
})

const MODE_LABELS = { quick: 'Quick', deep: 'Deep', research: 'Research' } as const

describe('recheck depth repair', () => {
  it.each(['quick', 'deep', 'research'] as const)('uses the original %s depth instead of always Quick', async mode => {
    const { api, root } = await renderFinding({ createScan: () => ok({ scanId: 'recheck' }) }, mode)
    // The re-scan sits with the fix and names the depth it will reuse.
    const recheck = root.querySelector<HTMLElement>('[data-section="fix"] .dshsec-recheck')!
    expect(recheck.querySelector('button')?.textContent).toContain(`Re-scan (${MODE_LABELS[mode]})`)
    await click(recheck.querySelector('button'))
    expect(api.callsOf('createScan')).toEqual([{ workspaceId: 'ws-1', mode, language: 'en' }])
  })
})

describe('stale model list repair', () => {
  it('reloads selected model metadata after refreshing the catalog', async () => {
    const { api, c } = await setup({
      getModelInfo: () => ok({ id: 'm', name: 'Model', reasoningEfforts: [{ id: 'high', name: 'High' }] }),
    })
    mounted = mount(<SettingsSection controller={c} />)
    await flush(10)
    expect(api.callsOf('getModelInfo')).toHaveLength(1)
    await act(async () => c.loadModels(true))
    await flush(10)
    expect(api.callsOf('getModelInfo')).toHaveLength(2)
    expect(c.store.getState().models.value?.[0]?.models[0]?.reasoningEfforts).toHaveLength(1)
  })

  it('keeps models visible but shows a refresh failure and retry in Settings', async () => {
    const { api, c } = await setup()
    mounted = mount(<SettingsSection controller={c} />)
    await flush(10)
    api.handlers.listModels = () => fail('security/transport')
    await act(async () => c.loadModels(true))
    await flush()
    const root = mounted.container
    expect(root.textContent).toContain('Previously loaded models are shown')
    expect(root.textContent).toContain('Model')
    api.handlers.listModels = () => ok(PROVIDERS)
    await click(byText(root, 'button', 'Retry'))
    expect(root.textContent).not.toContain('Previously loaded models are shown')
  })

  it.each([true, false])('shows retry with retained models and configured route=%s in New Scan', async configured => {
    const settings = configured ? SETTINGS : { ...SETTINGS, models: {} }
    const { api, c, dialog } = await renderDialog({ getBootstrap: () => ok(makeBootstrap({ settings })) })
    api.handlers.listModels = () => fail('security/transport')
    await act(async () => c.loadModels(true))
    await flush()
    expect(dialog.textContent).toContain('Previously loaded models are shown')
    expect(dialog.textContent).toContain('Model')
    api.handlers.listModels = () => ok(PROVIDERS)
    await click(byText(dialog, 'button', 'Retry'))
    expect(dialog.textContent).not.toContain('Previously loaded models are shown')
  })
})

it('shows a localized unavailable reason and retains legacy analyzer text only as technical details', async () => {
  const settings = { ...SETTINGS, ui: { language: 'ja' as const } }
  const { c } = await setup({
    getBootstrap: () =>
      ok(
        makeBootstrap({
          settings,
          capabilities: {
            llm: true,
            workspaces: true,
            analyzers: [{ id: 'sast', available: false, source: 'builtin', reason: 'Legacy technical failure' }],
          },
        }),
      ),
  })
  mounted = mount(<SettingsSection controller={c} />)
  await flush(10)
  const row = mounted.container.querySelector<HTMLElement>('.dshsec-analyzers li')!
  const technical = row.querySelector('details')!
  expect(technical.open).toBe(false)
  expect(technical.textContent).toContain('Legacy technical failure')
  expect(technical.querySelector('summary')?.textContent).toContain('技術情報')
  const mainText = row.cloneNode(true) as HTMLElement
  mainText.querySelector('details')?.remove()
  expect(mainText.textContent).not.toContain('Legacy technical failure')
  expect(mainText.textContent).toContain('技術情報')
})

it('describes fix-in-chat as a request, not confirmed navigation', async () => {
  const startSession = vi.fn()
  const { c } = await setup(
    { getFixPrompt: () => ok({ prompt: 'Fix safely.' }) },
    { uiWorkspace: () => ({ startSession }) },
  )
  mounted = mount(
    <ControllerProvider controller={c}>
      <FindingDetailView scan={makeScan()} findingId="f-1" />
    </ControllerProvider>,
  )
  await flush(10)
  await click(byText(mounted.container, 'button', 'Fix in DSH chat'))
  expect(mounted.container.textContent).not.toContain('Opened a new chat')
  expect(mounted.container.textContent).toContain('Requested a chat')
  expect(startSession).toHaveBeenCalledWith('ws-1', { prompt: 'Fix safely.', clearPreviousDraft: false })
})
