import { act } from 'react'
import { ConfirmDialog } from '../../src/client/components/ConfirmDialog.tsx'
import { ControllerProvider } from '../../src/client/context.tsx'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { createController, type SecurityController } from '../../src/client/controller.ts'
import { DETAIL_SECTIONS } from '../../src/client/views/FindingDetail.tsx'
import { SecurityPage } from '../../src/client/views/SecurityPage.tsx'
import { SettingsSection } from '../../src/client/views/Settings.tsx'
import {
  byText,
  click,
  fail,
  fakeApi,
  flush,
  type Handlers,
  makeBootstrap,
  makeDetail,
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

const WORKSPACES = [{ id: 'ws-1', title: 'Demo', displayPath: '~/demo' }]

function baseHandlers(extra: Handlers = {}): Handlers {
  return {
    getBootstrap: () => ok(makeBootstrap()),
    listWorkspaces: () => ok(WORKSPACES),
    listScans: () => ok([]),
    listModels: () =>
      ok([
        {
          id: 'deepseek',
          name: 'DeepSeek',
          models: [{ id: 'deepseek-chat', name: 'DeepSeek Chat', reasoningEfforts: [{ id: 'high', name: 'High' }] }],
        },
      ]),
    listToolkit: () => ok([]),
    estimateScan: () =>
      ok({
        files: 120,
        bytes: 1000,
        excluded: 0,
        languages: [{ language: 'TypeScript', files: 100 }],
        frameworks: ['express'],
        endpoints: 12,
        plannedTasks: 18,
        tokens: { min: 400_000, max: 1_200_000 },
        truncated: false,
      }),
    ...extra,
  }
}

async function renderPage(handlers: Handlers, host: Parameters<typeof createController>[0]['host'] = {}) {
  const api = fakeApi(handlers)
  controller = createController({ api, storage: null, host, dshLocale: 'en' })
  mounted = mount(<SecurityPage controller={controller} />)
  await flush(10)
  return { api, controller, container: mounted.container }
}

describe('first run', () => {
  it('explains the scan and offers the three modes with Deep preselected', async () => {
    const { container } = await renderPage(baseHandlers())
    expect(container.textContent).toContain('Check this project for security problems')
    expect(container.textContent).toContain('What leaves this machine')
    const radios = [...container.querySelectorAll<HTMLInputElement>('input[name="dshsec-intro-mode"]')]
    expect(radios.map(r => r.value)).toEqual(['quick', 'deep', 'research'])
    expect(radios.find(r => r.checked)?.value).toBe('deep')
  })

  it('tells the user to open a project when there are no workspaces', async () => {
    const { container } = await renderPage(baseHandlers({ listWorkspaces: () => ok([]) }))
    expect(container.textContent).toContain('Open a project first')
  })

  it('shows a retry affordance on transport errors', async () => {
    const { container, api } = await renderPage(
      baseHandlers({ listWorkspaces: () => fail('security/transport', 'HTTP 503') }),
    )
    expect(container.textContent).toContain('Couldn’t reach DSH')
    api.handlers.listWorkspaces = () => ok(WORKSPACES)
    await click(byText(container, 'button', 'Retry'))
    await flush(10)
    expect(container.textContent).toContain('Check this project for security problems')
  })

  it('shows the contract banner on a version mismatch', async () => {
    const { container } = await renderPage(
      baseHandlers({ getBootstrap: () => ok(makeBootstrap({ contractVersion: 999 })) }),
    )
    expect(container.textContent).toContain('Reload the page')
  })
})

describe('tabs', () => {
  it('uses tablist/tab/tabpanel and moves with arrow keys', async () => {
    const { container } = await renderPage(baseHandlers())
    const tabs = [...container.querySelectorAll<HTMLButtonElement>('[role="tab"]')]
    expect(tabs.map(t => t.textContent)).toEqual(['Overview', 'Findings', 'History', 'Settings'])
    expect(tabs[0]?.getAttribute('aria-selected')).toBe('true')
    tabs[0]?.focus()
    await act(async () => {
      tabs[0]?.dispatchEvent(new KeyboardEvent('keydown', { key: 'ArrowRight', bubbles: true }))
    })
    const after = [...container.querySelectorAll<HTMLButtonElement>('[role="tab"]')]
    expect(after[1]?.getAttribute('aria-selected')).toBe('true')
    expect(document.activeElement).toBe(after[1])
    const panel = container.querySelector('[role="tabpanel"]')
    expect(panel?.getAttribute('aria-labelledby')).toBe(after[1]?.id)
  })
})

describe('New Scan dialog', () => {
  const withModel = makeSettings({ models: { default: { provider: 'deepseek', model: 'deepseek-chat' } } })
  const consented = makeSettings({
    models: { default: { provider: 'deepseek', model: 'deepseek-chat' } },
    privacy: { ...makeSettings().privacy, sendCodeToModel: true },
  })

  async function openDialog(extra: Handlers = {}, bootstrap = makeBootstrap({ settings: withModel })) {
    const page = await renderPage(baseHandlers({ getBootstrap: () => ok(bootstrap), ...extra }))
    await click(byText(page.container, 'button', 'Start a scan'))
    await flush(10)
    const dialog = document.querySelector<HTMLElement>('[role="dialog"]')
    if (!dialog) throw new Error('dialog not open')
    return { ...page, dialog }
  }

  function approach(dialog: HTMLElement, value: 'ai' | 'builtin') {
    const radio = dialog.querySelector<HTMLInputElement>(`input[name="dshsec-newscan-approach"][value="${value}"]`)
    if (!radio) throw new Error(`no ${value} radio`)
    return radio
  }

  function select(dialog: HTMLElement, label: string): HTMLSelectElement {
    const labelEl = byText<HTMLLabelElement>(dialog, 'label', label)
    const el = document.getElementById(labelEl.htmlFor)
    if (!(el instanceof HTMLSelectElement)) throw new Error(`no select for ${label}`)
    return el
  }

  async function choose(el: HTMLSelectElement, value: string) {
    await act(async () => {
      el.value = value
      el.dispatchEvent(new Event('change', { bubbles: true }))
    })
    await flush()
  }

  it('explains unchecked dependencies and opens Settings without changing consent', async () => {
    const { dialog, controller: c, container, api } = await openDialog()
    const projectLabel = byText<HTMLLabelElement>(dialog, 'label', 'Project')
    const project = document.getElementById(projectLabel.htmlFor) as HTMLButtonElement
    expect(project.tagName).toBe('BUTTON')
    expect(project.disabled).toBe(true)
    expect(project.textContent).toBe('Demo~/demo')
    expect(dialog.textContent).toContain('Dependency vulnerability lookup is off')
    expect(dialog.textContent).toContain('unless offline OSV-Scanner returns results')
    expect(dialog.textContent).toContain('never code or paths')
    await click(approach(dialog, 'builtin'))
    expect(dialog.textContent).toContain('Dependency vulnerability lookup is off')
    await click(byText(dialog, 'button', 'Open privacy settings'))
    await flush(10)
    expect(document.querySelector('[role="dialog"]')).toBeNull()
    expect(c.store.getState().tab).toBe('settings')
    expect(container.textContent).toContain('Look up known vulnerabilities online (OSV)')
    expect(api.callsOf('updateSettings')).toHaveLength(0)
    expect(api.callsOf('createScan')).toHaveLength(0)
  })

  it('selects a project through the themed field and reports its id to estimates and scan creation', async () => {
    const shop = { id: 'ws-shop', title: 'Shop', displayPath: '~/code/shop' }
    const { dialog, api } = await openDialog(
      { listWorkspaces: () => ok([...WORKSPACES, shop]), createScan: () => ok({ scanId: 'shop-scan' }) },
      makeBootstrap({ settings: consented }),
    )
    const label = byText<HTMLLabelElement>(dialog, 'label', 'Project')
    const trigger = document.getElementById(label.htmlFor) as HTMLButtonElement
    expect(trigger.tagName).toBe('BUTTON')
    expect(trigger.classList.contains('dshsec-input')).toBe(true)
    const hintId = trigger.getAttribute('aria-describedby')!
    expect(document.getElementById(hintId)?.textContent).toContain('Projects are managed in DSH')
    await click(trigger)
    // The portal stays inside the dialog while escaping its scrolling form body.
    const list = dialog.querySelector('[role="listbox"]')!
    expect(list.closest('.dshsec-modal-body')).toBeNull()
    await act(async () => {
      document.activeElement?.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }))
    })
    expect(document.querySelector('[role="dialog"]')).toBe(dialog)
    expect(dialog.querySelector('[role="listbox"]')).toBeNull()
    expect(document.activeElement).toBe(trigger)
    await click(trigger)
    await click(byText(dialog, '[role="option"]', 'Shop'))
    expect(dialog.querySelector('[role="listbox"]')).toBeNull()
    expect(document.activeElement).toBe(trigger)
    expect(trigger.textContent).toContain('Shop')
    expect(api.callsOf('estimateScan').at(-1)).toMatchObject({ workspaceId: shop.id })
    await click(byText(dialog, 'button', 'Start scan'))
    expect(api.callsOf('createScan')[0]).toMatchObject({ workspaceId: shop.id })
  })

  it('hides the dependency hint when lookup is enabled', async () => {
    const settings = makeSettings({ ...withModel, privacy: { ...withModel.privacy, allowDependencyLookup: true } })
    const { dialog } = await openDialog({}, makeBootstrap({ settings }))
    expect(dialog.textContent).not.toContain('Dependency vulnerability lookup is off')
  })

  it.each([0, 1])('uses the supported dependency manifest estimate (%s files)', async count => {
    const { dialog } = await openDialog({
      estimateScan: () =>
        ok({
          files: 1,
          bytes: 1,
          excluded: 0,
          languages: [],
          frameworks: [],
          endpoints: 0,
          plannedTasks: 0,
          tokens: { min: 0, max: 0 },
          truncated: false,
          dependencyManifests: count,
        }),
    })
    expect(dialog.textContent?.includes('Dependency vulnerability lookup is off')).toBe(count > 0)
  })

  it('keeps the conditional hint when the estimate fails', async () => {
    const { dialog } = await openDialog({ estimateScan: () => fail('security/workspace-unavailable') })
    expect(dialog.textContent).toContain('Dependency vulnerability lookup is off')
    expect(dialog.textContent).toContain('If this project has dependencies')
  })

  it('passes the optional subfolder to estimates and scan creation', async () => {
    const { dialog, api } = await openDialog(
      { createScan: () => ok({ scanId: 'subpath-scan' }) },
      makeBootstrap({ settings: consented }),
    )
    const input = dialog.querySelector<HTMLInputElement>('input[placeholder="packages/app"]')!
    await act(async () => {
      const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set
      setter?.call(input, 'packages/app')
      input.dispatchEvent(new Event('input', { bubbles: true }))
    })
    await flush(10)
    expect(api.callsOf('estimateScan').at(-1)).toMatchObject({ subpath: 'packages/app' })
    await click(byText(dialog, 'button', 'Start scan'))
    expect(api.callsOf('createScan')[0]).toMatchObject({ subpath: 'packages/app' })
  })

  it('defaults to AI review, shows the estimate with ≈ and requires the consent checkbox', async () => {
    const { dialog, api } = await openDialog()
    expect(approach(dialog, 'ai').checked).toBe(true)
    expect(dialog.textContent).toContain('≈')
    expect(dialog.textContent).toContain('These numbers are an estimate')
    expect(dialog.textContent).toContain('Allow sending code to the AI model')
    await click(byText(dialog, 'button', 'Start scan'))
    expect(dialog.textContent).toContain('Tick the box above to continue.')
    expect(document.activeElement).toBe(dialog.querySelector('.dshsec-consent input[type="checkbox"]'))
    expect(api.callsOf('updateSettings')).toHaveLength(0)
    expect(api.callsOf('createScan')).toHaveLength(0)
  })

  it('enables sending code first, then creates the scan', async () => {
    const { dialog, api } = await openDialog({
      updateSettings: () =>
        ok({
          settings: makeSettings({ ...withModel, privacy: { ...withModel.privacy, sendCodeToModel: true } }),
          revision: 2,
        }),
      createScan: () => ok({ scanId: 'scan-9' }),
    })
    await click(dialog.querySelector('.dshsec-consent input[type="checkbox"]'))
    await click(byText(dialog, 'button', 'Start scan'))
    await flush(10)
    const order = api.calls.map(c => c.method).filter(m => m === 'updateSettings' || m === 'createScan')
    expect(order).toEqual(['updateSettings', 'createScan'])
    expect(api.callsOf('updateSettings')[0]).toEqual({
      patch: { privacy: { sendCodeToModel: true } },
      expectedRevision: 1,
    })
    expect(api.callsOf('createScan')[0]).toEqual({ workspaceId: 'ws-1', mode: 'deep', language: 'en' })
    expect(document.querySelector('[role="dialog"]')).toBeNull()
  })

  it('"Built-in checks only" hides consent and models and sends aiReview: false', async () => {
    const { dialog, api } = await openDialog(
      { createScan: () => ok({ scanId: 'scan-b' }) },
      makeBootstrap({ settings: makeSettings() }),
    )
    // Nothing configured: AI review offers the inline picker and the consent box.
    expect(dialog.textContent).toContain('Choose an AI model')
    expect(dialog.textContent).toContain('Allow sending code to the AI model')
    await click(approach(dialog, 'builtin'))
    expect(approach(dialog, 'builtin').checked).toBe(true)
    expect(dialog.textContent).not.toContain('Allow sending code to the AI model')
    expect(dialog.textContent).not.toContain('Choose an AI model')
    expect(dialog.querySelector('input[name="dshsec-newscan-mode"]')).toBeNull()
    expect(dialog.textContent).not.toContain('Tokens')
    await click(byText(dialog, 'button', 'Start built-in checks'))
    await flush(10)
    expect(api.callsOf('updateSettings')).toHaveLength(0)
    expect(api.callsOf('createScan')).toEqual([{ workspaceId: 'ws-1', mode: 'quick', language: 'en', aiReview: false }])
    expect(document.querySelector('[role="dialog"]')).toBeNull()
  })

  it('picks a model inline, saves it as models.default, then grants consent and creates the scan', async () => {
    let revision = 1
    let settings = makeSettings()
    const { dialog, api } = await openDialog(
      {
        getBootstrap: () => ok(makeBootstrap({ settings, settingsRevision: revision })),
        updateSettings: payload => {
          settings = {
            ...settings,
            models: { ...settings.models, ...(payload.patch.models as typeof settings.models) },
            privacy: { ...settings.privacy, ...payload.patch.privacy },
          }
          revision++
          return ok({ settings, revision })
        },
        createScan: () => ok({ scanId: 'scan-m' }),
      },
      makeBootstrap({ settings }),
    )
    expect(dialog.textContent).toContain('Choose an AI model')
    await click(dialog.querySelector('.dshsec-consent input[type="checkbox"]'))
    // The only provider is preselected; its single model too.
    expect(select(dialog, 'Provider').value).toBe('deepseek')
    expect(select(dialog, 'Model').value).toBe('deepseek-chat')
    await click(byText(dialog, 'button', 'Start scan'))
    await flush(10)
    expect(api.callsOf('updateSettings')).toEqual([
      { patch: { models: { default: { provider: 'deepseek', model: 'deepseek-chat' } } }, expectedRevision: 1 },
      { patch: { privacy: { sendCodeToModel: true } }, expectedRevision: 2 },
    ])
    expect(api.callsOf('createScan')).toEqual([{ workspaceId: 'ws-1', mode: 'deep', language: 'en' }])
    expect(document.querySelector('[role="dialog"]')).toBeNull()
  })

  it('lets the user choose between several providers and models', async () => {
    const { dialog, api } = await openDialog(
      {
        listModels: () =>
          ok([
            {
              id: 'a',
              name: 'Alpha',
              models: [
                { id: 'a1', name: 'A One' },
                { id: 'a2', name: 'A Two' },
              ],
            },
            { id: 'b', name: 'Beta', models: [{ id: 'b1', name: 'B One' }] },
            { id: 'c', name: 'Broken', models: [], error: 'HTTP 401' },
          ]),
        updateSettings: payload =>
          ok({ settings: makeSettings({ ...consented, models: payload.patch.models as never }), revision: 2 }),
        createScan: () => ok({ scanId: 'scan-x' }),
      },
      makeBootstrap({ settings: makeSettings({ privacy: consented.privacy }) }),
    )
    const provider = select(dialog, 'Provider')
    expect(provider.value).toBe('')
    // Without a model the dialog asks for one, focuses the picker and does not call the Host.
    await click(byText(dialog, 'button', 'Start scan'))
    expect(dialog.textContent).toContain('Choose a model to run the AI review')
    expect(document.activeElement).toBe(provider)
    expect(api.callsOf('updateSettings')).toHaveLength(0)
    expect([...provider.options].find(o => o.value === 'c')?.disabled).toBe(true)
    expect(select(dialog, 'Model').disabled).toBe(true)
    await choose(provider, 'a')
    expect(select(dialog, 'Model').value).toBe('')
    await choose(select(dialog, 'Model'), 'a2')
    // Consent was already given, so only the model is saved.
    await click(byText(dialog, 'button', 'Start scan'))
    await flush(10)
    expect(api.callsOf('updateSettings')).toEqual([
      { patch: { models: { default: { provider: 'a', model: 'a2' } } }, expectedRevision: 1 },
    ])
    expect(api.callsOf('createScan')).toHaveLength(1)
  })

  it('offers built-in checks when no model provider is connected', async () => {
    const { dialog } = await openDialog({ listModels: () => ok([]) }, makeBootstrap({ settings: makeSettings() }))
    expect(dialog.textContent).toContain('No AI model is connected to DSH yet')
    await click(byText(dialog, 'button', 'Use built-in checks only'))
    expect(approach(dialog, 'builtin').checked).toBe(true)
  })

  it('explains forbidden-remote, does not create a scan, and offers built-in checks', async () => {
    const { dialog, api } = await openDialog(
      { updateSettings: () => fail('security/forbidden-remote', 'forbidden') },
      makeBootstrap({ settings: withModel, canEditHighRiskSettings: false, loopback: false }),
    )
    expect(dialog.textContent).toContain('open from another device')
    await click(dialog.querySelector('.dshsec-consent input[type="checkbox"]'))
    await click(byText(dialog, 'button', 'Start scan'))
    await flush(10)
    expect(dialog.textContent).toContain('only allows this from the host machine itself')
    expect(api.callsOf('createScan')).toHaveLength(0)
    await click(byText(dialog, 'button', 'Use built-in checks only'))
    expect(approach(dialog, 'builtin').checked).toBe(true)
  })

  it('skips the consent box when sending code is already allowed and links to models on no-model', async () => {
    const {
      dialog,
      api,
      controller: c,
    } = await openDialog({ createScan: () => fail('security/no-model') }, makeBootstrap({ settings: consented }))
    expect(dialog.textContent).not.toContain('Allow sending code to the AI model')
    expect(dialog.textContent).toContain('Models that will be used')
    expect(dialog.textContent).toContain('DeepSeek · DeepSeek Chat')
    await click(byText(dialog, 'button', 'Start scan'))
    await flush(10)
    expect(api.callsOf('updateSettings')).toHaveLength(0)
    expect(dialog.textContent).toContain('No AI model is set up for scanning yet')
    await click(byText(dialog, 'button', 'Configure models'))
    expect(c.store.getState().tab).toBe('settings')
    expect(document.querySelector('[role="dialog"]')).toBeNull()
  })

  it('closes on Escape and traps Tab inside the dialog', async () => {
    const { dialog } = await openDialog()
    const focusables = [
      ...dialog.querySelectorAll<HTMLElement>('button:not([disabled]), input:not([disabled]), select:not([disabled])'),
    ].filter(el => el.getAttribute('aria-hidden') !== 'true' && !el.hidden)
    const last = focusables[focusables.length - 1]!
    last.focus()
    await act(async () => {
      dialog.dispatchEvent(new KeyboardEvent('keydown', { key: 'Tab', bubbles: true }))
    })
    expect(dialog.contains(document.activeElement)).toBe(true)
    expect(document.activeElement).not.toBe(last)
    await act(async () => {
      dialog.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }))
    })
    expect(document.querySelector('[role="dialog"]')).toBeNull()
  })
})

describe('Settings high-risk toggles', () => {
  async function renderSettings(canEdit: boolean, privacyOn: boolean) {
    const settings = makeSettings({
      privacy: {
        sendCodeToModel: privacyOn,
        withheldGlobs: [],
        allowDependencyLookup: privacyOn,
        useExternalAnalyzers: privacyOn,
      },
    })
    const api = fakeApi(
      baseHandlers({ getBootstrap: () => ok(makeBootstrap({ settings, canEditHighRiskSettings: canEdit })) }),
    )
    controller = createController({ api, storage: null, host: { layout: () => ({ selectPanel: vi.fn() }) } })
    const close = vi.fn()
    mounted = mount(<SettingsSection controller={controller} close={close} />)
    await flush(10)
    const sw = (label: string) => {
      const labelEl = byText<HTMLLabelElement>(mounted!.container, 'label', label)
      return document.getElementById(labelEl.htmlFor) as HTMLButtonElement
    }
    return { api, close, sw }
  }

  it('locks OFF high-risk switches without permission and explains why', async () => {
    const { sw } = await renderSettings(false, false)
    const send = sw('Send code to the AI model')
    expect(send.getAttribute('role')).toBe('switch')
    expect(send.getAttribute('aria-checked')).toBe('false')
    expect(send.disabled).toBe(true)
    expect(sw('Look up known vulnerabilities online (OSV)').disabled).toBe(true)
    expect(document.body.textContent).toContain('Turning this on is only allowed from the host machine itself')
  })

  it('lets ON high-risk switches be turned off without permission, and the save sends only that', async () => {
    const { sw, api } = await renderSettings(false, true)
    const send = sw('Send code to the AI model')
    expect(send.disabled).toBe(false)
    await click(send)
    expect(send.getAttribute('aria-checked')).toBe('false')
    api.handlers.updateSettings = () => ok({ settings: makeSettings(), revision: 2 })
    await click(byText(document.body, 'button', 'Save changes'))
    await flush(5)
    expect(api.callsOf('updateSettings')).toEqual([
      { patch: { privacy: { sendCodeToModel: false } }, expectedRevision: 1 },
    ])
  })

  it('allows enabling with permission', async () => {
    const { sw } = await renderSettings(true, false)
    const send = sw('Send code to the AI model')
    expect(send.disabled).toBe(false)
    await click(send)
    expect(send.getAttribute('aria-checked')).toBe('true')
    expect(document.body.textContent).toContain('You have unsaved changes.')
  })

  it('offers "Open Security page" which closes Settings and selects the panel', async () => {
    const selectPanel = vi.fn()
    const api = fakeApi(baseHandlers())
    controller = createController({ api, storage: null, host: { layout: () => ({ selectPanel }) } })
    const close = vi.fn()
    mounted = mount(<SettingsSection controller={controller} close={close} />)
    await flush(10)
    await click(byText(mounted.container, 'button', 'Open Security page'))
    expect(close).toHaveBeenCalledTimes(1)
    expect(selectPanel).toHaveBeenCalledWith('dsh-security')
  })
})

describe('finding detail', () => {
  const scan = makeScan({ id: 'scan-1', status: 'completed' })
  function handlers(extra: Handlers = {}): Handlers {
    return baseHandlers({
      listScans: () => ok([scan]),
      getScan: () => ok(makeDetail({ id: 'scan-1' })),
      listFindings: () => ok([makeFinding({ id: 'f-1' })]),
      getFinding: () => ok(makeFindingDetail({ id: 'f-1' })),
      getFixPrompt: () => ok({ prompt: 'Please fix the SQL injection.' }),
      ...extra,
    })
  }

  async function openFinding(host: Parameters<typeof createController>[0]['host'] = {}, extra: Handlers = {}) {
    const page = await renderPage(handlers(extra), host)
    page.controller.setTab('findings')
    await flush(10)
    await click(byText(page.container, '.dshsec-frow', 'SQL injection'))
    await flush(10)
    return page
  }

  it('renders sections in the required order', async () => {
    const { container } = await openFinding()
    const sections = [...container.querySelectorAll<HTMLElement>('.dshsec-detail [data-section]')].map(
      s => s.dataset.section,
    )
    expect(sections).toEqual([...DETAIL_SECTIONS])
    expect(DETAIL_SECTIONS).toEqual(['problem', 'sure', 'evidence', 'fix', 'recheck'])
    const headings = [...container.querySelectorAll('.dshsec-dsec-title')].map(h => h.textContent)
    expect(headings).toEqual([
      'What is the problem',
      'How sure we are',
      'Evidence',
      'How to fix',
      'Re-check after fixing',
    ])
    // Triage comes after the sections; CWE and references at the very bottom.
    const article = container.querySelector('.dshsec-detail')!
    const last = article.lastElementChild!
    expect(last.textContent).toContain('CWE-89')
    expect(last.textContent).toContain('cwe.mitre.org')
  })

  it('explains the verification level and marks unverified quotes', async () => {
    const { container } = await openFinding()
    expect(container.textContent).toContain('Confirmed by reading the code')
    expect(container.textContent).toContain('NOT VERIFIED')
    const pre = container.querySelector('.dshsec-code pre')!
    expect(pre.querySelector('.dshsec-code-ln')?.textContent?.trim()).toBe('10')
    // Recommendation is split into paragraphs, never injected as HTML.
    expect(container.querySelector('[data-section="fix"]')?.querySelectorAll('p').length).toBeGreaterThanOrEqual(2)
  })

  it('hides "Fix in DSH chat" without uiWorkspace and starts a session with it', async () => {
    const without = await openFinding()
    expect(without.container.textContent).not.toContain('Fix in DSH chat')
    mounted?.unmount()
    controller?.dispose()

    const startSession = vi.fn()
    const page = await openFinding({ uiWorkspace: () => ({ startSession }) })
    await click(byText(page.container, 'button', 'Fix in DSH chat'))
    await flush(5)
    expect(page.api.callsOf('getFixPrompt')).toEqual([{ scanId: 'scan-1', findingId: 'f-1' }])
    expect(startSession).toHaveBeenCalledWith('ws-1', {
      prompt: 'Please fix the SQL injection.',
      clearPreviousDraft: false,
    })
  })

  it('saves a triage decision', async () => {
    const page = await openFinding({}, { setTriage: payload => ok(makeFinding({ id: 'f-1', triage: payload.triage })) })
    const radio = byText<HTMLLabelElement>(page.container, 'label.dshsec-seg', 'False positive').querySelector('input')!
    await click(radio)
    await click(byText(page.container, 'button', 'Save decision'))
    await flush(5)
    expect(page.api.callsOf('setTriage')).toEqual([{ scanId: 'scan-1', findingId: 'f-1', triage: 'false_positive' }])
    expect(page.container.textContent).toContain('Decision saved.')
  })
})

describe('completed scan coverage', () => {
  it('renders the unchecked-dependency gap through the existing Coverage UI', async () => {
    const gap =
      '2 dependencies were found but not checked for known vulnerabilities: OSV lookup is off and OSV-Scanner is not installed.'
    const { container } = await renderPage(
      baseHandlers({
        listScans: () => ok([makeScan()]),
        listFindings: () => ok([]),
        getScan: () =>
          ok(
            makeDetail(
              {},
              {
                coverage: {
                  files: { total: 1, analyzed: 1, readByAi: 0, excluded: 0 },
                  endpoints: { total: 0, reviewed: 0 },
                  tasks: { planned: 0, completed: 0, skipped: 0, failed: 0 },
                  analyzers: [],
                  discardedUnverifiable: 0,
                  gaps: [gap],
                },
              },
            ),
          ),
      }),
    )
    expect(container.querySelector('.dshsec-coverage')?.textContent).toContain('Known gaps')
    expect(container.querySelector('.dshsec-coverage')?.textContent).toContain(gap)
  })
})

describe('overview of a running scan', () => {
  it('shows progress with an aria-live region and asks before cancelling', async () => {
    vi.useFakeTimers()
    try {
      const running = makeScan({ id: 's-run', status: 'running', phase: 'hunt' })
      const page = await renderPage(
        baseHandlers({
          listScans: () => ok([running]),
          getScan: () =>
            ok(
              makeDetail(
                { id: 's-run', status: 'running', phase: 'hunt' },
                {
                  phases: [
                    { phase: 'snapshot', state: 'done' },
                    { phase: 'hunt', state: 'running' },
                    { phase: 'report', state: 'pending' },
                  ],
                  progress: { done: 3, total: 10, unit: 'tasks' },
                  workers: [
                    {
                      id: 'w1',
                      role: 'hunter',
                      title: 'Review auth',
                      model: 'deepseek-chat',
                      state: 'running',
                      turns: 4,
                      toolCalls: 9,
                      startedAt: '2026-10-01T10:00:00Z',
                    },
                  ],
                },
              ),
            ),
          listEvents: () =>
            ok([{ seq: 1, at: '2026-10-01T10:00:00Z', level: 'info', type: 't', message: 'Started hunter' }]),
          cancelScan: () => ok(makeScan({ id: 's-run', status: 'cancelled' })),
        }),
      )
      await act(async () => {
        await vi.advanceTimersByTimeAsync(10)
      })
      const { container } = page
      expect(container.querySelector('[aria-live="polite"]')?.textContent).toContain('AI review')
      expect(container.textContent).toContain('3 of 10 tasks')
      expect(container.textContent).toContain('Review auth')
      expect(container.textContent).toContain('Started hunter')
      expect(container.querySelector('[aria-current="step"]')?.textContent).toContain('AI review')
      await click(byText(container, 'button', 'Cancel scan'))
      const alert = document.querySelector('[role="alertdialog"]')
      expect(alert?.textContent).toContain('Cancel this scan?')
      expect(page.api.callsOf('cancelScan')).toHaveLength(0)
    } finally {
      vi.useRealTimers()
    }
  })
})

describe('findings list keyboard navigation', () => {
  const scan = makeScan({ id: 'scan-1', status: 'completed' })
  const findings = [
    makeFinding({ id: 'f-1', title: 'First problem', severity: 'critical' }),
    makeFinding({ id: 'f-2', title: 'Second problem', severity: 'high' }),
    makeFinding({ id: 'f-3', title: 'Third problem', severity: 'medium' }),
  ]

  async function renderFindings(width: number) {
    const rect = vi.spyOn(HTMLElement.prototype, 'getBoundingClientRect').mockImplementation(function (
      this: HTMLElement,
    ) {
      return { width: this.classList.contains('dshsec-page') ? width : 0 } as DOMRect
    })
    try {
      const page = await renderPage(
        baseHandlers({
          listScans: () => ok([scan]),
          getScan: () => ok(makeDetail({ id: 'scan-1' })),
          listFindings: () => ok(findings),
          getFinding: payload =>
            ok(makeFindingDetail({ ...findings.find(f => f.id === payload.findingId), id: payload.findingId })),
        }),
      )
      page.controller.setTab('findings')
      await flush(10)
      return page
    } finally {
      rect.mockRestore()
    }
  }

  const rows = () => [...document.querySelectorAll<HTMLButtonElement>('[data-finding-row]')]
  const key = async (el: Element, k: string) => {
    await act(async () => {
      el.dispatchEvent(new KeyboardEvent('keydown', { key: k, bubbles: true }))
    })
    await act(async () => {
      await new Promise(resolve => requestAnimationFrame(() => resolve(undefined)))
    })
    await flush()
  }

  it('keeps one row in the Tab order and moves focus with the arrow keys; Enter opens', async () => {
    const { controller: c } = await renderFindings(0)
    expect(rows().map(r => r.tabIndex)).toEqual([0, -1, -1])
    expect(document.querySelector('.dshsec-flist')?.getAttribute('aria-describedby')).toBeTruthy()
    rows()[0]!.focus()
    await key(rows()[0]!, 'ArrowDown')
    expect(document.activeElement).toBe(rows()[1])
    expect(rows().map(r => r.tabIndex)).toEqual([-1, 0, -1])
    await key(rows()[1]!, 'End')
    expect(document.activeElement).toBe(rows()[2])
    await key(rows()[2]!, 'ArrowUp')
    expect(document.activeElement).toBe(rows()[1])
    // Narrow layout: moving does not open anything.
    expect(c.store.getState().selectedFinding?.findingId).toBeUndefined()
    await key(rows()[1]!, 'Enter')
    await flush(10)
    expect(c.store.getState().selectedFinding?.findingId).toBe('f-2')
    expect(document.activeElement?.classList.contains('dshsec-detail-title')).toBe(true)
    // Back returns focus to the row that opened the detail.
    await click(byText(document.body, 'button', 'Back to findings'))
    await act(async () => {
      await new Promise(resolve => requestAnimationFrame(() => resolve(undefined)))
    })
    expect(document.activeElement).toBe(rows()[1])
  })

  it('side by side, the detail follows the arrow keys and Esc returns to the list', async () => {
    const { controller: c, container } = await renderFindings(1400)
    expect(container.querySelector('.dshsec-findings.is-split')).not.toBeNull()
    expect(container.querySelector('.dshsec-page--split')).not.toBeNull()
    rows()[0]!.focus()
    await key(rows()[0]!, 'ArrowDown')
    expect(c.store.getState().selectedFinding?.findingId).toBe('f-2')
    expect(rows()[1]?.getAttribute('aria-current')).toBe('true')
    expect(rows()[1]?.classList.contains('is-selected')).toBe(true)
    // Focus stays in the list while browsing.
    expect(document.activeElement).toBe(rows()[1])
    await flush(10)
    expect(container.querySelector('.dshsec-detail-title')?.textContent).toBe('Second problem')
    await key(rows()[1]!, 'Enter')
    await flush(10)
    expect(document.activeElement?.classList.contains('dshsec-detail-title')).toBe(true)
    await key(document.activeElement!, 'Escape')
    expect(document.activeElement).toBe(rows()[1])
  })
})

describe('page header', () => {
  it('shows the project title with its path and switches projects', async () => {
    const two = [
      { id: 'ws-1', title: 'Demo', displayPath: '~/code/demo' },
      { id: 'ws-2', title: 'Shop', displayPath: '~/code/shop' },
    ]
    const { container, controller: c } = await renderPage(baseHandlers({ listWorkspaces: () => ok(two) }))
    const head = container.querySelector('.dshsec-head')!
    expect(head.querySelector('.dshsec-title')?.textContent).toBe('Security')
    expect(head.querySelector('.dshsec-btn--primary')?.textContent).toContain('New scan')
    expect(head.querySelector('.dshsec-project-title')?.textContent).toBe('Demo')
    expect(head.querySelector('.dshsec-project-path')?.textContent).toBe('~/code/demo')
    const picker = head.querySelector<HTMLButtonElement>('button[aria-haspopup="listbox"]')!
    await click(picker)
    const list = container.querySelector('[role="listbox"]')!
    expect(list.querySelector('[role="option"][aria-selected="true"]')?.textContent).toBe('Demo~/code/demo')
    await click(byText(list, '[role="option"]', 'Shop'))
    expect(c.store.getState().workspaceId).toBe('ws-2')
    expect(head.querySelector('.dshsec-project-title')?.textContent).toBe('Shop')
  })

  it('keeps a single project identity in the header and always shows the dialog Project field', async () => {
    const { container } = await renderPage(baseHandlers())
    expect(container.querySelector('.dshsec-project-title')?.textContent).toBe('Demo')
    expect(container.querySelector('.dshsec-head button[aria-haspopup="listbox"]')).toBeNull()
    expect(container.querySelector('[role="listbox"]')).toBeNull()
    await click(byText(container, 'button', 'New scan'))
    const dialog = document.querySelector<HTMLElement>('[role="dialog"]')!
    const label = byText<HTMLLabelElement>(dialog, 'label', 'Project')
    const project = document.getElementById(label.htmlFor) as HTMLButtonElement
    expect(project.disabled).toBe(true)
    expect(project.textContent).toContain('Demo~/demo')
    expect(project.hasAttribute('aria-haspopup')).toBe(false)
    expect(dialog.querySelector('[role="listbox"]')).toBeNull()
    expect(dialog.textContent).toContain('Projects are managed in DSH')
  })
})

describe('add project folder', () => {
  it('allows a new folder pick after a reconnect cancels the previous pick', async () => {
    const s = services()
    let finish: (value: string | null) => void = () => {}
    s.pickDirectory.mockImplementationOnce(
      () =>
        new Promise(resolve => {
          finish = resolve
        }),
    )
    const { container, controller: c } = await renderPage(s.handlers, s.host)
    const add = byText(container, 'button', 'Add project folder…')
    await click(add)
    await act(async () => c.reload())
    await click(add)
    await flush(10)
    expect(s.create).toHaveBeenCalledExactlyOnceWith({ path: '/code/shop' })
    await act(async () => {
      finish('/old/connection')
      await flush(10)
    })
    expect(s.create).toHaveBeenCalledTimes(1)
  })

  it('browses Host folders in Web mode and never opens the native picker', async () => {
    const s = services()
    const listDirectory = vi.fn(async (path?: string) => ({
      path: path ?? '/home/test',
      home: '/home/test',
      crumbs: [{ name: '/', path: '/', hidden: false }],
      entries: path ? [] : [{ name: 'Shop folder', path: '/code/shop', hidden: false }],
      truncated: false,
    }))
    const { container, controller: c } = await renderPage(s.handlers, {
      ...s.host,
      uiWorkspace: () => ({ listDirectory, pickDirectory: s.pickDirectory }),
    })
    await click(byText(container, 'button', 'Add project folder…'))
    await flush(10)
    await click(byText(document.body, 'button', 'Shop folder'))
    await flush(10)
    await click(byText(document.body, 'button', 'Add this folder'))
    await flush(10)
    expect(s.pickDirectory).not.toHaveBeenCalled()
    expect(s.create).toHaveBeenCalledExactlyOnceWith({ path: '/code/shop' })
    expect(c.store.getState().workspaceId).toBe('ws-shop')
  })

  it('falls back to the native picker only when DSH explicitly reports a native capability', async () => {
    const s = services()
    const listDirectory = vi.fn(async () => {
      throw { rpcError: { code: 'directory-picker/unavailable', details: { capability: 'native' } } }
    })
    const { container } = await renderPage(s.handlers, {
      ...s.host,
      uiWorkspace: () => ({ listDirectory, pickDirectory: s.pickDirectory }),
    })
    await click(byText(container, 'button', 'Add project folder…'))
    await flush(10)
    expect(s.pickDirectory).toHaveBeenCalledTimes(1)
    expect(s.create).toHaveBeenCalledExactlyOnceWith({ path: '/code/shop' })
  })

  it('keeps a failed browser open for retry and cancels without registering a folder', async () => {
    const s = services()
    const listDirectory = vi
      .fn(async () => ({ path: '/code/shop', home: '/home/test', crumbs: [], entries: [], truncated: false }))
      .mockRejectedValueOnce(new Error('permission denied'))
    const { container } = await renderPage(s.handlers, {
      ...s.host,
      uiWorkspace: () => ({ listDirectory, pickDirectory: s.pickDirectory }),
    })
    await click(byText(container, 'button', 'Add project folder…'))
    await flush(10)
    expect(document.body.textContent).toContain('Could not open this folder')
    expect(s.pickDirectory).not.toHaveBeenCalled()
    await click(byText(document.body, 'button', 'Open folder'))
    await flush(10)
    expect(document.body.textContent).not.toContain('Could not open this folder')
    await click(byText(document.querySelector('[role="dialog"]') as HTMLElement, 'button', 'Cancel'))
    expect(s.create).not.toHaveBeenCalled()
  })

  const shop = { id: 'ws-shop', title: 'Shop', displayPath: '~/code/shop' }

  function services(path: string | null = '/code/shop') {
    let projects = [...WORKSPACES]
    const pickDirectory = vi.fn(async () => path)
    const create = vi.fn(async () => {
      projects = [...WORKSPACES, shop]
      return { workspaceId: shop.id }
    })
    return {
      pickDirectory,
      create,
      handlers: baseHandlers({ listWorkspaces: () => ok(projects) }),
      host: { uiWorkspace: () => ({ pickDirectory }), workspaces: () => ({ create }) },
    }
  }

  it('registers the picked path, refreshes, selects it and opens a scoped scan from the header', async () => {
    const s = services()
    const { container, controller: c, api } = await renderPage(s.handlers, s.host)
    const add = byText<HTMLButtonElement>(container, 'button', 'Add project folder…')
    expect(container.textContent).toContain('Adds the selected folder to DSH’s project list')
    await click(add)
    expect(s.create).toHaveBeenCalledExactlyOnceWith({ path: '/code/shop' })
    expect(api.callsOf('listWorkspaces')).toHaveLength(2)
    expect(c.store.getState().workspaceId).toBe(shop.id)
    expect(c.store.getState().newScan).toEqual({ workspaceId: shop.id })
    const dialog = document.querySelector<HTMLElement>('[role="dialog"]')!
    expect(dialog.querySelector('.dshsec-projsel--field .dshsec-project-title')?.textContent).toBe(shop.title)
    expect(api.callsOf('createScan')).toHaveLength(0)
    await click(byText(dialog, 'button', 'Cancel'))
    expect(document.activeElement).toBe(add)
  })

  it('can add the first project when the DSH list is empty', async () => {
    const s = services()
    let registered = false
    s.create.mockImplementation(async () => {
      registered = true
      return { workspaceId: shop.id }
    })
    const { container, controller: c } = await renderPage(
      baseHandlers({ listWorkspaces: () => ok(registered ? [shop] : []) }),
      s.host,
    )
    await click(byText(container, 'button', 'Add project folder…'))
    expect(c.store.getState().workspaceId).toBe(shop.id)
    expect(c.store.getState().newScan?.workspaceId).toBe(shop.id)
  })

  it('treats picker cancellation as a silent no-op and keeps focus and selection', async () => {
    const s = services(null)
    const { container, controller: c, api } = await renderPage(s.handlers, s.host)
    const add = byText<HTMLButtonElement>(container, 'button', 'Add project folder…')
    await click(add)
    expect(s.create).not.toHaveBeenCalled()
    expect(api.callsOf('listWorkspaces')).toHaveLength(1)
    expect(c.store.getState().workspaceId).toBe('ws-1')
    expect(c.store.getState().newScan).toBeUndefined()
    expect(container.querySelector('[role="alert"]')).toBeNull()
    expect(document.activeElement).toBe(add)
  })

  it.each(['both', 'picker', 'create'] as const)('hides the action when %s services are absent', async absent => {
    const s = services()
    const { container, controller: c } = await renderPage(s.handlers, {
      ...(absent === 'create' ? { uiWorkspace: s.host.uiWorkspace } : {}),
      ...(absent === 'picker' ? { workspaces: s.host.workspaces } : {}),
    })
    expect(container.textContent).not.toContain('Add project folder…')
    expect(await c.addProjectFolder()).toBeUndefined()
    await click(byText(container, 'button', 'New scan'))
    expect(document.querySelector('[role="dialog"]')?.textContent).not.toContain('Add project folder…')
    expect(s.pickDirectory).not.toHaveBeenCalled()
    expect(s.create).not.toHaveBeenCalled()
  })

  it('selects an already-registered workspace returned by create without adding another row', async () => {
    const s = services('/code/demo')
    s.create.mockImplementation(async () => ({ workspaceId: 'ws-1' }))
    const { container, controller: c } = await renderPage(
      baseHandlers({ listWorkspaces: () => ok([shop, ...WORKSPACES]) }),
      s.host,
    )
    expect(c.store.getState().workspaceId).toBe(shop.id)
    await click(byText(container, 'button', 'Add project folder…'))
    expect(s.create).toHaveBeenCalledExactlyOnceWith({ path: '/code/demo' })
    expect(c.store.getState().workspaceId).toBe('ws-1')
    expect(c.store.getState().workspaces.value).toHaveLength(2)
    expect(c.store.getState().newScan?.workspaceId).toBe('ws-1')
    expect(container.querySelector('[role="alert"]')).toBeNull()
  })

  it('updates the existing scan dialog project and clears an old project subfolder', async () => {
    const s = services()
    const { container, controller: c, api } = await renderPage(s.handlers, s.host)
    await act(async () => c.openNewScan({ workspaceId: 'ws-1', subpath: 'old/folder' }))
    const dialog = document.querySelector<HTMLElement>('[role="dialog"]')!
    const add = byText<HTMLButtonElement>(dialog, 'button', 'Add project folder…')
    await click(add)
    expect(document.querySelectorAll('[role="dialog"]')).toHaveLength(1)
    expect(dialog.querySelector('.dshsec-projsel--field .dshsec-project-title')?.textContent).toBe(shop.title)
    expect(dialog.querySelector<HTMLInputElement>('input[placeholder="packages/app"]')?.value).toBe('')
    expect(api.callsOf('estimateScan').at(-1)).toMatchObject({ workspaceId: shop.id })
    expect(api.callsOf('estimateScan').at(-1)).not.toHaveProperty('subpath')
    expect(document.activeElement).toBe(add)
    expect(container.querySelector('.dshsec-project-title')?.textContent).toBe('Shop')
  })

  it.each(['picker', 'create'] as const)('shows a localized error when %s fails and keeps selection', async stage => {
    const s = services()
    const fail = async () => {
      throw new Error('private host diagnostic')
    }
    if (stage === 'picker') s.pickDirectory.mockImplementation(fail)
    else s.create.mockImplementation(fail)
    const { container, controller: c } = await renderPage(s.handlers, s.host)
    await click(byText(container, 'button', 'Add project folder…'))
    expect(container.textContent).toContain('Couldn’t pick or add the folder')
    expect(container.textContent).not.toContain('private host diagnostic')
    expect(c.store.getState().workspaceId).toBe('ws-1')
    expect(c.store.getState().newScan).toBeUndefined()
    expect(c.store.getState().addingProject).toBe(false)
  })

  it('reports committed registration separately if refreshing projects fails', async () => {
    const s = services()
    const { container, controller: c, api } = await renderPage(s.handlers, s.host)
    api.handlers.listWorkspaces = () => fail('security/transport')
    await click(byText(container, 'button', 'Add project folder…'))
    expect(container.textContent).toContain('The folder is registered in DSH')
    expect(c.store.getState().workspaceId).toBe('ws-1')
    expect(c.store.getState().newScan).toBeUndefined()
  })

  it('does not register or reopen a scan after its dialog closes during picking', async () => {
    const s = services()
    let resolve!: (path: string) => void
    s.pickDirectory.mockImplementation(
      () =>
        new Promise<string>(done => {
          resolve = done
        }),
    )
    const { container, controller: c } = await renderPage(s.handlers, s.host)
    await click(byText(container, 'button', 'New scan'))
    const dialog = document.querySelector<HTMLElement>('[role="dialog"]')!
    await click(byText(dialog, 'button', 'Add project folder…'))
    await click(byText(dialog, 'button', 'Cancel'))
    await act(async () => resolve('/code/shop'))
    await flush(10)
    expect(s.create).not.toHaveBeenCalled()
    expect(c.store.getState().workspaceId).toBe('ws-1')
    expect(c.store.getState().newScan).toBeUndefined()
    expect(c.store.getState().addingProject).toBe(false)
  })

  it('ignores a picker from the previous DSH connection', async () => {
    const s = services()
    let resolve!: (path: string) => void
    s.pickDirectory.mockImplementation(
      () =>
        new Promise<string>(done => {
          resolve = done
        }),
    )
    const { container, controller: c } = await renderPage(s.handlers, s.host)
    const add = byText(container, 'button', 'Add project folder…')
    await click(add)
    await click(add)
    expect(s.pickDirectory).toHaveBeenCalledTimes(1)
    await act(async () => {
      await c.reload()
      resolve('/code/shop')
    })
    await flush(10)
    expect(s.create).not.toHaveBeenCalled()
    expect(c.store.getState().workspaceId).toBe('ws-1')
    expect(c.store.getState().newScan).toBeUndefined()
  })
})

describe('render failures', () => {
  it('shows a retry instead of a blank panel and keeps the page header', async () => {
    const quiet = vi.spyOn(console, 'error').mockImplementation(() => {})
    try {
      const scan = makeScan({ id: 'scan-1', status: 'completed' })
      const { container, controller: c } = await renderPage(
        baseHandlers({
          listScans: () => ok([scan]),
          getScan: () => ok(makeDetail({ id: 'scan-1' })),
          // A malformed Host payload that the list cannot render.
          listFindings: () => ok([null as never]),
        }),
      )
      c.setTab('findings')
      await flush(10)
      expect(container.textContent).toContain('This part of the page couldn’t be shown.')
      expect(container.querySelector('.dshsec-title')?.textContent).toBe('Security')
      expect(byText(container, 'button', 'Retry')).toBeTruthy()
      // Switching tabs resets the boundary.
      c.setTab('history')
      await flush(5)
      expect(container.textContent).not.toContain('This part of the page couldn’t be shown.')
    } finally {
      quiet.mockRestore()
    }
  })
})

describe('settings models', () => {
  it('explains each role in one line and shows the default for unset roles', async () => {
    const settings = makeSettings({ models: { default: { provider: 'deepseek', model: 'deepseek-chat' } } })
    const api = fakeApi(baseHandlers({ getBootstrap: () => ok(makeBootstrap({ settings })) }))
    controller = createController({ api, storage: null })
    mounted = mount(<SettingsSection controller={controller} />)
    await flush(10)
    const roles = [...mounted.container.querySelectorAll<HTMLElement>('.dshsec-role')]
    expect(roles.map(r => r.dataset.slot)).toEqual(['default', 'planner', 'hunter', 'skeptic', 'chain'])
    for (const role of roles) expect(role.querySelector('.dshsec-hint')?.textContent?.length).toBeGreaterThan(10)
    const hunter = roles[2]!.querySelector('select')!
    expect(hunter.selectedOptions[0]?.textContent).toBe('Uses default · DeepSeek Chat')
    expect(roles[2]!.classList.contains('is-inherited')).toBe(true)

    // Give the hunter its own model; the save sends only that route.
    const option = [...hunter.options].find(o => o.textContent === 'DeepSeek Chat')!
    await act(async () => {
      hunter.value = option.value
      hunter.dispatchEvent(new Event('change', { bubbles: true }))
    })
    expect(mounted.container.textContent).toContain('You have unsaved changes.')
    api.handlers.updateSettings = () => ok({ settings, revision: 2 })
    await click(byText(mounted.container, 'button', 'Save changes'))
    await flush(5)
    expect(api.callsOf('updateSettings')).toEqual([
      { patch: { models: { hunter: { provider: 'deepseek', model: 'deepseek-chat' } } }, expectedRevision: 1 },
    ])
  })

  it('shows validation messages inline and in the save bar', async () => {
    const api = fakeApi(baseHandlers())
    controller = createController({ api, storage: null })
    mounted = mount(<SettingsSection controller={controller} />)
    await flush(10)
    const label = byText<HTMLLabelElement>(mounted.container, 'label', 'Reviewers working at once')
    const input = document.getElementById(label.htmlFor) as HTMLInputElement
    await act(async () => {
      const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')!.set!
      setter.call(input, '99')
      input.dispatchEvent(new Event('input', { bubbles: true }))
    })
    expect(input.getAttribute('aria-invalid')).toBe('true')
    expect(mounted.container.textContent).toContain('Enter a whole number from 1 to 4.')
    await click(byText(mounted.container, 'button', 'Save changes'))
    expect(api.callsOf('updateSettings')).toHaveLength(0)
    expect(mounted.container.querySelector('.dshsec-savebar')?.textContent).toContain('Fix the highlighted fields')
  })
})

describe('settings version & updates', () => {
  const SPEC = 'github:Aero123421/dsh-security-plugin#vX.Y.Z'
  const CLI = `dsh plugin --profile web add -w ${SPEC}`

  function versionSection(root: ParentNode): HTMLElement {
    const heading = byText<HTMLElement>(root, 'h2', 'Version & updates')
    return heading.closest('section') as HTMLElement
  }

  it('shows the running version, the supported DSH range, the releases link and both commands, offline', async () => {
    const fetchSpy = vi.fn()
    vi.stubGlobal('fetch', fetchSpy)
    try {
      const api = fakeApi(baseHandlers({ getBootstrap: () => ok(makeBootstrap({ pluginVersion: '1.4.2' })) }))
      controller = createController({ api, storage: null })
      mounted = mount(<SettingsSection controller={controller} />)
      await flush(10)
      const section = versionSection(mounted.container)
      expect(section.querySelector('[data-testid="dshsec-plugin-version"]')?.textContent).toBe('1.4.2')
      expect(section.textContent).toContain('0.2.1-alpha.2 – 0.2.x')
      const link = byText<HTMLAnchorElement>(section, 'a', 'Releases on GitHub')
      expect(link.href).toBe('https://github.com/Aero123421/dsh-security-plugin/releases')
      expect(link.target).toBe('_blank')
      expect(link.rel.split(' ')).toContain('noopener')
      const codes = [...section.querySelectorAll('code')].map(c => c.textContent)
      expect(codes).toEqual([SPEC, CLI])
      expect(section.textContent).toContain('Replace X.Y.Z with the release you want')
      // No update check: nothing beyond the page's usual RPCs, and no direct network access.
      expect(fetchSpy).not.toHaveBeenCalled()
      expect(new Set(api.calls.map(c => c.method))).toEqual(
        new Set(['getBootstrap', 'listWorkspaces', 'listScans', 'listModels', 'listToolkit']),
      )
    } finally {
      vi.unstubAllGlobals()
    }
  })

  it('copies a command and says so', async () => {
    const writeText = vi.fn(async () => undefined)
    vi.stubGlobal('navigator', { ...navigator, clipboard: { writeText } })
    try {
      controller = createController({ api: fakeApi(baseHandlers()), storage: null })
      mounted = mount(<SettingsSection controller={controller} />)
      await flush(10)
      const section = versionSection(mounted.container)
      const button = section.querySelector<HTMLButtonElement>(`button[aria-label="Copy: ${CLI}"]`)!
      expect(button.type).toBe('button')
      await click(button)
      await flush(3)
      expect(writeText).toHaveBeenCalledWith(CLI)
      expect(button.textContent).toBe('Copied')
      // Copying never submits the settings form.
      expect(mounted.container.textContent).not.toContain('You have unsaved changes.')
    } finally {
      vi.unstubAllGlobals()
    }
  })

  it('appears in the Security page Settings tab too, in Japanese when chosen', async () => {
    const settings = makeSettings({ ui: { language: 'ja' } })
    const api = fakeApi(baseHandlers({ getBootstrap: () => ok(makeBootstrap({ settings })) }))
    controller = createController({ api, storage: null, dshLocale: 'en' })
    controller.setTab('settings')
    mounted = mount(<SecurityPage controller={controller} />)
    await flush(10)
    const heading = byText<HTMLElement>(mounted.container, 'h2', 'バージョンと更新')
    const section = heading.closest('section') as HTMLElement
    expect(section.querySelector('[data-testid="dshsec-plugin-version"]')?.textContent).toBe('0.1.0')
    expect(section.textContent).toContain('手動で更新する')
    expect([...section.querySelectorAll('code')].map(c => c.textContent)).toEqual([SPEC, CLI])
  })
})

describe('B6 findings scope and scale', () => {
  it('clears selection when latest results change without loading a foreign finding', async () => {
    let scans = [makeScan()]
    const {
      controller: c,
      container,
      api,
    } = await renderPage(
      baseHandlers({
        listScans: () => ok(scans),
        getScan: () => ok(makeDetail()),
        listFindings: p => ok([makeFinding({ scanId: p.scanId, id: p.scanId === 'scan-1' ? 'f-1' : 'f-2' })]),
        getFinding: p => ok(makeFindingDetail({ scanId: p.scanId, id: p.findingId })),
      }),
    )
    await act(async () => c.setTab('findings'))
    await flush(10)
    await click(container.querySelector('[data-finding-row="f-1"]'))
    scans = [makeScan({ id: 'scan-2', createdAt: '2026-10-02T10:00:00Z' }), ...scans]
    await act(async () => {
      await c.refreshScans()
    })
    await flush(10)
    expect(container.querySelector('.dshsec-findings-detail')).toBeNull()
    expect(container.querySelector('[data-finding-row="f-2"]')).not.toBeNull()
    expect(api.callsOf('getFinding')).not.toContainEqual({ scanId: 'scan-2', findingId: 'f-1' })
  })

  it('keeps reading the previous results during a rescan and when explicitly viewing history', async () => {
    let scans = [makeScan()]
    const { controller: c, container } = await renderPage(
      baseHandlers({
        listScans: () => ok(scans),
        getScan: () => ok(makeDetail()),
        listFindings: () => ok([makeFinding()]),
        getFinding: () => ok(makeFindingDetail()),
        createScan: () => {
          scans = [makeScan({ id: 'scan-2', status: 'running', createdAt: '2026-10-02T10:00:00Z' }), ...scans]
          return ok({ scanId: 'scan-2' })
        },
      }),
    )
    await act(async () => c.setTab('findings'))
    await flush(10)
    await click(container.querySelector('[data-finding-row="f-1"]'))
    await act(async () => {
      await c.startScan({ workspaceId: 'ws-1', mode: 'quick', aiReview: false })
    })
    await flush(10)
    expect(container.querySelector('.dshsec-detail-title')?.textContent).toContain('SQL injection')
    await act(async () => c.viewScan('scan-1'))
    await flush()
    await click(container.querySelector('[data-finding-row="f-1"]'))
    scans = scans.map(s => ({ ...s, status: 'completed' as const }))
    await act(async () => {
      await c.refreshScans()
    })
    await flush(10)
    expect(container.querySelector('.dshsec-detail-title')?.textContent).toContain('SQL injection')
  })

  it('caps 1000 findings at 200 rows, shows more, and filters all results', async () => {
    const findings = Array.from({ length: 1000 }, (_, i) =>
      makeFinding({ id: `f-${i}`, title: `Problem ${String(i).padStart(4, '0')}` }),
    )
    const { controller: c, container } = await renderPage(
      baseHandlers({
        listScans: () => ok([makeScan()]),
        getScan: () => ok(makeDetail()),
        listFindings: () => ok(findings),
      }),
    )
    await act(async () => c.setTab('findings'))
    await flush(10)
    expect(container.querySelectorAll('[data-finding-row]')).toHaveLength(200)
    await click(byText(container, 'button', 'Show more'))
    expect(container.querySelectorAll('[data-finding-row]')).toHaveLength(400)
    await act(async () => c.setFilter(f => ({ ...f, text: '0999' })))
    expect(container.querySelectorAll('[data-finding-row]')).toHaveLength(1)
    expect(container.querySelector('[data-finding-row]')?.textContent).toContain('Problem 0999')
  })
})

describe('B6 modal busy focus', () => {
  it('parks disabled confirm focus inside the dialog and restores it after an RPC failure; Escape works', async () => {
    let resolve!: (value: ReturnType<typeof fail>) => void
    const request = new Promise<ReturnType<typeof fail>>(done => {
      resolve = done
    })
    controller = createController({ api: fakeApi(), storage: null })
    const close = vi.fn()
    mounted = mount(
      <ControllerProvider controller={controller}>
        <ConfirmDialog
          title="Delete scan?"
          body="Cannot undo"
          confirmLabel="Delete"
          onConfirm={() => request}
          onClose={close}
        />
      </ControllerProvider>,
    )
    const dialog = document.querySelector<HTMLElement>('[role="alertdialog"]')!
    const submit = byText<HTMLButtonElement>(dialog, 'button', 'Delete')
    submit.focus()
    await click(submit)
    expect(submit.disabled).toBe(true)
    expect(document.activeElement).toBe(dialog)
    await act(async () => resolve(fail('security/transport')))
    await flush()
    expect(dialog.contains(document.activeElement)).toBe(true)
    expect(document.activeElement).toBe(submit)
    await act(async () =>
      document.activeElement?.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true })),
    )
    expect(close).toHaveBeenCalledOnce()
  })

  it('keeps keyboard focus in New Scan after create fails', async () => {
    let resolve!: (value: ReturnType<typeof fail>) => void
    const request = new Promise<ReturnType<typeof fail>>(done => {
      resolve = done
    })
    const { controller: c, container } = await renderPage(baseHandlers({ createScan: () => request }))
    await click(byText(container, 'button', 'Start a scan'))
    const dialog = document.querySelector<HTMLElement>('[role="dialog"]')!
    await click(dialog.querySelector('input[name="dshsec-newscan-approach"][value="builtin"]'))
    const submit = byText<HTMLButtonElement>(dialog, 'button', 'Start built-in checks')
    submit.focus()
    await click(submit)
    expect(document.activeElement).toBe(dialog)
    await act(async () => resolve(fail('security/transport')))
    await flush(10)
    expect(dialog.contains(document.activeElement)).toBe(true)
    await act(async () =>
      document.activeElement?.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true })),
    )
    expect(c.store.getState().newScan).toBeUndefined()
  })
})

it('memoizes unchanged finding rows while the keyboard selection moves', async () => {
  let untouchedReads = 0
  const untouched = makeFinding({ id: 'third', severity: 'low' })
  Object.defineProperty(untouched, 'title', {
    get: () => {
      untouchedReads++
      return 'Untouched row'
    },
  })
  const rect = vi.spyOn(HTMLElement.prototype, 'getBoundingClientRect').mockReturnValue({ width: 1400 } as DOMRect)
  try {
    const { controller: c, container } = await renderPage(
      baseHandlers({
        listScans: () => ok([makeScan()]),
        getScan: () => ok(makeDetail()),
        listFindings: () =>
          ok([makeFinding({ id: 'first', severity: 'critical' }), makeFinding({ id: 'second' }), untouched]),
        getFinding: p => ok(makeFindingDetail({ id: p.findingId })),
      }),
    )
    await act(async () => c.setTab('findings'))
    await flush(10)
    expect(container.querySelector('.dshsec-findings.is-split')).not.toBeNull()
    untouchedReads = 0
    const row = container.querySelector<HTMLElement>('[data-finding-row="first"]')!
    row.focus()
    await act(async () => row.dispatchEvent(new KeyboardEvent('keydown', { key: 'ArrowDown', bubbles: true })))
    await flush(10)
    expect(c.store.getState().selectedFinding?.findingId).toBe('second')
    expect(untouchedReads).toBe(0)
  } finally {
    rect.mockRestore()
  }
})

it('traps Shift+Tab from the parked dialog container while a confirm request is busy', async () => {
  let resolve!: (value: ReturnType<typeof fail>) => void
  const request = new Promise<ReturnType<typeof fail>>(done => {
    resolve = done
  })
  controller = createController({ api: fakeApi(), storage: null })
  const close = vi.fn()
  mounted = mount(
    <ControllerProvider controller={controller}>
      <ConfirmDialog
        title="Delete scan?"
        body="Cannot undo"
        confirmLabel="Delete"
        onConfirm={() => request}
        onClose={close}
      />
    </ControllerProvider>,
  )
  const dialog = document.querySelector<HTMLElement>('[role="alertdialog"]')!
  const submit = byText<HTMLButtonElement>(dialog, 'button', 'Delete')
  submit.focus()
  await act(async () => {
    submit.click()
    // Simulate the browser dropping a disabled control's focus to body.
    document.body.tabIndex = -1
    document.body.focus()
  })
  await flush()
  expect(document.activeElement).toBe(dialog)
  await act(async () =>
    dialog.dispatchEvent(new KeyboardEvent('keydown', { key: 'Tab', shiftKey: true, bubbles: true })),
  )
  expect(dialog.contains(document.activeElement)).toBe(true)
  expect(document.activeElement).not.toBe(dialog)
  await act(async () => resolve(fail('security/transport')))
  await flush()
  // Do not steal focus back from the safe choice the keyboard user selected.
  expect(document.activeElement).toBe(byText(dialog, 'button', 'Cancel'))
  await act(async () =>
    document.activeElement?.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true })),
  )
  expect(close).toHaveBeenCalledOnce()
})
