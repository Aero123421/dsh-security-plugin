import { act } from 'react'
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
    expect(selectPanel).toHaveBeenCalledWith('security')
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
      clearPreviousDraft: true,
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
    expect(c.store.getState().selectedFindingId).toBeUndefined()
    await key(rows()[1]!, 'Enter')
    await flush(10)
    expect(c.store.getState().selectedFindingId).toBe('f-2')
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
    expect(c.store.getState().selectedFindingId).toBe('f-2')
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
    const picker = head.querySelector<HTMLSelectElement>('select[aria-label="Project"]')!
    await act(async () => {
      picker.value = 'ws-2'
      picker.dispatchEvent(new Event('change', { bubbles: true }))
    })
    expect(c.store.getState().workspaceId).toBe('ws-2')
    expect(head.querySelector('.dshsec-project-title')?.textContent).toBe('Shop')
  })

  it('has no picker for a single project', async () => {
    const { container } = await renderPage(baseHandlers())
    expect(container.querySelector('.dshsec-head select')).toBeNull()
    expect(container.querySelector('.dshsec-project-title')?.textContent).toBe('Demo')
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
