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

describe('New Scan dialog consent', () => {
  async function openDialog(extra: Handlers = {}, bootstrap = makeBootstrap()) {
    const page = await renderPage(baseHandlers({ getBootstrap: () => ok(bootstrap), ...extra }))
    await click(byText(page.container, 'button', 'Start a scan'))
    await flush(10)
    const dialog = document.querySelector<HTMLElement>('[role="dialog"]')
    if (!dialog) throw new Error('dialog not open')
    return { ...page, dialog }
  }

  it('shows the estimate with ≈ and requires the consent checkbox', async () => {
    const { dialog, api } = await openDialog()
    expect(dialog.textContent).toContain('≈')
    expect(dialog.textContent).toContain('These numbers are an estimate')
    expect(dialog.textContent).toContain('Allow sending code to the AI model')
    await click(byText(dialog, 'button', 'Start scan'))
    expect(dialog.textContent).toContain('Tick the box above to continue.')
    expect(api.callsOf('updateSettings')).toHaveLength(0)
    expect(api.callsOf('createScan')).toHaveLength(0)
  })

  it('enables sending code first, then creates the scan', async () => {
    const { dialog, api } = await openDialog({
      updateSettings: () =>
        ok({ settings: makeSettings({ privacy: { ...makeSettings().privacy, sendCodeToModel: true } }), revision: 2 }),
      createScan: () => ok({ scanId: 'scan-9' }),
    })
    await click(dialog.querySelector('input[type="checkbox"]'))
    await click(byText(dialog, 'button', 'Start scan'))
    await flush(10)
    const order = api.calls.map(c => c.method).filter(m => m === 'updateSettings' || m === 'createScan')
    expect(order).toEqual(['updateSettings', 'createScan'])
    expect(document.querySelector('[role="dialog"]')).toBeNull()
  })

  it('explains forbidden-remote and does not create a scan', async () => {
    const { dialog, api } = await openDialog(
      { updateSettings: () => fail('security/forbidden-remote', 'forbidden') },
      makeBootstrap({ canEditHighRiskSettings: false, loopback: false }),
    )
    expect(dialog.textContent).toContain('open from another device')
    await click(dialog.querySelector('input[type="checkbox"]'))
    await click(byText(dialog, 'button', 'Start scan'))
    await flush(10)
    expect(dialog.textContent).toContain('only allows this from the host machine itself')
    expect(api.callsOf('createScan')).toHaveLength(0)
  })

  it('skips the consent box when sending code is already allowed and links to models on no-model', async () => {
    const settings = makeSettings({ privacy: { ...makeSettings().privacy, sendCodeToModel: true } })
    const {
      dialog,
      api,
      controller: c,
    } = await openDialog({ createScan: () => fail('security/no-model') }, makeBootstrap({ settings }))
    expect(dialog.textContent).not.toContain('Allow sending code to the AI model')
    expect(dialog.textContent).toContain('No model is set for the Hunter')
    await click(byText(dialog, 'button', 'Start scan'))
    await flush(10)
    expect(api.callsOf('updateSettings')).toHaveLength(0)
    expect(dialog.textContent).toContain('No AI model is set up for scanning yet')
    await click(byText(dialog, 'button', 'Configure models'))
    expect(c.store.getState().tab).toBe('settings')
    expect(document.querySelector('[role="dialog"]')).toBeNull()
  })

  it('closes on Escape', async () => {
    const { dialog } = await openDialog()
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
      'How sure are we',
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
