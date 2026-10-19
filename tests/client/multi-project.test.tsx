import { act } from 'react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { ACTIVE_POLL_MS, createController, type SecurityController } from '../../src/client/controller.ts'
import { getTranslator } from '../../src/client/i18n.ts'
import { projectStatus, queueAhead } from '../../src/client/projects.ts'
import { SecurityPage } from '../../src/client/views/SecurityPage.tsx'
import type { ScanSummary, WorkspaceSummary } from '../../src/shared/contracts.ts'
import {
  byText,
  click,
  fakeApi,
  flush,
  type Handlers,
  makeBootstrap,
  makeDetail,
  makeScan,
  type Mounted,
  mount,
  ok,
} from './helpers.tsx'

const tr = getTranslator('en')
const DEMO: WorkspaceSummary = { id: 'ws-1', title: 'Demo', displayPath: '~/demo' }
const SHOP: WorkspaceSummary = { id: 'ws-2', title: 'Shop', displayPath: '~/shop' }

let mounted: Mounted | undefined
let controller: SecurityController | undefined
afterEach(() => {
  mounted?.unmount()
  mounted = undefined
  controller?.dispose()
  controller = undefined
  document.body.innerHTML = ''
  vi.useRealTimers()
})

describe('project status', () => {
  it('reports the project’s own queued, running or paused scan first', () => {
    expect(projectStatus(tr, DEMO, [makeScan({ status: 'running' })])).toEqual({ text: 'Scanning', tone: 'active' })
    expect(projectStatus(tr, DEMO, [makeScan({ status: 'queued' })])).toEqual({ text: 'Queued', tone: 'idle' })
    expect(projectStatus(tr, DEMO, [makeScan({ status: 'paused' })])).toEqual({ text: 'Paused', tone: 'idle' })
    // Another project's scan says nothing about this one.
    expect(projectStatus(tr, DEMO, [makeScan({ workspaceId: 'ws-2', status: 'running' })]).text).toBe('Not scanned')
  })

  it('otherwise summarizes the last scan by its worst open findings', () => {
    const last = (lastScan: ScanSummary) => projectStatus(tr, { ...DEMO, lastScan }, [])
    expect(last(makeScan({ counts: { critical: 2, high: 5, medium: 1, low: 0, info: 0 } }))).toEqual({
      text: '2 Critical · 5 High',
      tone: 'idle',
      severity: 'critical',
    })
    expect(last(makeScan({ counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 } }))).toEqual({
      text: 'No open findings',
      tone: 'none',
    })
    expect(last(makeScan({ status: 'failed' }))).toEqual({ text: 'Failed', tone: 'error' })
    expect(last(makeScan({ status: 'interrupted' }))).toEqual({ text: 'Interrupted', tone: 'warn' })
    expect(projectStatus(tr, DEMO, [])).toEqual({ text: 'Not scanned', tone: 'none' })
  })

  it('counts the running scans and the earlier queued ones as ahead in the shared queue', () => {
    const mine = makeScan({ id: 'mine', status: 'queued', createdAt: '2026-10-01T10:05:00Z' })
    const running = makeScan({ id: 'run', workspaceId: 'ws-2', status: 'running' })
    const earlier = makeScan({ id: 'early', workspaceId: 'ws-3', status: 'queued', createdAt: '2026-10-01T10:01:00Z' })
    const later = makeScan({ id: 'late', workspaceId: 'ws-3', status: 'queued', createdAt: '2026-10-01T10:09:00Z' })
    const paused = makeScan({ id: 'paused', workspaceId: 'ws-3', status: 'paused' })
    expect(queueAhead(mine, [later, earlier, mine, paused, running]).map(scan => scan.id)).toEqual(['run', 'early'])
  })
})

function handlers(scans: () => readonly ScanSummary[], extra: Handlers = {}): Handlers {
  return {
    getBootstrap: () => ok(makeBootstrap()),
    listWorkspaces: () => ok([DEMO, SHOP]),
    listScans: input => ok(scans().filter(scan => !input?.workspaceId || scan.workspaceId === input.workspaceId)),
    listModels: () => ok([]),
    listToolkit: () => ok([]),
    getScan: input => {
      const scan = scans().find(s => s.id === input?.scanId) ?? makeScan()
      return ok(makeDetail(scan))
    },
    listEvents: () => ok([]),
    listFindings: () => ok([]),
    ...extra,
  }
}

async function renderPage(h: Handlers) {
  const api = fakeApi(h)
  controller = createController({ api, storage: null, host: {}, dshLocale: 'en' })
  mounted = mount(<SecurityPage controller={controller} />)
  await flush(15)
  return { api, controller, container: mounted.container }
}

describe('scans across projects', () => {
  it('names the other project’s running scan a queued scan waits for, and switches to it', async () => {
    const shopRun = makeScan({ id: 'shop-run', workspaceId: 'ws-2', workspaceTitle: 'Shop', status: 'running' })
    const demoQueued = makeScan({
      id: 'demo-q',
      status: 'queued',
      phase: 'snapshot',
      createdAt: '2026-10-01T10:05:00Z',
      startedAt: undefined,
      finishedAt: undefined,
    })
    const { container, controller: c } = await renderPage(handlers(() => [shopRun, demoQueued]))
    const queue = container.querySelector('.dshsec-queue')!
    expect(queue.textContent).toContain('Waiting for the scan of Shop to finish.')
    await click(byText(queue, 'button', 'Show Shop'))
    expect(c.store.getState().workspaceId).toBe('ws-2')
  })

  it('shows each project’s state in the header picker', async () => {
    const shopRun = makeScan({ id: 'shop-run', workspaceId: 'ws-2', workspaceTitle: 'Shop', status: 'running' })
    const { container } = await renderPage(handlers(() => [shopRun]))
    await click(container.querySelector('.dshsec-head button[aria-haspopup="listbox"]'))
    const status = (title: string) =>
      byText(container, '[role="option"]', title).querySelector('.dshsec-projsel-status')
    expect(status('Shop')?.textContent).toBe('Scanning')
    expect(status('Shop')?.classList.contains('is-active')).toBe(true)
    expect(status('Demo')?.textContent).toBe('Not scanned')
  })

  it('polls the active scans of all projects while one runs, then stops and refreshes the projects', async () => {
    vi.useFakeTimers()
    let scans: ScanSummary[] = [makeScan({ id: 'shop-run', workspaceId: 'ws-2', status: 'running' })]
    const api = fakeApi(handlers(() => scans))
    controller = createController({ api, storage: null, host: {}, dshLocale: 'en' })
    controller.revalidate()
    await vi.advanceTimersByTimeAsync(0)
    const activeLists = () =>
      (api.callsOf('listScans') as { workspaceId?: string }[]).filter(call => call?.workspaceId === undefined).length
    expect(activeLists()).toBe(1)
    expect(controller.store.getState().activeScans.map(scan => scan.id)).toEqual(['shop-run'])
    await vi.advanceTimersByTimeAsync(ACTIVE_POLL_MS)
    expect(activeLists()).toBe(2)
    const projectLists = api.callsOf('listWorkspaces').length
    scans = [makeScan({ id: 'shop-run', workspaceId: 'ws-2', status: 'completed' })]
    await vi.advanceTimersByTimeAsync(ACTIVE_POLL_MS)
    expect(activeLists()).toBe(3)
    expect(controller.store.getState().activeScans).toEqual([])
    // The finished scan changes that project's last-scan status.
    expect(api.callsOf('listWorkspaces').length).toBeGreaterThan(projectLists)
    await vi.advanceTimersByTimeAsync(ACTIVE_POLL_MS * 4)
    expect(activeLists()).toBe(3)
  })

  it('stops polling when disposed', async () => {
    vi.useFakeTimers()
    const api = fakeApi(handlers(() => [makeScan({ id: 'shop-run', workspaceId: 'ws-2', status: 'queued' })]))
    controller = createController({ api, storage: null, host: {}, dshLocale: 'en' })
    controller.revalidate()
    await vi.advanceTimersByTimeAsync(0)
    const before = api.callsOf('listScans').length
    controller.dispose()
    controller = undefined
    await act(async () => {
      await vi.advanceTimersByTimeAsync(ACTIVE_POLL_MS * 3)
    })
    expect(api.callsOf('listScans').length).toBe(before)
  })
})
