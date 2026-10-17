import { act } from 'react'
import { afterEach, describe, expect, it } from 'vitest'
import { ControllerProvider } from '../../src/client/context.tsx'
import { createController, type SecurityController } from '../../src/client/controller.ts'
import { HistoryView } from '../../src/client/views/History.tsx'
import type { RpcResult, ScanSummary } from '../../src/shared/contracts.ts'
import {
  byText,
  click,
  fail,
  fakeApi,
  flush,
  type Handlers,
  makeBootstrap,
  makeScan,
  type Mounted,
  mount,
  ok,
} from './helpers.tsx'

let mounted: Mounted | undefined
let controller: SecurityController | undefined

afterEach(() => {
  mounted?.unmount()
  controller?.dispose()
  mounted = undefined
  controller = undefined
  document.body.innerHTML = ''
})

const scans = Array.from({ length: 51 }, (_, index) =>
  makeScan({
    id: `history-${index}`,
    createdAt: new Date(Date.UTC(2026, 9, 1, 0, 51 - index)).toISOString(),
  }),
)

async function renderHistory(listScans: NonNullable<Handlers['listScans']>) {
  const api = fakeApi({
    getBootstrap: () => ok(makeBootstrap()),
    listWorkspaces: () => ok([{ id: 'ws-1', title: 'Demo', displayPath: '~/demo' }]),
    listScans,
  })
  controller = createController({ api, storage: null, host: {}, dshLocale: 'en' })
  mounted = mount(
    <ControllerProvider controller={controller}>
      <HistoryView />
    </ControllerProvider>,
  )
  act(() => controller?.ensureLoaded())
  await flush(10)
  return { api, container: mounted.container }
}

describe('history pagination', () => {
  it('loads scans beyond the first 50 and disables further requests while loading', async () => {
    let resolvePage: ((value: RpcResult<readonly ScanSummary[]>) => void) | undefined
    const { api, container } = await renderHistory(payload => {
      if ((payload.offset ?? 0) === 0) return ok(scans.slice(0, 50))
      return new Promise(resolve => {
        resolvePage = resolve
      })
    })
    expect(container.querySelectorAll('tbody tr')).toHaveLength(50)
    await click(byText(container, 'button', 'Show more scans'))
    expect(byText<HTMLButtonElement>(container, 'button', 'Loading more scans').disabled).toBe(true)
    expect(container.querySelectorAll('tbody tr')).toHaveLength(50)
    await act(async () => {
      resolvePage?.(ok(scans.slice(50)))
    })
    await flush()
    expect(container.querySelectorAll('tbody tr')).toHaveLength(51)
    expect(container.textContent).not.toContain('Show more scans')
    expect(api.callsOf('listScans').at(-1)).toMatchObject({ workspaceId: 'ws-1', offset: 50, limit: 50 })
  })

  it('retains existing history on a page failure and retries the same offset', async () => {
    let pageAttempts = 0
    const { api, container } = await renderHistory(payload => {
      if ((payload.offset ?? 0) === 0) return ok(scans.slice(0, 50))
      pageAttempts++
      return pageAttempts === 1 ? fail('security/transport') : ok(scans.slice(50))
    })
    await click(byText(container, 'button', 'Show more scans'))
    expect(container.querySelectorAll('tbody tr')).toHaveLength(50)
    expect(container.textContent).toContain('Couldn’t reach DSH')
    await click(byText(container, 'button', 'Retry'))
    expect(container.querySelectorAll('tbody tr')).toHaveLength(51)
    expect(api.callsOf('listScans').slice(-2)).toEqual([
      { workspaceId: 'ws-1', limit: 50, offset: 50 },
      { workspaceId: 'ws-1', limit: 50, offset: 50 },
    ])
  })
})
