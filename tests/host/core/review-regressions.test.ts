import { execFileSync } from 'node:child_process'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { hostname, tmpdir } from 'node:os'
import { join } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { describe, expect, it, vi } from 'vitest'
import { createHandlers } from '../../../src/host/service.ts'
import { openSecurityStore } from '../../../src/host/store/sqlite.ts'
import {
  AI_SETTINGS,
  copyFixture,
  createHarness,
  gatedLlm,
  type Harness,
  oracleLlm,
  registryOf,
  scriptedLlm,
  until,
} from './helpers.ts'
import type { LlmPort, WorkspaceEntity } from '../../../src/host/dsh/ports.ts'

const call = () => ({ loopback: true, request: new Request('http://localhost'), signal: new AbortController().signal })
function handlers(h: Harness, workspaces: WorkspaceEntity[] = [], llm?: LlmPort) {
  return createHandlers({
    store: h.store,
    settings: h.settings,
    controller: h.controller,
    config: h.config,
    toolkit: undefined,
    astGrep: async () => undefined,
    workspaces: () => registryOf(workspaces),
    llm: () => llm,
    logger: h.logger,
    now: () => new Date(),
    pluginVersion: '0.4.0',
  })
}

describe('review regressions', () => {
  it('refuses a second controller without interrupting its live scan, then releases ownership on unload', async () => {
    const shop = await copyFixture('express-shop')
    const path = join(shop.root, 'security.db')
    const workspaces = [{ id: 'ws', title: 'shop', path: shop.root }]
    const llm = gatedLlm(await oracleLlm(), () => true)
    const a = createHarness({ store: openSecurityStore(path), workspaces, llm, settings: AI_SETTINGS })
    const secondStore = openSecurityStore(path)
    try {
      const scan = await a.controller.create({ workspaceId: 'ws', mode: 'quick' })
      await llm.waitForHeld(1)
      expect(() => createHarness({ store: secondStore, workspaces })).toThrow('Another DSH Security instance')
      expect(a.store.getScan(scan.id)?.status).toBe('running')
      expect(a.controller.isRunning(scan.id)).toBe(true)
      a.controller.start()
      a.controller.start()
      expect(a.store.getScan(scan.id)?.status).toBe('running')
      await a.controller.dispose()
      expect(a.store.getScan(scan.id)?.status).toBe('interrupted')
      const b = createHarness({ store: secondStore, workspaces, llm: await oracleLlm() })
      try {
        b.controller.start()
        b.controller.resume(scan.id)
        expect(await b.settle(scan.id)).toBe('completed')
      } finally {
        await b.controller.dispose()
      }
    } finally {
      await a.controller.dispose()
      a.store.close()
      secondStore.close()
      await shop.cleanup()
    }
  })

  it('keeps ownership when non-cooperative analysis outlives the shutdown grace period', async () => {
    const shop = await copyFixture('express-shop')
    const path = join(shop.root, 'security.db')
    const workspaces = [{ id: 'ws', title: 'shop', path: shop.root }]
    let releaseAnalysis: () => void = () => {}
    let entered = false
    const a = createHarness({
      store: openSecurityStore(path),
      workspaces,
      astGrep: () =>
        new Promise(resolve => {
          entered = true
          releaseAnalysis = () => resolve(undefined)
        }),
    })
    const secondStore = openSecurityStore(path)
    try {
      const scan = await a.controller.create({ workspaceId: 'ws', mode: 'quick', aiReview: false })
      await until(() => entered)
      vi.useFakeTimers()
      const stop = a.controller.dispose()
      await vi.advanceTimersByTimeAsync(5000)
      await stop
      expect(() => createHarness({ store: secondStore, workspaces })).toThrow('Another DSH Security instance')
      vi.useRealTimers()
      releaseAnalysis()
      await a.settle(scan.id)
      const b = createHarness({ store: secondStore, workspaces })
      await b.controller.dispose()
    } finally {
      vi.useRealTimers()
      releaseAnalysis()
      await a.controller.dispose()
      a.store.close()
      secondStore.close()
      await shop.cleanup()
    }
  })

  it('reclaims ownership after the owner process exits without cleanup', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'dsh-owner-'))
    const path = join(dir, 'security.db')
    const hooks = new URL('../../../bench/hooks.ts', import.meta.url).href
    const storeModule = new URL('../../../src/host/store/sqlite.ts', import.meta.url).href
    try {
      execFileSync(
        process.execPath,
        [
          '--experimental-strip-types',
          '--input-type=module',
          '-e',
          `const {registerTypeScriptTransform}=await import(${JSON.stringify(hooks)});registerTypeScriptTransform();
         const {openSecurityStore}=await import(${JSON.stringify(storeModule)});
         const s=openSecurityStore(${JSON.stringify(path)});s.acquireController();process.exit(0);`,
        ],
        { stdio: 'pipe' },
      )
      const store = openSecurityStore(path)
      try {
        const release = store.acquireController()
        release()
        release()
      } finally {
        store.close()
      }
    } finally {
      await rm(dir, { recursive: true, force: true })
    }
  })

  it('closes the database even when ownership cleanup fails', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'dsh-owner-close-'))
    const path = join(dir, 'security.db')
    const store = openSecurityStore(path)
    const raw = new DatabaseSync(path)
    try {
      store.acquireController()
      raw.exec('DROP TABLE meta')
      expect(() => store.close()).toThrow()
      expect(() => store.readSettings()).toThrow('store is closed')
      expect(() => store.close()).not.toThrow()
    } finally {
      raw.close()
      store.close()
      await rm(dir, { recursive: true, force: true })
    }
  })

  it('does not reclaim an owner on another machine sharing the data directory', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'dsh-owner-'))
    const path = join(dir, 'security.db')
    const store = openSecurityStore(path)
    const raw = new DatabaseSync(path)
    try {
      raw
        .prepare('INSERT INTO meta (key,value) VALUES (?,?)')
        .run('scan_controller_owner', JSON.stringify({ pid: process.pid, host: hostname() + '-other', id: 'other' }))
      expect(() => store.acquireController()).toThrow('Another DSH Security instance')
    } finally {
      raw.close()
      store.close()
      await rm(dir, { recursive: true, force: true })
    }
  })

  it.each([
    { succeeds: false, range: false, missingPage: false },
    { succeeds: true, range: false, missingPage: false },
    { succeeds: true, range: true, missingPage: false },
    { succeeds: true, range: false, missingPage: true },
  ])('exports truthful OSV coverage for %j', async ({ succeeds, range, missingPage }) => {
    const complete = succeeds && !range && !missingPage
    const dir = await mkdtemp(join(tmpdir(), 'dsh-osv-'))
    const workspaces = [{ id: 'ws', title: 'dependencies', path: dir }]
    const fetcher: typeof fetch = async (_input, init) => {
      if (!succeeds) throw new Error('test network failure')
      const body = JSON.parse(String(init?.body)) as { queries: { page_token?: string }[] }
      const results =
        missingPage && body.queries[0]?.page_token
          ? []
          : body.queries.map(() => (missingPage ? { next_page_token: 'p2' } : {}))
      return new Response(JSON.stringify({ results }))
    }
    const h = createHarness({ workspaces, fetch: fetcher, settings: { privacy: { allowDependencyLookup: true } } })
    try {
      await writeFile(join(dir, 'requirements.txt'), `flask==2.0.0\nrequests${range ? '>=' : '=='}2.20.0\n`)
      const scan = await h.controller.create({ workspaceId: 'ws', mode: 'quick', aiReview: false })
      expect(await h.settle(scan.id)).toBe('completed')
      const service = handlers(h, workspaces)
      const json = JSON.parse((await service.exportReport({ scanId: scan.id, format: 'json' }, call())).content)
      expect(json.scan.coverage.analyzers.find((a: { id: string }) => a.id === 'osv').available).toBe(complete)
      expect(json.scan.coverage.gapDetails.some((g: { code: string }) => g.code === 'dependencies-unchecked')).toBe(
        !complete,
      )
      const sarif = JSON.parse((await service.exportReport({ scanId: scan.id, format: 'sarif' }, call())).content)
      const notices = sarif.runs[0].invocations[0].toolExecutionNotifications ?? []
      expect(
        notices.some((n: { message: { text: string } }) =>
          n.message.text.includes('OSV dependency lookup was incomplete'),
        ),
      ).toBe(!complete)
    } finally {
      await h.controller.dispose()
      h.store.close()
      await rm(dir, { recursive: true, force: true })
    }
  })

  it('returns every model without resolving metadata, and resolves a model beyond index 100 on demand', async () => {
    const resolveModelInfo = vi.fn(async (provider: string, id: string) => ({
      provider,
      id,
      name: id,
      reasoning: { efforts: [{ id: 'high', name: 'High', description: 'Detailed' }], defaultEffort: 'high' },
    }))
    const llm = scriptedLlm(async function* () {}, {
      listModels: async () =>
        Array.from({ length: 250 }, (_, i) => ({ provider: 'scripted', id: `model-${i}`, name: `Model ${i}` })),
      resolveModelInfo,
    })
    const h = createHarness({ llm })
    try {
      const service = handlers(h, [], llm)
      const list = await service.listModels({}, call())
      expect(list[0]?.models).toHaveLength(250)
      expect(resolveModelInfo).not.toHaveBeenCalled()
      expect(await service.getModelInfo({ provider: 'scripted', model: 'model-249' }, call())).toMatchObject({
        id: 'model-249',
        defaultEffort: 'high',
      })
      expect(resolveModelInfo).toHaveBeenCalledTimes(1)
      await expect(
        service.getModelInfo({ provider: 'disconnected', model: 'model-249' }, call()),
      ).rejects.toMatchObject({ code: 'security/no-model' })
    } finally {
      await h.controller.dispose()
      h.store.close()
    }
  })
})
