import { existsSync, readFileSync } from 'node:fs'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'
import type { ConnectionFetchRoute, LoggerPort, WorkspaceRegistryPort } from '../../../src/host/dsh/ports.ts'
import { apply, Config, type HostContext, name } from '../../../src/host/index.ts'
import { rpcRoutePath } from '../../../src/host/rpc/server.ts'
import { RPC_METHOD_NAMES, type RpcMethodName } from '../../../src/shared/contracts.ts'
import { envelope, fakeConnection, type LogEntry, readEnvelope, rpcRequest } from '../rpc/helpers.ts'
import { AI_SETTINGS, copyFixture, gatedLlm, oracleLlm, registryOf, roleOf, type TempWorkspace } from './helpers.ts'

interface FakeHost {
  readonly ctx: HostContext
  readonly connection: ReturnType<typeof fakeConnection>
  readonly logs: LogEntry[]
  readonly labels: string[]
  /** Run every collected disposer in reverse order, awaiting async ones (as Cordis does). */
  dispose(): Promise<void>
}

function fakeHost(
  services: { connection?: unknown; workspaceRegistry?: WorkspaceRegistryPort; llm?: unknown } = {},
  options: { namedLogger?: 'ok' | 'throws' } = {},
): FakeHost {
  const logs: LogEntry[] = []
  const labels: string[] = []
  const disposers: (() => unknown)[] = []
  const methods: LoggerPort = {
    debug: (...args) => logs.push({ level: 'debug', args }),
    info: (...args) => logs.push({ level: 'info', args }),
    warn: (...args) => logs.push({ level: 'warn', args }),
    error: (...args) => logs.push({ level: 'error', args }),
  }
  const callable = (loggerName: string): LoggerPort => {
    if (options.namedLogger === 'throws') throw new Error('no named loggers')
    expect(loggerName).toBe('dsh-security')
    return methods
  }
  const logger = Object.assign(callable, methods)
  const connection = fakeConnection()
  const values: Record<string, unknown> = {
    connection: 'connection' in services ? services.connection : connection,
    workspaceRegistry: services.workspaceRegistry,
    llm: services.llm,
  }
  const make = (scope: string): HostContext => ({
    get: key => values[key],
    effect: (execute, label) => {
      labels.push(`${scope}:${label ?? '?'}`)
      disposers.push(execute())
      return undefined
    },
    inject: (deps, callback) => {
      expect(deps).toEqual(['connection'])
      callback(make('scoped'))
      return undefined
    },
    logger,
  })
  return {
    ctx: make('root'),
    connection,
    logs,
    labels,
    async dispose() {
      for (const dispose of disposers.splice(0).reverse()) await dispose()
    },
  }
}

async function post(route: ConnectionFetchRoute | undefined, method: RpcMethodName, payload: unknown = {}) {
  if (!route) throw new Error(`route ${method} is not registered`)
  return await readEnvelope(
    await route.fetch(rpcRequest(method, envelope(method, { payload, rpcId: `rpc-${method}` }))),
  )
}

const PKG_VERSION = (
  JSON.parse(readFileSync(new URL('../../../package.json', import.meta.url), 'utf8')) as { version: string }
).version

type Routes = ReadonlyMap<string, ConnectionFetchRoute>

async function statusOf(routes: Routes, scanId: string): Promise<string> {
  const response = await post(routes.get(rpcRoutePath('getScan')), 'getScan', { scanId })
  if (!response.result.ok) throw new Error(response.result.error.message)
  return (response.result.value as { summary: { status: string } }).summary.status
}

async function waitForStatus(routes: Routes, scanId: string, status: string): Promise<void> {
  const deadline = Date.now() + 15_000
  while ((await statusOf(routes, scanId)) !== status) {
    if (Date.now() > deadline) throw new Error(`scan never reached ${status}`)
    await new Promise(resolve => setTimeout(resolve, 2))
  }
}

let dataDir: string
let shop: TempWorkspace | undefined

// `vitest.config.ts` hands the same `define` object to the root config and to each project, and Vitest
// deletes the keys from the root copy while resolving it, so the projects get no defines at all. Provide
// the build-time constant as a global so `src/host/index.ts` runs either way.
beforeAll(() => {
  if ((globalThis as Record<string, unknown>).__PLUGIN_VERSION__ === undefined) {
    vi.stubGlobal('__PLUGIN_VERSION__', PKG_VERSION)
  }
})

afterAll(() => {
  vi.unstubAllGlobals()
})

beforeEach(async () => {
  dataDir = await mkdtemp(join(tmpdir(), 'dshsec-plugin-'))
})

afterEach(async () => {
  await rm(dataDir, { recursive: true, force: true })
  await shop?.cleanup()
  shop = undefined
})

describe('plugin entry', () => {
  it('exports its name and config schema', () => {
    expect(name).toBe('dsh-security')
    expect(Config.parse({})).toMatchObject({ maxParallelWorkers: 4, maxConcurrentScans: 1 })
  })

  it('registers one route per RPC method and serves the Connection envelope', async () => {
    const host = fakeHost()
    apply(host.ctx, { dataDir })
    expect(existsSync(join(dataDir, 'security.db'))).toBe(true)
    expect([...host.connection.routes.keys()].sort()).toEqual(
      RPC_METHOD_NAMES.map(m => `/api/dsh-security/${m}`).sort(),
    )
    for (const route of host.connection.routes.values()) {
      expect(route).toMatchObject({ methods: ['POST'], requestBody: 'buffered' })
    }
    expect(host.labels).toEqual([
      'root:dsh-security: store',
      'root:dsh-security: scans',
      'scoped:dsh-security: rpc routes',
    ])

    const body = await post(host.connection.routes.get(rpcRoutePath('getBootstrap')), 'getBootstrap')
    expect(body.type).toBe('server-response')
    expect(body.rpcId).toBe('rpc-getBootstrap')
    if (!body.result.ok) throw new Error(body.result.error.message)
    expect(body.result.value).toMatchObject({
      pluginVersion: PKG_VERSION,
      contractVersion: 1,
      settingsRevision: 0,
      loopback: true,
      capabilities: { llm: false, workspaces: false },
    })
    expect(host.logs.some(e => e.level === 'info' && String(e.args[0]).includes(`data in ${dataDir}`))).toBe(true)

    await host.dispose()
  })

  it('closes cleanly: routes unregistered, scans stopped, store closed', async () => {
    shop = await copyFixture('express-shop')
    const host = fakeHost({ workspaceRegistry: registryOf([{ id: 'ws', path: shop.root, title: 'shop' }]) })
    apply(host.ctx, { dataDir })
    const routes = new Map(host.connection.routes)
    const created = await post(routes.get(rpcRoutePath('createScan')), 'createScan', {
      workspaceId: 'ws',
      mode: 'quick',
      aiReview: false,
    })
    if (!created.result.ok) throw new Error(created.result.error.message)
    const { scanId } = created.result.value as { scanId: string }
    await waitForStatus(routes, scanId, 'completed')

    await host.dispose()
    expect(host.connection.routes.size).toBe(0)
    expect(host.connection.disposed.sort()).toEqual(RPC_METHOD_NAMES.map(m => `/api/dsh-security/${m}`).sort())
    // The store is closed: a handler kept from before now fails with a generic internal error.
    const after = await post(routes.get(rpcRoutePath('getBootstrap')), 'getBootstrap')
    expect(after.result.ok).toBe(false)
    if (!after.result.ok) expect(after.result.error.code).toBe('security/internal')

    // The database survives: a new instance sees the completed scan.
    const again = fakeHost({ workspaceRegistry: registryOf([{ id: 'ws', path: shop.root, title: 'shop' }]) })
    apply(again.ctx, { dataDir })
    const listed = await post(again.connection.routes.get(rpcRoutePath('listScans')), 'listScans', {})
    expect(listed.result.ok && (listed.result.value as { id: string; status: string }[])).toEqual([
      expect.objectContaining({ id: scanId, status: 'completed' }),
    ])
    await again.dispose()
  })

  it('stops a running scan on unload and leaves it resumable', async () => {
    shop = await copyFixture('express-shop')
    const registry = registryOf([{ id: 'ws', path: shop.root, title: 'shop' }])
    const llm = gatedLlm(await oracleLlm(), options => roleOf(options) === 'hunter')
    const host = fakeHost({ workspaceRegistry: registry, llm })
    apply(host.ctx, { dataDir })
    const routes = new Map(host.connection.routes)
    const settings = await post(routes.get(rpcRoutePath('updateSettings')), 'updateSettings', {
      patch: AI_SETTINGS,
      expectedRevision: 0,
    })
    expect(settings.result.ok).toBe(true)
    const created = await post(routes.get(rpcRoutePath('createScan')), 'createScan', {
      workspaceId: 'ws',
      mode: 'deep',
    })
    if (!created.result.ok) throw new Error(created.result.error.message)
    const { scanId } = created.result.value as { scanId: string }
    await llm.waitForHeld(1)
    expect(await statusOf(routes, scanId)).toBe('running')

    await host.dispose()

    llm.open()
    const next = fakeHost({ workspaceRegistry: registry, llm })
    apply(next.ctx, { dataDir })
    const nextRoutes = next.connection.routes
    expect(await statusOf(nextRoutes, scanId)).toBe('interrupted')
    const resumed = await post(nextRoutes.get(rpcRoutePath('resumeScan')), 'resumeScan', { scanId })
    expect(resumed.result.ok).toBe(true)
    await waitForStatus(nextRoutes, scanId, 'completed')
    await next.dispose()
  })

  it('works without exact-route support and with a logger that has no named children', async () => {
    const host = fakeHost({ connection: { fetch: {} } }, { namedLogger: 'throws' })
    apply(host.ctx, { dataDir })
    expect(host.connection.routes.size).toBe(0)
    expect(host.logs.some(e => e.level === 'warn' && String(e.args[0]).includes('no exact-route support'))).toBe(true)
    expect(host.labels).toEqual(['root:dsh-security: store', 'root:dsh-security: scans'])
    await host.dispose()
  })

  it('defaults the data directory to $DSH_HOME/security', async () => {
    const previous = process.env.DSH_HOME
    process.env.DSH_HOME = dataDir
    try {
      const host = fakeHost()
      apply(host.ctx)
      expect(existsSync(join(dataDir, 'security', 'security.db'))).toBe(true)
      await host.dispose()
    } finally {
      if (previous === undefined) delete process.env.DSH_HOME
      else process.env.DSH_HOME = previous
    }
  })

  it('rejects invalid operator configuration', () => {
    const host = fakeHost()
    expect(() => apply(host.ctx, { dataDir, maxParallelWorkers: 0 })).toThrow()
    expect(host.connection.routes.size).toBe(0)
  })
})
