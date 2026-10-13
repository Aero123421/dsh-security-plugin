import { mkdir, mkdtemp, realpath, rm, symlink } from 'node:fs/promises'
import { homedir, tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { createPathMasker, homeRelative, maskDeep } from '../../../src/host/paths.ts'
import { RpcError, toRpcFailure } from '../../../src/host/rpc/errors.ts'
import type { RpcCallContext, RpcHandlers } from '../../../src/host/rpc/server.ts'
import { createHandlers } from '../../../src/host/service.ts'
import { recordingLogger } from '../rpc/helpers.ts'
import { copyFixture, createHarness, type Harness, registryOf, type TempWorkspace } from './helpers.ts'
import { fakeGitleaksToolkit, gitleaksFailing } from './toolkit-helpers.ts'

describe('createPathMasker', () => {
  const mask = createPathMasker({
    workspaceRoots: ['/home/ana/code/shop'],
    dataDir: '/home/ana/.dsh/security',
    tmp: '/tmp',
    home: '/home/ana',
  })

  it('replaces the longest directory first', () => {
    expect(mask('open /home/ana/code/shop/src/a.ts: denied')).toBe('open <project>/src/a.ts: denied')
    expect(mask('cache /home/ana/.dsh/security/toolkit/gitleaks')).toBe('cache <data>/toolkit/gitleaks')
    expect(mask('config /home/ana/.config/x and /tmp/dsh-gitleaks-1/report.json')).toBe(
      'config ~/.config/x and <tmp>/dsh-gitleaks-1/report.json',
    )
    expect(mask('/home/ana')).toBe('~')
  })

  it('respects path boundaries and sentence ends', () => {
    expect(mask('/home/anabel/x and /srv/home/ana/x')).toBe('/home/anabel/x and /srv/home/ana/x')
    expect(mask('failed in /home/ana/code/shop.')).toBe('failed in <project>.')
    expect(mask('/home/ana/code/shop.git')).toBe('~/code/shop.git')
    expect(mask('"/home/ana/code/shop"')).toBe('"<project>"')
    expect(mask('file:///home/ana/code/shop/x')).toBe('file://<project>/x')
  })

  it('handles both separators and Windows case-insensitivity', () => {
    const win = createPathMasker({ workspaceRoots: ['C:\\Users\\Ana\\shop\\'], home: 'C:\\Users\\Ana' })
    expect(win('at c:\\users\\ana\\SHOP\\src\\a.ts')).toBe('at <project>\\src\\a.ts')
    expect(win('at C:/Users/Ana/shop/src/a.ts')).toBe('at <project>/src/a.ts')
    expect(win('at C:\\Users\\Ana\\AppData\\x')).toBe('at ~\\AppData\\x')
    // POSIX paths stay case-sensitive.
    expect(mask('/HOME/ANA/x')).toBe('/HOME/ANA/x')
  })

  it('ignores roots that are too short to be specific', () => {
    const loose = createPathMasker({ workspaceRoots: ['/', 'C:\\'], home: '' })
    expect(loose('/etc/passwd C:\\x')).toBe('/etc/passwd C:\\x')
  })

  it('masks nested strings and computes home-relative display paths', () => {
    expect(maskDeep({ a: ['/home/ana/x', 1], b: { c: '/home/ana/code/shop' } }, mask)).toEqual({
      a: ['~/x', 1],
      b: { c: '<project>' },
    })
    expect(homeRelative('/home/ana/code/shop', '/home/ana')).toBe('~/code/shop')
    expect(homeRelative('/home/anabel/shop', '/home/ana')).toBe('/home/anabel/shop')
    expect(homeRelative('C:\\users\\ana\\shop', 'C:\\Users\\Ana')).toBe('~\\shop')
  })

  it('masks RpcError messages and details on the wire', () => {
    const failure = toRpcFailure(
      new RpcError('security/toolkit-unavailable', 'Extracting failed: /home/ana/.dsh/security/toolkit/x', {
        reason: 'toolkit-extract-failed',
        nested: { path: '/home/ana/code/shop/a' },
      }),
      recordingLogger(),
      mask,
    )
    expect(failure.message).toBe('Extracting failed: <data>/toolkit/x')
    expect(failure.details).toEqual({ reason: 'toolkit-extract-failed', nested: { path: '<project>/a' } })
  })
})

describe.skipIf(process.platform === 'win32')('no absolute Host path reaches the browser', () => {
  let app: TempWorkspace
  let dataDir: string
  let h: Harness
  let handlers: RpcHandlers
  let scanId: string
  const responses: { method: string; json: string }[] = []

  const call = (): RpcCallContext => ({
    request: new Request('http://localhost/api/dsh-security/test', { method: 'POST' }),
    loopback: true,
    signal: new AbortController().signal,
  })

  beforeAll(async () => {
    app = await copyFixture('express-shop')
    dataDir = await mkdtemp(join(tmpdir(), 'dshsec-data-'))
    const home = homedir()
    const toolkit = await fakeGitleaksToolkit(
      dataDir,
      gitleaksFailing(
        `fatal: cannot open ${app.root}/src/app.js (config ${home}/.config/gitleaks.toml, cache ${dataDir}/toolkit/cache)`,
      ),
      {
        fetch: async () => {
          throw new Error(`EACCES: ${dataDir}/toolkit/osv-scanner/.staging-1/download via ${home}/.npmrc proxy`)
        },
      },
    )
    const workspaces = [{ id: 'ws-shop', path: app.root, title: 'express-shop' }]
    h = createHarness({ toolkit, workspaces, dataDir })
    handlers = createHandlers({
      store: h.store,
      settings: h.settings,
      controller: h.controller,
      toolkit,
      config: h.config,
      llm: () => undefined,
      workspaces: () => registryOf(workspaces),
      astGrep: async () => undefined,
      logger: h.logger,
      pluginVersion: '0.0.0-test',
      now: () => new Date(),
      dataDir,
    })
    const created = await handlers.createScan({ workspaceId: 'ws-shop', mode: 'quick', aiReview: false }, call())
    scanId = created.scanId
    expect(await h.settle(scanId)).toBe('completed')
  })

  afterAll(async () => {
    await h?.controller.dispose()
    await app?.cleanup()
    if (dataDir) await rm(dataDir, { recursive: true, force: true })
  })

  it('masks external-tool failures in getScan, listScans, listEvents, listToolkit and installTool errors', async () => {
    const record = async (method: string, value: unknown) => {
      responses.push({ method, json: JSON.stringify(value) })
    }
    await record('getScan', await handlers.getScan({ scanId }, call()))
    await record('listScans', await handlers.listScans({}, call()))
    await record('listEvents', await handlers.listEvents({ scanId }, call()))
    await record('listToolkit', await handlers.listToolkit({}, call()))
    await record('exportReport', await handlers.exportReport({ scanId, format: 'markdown' }, call()))
    try {
      await handlers.installTool({ toolId: 'osv-scanner', acceptLicense: true }, call())
      expect.unreachable('the download must fail')
    } catch (error) {
      expect(error).toBeInstanceOf(RpcError)
      await record('installTool', toRpcFailure(error, recordingLogger()))
    }

    const detail = JSON.parse(responses[0]?.json ?? '{}') as {
      coverage?: { analyzers: { id: string; reason?: string }[]; gaps: string[] }
    }
    const reason = detail.coverage?.analyzers.find(a => a.id === 'gitleaks')?.reason ?? ''
    expect(reason).toContain('<project>/src/app.js')
    expect(reason).toContain('~/.config/gitleaks.toml')
    expect(reason).toContain('<data>/toolkit/cache')
    const events = responses.find(r => r.method === 'listEvents')?.json ?? ''
    expect(events).toContain('<project>/src/app.js')
    expect(responses.find(r => r.method === 'installTool')?.json).toContain('<data>/toolkit/osv-scanner')

    for (const { method, json } of responses) {
      for (const dir of [app.root, dataDir, homedir(), tmpdir()]) {
        expect(json.includes(dir), `${method} leaks ${dir}`).toBe(false)
      }
    }
  })
})

describe('createPathMasker canonical paths', () => {
  it('also masks the canonical spelling of a symlinked directory', async () => {
    const base = await realpath(await mkdtemp(join(tmpdir(), 'dshsec-mask-')))
    try {
      const real = join(base, 'real-project')
      const link = join(base, 'linked-project')
      await mkdir(real)
      try {
        await symlink(real, link, 'dir')
      } catch {
        return // Creating symlinks needs extra privileges on some Windows setups.
      }
      const mask = createPathMasker({ workspaceRoots: [link] })
      for (const dir of [real, link]) {
        const masked = mask(`failed to read ${join(dir, 'a.ts')}`)
        expect(masked).toContain('<project>')
        expect(masked).not.toContain(base)
      }
    } finally {
      await rm(base, { recursive: true, force: true })
    }
  })
})
