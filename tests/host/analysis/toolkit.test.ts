import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { lstat, mkdir, readdir, readFile, symlink, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import {
  loadToolkitLock,
  platformKey,
  Toolkit,
  ToolkitError,
  type ToolkitLock,
} from '../../../src/host/analysis/toolkit.ts'
import { makeTempDir } from './helpers.ts'

const LOCK_PATH = fileURLToPath(new URL('../../../toolkit.lock.json', import.meta.url))
const PLATFORM = 'linux-x64'
const isPosix = process.platform !== 'win32'
const sha256 = (bytes: Buffer): string => createHash('sha256').update(bytes).digest('hex')

function lockWith(asset: Record<string, unknown>, tool: 'gitleaks' | 'osv-scanner' = 'osv-scanner'): ToolkitLock {
  return loadToolkitLock({
    schemaVersion: 1,
    tools: {
      [tool]: {
        name: tool === 'gitleaks' ? 'Gitleaks' : 'OSV-Scanner',
        version: '2.2.2',
        license: 'Apache-2.0',
        homepage: 'https://example.com/tool',
        assets: { [PLATFORM]: { url: 'https://downloads.example.com/tool', size: null, ...asset } },
      },
    },
  })
}

/** A fetch that serves fixed bytes and counts calls. */
function serve(bytes: Buffer, status = 200): { fetch: typeof fetch; calls: string[] } {
  const calls: string[] = []
  const impl = async (input: string | URL | Request): Promise<Response> => {
    calls.push(String(input))
    return new Response(new Uint8Array(bytes), { status })
  }
  return { fetch: impl as typeof fetch, calls }
}

async function expectCode(promise: Promise<unknown>, code: string): Promise<void> {
  const error = await promise.then(
    () => undefined,
    (e: unknown) => e,
  )
  expect(error).toBeInstanceOf(ToolkitError)
  expect((error as ToolkitError).code).toBe(code)
}

describe('loadToolkitLock', () => {
  it('accepts the repository lock file', async () => {
    const lock = loadToolkitLock(JSON.parse(await readFile(LOCK_PATH, 'utf8')))
    expect(lock.tools.gitleaks?.version).toMatch(/^\d+\.\d+\.\d+$/)
    expect(lock.tools['osv-scanner']?.assets['linux-x64']?.archive).toBe('none')
    expect(lock.tools.gitleaks?.assets['win32-x64']?.binary).toBe('gitleaks.exe')
  })

  it.each([
    ['http URL', { url: 'http://example.com/x', sha256: null, archive: 'none', binary: 'x' }],
    ['traversal binary', { url: 'https://example.com/x', sha256: null, archive: 'tar.gz', binary: '../x' }],
    ['nested binary path', { url: 'https://example.com/x', sha256: null, archive: 'tar.gz', binary: 'bin/x' }],
    ['bad sha', { url: 'https://example.com/x', sha256: 'abc', archive: 'none', binary: 'x' }],
    ['unknown archive', { url: 'https://example.com/x', sha256: null, archive: 'rar', binary: 'x' }],
  ])('rejects %s', (_label, asset) => {
    expect(() =>
      loadToolkitLock({
        schemaVersion: 1,
        tools: {
          gitleaks: {
            name: 'G',
            version: '1.0.0',
            license: 'MIT',
            homepage: 'https://example.com',
            assets: { [PLATFORM]: asset },
          },
        },
      }),
    ).toThrow(/Invalid toolkit\.lock\.json/)
  })

  it('rejects unknown schema versions and platform keys', () => {
    expect(() => loadToolkitLock({ schemaVersion: 2, tools: {} })).toThrow()
    expect(() =>
      loadToolkitLock({
        schemaVersion: 1,
        tools: {
          gitleaks: {
            name: 'G',
            version: '1.0.0',
            license: 'MIT',
            homepage: 'https://e.com',
            assets: { 'aix-ppc': {} },
          },
        },
      }),
    ).toThrow()
  })

  it('normalizes sha256 to lower case', () => {
    const lock = lockWith({ sha256: 'A'.repeat(64), archive: 'none', binary: 'osv-scanner' })
    expect(lock.tools['osv-scanner']?.assets[PLATFORM]?.sha256).toBe('a'.repeat(64))
  })
})

describe('platformKey', () => {
  it('combines platform and arch', () => {
    expect(platformKey('darwin', 'arm64')).toBe('darwin-arm64')
    expect(platformKey()).toBe(`${process.platform}-${process.arch}`)
  })
})

describe('Toolkit', () => {
  let dir: string
  let cleanup: () => Promise<void>
  beforeEach(async () => {
    ;({ dir, cleanup } = await makeTempDir('dsh-toolkit-'))
  })
  afterEach(async () => {
    await cleanup()
  })

  const binary = Buffer.from('#!/bin/sh\necho "osv-scanner version: 2.2.2"\n')

  it('refuses when managed install is disabled', async () => {
    const { fetch, calls } = serve(binary)
    const lock = lockWith({ sha256: sha256(binary), archive: 'none', binary: 'osv-scanner' })
    const toolkit = new Toolkit({ dir, lock, allowManagedInstall: false, fetch, platform: PLATFORM })
    await expectCode(toolkit.install('osv-scanner'), 'toolkit-disabled')
    expect(calls).toEqual([])
  })

  it('refuses unpinned assets without downloading', async () => {
    const { fetch, calls } = serve(binary)
    const lock = lockWith({ sha256: null, archive: 'none', binary: 'osv-scanner' })
    const toolkit = new Toolkit({ dir, lock, allowManagedInstall: true, fetch, platform: PLATFORM })
    await expectCode(toolkit.install('osv-scanner'), 'toolkit-unpinned')
    expect(calls).toEqual([])
    const entry = (await toolkit.status()).find(e => e.id === 'osv-scanner')!
    expect(entry.managed).toBeUndefined()
    expect(entry.status.available).toBe(false)
  })

  it('refuses tools or platforms with no managed download (and semgrep)', async () => {
    const { fetch } = serve(binary)
    const lock = lockWith({ sha256: sha256(binary), archive: 'none', binary: 'osv-scanner' })
    const other = new Toolkit({ dir, lock, allowManagedInstall: true, fetch, platform: 'darwin-arm64' })
    await expectCode(other.install('osv-scanner'), 'toolkit-unavailable')
    await expectCode(other.install('gitleaks'), 'toolkit-unavailable')
    await expectCode(other.install('semgrep'), 'toolkit-unavailable')
  })

  it('refuses a download whose SHA-256 does not match and installs nothing', async () => {
    const { fetch, calls } = serve(Buffer.from('tampered binary'))
    const lock = lockWith({ sha256: sha256(binary), archive: 'none', binary: 'osv-scanner' })
    const toolkit = new Toolkit({ dir, lock, allowManagedInstall: true, fetch, platform: PLATFORM })
    await expectCode(toolkit.install('osv-scanner'), 'toolkit-checksum-mismatch')
    expect(calls).toEqual(['https://downloads.example.com/tool'])
    expect(await readdir(join(dir, 'osv-scanner'))).toEqual([])
    expect(await toolkit.resolveHandle('osv-scanner').then(h => h?.source)).not.toBe('managed')
  })

  it('refuses downloads over the pinned size or with an HTTP error', async () => {
    const lock = lockWith({ sha256: sha256(binary), size: 10, archive: 'none', binary: 'osv-scanner' })
    const toolkit = new Toolkit({
      dir,
      lock,
      allowManagedInstall: true,
      fetch: serve(binary).fetch,
      platform: PLATFORM,
    })
    await expectCode(toolkit.install('osv-scanner'), 'toolkit-download-failed')

    const lock2 = lockWith({ sha256: sha256(binary), archive: 'none', binary: 'osv-scanner' })
    const failing = new Toolkit({
      dir,
      lock: lock2,
      allowManagedInstall: true,
      fetch: serve(Buffer.from(''), 404).fetch,
      platform: PLATFORM,
    })
    await expectCode(failing.install('osv-scanner'), 'toolkit-download-failed')
  })

  it.runIf(isPosix)('installs a verified raw binary and resolves it as managed', async () => {
    const { fetch } = serve(binary)
    const lock = lockWith({ sha256: sha256(binary), size: binary.length, archive: 'none', binary: 'osv-scanner' })
    const toolkit = new Toolkit({ dir, lock, allowManagedInstall: true, fetch, platform: PLATFORM })
    const entry = await toolkit.install('osv-scanner')
    expect(entry.status).toMatchObject({ id: 'osv-scanner', available: true, source: 'managed', version: '2.2.2' })
    expect(entry.managed).toMatchObject({ version: '2.2.2', sha256: sha256(binary), sizeBytes: binary.length })

    const installed = join(dir, 'osv-scanner', '2.2.2', 'osv-scanner')
    expect(await toolkit.resolve('osv-scanner')).toBe(installed)
    expect((await lstat(installed)).mode & 0o777).toBe(0o755)
    const meta = JSON.parse(await readFile(join(dir, 'osv-scanner', '2.2.2', 'installed.json'), 'utf8'))
    expect(meta).toMatchObject({ version: '2.2.2', assetSha256: sha256(binary) })
    // No staging leftovers.
    expect(await readdir(join(dir, 'osv-scanner'))).toEqual(['2.2.2'])

    // Tampering with the installed binary makes it unresolvable as managed.
    await writeFile(installed, '#!/bin/sh\necho evil\n')
    const fresh = new Toolkit({ dir, lock, allowManagedInstall: true, fetch, platform: PLATFORM })
    expect((await fresh.resolveHandle('osv-scanner'))?.source).not.toBe('managed')
  })

  it.runIf(isPosix)('extracts a single binary from a verified tar.gz', async () => {
    const work = join(dir, 'build')
    await mkdir(work)
    await writeFile(join(work, 'gitleaks'), '#!/bin/sh\necho v8.28.0\n')
    await writeFile(join(work, 'README.md'), 'readme')
    const archive = join(dir, 'gitleaks.tar.gz')
    execFileSync('tar', ['-czf', archive, '-C', work, 'gitleaks', 'README.md'])
    const bytes = await readFile(archive)

    const lock = lockWith({ sha256: sha256(bytes), archive: 'tar.gz', binary: 'gitleaks' }, 'gitleaks')
    const installDir = join(dir, 'tools')
    const toolkit = new Toolkit({
      dir: installDir,
      lock,
      allowManagedInstall: true,
      fetch: serve(bytes).fetch,
      platform: PLATFORM,
    })
    const entry = await toolkit.install('gitleaks')
    expect(entry.status.source).toBe('managed')
    const files = await readdir(join(installDir, 'gitleaks', '2.2.2'))
    expect(files.sort()).toEqual(['gitleaks', 'installed.json'])
  })

  it.runIf(isPosix)('rejects an archive whose binary is a symlink', async () => {
    const work = join(dir, 'build')
    await mkdir(work)
    await symlink('/bin/sh', join(work, 'gitleaks'))
    const archive = join(dir, 'evil.tar.gz')
    execFileSync('tar', ['-czf', archive, '-C', work, 'gitleaks'])
    const bytes = await readFile(archive)

    const lock = lockWith({ sha256: sha256(bytes), archive: 'tar.gz', binary: 'gitleaks' }, 'gitleaks')
    const installDir = join(dir, 'tools')
    const toolkit = new Toolkit({
      dir: installDir,
      lock,
      allowManagedInstall: true,
      fetch: serve(bytes).fetch,
      platform: PLATFORM,
    })
    await expectCode(toolkit.install('gitleaks'), 'toolkit-extract-failed')
    expect(await readdir(join(installDir, 'gitleaks'))).toEqual([])
  })

  it.runIf(isPosix)('fails cleanly when the archive lacks the binary', async () => {
    const work = join(dir, 'build')
    await mkdir(work)
    await writeFile(join(work, 'other'), 'x')
    const archive = join(dir, 'a.tar.gz')
    execFileSync('tar', ['-czf', archive, '-C', work, 'other'])
    const bytes = await readFile(archive)
    const lock = lockWith({ sha256: sha256(bytes), archive: 'tar.gz', binary: 'gitleaks' }, 'gitleaks')
    const toolkit = new Toolkit({
      dir: join(dir, 'tools'),
      lock,
      allowManagedInstall: true,
      fetch: serve(bytes).fetch,
      platform: PLATFORM,
    })
    await expectCode(toolkit.install('gitleaks'), 'toolkit-extract-failed')
  })

  it('reports status with install hints for every tool', async () => {
    const lock = loadToolkitLock(JSON.parse(await readFile(LOCK_PATH, 'utf8')))
    const toolkit = new Toolkit({
      dir,
      lock,
      allowManagedInstall: true,
      fetch: serve(Buffer.from('')).fetch,
      platform: PLATFORM,
    })
    const entries = await toolkit.status()
    expect(entries.map(e => e.id)).toEqual(['gitleaks', 'osv-scanner', 'semgrep'])
    for (const entry of entries) {
      expect(entry.installHint.length).toBeGreaterThan(10)
      expect(entry.homepage).toMatch(/^https:\/\//)
      if (!entry.status.available) expect(entry.status.reason).toBeTruthy()
    }
    expect(entries.find(e => e.id === 'semgrep')!.installHint).toMatch(/pipx install semgrep/)
    // A managed download is offered exactly for tools whose shipped lock entry is pinned for this platform;
    // Semgrep is never downloaded.
    for (const entry of entries) {
      const asset = lock.tools[entry.id]?.assets[PLATFORM]
      expect(entry.managed !== undefined, entry.id).toBe(asset?.sha256 != null)
    }
    expect(entries.find(e => e.id === 'semgrep')!.managed).toBeUndefined()
  })
})
