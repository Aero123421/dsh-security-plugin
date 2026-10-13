/**
 * Managed external-analyzer toolkit. Binaries come only from the pinned URLs
 * in `toolkit.lock.json` and are installed only after their SHA-256 matches
 * the pin. Nothing is executed during installation except the system `tar`
 * extracting one named member; no install scripts, no shell.
 */

import { createHash } from 'node:crypto'
import { constants } from 'node:fs'
import { chmod, lstat, mkdir, mkdtemp, open, readFile, realpath, rename, rm, stat, writeFile } from 'node:fs/promises'
import { join, sep } from 'node:path'
import { z } from 'zod'
import type { AnalyzerStatus, ToolkitEntry } from '../../shared/contracts.ts'
import type { ToolHandle } from './external/common.ts'
import { findExecutable, probeVersion } from './external/locate.ts'
import { runTool } from './external/process.ts'

export type ToolId = ToolkitEntry['id']
export type ManagedToolId = Exclude<ToolId, 'semgrep'>

export type ToolkitErrorCode =
  | 'toolkit-disabled'
  | 'toolkit-unavailable'
  | 'toolkit-unpinned'
  | 'toolkit-download-failed'
  | 'toolkit-checksum-mismatch'
  | 'toolkit-extract-failed'

/** Installation refusal or failure; branch on `code`, not the message. */
export class ToolkitError extends Error {
  readonly code: ToolkitErrorCode

  constructor(code: ToolkitErrorCode, message: string, options?: ErrorOptions) {
    super(message, options)
    this.name = 'ToolkitError'
    this.code = code
  }
}

// ---------------------------------------------------------------------------
// Lock file
// ---------------------------------------------------------------------------

const PLATFORM_KEY_RE = /^(?:linux|darwin|win32)-(?:x64|arm64)$/
const BINARY_NAME_RE = /^(?!\.{1,2}$)[A-Za-z0-9._-]{1,64}$/

const assetSchema = z.object({
  url: z.url({ protocol: /^https$/ }),
  sha256: z
    .string()
    .regex(/^[0-9a-f]{64}$/i)
    .transform(value => value.toLowerCase())
    .nullable(),
  size: z.number().int().positive().nullish(),
  archive: z.enum(['tar.gz', 'zip', 'none']),
  binary: z.string().regex(BINARY_NAME_RE, 'binary must be a plain file name'),
})

const toolSchema = z.object({
  name: z.string().min(1),
  version: z.string().regex(/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/),
  license: z.string().min(1),
  homepage: z.url({ protocol: /^https$/ }),
  checksumsUrl: z.url({ protocol: /^https$/ }).optional(),
  assets: z.record(z.string().regex(PLATFORM_KEY_RE), assetSchema),
})

const lockSchema = z.object({
  schemaVersion: z.literal(1),
  tools: z.object({
    gitleaks: toolSchema.optional(),
    'osv-scanner': toolSchema.optional(),
  }),
})

export type ToolkitLock = z.infer<typeof lockSchema>
export type ToolkitLockTool = z.infer<typeof toolSchema>
export type ToolkitAsset = z.infer<typeof assetSchema>

/** Validate parsed `toolkit.lock.json` content; throws on any schema violation. */
export function loadToolkitLock(json: unknown): ToolkitLock {
  const parsed = lockSchema.safeParse(json)
  if (!parsed.success) throw new Error(`Invalid toolkit.lock.json: ${z.prettifyError(parsed.error)}`)
  return parsed.data
}

/** Lock-file platform key for this machine, e.g. `linux-x64`, `darwin-arm64`, `win32-x64`. */
export function platformKey(platform: string = process.platform, arch: string = process.arch): string {
  return `${platform}-${arch}`
}

// ---------------------------------------------------------------------------
// Toolkit
// ---------------------------------------------------------------------------

export interface ToolkitOptions {
  /** Managed install directory (one `<id>/<version>/` subdirectory per tool). */
  readonly dir: string
  readonly lock: ToolkitLock
  readonly allowManagedInstall: boolean
  readonly fetch: typeof fetch
  /** Platform key override (tests). */
  readonly platform?: string
  /** Download timeout; default 10 minutes. */
  readonly downloadTimeoutMs?: number
}

interface ToolInfo {
  readonly name: string
  readonly license: string
  readonly homepage: string
  readonly executable: string
  readonly versionArgs: readonly string[]
  readonly installHint: string
}

const TOOLS: Readonly<Record<ToolId, ToolInfo>> = {
  gitleaks: {
    name: 'Gitleaks',
    license: 'MIT',
    homepage: 'https://github.com/gitleaks/gitleaks',
    executable: 'gitleaks',
    versionArgs: ['version'],
    installHint:
      'Install Gitleaks 8.19 or later: `brew install gitleaks` (macOS/Linux), or download a release from ' +
      'https://github.com/gitleaks/gitleaks/releases and put the binary on PATH.',
  },
  'osv-scanner': {
    name: 'OSV-Scanner',
    license: 'Apache-2.0',
    homepage: 'https://github.com/google/osv-scanner',
    executable: 'osv-scanner',
    versionArgs: ['--version'],
    installHint:
      'Install OSV-Scanner v2: `brew install osv-scanner`, ' +
      '`go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest`, or download a release from ' +
      'https://github.com/google/osv-scanner/releases and put the binary on PATH.',
  },
  semgrep: {
    name: 'Semgrep',
    license: 'LGPL-2.1',
    homepage: 'https://github.com/semgrep/semgrep',
    executable: 'semgrep',
    versionArgs: ['--version'],
    installHint:
      'Semgrep is not downloaded by this plugin. Install it with `pipx install semgrep` or `brew install semgrep` ' +
      'and configure a local rules path; registry rules are never fetched.',
  },
}

const TOOL_IDS: readonly ToolId[] = ['gitleaks', 'osv-scanner', 'semgrep']
const MAX_DOWNLOAD_BYTES = 200 * 1024 * 1024
const DEFAULT_DOWNLOAD_TIMEOUT_MS = 10 * 60_000
const TAR_TIMEOUT_MS = 2 * 60_000
const INSTALLED_FILE = 'installed.json'

const installedSchema = z.object({
  id: z.string(),
  version: z.string(),
  binary: z.string().regex(BINARY_NAME_RE),
  assetSha256: z.string(),
  binarySha256: z.string().regex(/^[0-9a-f]{64}$/),
  installedAt: z.string(),
})

/** Status, discovery, and verified installation of the external analyzers. */
export class Toolkit {
  readonly #opts: ToolkitOptions
  readonly #platform: string
  readonly #installs = new Map<ToolId, Promise<ToolkitEntry>>()
  /** Verified managed binaries: path → `size:mtime` at verification time. */
  readonly #verified = new Map<string, string>()
  /** PATH version probes: path → `size:mtime` and the parsed version. */
  readonly #probed = new Map<string, { key: string; version: string | undefined }>()

  constructor(opts: ToolkitOptions) {
    this.#opts = opts
    this.#platform = opts.platform ?? platformKey()
  }

  /** Status and install guidance for every supported tool. */
  async status(): Promise<ToolkitEntry[]> {
    return await Promise.all(TOOL_IDS.map(id => this.#entry(id)))
  }

  /** Absolute path of a usable executable: the managed install first, then PATH. */
  async resolve(id: ToolId): Promise<string | undefined> {
    return (await this.resolveHandle(id))?.path
  }

  /** Like `resolve`, with the source and (best-effort) version for the runners. */
  async resolveHandle(id: ToolId): Promise<ToolHandle | undefined> {
    const managed = await this.#managedBinary(id)
    if (managed) return { path: managed.path, source: 'managed', version: managed.version }
    const onPath = await findExecutable(TOOLS[id].executable, [])
    if (!onPath) return undefined
    const version = await this.#probe(onPath, TOOLS[id].versionArgs)
    return { path: onPath, source: 'path', ...(version ? { version } : {}) }
  }

  /**
   * Download, verify, and install the pinned build of `id` for this platform.
   * Throws `ToolkitError` with `toolkit-disabled`, `toolkit-unavailable`,
   * `toolkit-unpinned`, `toolkit-download-failed`, `toolkit-checksum-mismatch`,
   * or `toolkit-extract-failed`.
   */
  install(id: ToolId, options: { readonly signal?: AbortSignal } = {}): Promise<ToolkitEntry> {
    const running = this.#installs.get(id)
    if (running) return running
    const promise = this.#install(id, options.signal).finally(() => this.#installs.delete(id))
    this.#installs.set(id, promise)
    return promise
  }

  /** Settles once every install in progress has finished or failed (for unload). */
  async settled(): Promise<void> {
    await Promise.allSettled([...this.#installs.values()])
  }

  // -------------------------------------------------------------------------

  async #install(id: ToolId, signal: AbortSignal | undefined): Promise<ToolkitEntry> {
    if (!this.#opts.allowManagedInstall) {
      throw new ToolkitError('toolkit-disabled', 'Managed tool installation is disabled by the operator.')
    }
    const tool = id === 'semgrep' ? undefined : this.#opts.lock.tools[id]
    if (!tool) throw new ToolkitError('toolkit-unavailable', `${TOOLS[id].name} has no managed download.`)
    const asset = tool.assets[this.#platform]
    if (!asset) {
      throw new ToolkitError('toolkit-unavailable', `${tool.name} has no managed download for ${this.#platform}.`)
    }
    if (!asset.sha256) {
      throw new ToolkitError(
        'toolkit-unpinned',
        `${tool.name} ${tool.version} for ${this.#platform} has no pinned SHA-256; refusing to install.`,
      )
    }
    signal?.throwIfAborted()

    await mkdir(this.#opts.dir, { recursive: true, mode: 0o700 })
    const toolDir = join(this.#opts.dir, id)
    await mkdir(toolDir, { recursive: true, mode: 0o700 })
    // Staging lives next to the destination so the final rename is atomic.
    const staging = await mkdtemp(join(toolDir, '.staging-'))
    try {
      const download = join(staging, 'download')
      const outDir = join(staging, 'out')
      await mkdir(outDir, { mode: 0o700 })

      const assetSha256 = await this.#download(asset, download, signal)
      if (assetSha256 !== asset.sha256) {
        throw new ToolkitError(
          'toolkit-checksum-mismatch',
          `${tool.name} download does not match the pinned SHA-256 (expected ${asset.sha256}, got ${assetSha256}).`,
        )
      }
      signal?.throwIfAborted()

      const binaryPath = join(outDir, asset.binary)
      if (asset.archive === 'none') {
        await rename(download, binaryPath)
      } else {
        await extractMember(download, outDir, asset.binary, asset.archive, signal)
      }
      await assertRegularFileInside(binaryPath, outDir)
      if (process.platform !== 'win32') await chmod(binaryPath, 0o755)
      const binarySha256 = await hashFile(binaryPath)
      await writeFile(
        join(outDir, INSTALLED_FILE),
        `${JSON.stringify(
          {
            id,
            version: tool.version,
            binary: asset.binary,
            assetSha256,
            binarySha256,
            installedAt: new Date().toISOString(),
          },
          null,
          2,
        )}\n`,
        { mode: 0o644 },
      )

      const dest = join(toolDir, tool.version)
      const previous = join(staging, 'previous')
      try {
        await rename(dest, previous)
      } catch (error) {
        if (errorCode(error) !== 'ENOENT') throw error
      }
      await rename(outDir, dest)
      this.#verified.delete(join(dest, asset.binary))
    } finally {
      await rm(staging, { recursive: true, force: true }).catch(() => undefined)
    }
    return await this.#entry(id)
  }

  async #download(asset: ToolkitAsset, target: string, signal: AbortSignal | undefined): Promise<string> {
    const timeout = AbortSignal.timeout(this.#opts.downloadTimeoutMs ?? DEFAULT_DOWNLOAD_TIMEOUT_MS)
    const combined = signal ? AbortSignal.any([signal, timeout]) : timeout
    const limit = Math.min(MAX_DOWNLOAD_BYTES, asset.size ?? MAX_DOWNLOAD_BYTES)
    const hash = createHash('sha256')
    const fh = await open(target, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL, 0o600)
    try {
      let response: Response
      try {
        // GitHub release URLs redirect to a CDN; integrity comes from the pinned hash, not the host.
        response = await this.#opts.fetch(asset.url, { redirect: 'follow', signal: combined })
      } catch (error) {
        signal?.throwIfAborted()
        throw new ToolkitError('toolkit-download-failed', `Download failed: ${describe(error, timeout)}`, {
          cause: error,
        })
      }
      if (!response.ok || !response.body) {
        await response.body?.cancel().catch(() => undefined)
        throw new ToolkitError('toolkit-download-failed', `Download failed with HTTP ${response.status}.`)
      }
      const declared = Number(response.headers.get('content-length'))
      if (Number.isFinite(declared) && declared > limit) {
        await response.body.cancel().catch(() => undefined)
        throw new ToolkitError('toolkit-download-failed', `Download is larger than the allowed ${limit} bytes.`)
      }
      const reader = response.body.getReader()
      let total = 0
      try {
        for (;;) {
          const { done, value } = await reader.read()
          if (done) break
          total += value.byteLength
          if (total > limit) {
            await reader.cancel().catch(() => undefined)
            throw new ToolkitError('toolkit-download-failed', `Download is larger than the allowed ${limit} bytes.`)
          }
          hash.update(value)
          await fh.write(value)
        }
      } catch (error) {
        if (error instanceof ToolkitError) throw error
        signal?.throwIfAborted()
        throw new ToolkitError('toolkit-download-failed', `Download failed: ${describe(error, timeout)}`, {
          cause: error,
        })
      }
      return hash.digest('hex')
    } finally {
      await fh.close()
    }
  }

  async #entry(id: ToolId): Promise<ToolkitEntry> {
    const info = TOOLS[id]
    const lockTool = id === 'semgrep' ? undefined : this.#opts.lock.tools[id]
    const asset = lockTool?.assets[this.#platform]
    const managedOffer =
      lockTool && asset?.sha256
        ? {
            version: lockTool.version,
            url: asset.url,
            sha256: asset.sha256,
            ...(asset.size ? { sizeBytes: asset.size } : {}),
          }
        : undefined
    const handle = await this.resolveHandle(id)
    let status: AnalyzerStatus
    if (handle) {
      status = {
        id,
        available: true,
        source: handle.source,
        ...(handle.version ? { version: handle.version } : {}),
      }
    } else {
      let reason = `${info.name} was not found on PATH.`
      if (managedOffer && this.#opts.allowManagedInstall) reason += ' A verified download is available.'
      else if (lockTool && asset && !asset.sha256) reason += ' The managed download is not pinned yet.'
      status = { id, available: false, source: 'disabled', reason }
    }
    return {
      id,
      name: lockTool?.name ?? info.name,
      license: lockTool?.license ?? info.license,
      homepage: lockTool?.homepage ?? info.homepage,
      status,
      ...(managedOffer ? { managed: managedOffer } : {}),
      installHint: info.installHint,
    }
  }

  /** The installed managed binary for the locked version, after integrity checks. */
  async #managedBinary(id: ToolId): Promise<{ path: string; version: string } | undefined> {
    if (id === 'semgrep') return undefined
    const tool = this.#opts.lock.tools[id]
    if (!tool) return undefined
    const dir = join(this.#opts.dir, id, tool.version)
    try {
      const meta = installedSchema.parse(JSON.parse(await readFile(join(dir, INSTALLED_FILE), 'utf8')))
      if (meta.id !== id || meta.version !== tool.version) return undefined
      const path = join(dir, meta.binary)
      const st = await lstat(path)
      if (!st.isFile()) return undefined
      const key = `${st.size}:${st.mtimeMs}`
      if (this.#verified.get(path) !== key) {
        if ((await hashFile(path)) !== meta.binarySha256) return undefined
        this.#verified.set(path, key)
      }
      return { path, version: tool.version }
    } catch {
      return undefined
    }
  }

  async #probe(path: string, args: readonly string[]): Promise<string | undefined> {
    let key = ''
    try {
      const st = await stat(path)
      key = `${st.size}:${st.mtimeMs}`
    } catch {
      return undefined
    }
    const cached = this.#probed.get(path)
    if (cached?.key === key) return cached.version
    const version = await probeVersion(path, args)
    this.#probed.set(path, { key, version })
    return version
  }
}

// ---------------------------------------------------------------------------
// Extraction
// ---------------------------------------------------------------------------

/** Extract exactly one member with the system `tar` (bsdtar on macOS/Windows also reads zip). */
async function extractMember(
  archive: string,
  outDir: string,
  member: string,
  kind: 'tar.gz' | 'zip',
  signal: AbortSignal | undefined,
): Promise<void> {
  const tar = await systemTar()
  if (!tar) throw new ToolkitError('toolkit-extract-failed', 'No system `tar` was found to extract the download.')
  // Ownership from the archive is never applied, even when the Host runs as root.
  const args = [kind === 'tar.gz' ? '-xzf' : '-xf', archive, '--no-same-owner', '-C', outDir, member]
  let result: Awaited<ReturnType<typeof runTool>>
  try {
    result = await runTool(tar, args, {
      cwd: outDir,
      timeoutMs: TAR_TIMEOUT_MS,
      maxOutputBytes: 64 * 1024,
      ...(signal ? { signal } : {}),
    })
  } catch (error) {
    signal?.throwIfAborted()
    throw new ToolkitError('toolkit-extract-failed', `Could not run tar: ${describe(error)}`, { cause: error })
  }
  if (result.timedOut || result.code !== 0) {
    const detail = result.timedOut ? 'timed out' : result.stderr.trim().split('\n')[0] || `exit code ${result.code}`
    throw new ToolkitError('toolkit-extract-failed', `Extracting ${member} failed: ${detail}`)
  }
}

async function systemTar(): Promise<string | undefined> {
  if (process.platform === 'win32') {
    const systemRoot = process.env.SystemRoot ?? process.env.SYSTEMROOT ?? 'C:\\Windows'
    const builtin = join(systemRoot, 'System32', 'tar.exe')
    if (await isFile(builtin)) return builtin
  } else {
    for (const candidate of ['/usr/bin/tar', '/bin/tar']) if (await isFile(candidate)) return candidate
  }
  return await findExecutable('tar', [])
}

/** The extracted binary must be a regular, singly-linked file that really lives inside `dir`. */
async function assertRegularFileInside(path: string, dir: string): Promise<void> {
  let st: Awaited<ReturnType<typeof lstat>>
  try {
    st = await lstat(path)
  } catch {
    throw new ToolkitError('toolkit-extract-failed', 'The archive did not contain the expected binary.')
  }
  if (!st.isFile() || st.nlink > 1) {
    throw new ToolkitError('toolkit-extract-failed', 'The extracted binary is not a regular file.')
  }
  const [realDir, realPath] = await Promise.all([realpath(dir), realpath(path)])
  if (!realPath.startsWith(realDir.endsWith(sep) ? realDir : realDir + sep)) {
    throw new ToolkitError('toolkit-extract-failed', 'The extracted binary resolved outside the staging directory.')
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async function hashFile(path: string): Promise<string> {
  const hash = createHash('sha256')
  const fh = await open(path, 'r')
  try {
    const buffer = Buffer.allocUnsafe(1 << 20)
    for (;;) {
      const { bytesRead } = await fh.read(buffer, 0, buffer.length, null)
      if (bytesRead === 0) break
      hash.update(buffer.subarray(0, bytesRead))
    }
  } finally {
    await fh.close()
  }
  return hash.digest('hex')
}

async function isFile(path: string): Promise<boolean> {
  try {
    return (await stat(path)).isFile()
  } catch {
    return false
  }
}

function describe(error: unknown, timeout?: AbortSignal): string {
  if (timeout?.aborted) return 'timed out'
  return error instanceof Error ? error.message : String(error)
}

function errorCode(error: unknown): string | undefined {
  return typeof error === 'object' && error !== null && 'code' in error && typeof error.code === 'string'
    ? error.code
    : undefined
}
