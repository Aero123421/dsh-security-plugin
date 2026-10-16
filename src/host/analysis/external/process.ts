/**
 * Child-process runner for external analyzers. No shell is ever involved,
 * the environment is reduced to a small allowlist, output is capped, and the
 * whole process tree is killed on timeout or abort.
 */

import { spawn } from 'node:child_process'
import { stat } from 'node:fs/promises'
import { join } from 'node:path'

export interface RunToolOptions {
  /** Working directory. Prefer a neutral temp dir over the scanned repository. */
  readonly cwd: string
  readonly timeoutMs: number
  readonly signal?: AbortSignal
  /** Cap per stream (stdout and stderr each); excess output is discarded. */
  readonly maxOutputBytes: number
  /** Variables added to the scrubbed environment. */
  readonly env?: Readonly<Record<string, string>>
  /** Poll a private report while running; kill immediately when it grows past the cap. */
  readonly report?: { readonly path: string; readonly maxBytes: number }
}

export interface RunToolResult {
  /** Exit code, or `null` when the process was killed by a signal. */
  readonly code: number | null
  readonly signal: NodeJS.Signals | null
  readonly stdout: string
  readonly stderr: string
  readonly timedOut: boolean
  /** Some stdout or stderr was discarded because of `maxOutputBytes`. */
  readonly truncated: boolean
  readonly reportLimitExceeded: boolean
}

/** Variables inherited from the Host; everything else (tokens, proxies, NODE_OPTIONS, …) is dropped. */
const INHERITED_ENV = ['PATH', 'HOME', 'USERPROFILE', 'SystemRoot', 'SYSTEMROOT', 'TEMP', 'TMP', 'TMPDIR', 'LANG']

const KILL_GRACE_MS = 2_000
/** After SIGKILL, give up waiting for stdio to close (a re-parented grandchild may hold it). */
const CLOSE_FALLBACK_MS = 5_000

/** Build the minimal environment a tool runs with. */
export function scrubbedEnv(extra: Readonly<Record<string, string>> = {}): Record<string, string> {
  const env: Record<string, string> = {}
  for (const key of INHERITED_ENV) {
    const value = process.env[key]
    if (value !== undefined) env[key] = value
  }
  // Windows env names are case-insensitive; `Path` is the usual spelling there.
  if (env.PATH === undefined && process.env.Path !== undefined) env.PATH = process.env.Path
  return { ...env, ...extra }
}

/**
 * Run `cmd` with `args` (no shell) and capture its output. Resolves when the
 * process exits, including after a timeout kill (`timedOut: true`). Rejects
 * with the spawn error (e.g. `ENOENT`), or with `signal.reason` after killing
 * the process tree when `signal` aborts.
 */
export function runTool(cmd: string, args: readonly string[], options: RunToolOptions): Promise<RunToolResult> {
  const { signal } = options
  if (signal?.aborted) return Promise.reject(signal.reason)
  return new Promise<RunToolResult>((resolve, reject) => {
    const isWindows = process.platform === 'win32'
    const child = spawn(cmd, [...args], {
      cwd: options.cwd,
      env: scrubbedEnv(options.env),
      stdio: ['ignore', 'pipe', 'pipe'],
      shell: false,
      windowsHide: true,
      // A new process group on POSIX lets us kill grandchildren too.
      detached: !isWindows,
    })

    const stdout = new CappedBuffer(options.maxOutputBytes)
    const stderr = new CappedBuffer(options.maxOutputBytes)
    child.stdout?.on('data', (chunk: Buffer) => stdout.push(chunk))
    child.stderr?.on('data', (chunk: Buffer) => stderr.push(chunk))

    let settled = false
    let timedOut = false
    let aborted = false
    let reportLimitExceeded = false
    let checkingReport = false
    let reportTimer: NodeJS.Timeout | undefined
    let killTimer: NodeJS.Timeout | undefined
    let fallbackTimer: NodeJS.Timeout | undefined

    const cleanup = (): void => {
      clearTimeout(timeoutTimer)
      clearTimeout(killTimer)
      clearTimeout(fallbackTimer)
      clearInterval(reportTimer)
      signal?.removeEventListener('abort', onAbort)
    }
    const finish = (code: number | null, exitSignal: NodeJS.Signals | null): void => {
      if (settled) return
      settled = true
      cleanup()
      if (aborted) {
        reject(signal?.reason)
        return
      }
      resolve({
        code,
        signal: exitSignal,
        stdout: stdout.toString(),
        stderr: stderr.toString(),
        timedOut,
        truncated: stdout.truncated || stderr.truncated,
        reportLimitExceeded,
      })
    }
    const terminate = (): void => {
      if (child.pid === undefined) return
      killTree(child.pid, 'SIGTERM')
      killTimer = setTimeout(() => {
        if (child.pid !== undefined) killTree(child.pid, 'SIGKILL')
        fallbackTimer = setTimeout(() => {
          child.stdout?.destroy()
          child.stderr?.destroy()
          finish(child.exitCode, child.signalCode)
        }, CLOSE_FALLBACK_MS)
        fallbackTimer.unref()
      }, KILL_GRACE_MS)
      killTimer.unref()
    }
    const onAbort = (): void => {
      aborted = true
      terminate()
    }

    const timeoutTimer = setTimeout(() => {
      timedOut = true
      terminate()
    }, options.timeoutMs)
    timeoutTimer.unref()
    signal?.addEventListener('abort', onAbort, { once: true })
    const report = options.report
    if (report) {
      reportTimer = setInterval(async () => {
        if (settled || checkingReport || reportLimitExceeded) return
        checkingReport = true
        try {
          const info = await stat(report.path)
          if (!settled && info.size > report.maxBytes) {
            reportLimitExceeded = true
            clearInterval(reportTimer)
            // Do not give an over-limit writer a grace period to fill the disk.
            terminate()
            if (child.pid !== undefined) killTree(child.pid, 'SIGKILL')
          }
        } catch {
          // Not created yet; final readReport still validates size/readability.
        } finally {
          checkingReport = false
        }
      }, 25)
      reportTimer.unref()
    }

    child.once('error', error => {
      if (settled) return
      settled = true
      cleanup()
      reject(aborted ? signal?.reason : error)
    })
    child.once('close', (code, exitSignal) => finish(code, exitSignal))
  })
}

/** Kill a process and its descendants. Errors (already exited) are ignored. */
function killTree(pid: number, sig: NodeJS.Signals): void {
  if (process.platform === 'win32') {
    const systemRoot = process.env.SystemRoot ?? process.env.SYSTEMROOT ?? 'C:\\Windows'
    try {
      const killer = spawn(join(systemRoot, 'System32', 'taskkill.exe'), ['/PID', String(pid), '/T', '/F'], {
        stdio: 'ignore',
        windowsHide: true,
        shell: false,
      })
      killer.on('error', () => undefined)
    } catch {
      // Fall through to the direct kill below.
    }
    try {
      process.kill(pid, sig)
    } catch {
      // Already gone.
    }
    return
  }
  try {
    process.kill(-pid, sig)
  } catch {
    try {
      process.kill(pid, sig)
    } catch {
      // Already gone.
    }
  }
}

/** Accumulates at most `limit` bytes. */
class CappedBuffer {
  readonly #limit: number
  readonly #chunks: Buffer[] = []
  #size = 0
  truncated = false

  constructor(limit: number) {
    this.#limit = Math.max(0, limit)
  }

  push(chunk: Buffer): void {
    const room = this.#limit - this.#size
    if (room <= 0) {
      this.truncated = true
      return
    }
    const part = chunk.length > room ? chunk.subarray(0, room) : chunk
    if (part.length < chunk.length) this.truncated = true
    this.#chunks.push(part)
    this.#size += part.length
  }

  toString(): string {
    return Buffer.concat(this.#chunks, this.#size).toString('utf8')
  }
}
