/**
 * Executable discovery. Only absolute directories are searched, so a PATH
 * entry like `.` can never resolve a binary planted in the scanned repository.
 */

import { constants } from 'node:fs'
import { access, stat } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { delimiter, isAbsolute, join } from 'node:path'
import { runTool } from './process.ts'

const PROBE_TIMEOUT_MS = 15_000
const PROBE_OUTPUT_BYTES = 64 * 1024

/**
 * Find `name` in `extraDirs` (searched first, e.g. the managed toolkit dir)
 * then in `PATH`. On Windows only `.exe` files are considered: `.cmd`/`.bat`
 * would need a shell, which this plugin never uses.
 */
export async function findExecutable(name: string, extraDirs: readonly string[]): Promise<string | undefined> {
  if (name === '' || /[\\/]/.test(name)) return undefined
  const isWindows = process.platform === 'win32'
  const fileName = isWindows && !name.toLowerCase().endsWith('.exe') ? `${name}.exe` : name
  const pathValue = process.env.PATH ?? process.env.Path ?? ''
  const dirs = [...extraDirs, ...pathValue.split(delimiter)]
  const seen = new Set<string>()
  for (const raw of dirs) {
    const dir = raw.trim().replace(/^"(.*)"$/, '$1')
    if (dir === '' || !isAbsolute(dir) || seen.has(dir)) continue
    seen.add(dir)
    const candidate = join(dir, fileName)
    if (await isExecutableFile(candidate)) return candidate
  }
  return undefined
}

/**
 * Run `path args…` and return the first version-looking token from its
 * output (e.g. `8.28.0`), or `undefined` if the probe fails.
 */
export async function probeVersion(path: string, args: readonly string[]): Promise<string | undefined> {
  try {
    const result = await runTool(path, args, {
      cwd: tmpdir(),
      timeoutMs: PROBE_TIMEOUT_MS,
      maxOutputBytes: PROBE_OUTPUT_BYTES,
    })
    if (result.timedOut) return undefined
    return parseVersion(`${result.stdout}\n${result.stderr}`)
  } catch {
    return undefined
  }
}

/** Extract a dotted version number (`v1.2.3` → `1.2.3`) from free text. */
export function parseVersion(text: string): string | undefined {
  return /\bv?(\d+\.\d+(?:\.\d+)?(?:-[0-9A-Za-z.]+)?)\b/.exec(text)?.[1]
}

async function isExecutableFile(path: string): Promise<boolean> {
  try {
    if (!(await stat(path)).isFile()) return false
    if (process.platform !== 'win32') await access(path, constants.X_OK)
    return true
  } catch {
    return false
  }
}
