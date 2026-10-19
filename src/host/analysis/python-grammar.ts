/**
 * tree-sitter-python prebuilds shipped in `vendor/tree-sitter-python`.
 *
 * `@ast-grep/lang-python` is not a dependency: its postinstall makes pnpm 11
 * and 12 reject the whole plugin install (`ERR_PNPM_IGNORED_BUILDS`). The
 * prebuild is a normal native library. `@ast-grep/napi` loads it by path when
 * one exists for this OS and CPU. Callers treat `undefined` as "use the
 * built-in Python parser".
 *
 * The Linux files are glibc binaries (`NEEDED` `libc.so.6`). Loading one on
 * musl, or on a glibc older than the file's versioned symbols, makes the
 * native registrar abort the process. Linux without
 * `process.report` `header.glibcVersionRuntime`, and Linux whose reported
 * glibc is older than {@link PYTHON_LINUX_GLIBC_MIN}, does not get a path.
 */

import { existsSync, readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const PLATFORM: Readonly<Record<string, string>> = {
  darwin: 'macOS',
  linux: 'Linux',
  win32: 'Windows',
}

const ARCH: Readonly<Record<string, string>> = {
  x64: 'X64',
  arm64: 'ARM64',
}

/** Directory names under `prebuilds/`, without the `prebuild-` prefix. */
export const PYTHON_GRAMMAR_TARGETS = ['Linux-X64', 'Linux-ARM64', 'macOS-X64', 'macOS-ARM64', 'Windows-X64'] as const

/** glibc Linux can load the shipped Linux parser when it is new enough. musl must not. */
export type LibcFamily = 'glibc' | 'musl' | 'other'

/**
 * Highest `GLIBC_` symbol version in each shipped Linux `parser.so`
 * (`objdump -T` and `readelf -V` on `@ast-grep/lang-python` 0.0.6).
 * Linux x64 needs 2.2.5. Linux arm64 needs 2.17. A runtime older than
 * that must not load the file.
 */
export const PYTHON_LINUX_GLIBC_MIN = {
  'Linux-X64': [2, 2, 5],
  'Linux-ARM64': [2, 17],
} as const

export type PythonLinuxTarget = keyof typeof PYTHON_LINUX_GLIBC_MIN

/**
 * `glibc` only when the Node diagnostic report names a glibc runtime.
 * An absent or empty `glibcVersionRuntime` is musl (Alpine) or another
 * non-glibc libc. A report that cannot be read is musl, so the glibc
 * parser is not registered.
 */
export function libcFamilyFromReport(report: unknown): Exclude<LibcFamily, 'other'> {
  if (!isRecord(report) || !isRecord(report.header)) return 'musl'
  const version = report.header.glibcVersionRuntime
  return typeof version === 'string' && version.length > 0 ? 'glibc' : 'musl'
}

/** The report's `glibcVersionRuntime` when it is a non-empty string. */
export function glibcVersionFromReport(report: unknown): string | undefined {
  if (!isRecord(report) || !isRecord(report.header)) return undefined
  const version = report.header.glibcVersionRuntime
  return typeof version === 'string' && version.length > 0 ? version : undefined
}

/**
 * Numeric glibc components, or `undefined` when `value` is not a dotted
 * list of integers. `2.17` is `[2, 17]`, which compares greater than `2.9`.
 */
export function parseGlibcVersion(value: string): number[] | undefined {
  if (!/^\d+(?:\.\d+)*$/.test(value)) return undefined
  const parts = value.split('.').map(part => Number(part))
  if (parts.some(part => !Number.isSafeInteger(part))) return undefined
  return parts
}

/** Negative when `left` is older. Missing components compare as 0, so `2.17` equals `2.17.0`. */
export function compareGlibcVersion(left: readonly number[], right: readonly number[]): number {
  const length = Math.max(left.length, right.length)
  for (let i = 0; i < length; i++) {
    const a = left[i] ?? 0
    const b = right[i] ?? 0
    if (a !== b) return a < b ? -1 : 1
  }
  return 0
}

/** True when `runtime` is at least the shipped file's GLIBC symbol version. */
export function glibcSatisfiesPython(target: PythonLinuxTarget, runtime: string | undefined): boolean {
  if (runtime === undefined) return false
  const parsed = parseGlibcVersion(runtime)
  if (!parsed) return false
  return compareGlibcVersion(parsed, PYTHON_LINUX_GLIBC_MIN[target]) >= 0
}

let hostLibc: LibcFamily | undefined
let hostGlibcVersion: string | undefined

function readHostLibc(): void {
  if (hostLibc) return
  if (process.platform !== 'linux') {
    hostLibc = 'other'
    return
  }
  try {
    const report = process.report.getReport()
    hostLibc = libcFamilyFromReport(report)
    hostGlibcVersion = glibcVersionFromReport(report)
  } catch {
    hostLibc = 'musl'
  }
}

/** This process's libc. Non-Linux is `other`. The result is cached. */
export function detectHostLibc(): LibcFamily {
  readHostLibc()
  return hostLibc ?? 'musl'
}

/** This process's `glibcVersionRuntime`, when Linux reported one. Cached with {@link detectHostLibc}. */
export function detectHostGlibcVersion(): string | undefined {
  readHostLibc()
  return hostGlibcVersion
}

/** Registration fields copied from `@ast-grep/lang-python` 0.0.6. `expandoChar` is U+00B5. */
export const PYTHON_DYNAMIC_LANGUAGE = {
  extensions: ['py'],
  languageSymbol: 'tree_sitter_python',
  expandoChar: '\u00b5',
} as const

/**
 * `Linux-X64` and the like, or `undefined` when this plugin ships no grammar
 * for the pair. On Linux, `libc` and `glibcVersion` default to this process.
 * Anything other than glibc, and a glibc older than {@link PYTHON_LINUX_GLIBC_MIN},
 * returns `undefined` even though a Linux file is in the package.
 * `glibcVersion` is compared only for Linux. An omitted version uses this
 * process's report, which is absent off Linux, so the Linux file is not selected.
 */
export function pythonPrebuildName(
  platform: string,
  arch: string,
  libc?: LibcFamily,
  glibcVersion?: string,
): string | undefined {
  const family = libc ?? (platform === 'linux' ? detectHostLibc() : 'other')
  if (platform === 'linux' && family !== 'glibc') return undefined
  const os = PLATFORM[platform]
  const cpu = ARCH[arch]
  if (!os || !cpu) return undefined
  const name = `${os}-${cpu}`
  if (!(PYTHON_GRAMMAR_TARGETS as readonly string[]).includes(name)) return undefined
  if (platform === 'linux') {
    const target = linuxTarget(name)
    if (!target || !glibcSatisfiesPython(target, glibcVersion ?? detectHostGlibcVersion())) return undefined
  }
  return name
}

function linuxTarget(name: string): PythonLinuxTarget | undefined {
  return name === 'Linux-X64' || name === 'Linux-ARM64' ? name : undefined
}

/**
 * Directory that contains this plugin's `package.json`. Walks up from the
 * bundled `lib/index.js` and from the TypeScript source used by tests.
 */
export function pluginPackageRoot(from = fileURLToPath(import.meta.url)): string | undefined {
  let dir = dirname(from)
  for (let i = 0; i < 8; i++) {
    const manifest = join(dir, 'package.json')
    if (existsSync(manifest)) {
      try {
        const parsed: unknown = JSON.parse(readFileSync(manifest, 'utf8'))
        if (isRecord(parsed) && parsed.name === 'dsh-security-plugin') return dir
      } catch {
        // Unreadable, or a package.json that is not this plugin. Keep walking.
      }
    }
    const parent = dirname(dir)
    if (parent === dir) return undefined
    dir = parent
  }
  return undefined
}

/**
 * Absolute path of the prebuild for `platform`/`arch`, when that file is in
 * the package and this libc can load it. `libc` defaults the same way as
 * {@link pythonPrebuildName}.
 */
export function vendoredPythonLibrary(
  platform = process.platform,
  arch = process.arch,
  libc?: LibcFamily,
  glibcVersion?: string,
): string | undefined {
  const target = pythonPrebuildName(platform, arch, libc, glibcVersion)
  const root = pluginPackageRoot()
  if (!target || !root) return undefined
  const path = join(root, 'vendor', 'tree-sitter-python', 'prebuilds', `prebuild-${target}`, 'parser.so')
  return existsSync(path) ? path : undefined
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null
}
