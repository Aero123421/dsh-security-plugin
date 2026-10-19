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
 * musl makes the native registrar abort the process, so Linux without
 * `process.report` `header.glibcVersionRuntime` does not get a path.
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

/** glibc Linux can load the shipped Linux parser. musl must not. */
export type LibcFamily = 'glibc' | 'musl' | 'other'

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

let hostLibc: LibcFamily | undefined

/** This process's libc. Non-Linux is `other`. The result is cached. */
export function detectHostLibc(): LibcFamily {
  if (hostLibc) return hostLibc
  if (process.platform !== 'linux') {
    hostLibc = 'other'
    return hostLibc
  }
  try {
    hostLibc = libcFamilyFromReport(process.report.getReport())
  } catch {
    hostLibc = 'musl'
  }
  return hostLibc
}

/** Registration fields copied from `@ast-grep/lang-python` 0.0.6. `expandoChar` is U+00B5. */
export const PYTHON_DYNAMIC_LANGUAGE = {
  extensions: ['py'],
  languageSymbol: 'tree_sitter_python',
  expandoChar: '\u00b5',
} as const

/**
 * `Linux-X64` and the like, or `undefined` when this plugin ships no grammar
 * for the pair. On Linux, `libc` defaults to this process. Anything other
 * than glibc returns `undefined` even though a Linux file is in the package.
 */
export function pythonPrebuildName(platform: string, arch: string, libc?: LibcFamily): string | undefined {
  const family = libc ?? (platform === 'linux' ? detectHostLibc() : 'other')
  if (platform === 'linux' && family !== 'glibc') return undefined
  const os = PLATFORM[platform]
  const cpu = ARCH[arch]
  if (!os || !cpu) return undefined
  const name = `${os}-${cpu}`
  return (PYTHON_GRAMMAR_TARGETS as readonly string[]).includes(name) ? name : undefined
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
): string | undefined {
  const target = pythonPrebuildName(platform, arch, libc)
  const root = pluginPackageRoot()
  if (!target || !root) return undefined
  const path = join(root, 'vendor', 'tree-sitter-python', 'prebuilds', `prebuild-${target}`, 'parser.so')
  return existsSync(path) ? path : undefined
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null
}
