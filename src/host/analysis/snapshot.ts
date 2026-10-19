/**
 * Read-only, bounded snapshot of a workspace. Every later phase (analyzers,
 * AI review, evidence checks) works from this in-memory copy, never from the
 * live tree, so results are reproducible and a hostile repository cannot
 * steer reads outside its root through symlinks.
 */

import { createHash } from 'node:crypto'
import { constants } from 'node:fs'
import { lstat, open, opendir, realpath, stat } from 'node:fs/promises'
import { isAbsolute, join, relative, resolve, sep } from 'node:path'
import ignore from 'ignore'
import { DEPENDENCY_FILE_MAX_BYTES, isDependencyFileName } from './dependencies.ts'
import {
  type ExcludedPath,
  type ExcludeReason,
  type Language,
  type Snapshot,
  type SnapshotFile,
  type SnapshotOptions,
  yieldToEventLoop,
} from './types.ts'

type Ignore = ReturnType<typeof ignore>

/** Directory names never descended into: VCS metadata, dependencies, build output, caches, IDE state. */
const DEFAULT_IGNORED_DIRS: ReadonlySet<string> = new Set([
  '.git',
  '.hg',
  '.svn',
  'node_modules',
  'bower_components',
  'jspm_packages',
  'vendor',
  '.venv',
  '__pycache__',
  '.tox',
  '.nox',
  '.mypy_cache',
  '.pytest_cache',
  '.ruff_cache',
  'dist',
  'build',
  'out',
  '.next',
  '.nuxt',
  '.svelte-kit',
  'coverage',
  '.nyc_output',
  '.turbo',
  '.cache',
  '.parcel-cache',
  'target',
  '.gradle',
  '.idea',
  '.vscode',
  '.terraform',
  '.dsh-security',
])

/** Directory names that are ignored only when they hold a Python virtualenv (`pyvenv.cfg`). */
const VENV_CANDIDATE_DIRS: ReadonlySet<string> = new Set(['venv', 'env', 'virtualenv', '.virtualenv', '.env'])

/** Minified bundles and source maps: huge, generated, and not reviewable. Lock files are kept on purpose. */
const DEFAULT_IGNORED_FILE_SUFFIXES = ['.min.js', '.min.mjs', '.min.cjs', '.min.css', '.map']
const DEFAULT_IGNORED_FILE_NAMES: ReadonlySet<string> = new Set(['.DS_Store', 'Thumbs.db'])

const BINARY_EXTENSIONS: ReadonlySet<string> = new Set([
  // images
  'png',
  'jpg',
  'jpeg',
  'gif',
  'bmp',
  'ico',
  'icns',
  'webp',
  'tif',
  'tiff',
  'psd',
  'avif',
  'heic',
  'heif',
  'svgz',
  // archives and packages
  'zip',
  'gz',
  'tgz',
  'bz2',
  'xz',
  'lz',
  'lz4',
  'lzma',
  'zst',
  '7z',
  'rar',
  'tar',
  'jar',
  'war',
  'ear',
  'aar',
  'apk',
  'aab',
  'ipa',
  'dmg',
  'iso',
  'deb',
  'rpm',
  'msi',
  'whl',
  'egg',
  'nupkg',
  'gem',
  'crate',
  'lockb',
  // fonts
  'woff',
  'woff2',
  'ttf',
  'otf',
  'eot',
  // audio / video
  'mp3',
  'mp4',
  'm4a',
  'm4v',
  'wav',
  'ogg',
  'oga',
  'flac',
  'aac',
  'avi',
  'mov',
  'mkv',
  'webm',
  'wmv',
  'flv',
  'swf',
  // documents
  'pdf',
  'doc',
  'docx',
  'xls',
  'xlsx',
  'ppt',
  'pptx',
  'odt',
  'ods',
  'odp',
  // compiled code and native objects
  'exe',
  'dll',
  'so',
  'dylib',
  'a',
  'lib',
  'o',
  'obj',
  'bin',
  'class',
  'pyc',
  'pyo',
  'pyd',
  'wasm',
  'node',
  'pdb',
  // data blobs and models
  'sqlite',
  'sqlite3',
  'db',
  'npy',
  'npz',
  'pkl',
  'pickle',
  'h5',
  'hdf5',
  'onnx',
  'pt',
  'pth',
  'ckpt',
  'safetensors',
  'tflite',
  'parquet',
  'avro',
  'orc',
  'glb',
  'fbx',
  'blend',
])

const EXTENSION_LANGUAGES: Readonly<Record<string, Language>> = {
  ts: 'typescript',
  tsx: 'typescript',
  mts: 'typescript',
  cts: 'typescript',
  js: 'javascript',
  jsx: 'javascript',
  mjs: 'javascript',
  cjs: 'javascript',
  py: 'python',
  pyi: 'python',
  pyw: 'python',
  go: 'go',
  java: 'java',
  kt: 'kotlin',
  kts: 'kotlin',
  rb: 'ruby',
  rake: 'ruby',
  gemspec: 'ruby',
  erb: 'ruby',
  php: 'php',
  phtml: 'php',
  cs: 'csharp',
  csx: 'csharp',
  rs: 'rust',
  sh: 'shell',
  bash: 'shell',
  zsh: 'shell',
  ksh: 'shell',
  html: 'html',
  htm: 'html',
  xhtml: 'html',
  vue: 'vue',
  svelte: 'svelte',
  sql: 'sql',
  yaml: 'yaml',
  yml: 'yaml',
  json: 'json',
  jsonc: 'json',
  json5: 'json',
  toml: 'toml',
  xml: 'xml',
  xsd: 'xml',
  xsl: 'xml',
  xslt: 'xml',
  svg: 'xml',
  plist: 'xml',
  csproj: 'xml',
  fsproj: 'xml',
  vbproj: 'xml',
  tf: 'terraform',
  tfvars: 'terraform',
  hcl: 'terraform',
  md: 'markdown',
  markdown: 'markdown',
  mdx: 'markdown',
  env: 'env',
  dockerfile: 'dockerfile',
}

const FILENAME_LANGUAGES: Readonly<Record<string, Language>> = {
  containerfile: 'dockerfile',
  gemfile: 'ruby',
  rakefile: 'ruby',
  vagrantfile: 'ruby',
  podfile: 'ruby',
  brewfile: 'ruby',
  pipfile: 'toml',
  'cargo.lock': 'toml',
  'poetry.lock': 'toml',
  'uv.lock': 'toml',
  '.bashrc': 'shell',
  '.zshrc': 'shell',
  '.profile': 'shell',
  '.bash_profile': 'shell',
}

const TEST_DIR_SEGMENTS: ReadonlySet<string> = new Set([
  'test',
  'tests',
  '__tests__',
  'spec',
  'specs',
  'e2e',
  'fixtures',
  '__fixtures__',
  '__mocks__',
  'testdata',
  'examples',
  'example',
])

const TEST_FILE_PATTERNS: readonly RegExp[] = [
  /\.(?:test|spec)\.[^/]+$/i,
  /^test_[^/]*\.py$/i,
  /_test\.(?:py|go)$/i,
  /^conftest\.py$/i,
  /_spec\.rb$/i,
  /Tests?\.java$/,
]

const GENERATED_MARKERS = /@generated|DO NOT EDIT|Code generated/
const COMMENT_START = /^\s*(?:\/\/|\/\*|\*|#|<!--|--|;|""")/
const MINIFIABLE_EXTENSIONS: ReadonlySet<string> = new Set(['js', 'mjs', 'cjs', 'jsx', 'css'])

const EXCLUDED_CAP = 5000
/** Extra `excluded` room for oversized lock files, so the dependency warning for them is never lost to the cap. */
const EXCLUDED_DEPENDENCY_RESERVE = 1000
const NUL_SCAN_BYTES = 8192
const GITIGNORE_MAX_BYTES = 512 * 1024
const YIELD_EVERY = 50
const SHA_RE = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/i

/**
 * `O_NOFOLLOW` refuses a symlink swapped in after `lstat`; `O_NONBLOCK` keeps
 * a FIFO swapped in the same way from blocking the open. Both are undefined
 * on Windows, where they are simply omitted.
 */
const SAFE_OPEN_FLAGS = constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0)

interface GitignoreLevel {
  /** Directory (workspace-relative, '' for root) holding the `.gitignore`. */
  readonly base: string
  readonly ig: Ignore
}

interface DirTask {
  readonly rel: string
  readonly abs: string
  readonly levels: readonly GitignoreLevel[]
}

type ReadOutcome =
  | { readonly kind: 'ok'; readonly bytes: Buffer }
  | { readonly kind: 'too-large' }
  | { readonly kind: 'symlink' }
  | { readonly kind: 'unreadable' }

/** Detect a file's language from its name and extension. */
export function detectLanguage(path: string): Language {
  const name = baseName(path).toLowerCase()
  if (name.startsWith('dockerfile') || name.endsWith('.dockerfile')) return 'dockerfile'
  if (name === '.env' || name.startsWith('.env.')) return 'env'
  const byName = FILENAME_LANGUAGES[name]
  if (byName) return byName
  const dot = name.lastIndexOf('.')
  if (dot < 0 || dot === name.length - 1) return 'other'
  return EXTENSION_LANGUAGES[name.slice(dot + 1)] ?? 'other'
}

/** Whether a workspace-relative path looks like a test, fixture, mock, or example. */
export function isTestPath(path: string): boolean {
  const segments = path.split('/')
  const name = segments.pop() ?? ''
  if (segments.some(segment => TEST_DIR_SEGMENTS.has(segment.toLowerCase()))) return true
  return TEST_FILE_PATTERNS.some(pattern => pattern.test(name))
}

/** Heuristic for minified or tool-generated content. */
export function isGeneratedContent(path: string, content: string): boolean {
  const head = firstLines(content, 50)
  for (let i = 0; i < Math.min(head.length, 20); i++) {
    const line = head[i] ?? ''
    if (line.length <= 2000 && COMMENT_START.test(line) && GENERATED_MARKERS.test(line)) return true
  }
  if (MINIFIABLE_EXTENSIONS.has(extensionOf(path))) {
    const nonempty = head.filter(line => line.trim() !== '')
    const long = nonempty.filter(line => line.length > 1000)
    // One embedded SVG/data literal must not suppress analysis of a hand-written component.
    return long.length > 0 && long.length / nonempty.length >= 0.8
  }
  return false
}

/**
 * Walk `rootInput` and capture every reviewable text file under the given
 * limits. Symlinks are never followed; ignored, binary, oversized, and
 * over-limit paths are recorded in `excluded` (capped at 5000 entries).
 * Dependency manifests and lock files may exceed `maxFileBytes` up to
 * {@link DEPENDENCY_FILE_MAX_BYTES}; they still count toward `maxTotalBytes`.
 */
export async function takeSnapshot(rootInput: string, options: SnapshotOptions): Promise<Snapshot> {
  const { signal } = options
  signal?.throwIfAborted()
  const root = await realpath(rootInput)
  const workspaceRoot = options.workspaceRoot ? await realpath(options.workspaceRoot) : root
  if (!isInside(workspaceRoot, root)) throw new Error('Snapshot root is outside the workspace')
  const pathPrefix = relative(workspaceRoot, root).split(sep).join('/')
  const rootStat = await stat(root)
  if (!rootStat.isDirectory()) throw new Error(`Snapshot root is not a directory: ${rootInput}`)

  const userIgnore = snapshotIgnore(options.excludeGlobs.filter(p => p.trim() !== ''))
  const maxEntries = options.maxEntries ?? 100_000
  const files: SnapshotFile[] = []
  const excluded: ExcludedPath[] = []
  let totalBytes = 0
  let truncated = false
  let processed = 0
  let excludedCount = 0
  let unvisitedEntries = 0
  let unvisitedDirectories = 0
  const excludedByReason: Partial<Record<ExcludeReason, number>> = {}

  const exclude = (path: string, reason: ExcludeReason, reserved = false): void => {
    excludedCount++
    excludedByReason[reason] = (excludedByReason[reason] ?? 0) + 1
    // The path list is capped. Counts above are not, so estimates can name every reason.
    if (excluded.length < EXCLUDED_CAP + (reserved ? EXCLUDED_DEPENDENCY_RESERVE : 0)) excluded.push({ path, reason })
  }

  // Breadth-first so a truncated snapshot favours shallow, usually more central files.
  const ancestors: GitignoreLevel[] = []
  if (pathPrefix) {
    let dir = workspaceRoot
    for (const segment of pathPrefix.split('/')) {
      const rules = await readDirectoryGitignore(dir)
      if (rules)
        ancestors.push({
          base: relative(workspaceRoot, dir).split(sep).join('/'),
          ig: snapshotIgnore(rules),
        })
      dir = join(dir, segment)
    }
  }
  const queue: DirTask[] = [{ rel: pathPrefix, abs: root, levels: ancestors }]
  walk: for (let head = 0; head < queue.length; head++) {
    const task = queue[head]!
    signal?.throwIfAborted()

    {
      let real: string
      try {
        real = await realpath(task.abs)
      } catch {
        exclude(task.rel, 'unreadable')
        continue
      }
      if (!isInside(root, real)) {
        exclude(task.rel, 'outside-root')
        continue
      }
      if (real !== task.abs) {
        exclude(task.rel, 'symlink')
        continue
      }
    }

    let names: string[]
    try {
      names = await directoryNames(task.abs, Math.max(1, maxEntries - processed + 1), signal)
    } catch {
      exclude(task.rel, 'unreadable')
      continue
    }
    names.sort(compareStrings)

    let levels = task.levels
    const rules = await readDirectoryGitignore(task.abs, names)
    if (rules) levels = [...levels, { base: task.rel, ig: snapshotIgnore(rules) }]

    for (const [index, name] of names.entries()) {
      if (processed >= maxEntries) {
        truncated = true
        // We intentionally do not enumerate unopened subtrees just to count them.
        unvisitedEntries = names.length - index
        unvisitedDirectories = queue.length - head - 1
        exclude(task.rel === '' ? name : `${task.rel}/${name}`, 'limit-entries')
        for (const pending of queue.slice(head + 1)) exclude(`${pending.rel}/`, 'limit-entries')
        break walk
      }
      if (++processed % YIELD_EVERY === 0) await yieldToEventLoop()
      signal?.throwIfAborted()

      const rel = task.rel === '' ? name : `${task.rel}/${name}`
      const abs = join(task.abs, name)
      if (!isInside(root, abs) || name === '..' || name === '.' || name.includes('\0')) {
        exclude(rel, 'outside-root')
        continue
      }

      let st: Awaited<ReturnType<typeof lstat>>
      try {
        st = await lstat(abs)
      } catch {
        exclude(rel, 'unreadable')
        continue
      }
      if (st.isSymbolicLink()) {
        exclude(rel, 'symlink')
        continue
      }
      const isDir = st.isDirectory()
      if (await isDefaultIgnored(name, isDir, abs)) {
        exclude(rel, 'default-ignore')
        continue
      }
      if (isGitignored(levels, rel, isDir)) {
        exclude(rel, 'gitignore')
        continue
      }
      if (testIgnore(userIgnore, isDir ? `${rel}/` : rel)) {
        exclude(rel, 'user-exclude')
        continue
      }
      if (isDir) {
        queue.push({ rel, abs, levels })
        continue
      }
      if (!st.isFile()) {
        exclude(rel, 'unreadable')
        continue
      }
      if (BINARY_EXTENSIONS.has(extensionOf(name))) {
        exclude(rel, 'binary')
        continue
      }
      // Lock files and manifests are often larger than ordinary sources, and skipping one silently
      // drops dependency coverage: they get their own ceiling (still counted toward the total).
      const dependencyFile = isDependencyFileName(name)
      const fileLimit = dependencyFile
        ? Math.max(options.maxFileBytes, DEPENDENCY_FILE_MAX_BYTES)
        : options.maxFileBytes
      if (st.size > fileLimit) {
        exclude(rel, 'too-large', dependencyFile)
        continue
      }
      if (files.length >= options.maxFiles) {
        exclude(rel, 'limit-files')
        truncated = true
        continue
      }
      if (totalBytes + st.size > options.maxTotalBytes) {
        exclude(rel, 'limit-bytes')
        truncated = true
        continue
      }

      const outcome = await readBounded(abs, fileLimit)
      if (outcome.kind !== 'ok') {
        exclude(rel, outcome.kind, dependencyFile)
        continue
      }
      const bytes = outcome.bytes
      if (totalBytes + bytes.length > options.maxTotalBytes) {
        exclude(rel, 'limit-bytes')
        truncated = true
        continue
      }
      if (bytes.subarray(0, NUL_SCAN_BYTES).includes(0)) {
        exclude(rel, 'binary')
        continue
      }
      let content = bytes.toString('utf8')
      if (content.charCodeAt(0) === 0xfeff) content = content.slice(1)
      totalBytes += bytes.length
      files.push({
        path: rel,
        size: bytes.length,
        sha256: createHash('sha256').update(bytes).digest('hex'),
        language: detectLanguage(rel),
        content,
        isTest: isTestPath(rel),
        isGenerated: isGeneratedContent(rel, content),
      })
    }
  }

  files.sort((a, b) => compareStrings(a.path, b.path))
  excluded.sort((a, b) => compareStrings(a.path, b.path))
  const commit = await readGitCommit(workspaceRoot)
  return {
    root,
    ...(options.workspaceRoot ? { workspaceRoot } : {}),
    ...(pathPrefix ? { pathPrefix } : {}),
    files: new Map(files.map(file => [file.path, file])),
    excluded,
    totalBytes,
    excludedCount,
    excludedByReason,
    ...(unvisitedEntries ? { unvisitedEntries } : {}),
    ...(unvisitedDirectories ? { unvisitedDirectories } : {}),
    truncated,
    ...(commit ? { commit } : {}),
    takenAt: new Date().toISOString(),
  }
}

/**
 * Re-hash one snapshot file on disk, e.g. when a paused scan resumes, to tell
 * whether evidence quoted from the snapshot still matches the working tree.
 */
export async function verifySnapshotFile(
  rootInput: string,
  file: SnapshotFile,
): Promise<'same' | 'changed' | 'missing'> {
  let root: string
  try {
    root = await realpath(rootInput)
  } catch {
    return 'missing'
  }
  const segments = file.path.split('/')
  if (isAbsolute(file.path) || segments.some(s => s === '..' || s === '.' || s === '')) return 'missing'
  const abs = resolve(root, ...segments)
  if (!isInside(root, abs)) return 'missing'
  try {
    // A directory on the path swapped for a symlink means the file is no longer the one we hashed.
    if ((await realpath(abs)) !== abs) return 'changed'
  } catch (error) {
    return errorCode(error) === 'ENOENT' || errorCode(error) === 'ENOTDIR' ? 'missing' : 'changed'
  }
  let fh: Awaited<ReturnType<typeof open>>
  try {
    fh = await open(abs, SAFE_OPEN_FLAGS)
  } catch (error) {
    return errorCode(error) === 'ENOENT' || errorCode(error) === 'ENOTDIR' ? 'missing' : 'changed'
  }
  try {
    const st = await fh.stat()
    if (!st.isFile() || st.size !== file.size) return 'changed'
    const bytes = await readHandle(fh, file.size + 1)
    if (bytes.length !== file.size) return 'changed'
    return createHash('sha256').update(bytes).digest('hex') === file.sha256 ? 'same' : 'changed'
  } catch {
    return 'changed'
  } finally {
    await fh.close().catch(() => undefined)
  }
}

// ---------------------------------------------------------------------------
// Ignore handling
// ---------------------------------------------------------------------------

async function isDefaultIgnored(name: string, isDir: boolean, abs: string): Promise<boolean> {
  if (isDir) {
    if (DEFAULT_IGNORED_DIRS.has(name)) return true
    if (VENV_CANDIDATE_DIRS.has(name)) {
      try {
        return (await lstat(join(abs, 'pyvenv.cfg'))).isFile()
      } catch {
        return false
      }
    }
    return false
  }
  if (name === '.git' || DEFAULT_IGNORED_FILE_NAMES.has(name)) return true
  const lower = name.toLowerCase()
  return DEFAULT_IGNORED_FILE_SUFFIXES.some(suffix => lower.endsWith(suffix))
}

/**
 * Nested `.gitignore` semantics: the deepest file with a matching rule wins,
 * and within one file the last matching rule (ignore or negation) wins.
 */
function isGitignored(levels: readonly GitignoreLevel[], rel: string, isDir: boolean): boolean {
  for (let i = levels.length - 1; i >= 0; i--) {
    const level = levels[i]!
    const local = level.base === '' ? rel : rel.slice(level.base.length + 1)
    try {
      const result = level.ig.test(isDir ? `${local}/` : local)
      if (result.ignored) return true
      if (result.unignored) return false
    } catch {
      // Paths the matcher rejects are simply not ignored.
    }
  }
  return false
}

function testIgnore(ig: Ignore, path: string): boolean {
  try {
    return ig.ignores(path)
  } catch {
    return false
  }
}

/** Match case as the platform's usual filesystem does (custom case-sensitive volumes may differ). */
export function snapshotIgnore(patterns: readonly string[], platform: NodeJS.Platform = process.platform): Ignore {
  return ignore({ ignorecase: platform === 'win32' || platform === 'darwin' }).add(patterns)
}

export function gitignoreEntry(
  names: readonly string[],
  platform: NodeJS.Platform = process.platform,
): string | undefined {
  return names.includes('.gitignore')
    ? '.gitignore'
    : platform === 'win32' || platform === 'darwin'
      ? names.find(name => name.toLowerCase() === '.gitignore')
      : undefined
}

/** Enumerate only a bounded prefix; the extra entry proves there is unvisited work. */
async function directoryNames(abs: string, limit: number, signal?: AbortSignal): Promise<string[]> {
  const names: string[] = []
  const directory = await opendir(abs)
  try {
    for (;;) {
      signal?.throwIfAborted()
      const entry = await directory.read()
      if (!entry) break
      names.push(entry.name)
      if (names.length >= limit) break
    }
  } finally {
    await directory.close()
  }
  return names
}

async function readDirectoryGitignore(abs: string, names?: readonly string[]): Promise<string[] | undefined> {
  // Exact open works with differently cased names on case-insensitive filesystems too.
  const exact = await readGitignore(join(abs, '.gitignore'))
  if (exact) return exact
  if (process.platform !== 'win32' && process.platform !== 'darwin') return undefined
  const entry = gitignoreEntry(names ?? (await directoryNames(abs, 100_000)))
  return entry && entry !== '.gitignore' ? readGitignore(join(abs, entry)) : undefined
}

async function readGitignore(abs: string): Promise<string[] | undefined> {
  const outcome = await readBounded(abs, GITIGNORE_MAX_BYTES)
  if (outcome.kind !== 'ok') return undefined
  return outcome.bytes.toString('utf8').replace(/^﻿/, '').split(/\r?\n/)
}

// ---------------------------------------------------------------------------
// File reading
// ---------------------------------------------------------------------------

async function readBounded(abs: string, limit: number): Promise<ReadOutcome> {
  let fh: Awaited<ReturnType<typeof open>>
  try {
    fh = await open(abs, SAFE_OPEN_FLAGS)
  } catch (error) {
    return { kind: errorCode(error) === 'ELOOP' ? 'symlink' : 'unreadable' }
  }
  try {
    const st = await fh.stat()
    if (!st.isFile()) return { kind: 'unreadable' }
    if (st.size > limit) return { kind: 'too-large' }
    const bytes = await readHandle(fh, limit + 1)
    if (bytes.length > limit) return { kind: 'too-large' }
    return { kind: 'ok', bytes }
  } catch {
    return { kind: 'unreadable' }
  } finally {
    await fh.close().catch(() => undefined)
  }
}

/** Read up to `max` bytes from the start of an open handle. */
async function readHandle(fh: Awaited<ReturnType<typeof open>>, max: number): Promise<Buffer> {
  const chunks: Buffer[] = []
  let total = 0
  while (total < max) {
    const want = Math.min(max - total, 1 << 20)
    const buffer = Buffer.allocUnsafe(want)
    const { bytesRead } = await fh.read(buffer, 0, want, total)
    if (bytesRead === 0) break
    chunks.push(bytesRead === want ? buffer : buffer.subarray(0, bytesRead))
    total += bytesRead
  }
  return chunks.length === 1 ? chunks[0]! : Buffer.concat(chunks, total)
}

async function readSmallFile(abs: string, max: number): Promise<string> {
  const fh = await open(abs, SAFE_OPEN_FLAGS)
  try {
    if (!(await fh.stat()).isFile()) throw new Error('not a file')
    return (await readHandle(fh, max)).toString('utf8')
  } finally {
    await fh.close().catch(() => undefined)
  }
}

// ---------------------------------------------------------------------------
// Git metadata (read directly; the git binary is never executed)
// ---------------------------------------------------------------------------

async function readGitCommit(root: string): Promise<string | undefined> {
  try {
    const dotGit = join(root, '.git')
    const st = await lstat(dotGit)
    let gitDir: string
    if (st.isDirectory()) {
      gitDir = dotGit
    } else if (st.isFile()) {
      const pointer = /^gitdir:\s*(.+?)\s*$/m.exec(await readSmallFile(dotGit, 4096))?.[1]
      if (!pointer) return undefined
      gitDir = isAbsolute(pointer) ? pointer : resolve(root, pointer)
    } else {
      return undefined
    }

    let commonDir = gitDir
    try {
      const common = (await readSmallFile(join(gitDir, 'commondir'), 4096)).trim()
      if (common) commonDir = isAbsolute(common) ? common : resolve(gitDir, common)
    } catch {
      // Not a linked worktree.
    }

    const head = (await readSmallFile(join(gitDir, 'HEAD'), 4096)).trim()
    if (SHA_RE.test(head)) return head.toLowerCase()
    const ref = /^ref:\s*(refs\/\S+)$/.exec(head)?.[1]
    if (!ref || !isSafeRef(ref)) return undefined

    for (const dir of new Set([gitDir, commonDir])) {
      try {
        const value = (await readSmallFile(join(dir, ...ref.split('/')), 4096)).trim()
        if (SHA_RE.test(value)) return value.toLowerCase()
      } catch {
        // Loose ref missing; try packed-refs.
      }
    }
    const packed = await readSmallFile(join(commonDir, 'packed-refs'), 16 * 1024 * 1024)
    for (const line of packed.split('\n')) {
      if (line.startsWith('#') || line.startsWith('^')) continue
      const [sha, name] = line.trim().split(' ')
      if (name === ref && sha && SHA_RE.test(sha)) return sha.toLowerCase()
    }
    return undefined
  } catch {
    return undefined
  }
}

function isSafeRef(ref: string): boolean {
  return /^refs\/[A-Za-z0-9._/+-]+$/.test(ref) && !ref.split('/').some(s => s === '' || s === '.' || s === '..')
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

function isInside(root: string, candidate: string): boolean {
  if (candidate === root) return true
  const prefix = root.endsWith(sep) ? root : root + sep
  return candidate.startsWith(prefix)
}

function compareStrings(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0
}

function baseName(path: string): string {
  const slash = path.lastIndexOf('/')
  return slash < 0 ? path : path.slice(slash + 1)
}

function extensionOf(path: string): string {
  const name = baseName(path)
  const dot = name.lastIndexOf('.')
  return dot <= 0 ? '' : name.slice(dot + 1).toLowerCase()
}

function firstLines(content: string, count: number): string[] {
  const lines: string[] = []
  let start = 0
  while (lines.length < count && start <= content.length) {
    const end = content.indexOf('\n', start)
    if (end < 0) {
      lines.push(content.slice(start))
      break
    }
    lines.push(content.slice(start, end))
    start = end + 1
  }
  return lines
}

function errorCode(error: unknown): string | undefined {
  return typeof error === 'object' && error !== null && 'code' in error && typeof error.code === 'string'
    ? error.code
    : undefined
}
