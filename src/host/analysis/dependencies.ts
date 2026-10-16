/**
 * Dependency extraction from lock files and manifests. Parsers are tolerant:
 * a malformed file yields a warning and whatever could be read, never a throw.
 * Lock files win over their sibling manifests because they pin exact versions.
 */

import { posix } from 'node:path'
import { parse as parseYaml } from 'yaml'
import { type Dependency, type Ecosystem, type Snapshot, type SnapshotFile, yieldToEventLoop } from './types.ts'

type Mutable<T> = { -readonly [K in keyof T]: T[K] }
type DepDraft = Omit<Mutable<Dependency>, 'manifest'>

interface ParseContext {
  readonly file: SnapshotFile
  /** Another file in the same directory, e.g. the `package.json` next to a lock. */
  readonly sibling: (name: string) => SnapshotFile | undefined
  readonly add: (dep: DepDraft) => void
  readonly warn: (message: string) => void
  readonly include?: (target: string, line: number) => Promise<void>
}

const NPM_LOCKS = ['package-lock.json', 'npm-shrinkwrap.json', 'pnpm-lock.yaml', 'yarn.lock'] as const

/**
 * Largest manifest or lock file read into a snapshot and parsed, in bytes.
 * The snapshot exempts the files {@link isDependencyFileName} accepts from the
 * per-file limit up to this size, because real lock files often exceed it.
 */
export const DEPENDENCY_FILE_MAX_BYTES = 32 * 1024 * 1024
const YIELD_EVERY = 50
/** Lock entries (or lines) handled between event-loop yields in one file. */
const YIELD_EVERY_ENTRIES = 2000

/** Whether `name` (a base name) is a manifest or lock file {@link parseDependencies} reads. */
export function isDependencyFileName(name: string): boolean {
  return pickParser(name, () => false) !== undefined
}

/**
 * Parse every supported manifest and lock file in the snapshot. Results are
 * de-duplicated per ecosystem, name, version, and manifest, and sorted.
 */
export async function parseDependencies(
  snapshot: Snapshot,
): Promise<{ dependencies: Dependency[]; warnings: string[] }> {
  const warnings: string[] = []
  const byKey = new Map<string, Mutable<Dependency>>()
  let count = 0

  // A lock file left out of the snapshot silently drops dependency coverage: say so first.
  for (const entry of snapshot.excluded) {
    if (entry.reason === 'too-large' && isDependencyFileName(baseName(entry.path))) {
      warnings.push(
        `${entry.path}: not analyzed, larger than the ${DEPENDENCY_FILE_MAX_BYTES / (1024 * 1024)} MiB limit for dependency files; its dependencies are missing from this scan`,
      )
    }
  }

  const parsed = new Set<string>()
  const active = new Set<string>()
  const parseFile = async (file: SnapshotFile, requirements = false, depth = 0): Promise<void> => {
    if (parsed.has(file.path)) return
    if (++count % YIELD_EVERY === 0) await yieldToEventLoop()
    const name = baseName(file.path)
    const dir = dirName(file.path)
    const sibling = (n: string): SnapshotFile | undefined => snapshot.files.get(dir === '' ? n : `${dir}/${n}`)
    const parser =
      requirements || /(?:^|\/)requirements\/.*\.txt$/i.test(file.path)
        ? parseRequirements
        : pickParser(name, n => sibling(n) !== undefined)
    if (!parser) return
    if (file.content.length > DEPENDENCY_FILE_MAX_BYTES) {
      warnings.push(`${file.path}: skipped, file too large to parse`)
      return
    }
    active.add(file.path)
    const ctx: ParseContext = {
      file,
      sibling,
      add: draft => {
        const name = draft.ecosystem === 'PyPI' ? normalizePypiName(draft.name) : draft.name
        if (!name || !draft.version) return
        const dep: Mutable<Dependency> = { ...draft, name, manifest: file.path }
        const key = `${dep.ecosystem}\0${dep.name}\0${dep.version}\0${dep.manifest}`
        const existing = byKey.get(key)
        if (!existing) {
          byKey.set(key, dep)
          return
        }
        // The same package reached several ways: direct beats transitive, prod beats dev.
        existing.direct ||= dep.direct
        existing.dev &&= dep.dev
        if (existing.line === undefined && dep.line !== undefined) existing.line = dep.line
      },
      warn: message => warnings.push(`${file.path}: ${message}`),
      include: async (target, line) => {
        const warn = (message: string): void => {
          warnings.push(`${file.path}: line ${line}: ${message}`)
        }
        if (target.startsWith('/') || /^(?:[A-Za-z][\w+.-]*:|\\)/.test(target)) {
          warn(`requirement include '${target}' is not confined to snapshot files`)
          return
        }
        const path = posix.normalize(posix.join(dir, target))
        if (path === '..' || path.startsWith('../')) {
          warn(`requirement include '${target}' is outside the snapshot`)
          return
        }
        if (active.has(path)) {
          warn(`requirement include cycle at '${target}'`)
          return
        }
        if (depth >= 16) {
          warn(`requirement include depth limit reached at '${target}'`)
          return
        }
        const child = snapshot.files.get(path)
        if (!child) {
          warn(`requirement include '${target}' is missing from the snapshot`)
          return
        }
        await parseFile(child, true, depth + 1)
      },
    }
    try {
      await parser(ctx)
    } catch (error) {
      ctx.warn(`could not parse (${error instanceof Error ? error.message : String(error)})`)
    } finally {
      active.delete(file.path)
      parsed.add(file.path)
    }
  }
  for (const file of snapshot.files.values()) await parseFile(file)

  const dependencies = [...byKey.values()].sort(
    (a, b) =>
      compare(a.ecosystem, b.ecosystem) ||
      compare(a.name, b.name) ||
      compare(a.version, b.version) ||
      compare(a.manifest, b.manifest),
  )
  return { dependencies, warnings }
}

/** PEP 503 name normalization: lower-case, runs of `-`, `_`, `.` become `-`. */
export function normalizePypiName(name: string): string {
  return name
    .trim()
    .toLowerCase()
    .replace(/[-_.]+/g, '-')
}

type Parser = (ctx: ParseContext) => void | Promise<void>

function pickParser(name: string, sibling: (name: string) => boolean): Parser | undefined {
  switch (name) {
    case 'package-lock.json':
    case 'npm-shrinkwrap.json':
      return parsePackageLock
    case 'pnpm-lock.yaml':
      return parsePnpmLock
    case 'yarn.lock':
      return parseYarnLock
    case 'package.json':
      return NPM_LOCKS.some(sibling) ? undefined : parsePackageJson
    case 'poetry.lock':
    case 'uv.lock':
      return parseTomlPackages(name === 'uv.lock' ? 'uv' : 'poetry')
    case 'Pipfile.lock':
      return parsePipfileLock
    case 'go.mod':
      return parseGoMod
    case 'Cargo.lock':
      return parseTomlPackages('cargo')
  }
  // Parsed even next to a Python lock: pip-compile output is often the real deploy input.
  return /^requirements[^/]*\.txt$/i.test(name) ? parseRequirements : undefined
}

// ---------------------------------------------------------------------------
// npm
// ---------------------------------------------------------------------------

interface DeclaredDep {
  readonly range: string
  readonly dev: boolean
}

/** Direct dependencies declared by the `package.json` next to a lock: name → range and dev-only flag. */
function declaredNpmDeps(ctx: ParseContext): Map<string, DeclaredDep> {
  const declared = new Map<string, DeclaredDep>()
  const pkg = ctx.sibling('package.json')
  if (!pkg) return declared
  let json: unknown
  try {
    json = JSON.parse(pkg.content)
  } catch {
    return declared
  }
  if (!isRecord(json)) return declared
  const sections: [string, boolean][] = [
    ['devDependencies', true],
    ['peerDependencies', false],
    ['optionalDependencies', false],
    ['dependencies', false],
  ]
  for (const [section, dev] of sections) {
    for (const [name, range] of Object.entries(asRecord(json[section]))) {
      if (typeof range === 'string') declared.set(name, { range, dev })
    }
  }
  return declared
}

/** Whether a yarn lock entry was resolved for the range `package.json` declares. */
function matchDeclared(
  declared: ReadonlyMap<string, DeclaredDep>,
  specs: readonly YarnSpec[],
  name: string,
): DeclaredDep | undefined {
  const dep = declared.get(name)
  if (!dep) return undefined
  return specs.some(spec => spec.name === name && (spec.range === dep.range || spec.range === `npm:${dep.range}`))
    ? dep
    : undefined
}

async function parsePackageLock(ctx: ParseContext): Promise<void> {
  const json = parseJson(ctx)
  if (!isRecord(json)) return
  const root = isRecord(json.packages) ? json.packages[''] : undefined
  const directProd = new Set<string>()
  const directDev = new Set<string>()
  if (isRecord(root)) {
    for (const name of Object.keys(asRecord(root.dependencies))) directProd.add(name)
    for (const name of Object.keys(asRecord(root.optionalDependencies))) directProd.add(name)
    for (const name of Object.keys(asRecord(root.devDependencies))) directDev.add(name)
  }
  const lines = new LineIndex(ctx.file.content)
  let entries = 0

  if (isRecord(json.packages)) {
    // lockfileVersion 2/3: flat map keyed by install path.
    for (const [key, raw] of Object.entries(json.packages)) {
      if (++entries % YIELD_EVERY_ENTRIES === 0) await yieldToEventLoop()
      if (key === '' || !isRecord(raw)) continue
      const idx = key.lastIndexOf('node_modules/')
      if (idx < 0) continue // workspace package source folder, not an installed dependency
      if (raw.link === true) continue
      const name = typeof raw.name === 'string' ? raw.name : key.slice(idx + 'node_modules/'.length)
      const version = typeof raw.version === 'string' ? raw.version : undefined
      if (!version || !isValidNpmName(name)) continue
      const topLevel = key === `node_modules/${name}`
      ctx.add({
        ecosystem: 'npm',
        name,
        version,
        exact: isExactSemver(version),
        line: lines.find(JSON.stringify(key)),
        direct: topLevel && (directProd.has(name) || directDev.has(name)),
        dev: raw.dev === true || raw.devOptional === true,
      })
    }
    return
  }

  // lockfileVersion 1: nested `dependencies` tree. Top level also holds hoisted
  // transitive packages, so `package.json` decides what is direct when present.
  const declared = declaredNpmDeps(ctx)
  const visit = async (deps: unknown, depth: number): Promise<void> => {
    if (!isRecord(deps) || depth > 64) return
    for (const [name, raw] of Object.entries(deps)) {
      if (++entries % YIELD_EVERY_ENTRIES === 0) await yieldToEventLoop()
      if (!isRecord(raw)) continue
      const version = typeof raw.version === 'string' ? raw.version : undefined
      if (version && isValidNpmName(name) && !/^(?:file|link|git|github|https?):/.test(version)) {
        ctx.add({
          ecosystem: 'npm',
          name,
          version,
          exact: isExactSemver(version),
          line: lines.find(JSON.stringify(name)),
          direct: depth === 0 && (declared.size === 0 || declared.has(name)),
          dev: raw.dev === true,
        })
      }
      await visit(raw.dependencies, depth + 1)
    }
  }
  if (!isRecord(json.dependencies)) {
    ctx.warn('no "packages" or "dependencies" section')
    return
  }
  await visit(json.dependencies, 0)
}

async function parsePnpmLock(ctx: ParseContext): Promise<void> {
  const doc = await parseYamlDoc(ctx)
  if (!isRecord(doc)) return
  const lines = new LineIndex(ctx.file.content)

  // Direct dependencies: `importers` (workspaces, v6+) or top-level fields (v5).
  const direct = new Map<string, { version: string; dev: boolean }[]>()
  const addDirect = (section: unknown, dev: boolean): void => {
    for (const [name, spec] of Object.entries(asRecord(section))) {
      const version = typeof spec === 'string' ? spec : isRecord(spec) ? spec.version : undefined
      if (typeof version !== 'string') continue
      const list = direct.get(name) ?? []
      list.push({ version: stripPeerSuffix(version), dev })
      direct.set(name, list)
    }
  }
  const importers = isRecord(doc.importers) ? Object.values(doc.importers) : [doc]
  for (const importer of importers) {
    if (!isRecord(importer)) continue
    addDirect(importer.dependencies, false)
    addDirect(importer.optionalDependencies, false)
    addDirect(importer.devDependencies, true)
  }

  const packages = asRecord(doc.packages)
  if (Object.keys(packages).length === 0 && direct.size === 0) {
    ctx.warn('no "packages" or "importers" section')
    return
  }
  // v5/v6 mark `dev` on each package; v9 does not, so derive it from the `snapshots` graph.
  const prodReachable = isRecord(doc.snapshots) ? pnpmProdReachable(doc.snapshots, direct) : undefined
  let entries = 0
  for (const [key, raw] of Object.entries(packages)) {
    if (++entries % YIELD_EVERY_ENTRIES === 0) await yieldToEventLoop()
    const parsed = parsePnpmKey(key)
    if (!parsed) continue
    const meta = asRecord(raw)
    const name = typeof meta.name === 'string' ? meta.name : parsed.name
    const version = typeof meta.version === 'string' ? meta.version : parsed.version
    if (!isValidNpmName(name) || !isExactSemver(version)) continue
    const directEntries = direct.get(name)?.filter(entry => entry.version === version) ?? []
    const isDirect = directEntries.length > 0
    let dev: boolean
    if (typeof meta.dev === 'boolean') dev = meta.dev
    else if (prodReachable) dev = !prodReachable.has(`${name}@${version}`)
    else dev = isDirect && directEntries.every(entry => entry.dev)
    ctx.add({
      ecosystem: 'npm',
      name,
      version,
      exact: true,
      line: lines.yamlKey(key) ?? lines.yamlKey(`'${key}'`),
      direct: isDirect,
      dev,
    })
  }
}

/** `name@version` pairs reachable from production direct dependencies in a v9 `snapshots` map. */
function pnpmProdReachable(
  snapshots: Record<string, unknown>,
  direct: ReadonlyMap<string, readonly { version: string; dev: boolean }[]>,
): Set<string> {
  const edges = new Map<string, string[]>()
  for (const [key, raw] of Object.entries(snapshots)) {
    const parsed = parsePnpmKey(key)
    if (!parsed) continue
    const node = `${parsed.name}@${parsed.version}`
    const meta = asRecord(raw)
    const children = edges.get(node) ?? []
    for (const section of [meta.dependencies, meta.optionalDependencies]) {
      for (const [name, version] of Object.entries(asRecord(section))) {
        if (typeof version === 'string') children.push(`${name}@${stripPeerSuffix(version)}`)
      }
    }
    edges.set(node, children)
  }
  const reachable = new Set<string>()
  const queue: string[] = []
  for (const [name, entries] of direct) {
    for (const entry of entries) if (!entry.dev) queue.push(`${name}@${entry.version}`)
  }
  while (queue.length > 0) {
    const node = queue.pop()!
    if (reachable.has(node)) continue
    reachable.add(node)
    for (const child of edges.get(node) ?? []) if (!reachable.has(child)) queue.push(child)
  }
  return reachable
}

/**
 * pnpm package keys:
 * v5 `/name/1.2.3`, v6 `/name@1.2.3(peer@1)`, v9 `name@1.2.3(peer@1)`,
 * scoped `/@scope/name@1.2.3`.
 */
function parsePnpmKey(key: string): { name: string; version: string } | undefined {
  const bare = stripPeerSuffix(key.replace(/^\//, ''))
  const at = bare.lastIndexOf('@')
  if (at > 0) {
    const name = bare.slice(0, at)
    const version = bare.slice(at + 1)
    if (!name.includes('/') || name.startsWith('@')) {
      if (isValidNpmName(name) && version !== '') return { name, version }
    }
  }
  // v5: `/name/1.2.3` or `/@scope/name/1.2.3`
  const slash = bare.lastIndexOf('/')
  if (slash > 0) {
    const name = bare.slice(0, slash)
    const version = bare.slice(slash + 1).split('_')[0] ?? ''
    if (isValidNpmName(name) && isExactSemver(version)) return { name, version }
  }
  return undefined
}

function stripPeerSuffix(version: string): string {
  const paren = version.indexOf('(')
  return paren < 0 ? version : version.slice(0, paren)
}

async function parseYarnLock(ctx: ParseContext): Promise<void> {
  const content = ctx.file.content
  if (/^__metadata:/m.test(content)) {
    await parseYarnBerry(ctx)
    return
  }
  // Classic v1: unindented `"a@^1", a@~1.2:` headers, indented `version "1.2.3"`.
  const declared = declaredNpmDeps(ctx)
  const lines = content.split(/\r?\n/)
  let specs: YarnSpec[] = []
  let headerLine = 0
  let found = 0
  for (let i = 0; i < lines.length; i++) {
    if ((i + 1) % (YIELD_EVERY_ENTRIES * 8) === 0) await yieldToEventLoop()
    const line = lines[i]!
    if (line === '' || line.startsWith('#')) continue
    if (!/^\s/.test(line)) {
      specs = line.endsWith(':') ? parseYarnHeader(line.slice(0, -1)) : []
      headerLine = i + 1
      continue
    }
    const version = /^\s+version:?\s+"?([^"\s]+)"?\s*$/.exec(line)?.[1]
    if (!version || specs.length === 0) continue
    for (const name of new Set(specs.map(spec => spec.name))) {
      found++
      const direct = matchDeclared(declared, specs, name)
      ctx.add({
        ecosystem: 'npm',
        name,
        version,
        exact: isExactSemver(version),
        line: headerLine,
        direct: direct !== undefined,
        dev: direct?.dev === true,
      })
    }
    specs = []
  }
  if (found === 0 && content.trim() !== '' && !/^# yarn lockfile/m.test(content)) {
    ctx.warn('no package entries found')
  }
}

async function parseYarnBerry(ctx: ParseContext): Promise<void> {
  const doc = await parseYamlDoc(ctx)
  if (!isRecord(doc)) return
  const declared = declaredNpmDeps(ctx)
  const lines = new LineIndex(ctx.file.content)
  let entries = 0
  for (const [header, raw] of Object.entries(doc)) {
    if (++entries % YIELD_EVERY_ENTRIES === 0) await yieldToEventLoop()
    if (header === '__metadata' || !isRecord(raw)) continue
    const version = typeof raw.version === 'string' ? raw.version : undefined
    if (!version) continue
    const resolution = typeof raw.resolution === 'string' ? raw.resolution : ''
    // Skip workspace packages, local links, patches resolved to non-registry sources.
    if (/@(?:workspace|link|portal|file|exec):/.test(resolution)) continue
    const specs = parseYarnHeader(header)
    for (const name of new Set(specs.map(spec => spec.name))) {
      const direct = matchDeclared(declared, specs, name)
      ctx.add({
        ecosystem: 'npm',
        name,
        version,
        exact: isExactSemver(version),
        line: lines.yamlKey(`"${header}"`) ?? lines.yamlKey(header),
        direct: direct !== undefined,
        dev: direct?.dev === true,
      })
    }
  }
}

interface YarnSpec {
  readonly name: string
  readonly range: string
}

/** `"@scope/a@^1.0.0", a@npm:^2` → name and requested range per descriptor. */
function parseYarnHeader(header: string): YarnSpec[] {
  const specs: YarnSpec[] = []
  for (const part of header.split(',')) {
    const spec = part.trim().replace(/^"|"$/g, '')
    const at = spec.indexOf('@', spec.startsWith('@') ? 1 : 0)
    const name = at < 0 ? spec : spec.slice(0, at)
    if (isValidNpmName(name)) specs.push({ name, range: at < 0 ? '' : spec.slice(at + 1) })
  }
  return specs
}

function parsePackageJson(ctx: ParseContext): void {
  const json = parseJson(ctx)
  if (!isRecord(json)) return
  const lines = new LineIndex(ctx.file.content)
  const sections: [string, boolean][] = [
    ['dependencies', false],
    ['optionalDependencies', false],
    ['peerDependencies', false],
    ['devDependencies', true],
  ]
  for (const [section, dev] of sections) {
    for (const [name, spec] of Object.entries(asRecord(json[section]))) {
      if (typeof spec !== 'string' || !isValidNpmName(name)) continue
      if (/^(?:file|link|workspace|portal|git|github|git\+\w+|https?):/.test(spec) || spec.includes('/')) {
        if (!spec.startsWith('npm:')) continue
      }
      ctx.add({
        ecosystem: 'npm',
        name,
        version: spec,
        exact: isExactSemver(spec),
        line: lines.find(`${JSON.stringify(name)}:`) ?? lines.find(JSON.stringify(name)),
        direct: true,
        dev,
      })
    }
  }
}

// ---------------------------------------------------------------------------
// Python
// ---------------------------------------------------------------------------

async function parseRequirements(ctx: ParseContext): Promise<void> {
  const lines = ctx.file.content.split(/\r?\n/)
  let logical = ''
  let startLine = 0
  for (let i = 0; i < lines.length; i++) {
    let line = lines[i]!
    if (logical === '') startLine = i + 1
    if (line.endsWith('\\')) {
      logical += `${line.slice(0, -1)} `
      continue
    }
    line = (logical + line).replace(/(^|\s)#.*$/, '').trim()
    logical = ''
    const include = /^(?:-r\s*|--requirement(?:\s+|=))(.+)$/.exec(line)
    if (include) {
      const target = include[1]!.trim().replace(/^(['"])(.*)\1$/, '$2')
      await ctx.include?.(target, startLine)
      continue
    }
    if (line === '' || line.startsWith('-')) continue // -c, -e, --hash, --index-url …
    if (/^(?:https?|git\+|file):|^\.{0,2}\//.test(line)) continue // direct URLs and local paths
    const spec = line
      .split(';')[0]!
      .replace(/\s--hash=\S+/g, '')
      .trim()
    const match = /^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(.*)$/.exec(spec)
    if (!match) {
      ctx.warn(`line ${startLine}: unrecognized requirement`)
      continue
    }
    const name = match[1]!
    const constraint = match[2]!.trim()
    if (constraint.startsWith('@')) continue // PEP 508 direct reference
    const exactVersion = /^===?\s*([A-Za-z0-9._+!-]+)$/.exec(constraint)?.[1]
    ctx.add({
      ecosystem: 'PyPI',
      name,
      version: exactVersion ?? (constraint === '' ? '*' : constraint.replace(/\s+/g, '')),
      exact: exactVersion !== undefined && !exactVersion.includes('*'),
      line: startLine,
      direct: true,
      dev: /(?:^|[-_./])(?:dev|test|tests|lint|docs?)(?:[-_.]|$)/i.test(baseName(ctx.file.path)),
    })
  }
}

async function parsePipfileLock(ctx: ParseContext): Promise<void> {
  const json = parseJson(ctx)
  if (!isRecord(json)) return
  const lines = new LineIndex(ctx.file.content)
  let found = false
  let entries = 0
  for (const [section, dev] of [
    ['default', false],
    ['develop', true],
  ] as const) {
    for (const [name, raw] of Object.entries(asRecord(json[section]))) {
      if (++entries % YIELD_EVERY_ENTRIES === 0) await yieldToEventLoop()
      found = true
      const spec = isRecord(raw) && typeof raw.version === 'string' ? raw.version : undefined
      const version = spec ? /^===?\s*(\S+)$/.exec(spec)?.[1] : undefined
      if (!version) continue // VCS / path entries carry no version
      ctx.add({
        ecosystem: 'PyPI',
        name,
        version,
        exact: true,
        line: lines.find(`${JSON.stringify(name)}:`),
        direct: false,
        dev,
      })
    }
  }
  if (!found) ctx.warn('no "default" or "develop" section')
}

// ---------------------------------------------------------------------------
// TOML `[[package]]` locks: poetry.lock, uv.lock, Cargo.lock
// ---------------------------------------------------------------------------

interface TomlPackage {
  name?: string
  version?: string
  category?: string
  groups?: string[]
  source?: string
  line: number
}

function parseTomlPackages(kind: 'poetry' | 'uv' | 'cargo'): Parser {
  return async ctx => {
    const packages = await readTomlPackageBlocks(ctx.file.content)
    if (packages.length === 0) {
      ctx.warn('no [[package]] entries found')
      return
    }
    const ecosystem: Ecosystem = kind === 'cargo' ? 'crates.io' : 'PyPI'
    for (const pkg of packages) {
      if (!pkg.name || !pkg.version) continue
      // Path/git/workspace members are not registry packages.
      if (kind === 'cargo' && pkg.source !== undefined && !pkg.source.startsWith('registry+')) continue
      if (kind === 'cargo' && pkg.source === undefined) continue
      if (kind === 'uv' && pkg.source !== undefined && !/registry/.test(pkg.source)) continue
      const dev =
        pkg.category !== undefined
          ? pkg.category !== 'main'
          : pkg.groups !== undefined && pkg.groups.length > 0 && !pkg.groups.includes('main')
      ctx.add({
        ecosystem,
        name: pkg.name,
        version: pkg.version,
        exact: true,
        line: pkg.line,
        direct: false,
        dev,
      })
    }
  }
}

/** Minimal reader for the flat `[[package]]` tables used by poetry, uv, and Cargo locks. */
async function readTomlPackageBlocks(content: string): Promise<TomlPackage[]> {
  const packages: TomlPackage[] = []
  let current: TomlPackage | undefined
  const lines = content.split(/\r?\n/)
  for (let i = 0; i < lines.length; i++) {
    if ((i + 1) % (YIELD_EVERY_ENTRIES * 8) === 0) await yieldToEventLoop()
    const line = lines[i]!.trim()
    if (line.startsWith('[')) {
      current = line === '[[package]]' ? { line: i + 1 } : undefined
      if (current) packages.push(current)
      continue
    }
    if (!current) continue
    const kv = /^([A-Za-z0-9_-]+)\s*=\s*(.+)$/.exec(line)
    if (!kv) continue
    const key = kv[1]!
    const value = kv[2]!
    switch (key) {
      case 'name':
      case 'version':
      case 'category':
        current[key] = readTomlString(value)
        break
      case 'groups':
        current.groups = [...value.matchAll(/"([^"]*)"/g)].map(m => m[1]!)
        break
      case 'source':
        current.source = readTomlString(value) ?? value
        break
    }
  }
  return packages
}

function readTomlString(value: string): string | undefined {
  const match = /^"((?:[^"\\]|\\.)*)"|^'([^']*)'/.exec(value)
  if (!match) return undefined
  return match[2] ?? match[1]!.replace(/\\(["\\])/g, '$1')
}

// ---------------------------------------------------------------------------
// Go
// ---------------------------------------------------------------------------

function parseGoMod(ctx: ParseContext): void {
  const lines = ctx.file.content.split(/\r?\n/)
  let inRequire = false
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i]!
    const indirect = /\/\/\s*indirect\b/.test(raw)
    const line = raw.replace(/\/\/.*$/, '').trim()
    if (line === '') continue
    if (inRequire) {
      if (line === ')') {
        inRequire = false
        continue
      }
      addGoRequire(ctx, line, i + 1, indirect)
      continue
    }
    if (/^require\s*\($/.test(line)) {
      inRequire = true
      continue
    }
    const single = /^require\s+(.+)$/.exec(line)?.[1]
    if (single) addGoRequire(ctx, single, i + 1, indirect)
  }
}

function addGoRequire(ctx: ParseContext, spec: string, line: number, indirect: boolean): void {
  const [module, version] = spec.split(/\s+/)
  if (!module || !version || !/^v\d/.test(version)) return
  ctx.add({
    ecosystem: 'Go',
    name: module.replace(/^"|"$/g, ''),
    version,
    exact: true,
    line,
    direct: !indirect,
    dev: false,
  })
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** A complete JSON string literal, optionally followed by `:` (an object key). */
const JSON_LITERAL = /^"(?:[^"\\]|\\.)*":?$/

/**
 * 1-based line lookups for lock-file keys. Each index is built lazily in one
 * pass over the file, so a parse costs O(file size + entries) rather than a
 * scan from the start of the file per package (quadratic on large locks).
 * Exported for tests.
 */
export class LineIndex {
  readonly #content: string
  #starts: number[] | undefined
  /** JSON string literal as written → offset of its first occurrence. */
  #jsonStrings: Map<string, number> | undefined
  /** JSON string literal directly followed by `:` → offset of its first such occurrence. */
  #jsonKeys: Map<string, number> | undefined
  /** YAML mapping key as written at the start of a line (quotes kept) → first line. */
  #yamlKeys: Map<string, number> | undefined

  constructor(content: string) {
    this.#content = content
  }

  /**
   * Line of the first occurrence of `needle` in a JSON document. A complete
   * string literal (`"lodash"`), optionally followed by `:` (`"lodash":`), is
   * answered from an index of the document's string tokens; any other needle
   * is searched for directly.
   */
  find(needle: string): number | undefined {
    if (JSON_LITERAL.test(needle)) {
      if (!this.#jsonStrings || !this.#jsonKeys) this.#indexJson()
      const index = needle.endsWith(':') ? this.#jsonKeys!.get(needle.slice(0, -1)) : this.#jsonStrings!.get(needle)
      return index === undefined ? undefined : this.#lineOf(index)
    }
    const index = this.#content.indexOf(needle)
    return index < 0 ? undefined : this.#lineOf(index)
  }

  /**
   * First line whose YAML mapping key, as written, is exactly `key`: pass a
   * quoted key with its quotes (`'/a@1.0.0(b@2)'`, `"a@npm:^1"`).
   */
  yamlKey(key: string): number | undefined {
    if (!this.#yamlKeys) this.#indexYaml()
    return this.#yamlKeys!.get(key)
  }

  #indexJson(): void {
    const content = this.#content
    const strings = new Map<string, number>()
    const keys = new Map<string, number>()
    let open = content.indexOf('"')
    while (open >= 0) {
      let close = content.indexOf('"', open + 1)
      while (close >= 0 && isEscapedAt(content, close)) close = content.indexOf('"', close + 1)
      if (close < 0) break
      const literal = content.slice(open, close + 1)
      if (!strings.has(literal)) strings.set(literal, open)
      if (content.charCodeAt(close + 1) === 0x3a && !keys.has(literal)) keys.set(literal, open)
      open = content.indexOf('"', close + 1)
    }
    this.#jsonStrings = strings
    this.#jsonKeys = keys
  }

  #indexYaml(): void {
    const content = this.#content
    const keys = new Map<string, number>()
    let line = 1
    for (let start = 0; start <= content.length; line++) {
      let end = content.indexOf('\n', start)
      if (end < 0) end = content.length
      let body = start
      while (body < end && WHITESPACE.test(content[body]!)) body++
      const key = yamlKeyAt(content, body, end)
      if (key !== undefined && !keys.has(key)) keys.set(key, line)
      start = end + 1
    }
    this.#yamlKeys = keys
  }

  #lineOf(index: number): number {
    if (!this.#starts) {
      this.#starts = [0]
      for (let i = this.#content.indexOf('\n'); i >= 0; i = this.#content.indexOf('\n', i + 1)) this.#starts.push(i + 1)
    }
    const starts = this.#starts
    let lo = 0
    let hi = starts.length - 1
    while (lo < hi) {
      const mid = (lo + hi + 1) >>> 1
      if (starts[mid]! <= index) lo = mid
      else hi = mid - 1
    }
    return lo + 1
  }
}

const WHITESPACE = /\s/

/** Whether the character at `index` is escaped by an odd run of backslashes. */
function isEscapedAt(text: string, index: number): boolean {
  let backslashes = 0
  for (let i = index - 1; i >= 0 && text.charCodeAt(i) === 0x5c; i--) backslashes++
  return backslashes % 2 === 1
}

/**
 * The mapping key a YAML line starting at `body` declares, as written: a
 * quoted key with its quotes, or plain text up to the `:` that ends it.
 */
function yamlKeyAt(content: string, body: number, end: number): string | undefined {
  const quote = content[body]
  if (quote === "'") {
    for (let i = content.indexOf("'", body + 1); i >= 0 && i < end; i = content.indexOf("'", i + 2)) {
      if (content[i + 1] !== "'") return content.slice(body, i + 1)
    }
    return undefined
  }
  if (quote === '"') {
    let i = content.indexOf('"', body + 1)
    while (i >= 0 && i < end && isEscapedAt(content, i)) i = content.indexOf('"', i + 1)
    return i >= 0 && i < end ? content.slice(body, i + 1) : undefined
  }
  for (let i = content.indexOf(':', body); i >= 0 && i < end; i = content.indexOf(':', i + 1)) {
    if (i + 1 >= end || WHITESPACE.test(content[i + 1]!)) return content.slice(body, i)
  }
  return undefined
}

/** Parse a JSON lock or manifest; anything but an object root is a warning. */
function parseJson(ctx: ParseContext): Record<string, unknown> | undefined {
  let value: unknown
  try {
    value = JSON.parse(ctx.file.content)
  } catch (error) {
    ctx.warn(`invalid JSON (${error instanceof Error ? error.message : String(error)})`)
    return undefined
  }
  if (!isRecord(value)) {
    ctx.warn('expected a JSON object at the top level')
    return undefined
  }
  return value
}

/**
 * Parse a YAML lock; anything but a mapping root is a warning. Lock files are
 * read with {@link readLockYaml} first: the general parser needs over a second
 * per few megabytes, all of it blocking the event loop.
 */
async function parseYamlDoc(ctx: ParseContext): Promise<Record<string, unknown> | undefined> {
  const fast = await readLockYaml(ctx.file.content)
  if (fast) return fast
  let value: unknown
  try {
    // Lock files never need aliases; a small cap defeats alias-expansion bombs.
    value = parseYaml(ctx.file.content, { maxAliasCount: 100, uniqueKeys: false })
  } catch (error) {
    ctx.warn(`invalid YAML (${error instanceof Error ? error.message.split('\n')[0] : String(error)})`)
    return undefined
  }
  if (!isRecord(value)) {
    ctx.warn('expected a YAML mapping at the top level')
    return undefined
  }
  return value
}

/** Thrown inside {@link readLockYaml} for input outside the subset it reads. */
const UNSUPPORTED = Symbol('unsupported YAML')

/** Plain scalars the YAML core schema resolves to something other than a string. */
const NON_STRING_PLAIN =
  /^(?:~|null|Null|NULL|true|True|TRUE|false|False|FALSE|[-+]?(?:\.[0-9]+|[0-9]+(?:\.[0-9]*)?)(?:[eE][-+]?[0-9]+)?|0o[0-7]+|0x[0-9a-fA-F]+|[-+]?\.(?:inf|Inf|INF)|\.nan|\.NaN|\.NAN)$/

type YamlFrame =
  | { readonly indent: number; readonly map: Record<string, unknown> }
  | { readonly indent: number; readonly seq: unknown[] }

/**
 * Reader for the block YAML subset lock files are written in (pnpm, yarn
 * berry): nested block mappings, block sequences of scalars, plain and quoted
 * single-line scalars, and single-line flow collections. Anything else
 * (anchors, tags, block or multi-line scalars, comments after values,
 * several documents, …) returns `undefined` so the caller falls back to the
 * full parser. On input it accepts, the result equals `yaml.parse` with the
 * core schema. Exported for tests.
 */
export async function readLockYaml(content: string): Promise<Record<string, unknown> | undefined> {
  try {
    return await readLockYamlOrThrow(content)
  } catch (error) {
    if (error === UNSUPPORTED) return undefined
    throw error
  }
}

async function readLockYamlOrThrow(content: string): Promise<Record<string, unknown>> {
  const root: Record<string, unknown> = {}
  const stack: YamlFrame[] = [{ indent: 0, map: root }]
  /** A `key:` with no inline value, waiting to learn whether a nested block follows. */
  let open: { readonly map: Record<string, unknown>; readonly key: string; readonly indent: number } | undefined
  let lineNo = 0
  for (let start = 0; start < content.length; ) {
    if (++lineNo % (YIELD_EVERY_ENTRIES * 8) === 0) await yieldToEventLoop()
    let end = content.indexOf('\n', start)
    if (end < 0) end = content.length
    const lineStart = start
    start = end + 1
    if (content.charCodeAt(end - 1) === 0x0d) end--
    let bodyStart = lineStart
    while (bodyStart < end && content.charCodeAt(bodyStart) === 0x20) bodyStart++
    if (bodyStart === end) continue
    const body = content.slice(bodyStart, end)
    if (body.includes('\t') || body.includes('\r')) throw UNSUPPORTED
    if (body.startsWith('#')) continue
    const indent = bodyStart - lineStart
    if (indent === 0 && (body.startsWith('---') || body.startsWith('...') || body.startsWith('%'))) throw UNSUPPORTED
    const item = body === '-' || body.startsWith('- ')

    if (open) {
      if (indent > open.indent || (indent === open.indent && item)) {
        const frame: YamlFrame = item ? { indent, seq: [] } : { indent, map: {} }
        open.map[open.key] = 'seq' in frame ? frame.seq : frame.map
        stack.push(frame)
      }
      open = undefined
    }
    let top = stack[stack.length - 1]!
    while (top.indent > indent || (top.indent === indent && 'seq' in top && !item)) {
      stack.pop()
      top = stack[stack.length - 1]!
    }
    if (top.indent !== indent) throw UNSUPPORTED

    if ('seq' in top) {
      if (!item || body === '-') throw UNSUPPORTED
      top.seq.push(readInlineValue(body.slice(2).trim()))
      continue
    }
    if (item) throw UNSUPPORTED
    const { key, rest } = readBlockKey(body)
    if (key === '__proto__' || key === '<<') throw UNSUPPORTED
    if (rest === '') {
      top.map[key] = null
      open = { map: top.map, key, indent }
    } else {
      top.map[key] = readInlineValue(rest)
    }
  }
  return root
}

/** `key: rest` → the key and the trimmed text after `:`. */
function readBlockKey(body: string): { key: string; rest: string } {
  let key: string
  let after: number
  if (body[0] === "'" || body[0] === '"') {
    const quoted = readQuoted(body, 0)
    key = quoted.value
    after = quoted.end
    while (body[after] === ' ') after++
    if (body[after] !== ':') throw UNSUPPORTED
  } else {
    if ('-?:,[]{}#&*!|>%@`'.includes(body[0]!)) throw UNSUPPORTED
    const colon = body.search(/:(?: |$)/)
    if (colon < 0) throw UNSUPPORTED
    key = body.slice(0, colon).trimEnd()
    if (key.includes(' #') || NON_STRING_PLAIN.test(key)) throw UNSUPPORTED
    after = colon
  }
  const next = body[after + 1]
  if (next !== undefined && next !== ' ') throw UNSUPPORTED
  return { key, rest: body.slice(after + 1).trim() }
}

/** A scalar or flow collection that fills the rest of a line. */
function readInlineValue(text: string): unknown {
  const first = text[0]
  if (first === "'" || first === '"' || first === '{' || first === '[') {
    const { value, end } = first === '{' || first === '[' ? readFlow(text, 0) : readQuoted(text, 0)
    if (text.slice(end).trim() !== '') throw UNSUPPORTED
    return value
  }
  if (first === undefined || '#&*!|>%@`,]}'.includes(first) || /^[-?:](?: |$)/.test(text)) throw UNSUPPORTED
  if (text.includes(' #') || text.includes(': ') || text.endsWith(':')) throw UNSUPPORTED
  return resolvePlain(text)
}

function resolvePlain(text: string): unknown {
  if (!NON_STRING_PLAIN.test(text)) return text
  if (/^[-+]?[0-9]+$/.test(text)) return Number.parseInt(text, 10)
  if (/^(?:true|True|TRUE)$/.test(text)) return true
  if (/^(?:false|False|FALSE)$/.test(text)) return false
  throw UNSUPPORTED
}

/** A single-line quoted scalar starting at `start`; `end` is just past the closing quote. */
function readQuoted(text: string, start: number): { value: string; end: number } {
  if (text[start] === "'") {
    let value = ''
    let from = start + 1
    for (;;) {
      const quote = text.indexOf("'", from)
      if (quote < 0) throw UNSUPPORTED
      value += text.slice(from, quote)
      if (text[quote + 1] !== "'") return { value, end: quote + 1 }
      value += "'"
      from = quote + 2
    }
  }
  let close = text.indexOf('"', start + 1)
  while (close >= 0 && isEscapedAt(text, close)) close = text.indexOf('"', close + 1)
  if (close < 0) throw UNSUPPORTED
  const raw = text.slice(start + 1, close)
  const value = raw.replace(/\\(.)/g, (_, ch: string) => {
    const unescaped = DOUBLE_QUOTED_ESCAPES[ch]
    if (unescaped === undefined) throw UNSUPPORTED
    return unescaped
  })
  return { value, end: close + 1 }
}

const DOUBLE_QUOTED_ESCAPES: Readonly<Record<string, string>> = {
  '\\': '\\',
  '"': '"',
  '/': '/',
  n: '\n',
  t: '\t',
  r: '\r',
  '0': '\0',
}

/** A single-line flow mapping or sequence starting at `start`. */
function readFlow(text: string, start: number): { value: unknown; end: number } {
  const isMap = text[start] === '{'
  const close = isMap ? '}' : ']'
  const map: Record<string, unknown> = {}
  const seq: unknown[] = []
  let i = skipSpaces(text, start + 1)
  while (text[i] !== close) {
    if (isMap) {
      const key = readFlowScalar(text, i)
      if (typeof key.value !== 'string' || key.value === '__proto__' || key.value === '<<') throw UNSUPPORTED
      i = skipSpaces(text, key.end)
      if (text[i] !== ':') throw UNSUPPORTED
      const value = readFlowScalar(text, skipSpaces(text, i + 1))
      map[key.value] = value.value
      i = skipSpaces(text, value.end)
    } else {
      const value = readFlowScalar(text, i)
      seq.push(value.value)
      i = skipSpaces(text, value.end)
      if (text[i] === ':') throw UNSUPPORTED
    }
    if (text[i] === ',') {
      i = skipSpaces(text, i + 1)
      if (text[i] === close) throw UNSUPPORTED
    } else if (text[i] !== close) {
      throw UNSUPPORTED
    }
  }
  return { value: isMap ? map : seq, end: i + 1 }
}

/** A scalar or nested collection inside a flow collection. */
function readFlowScalar(text: string, start: number): { value: unknown; end: number } {
  const first = text[start]
  if (first === undefined) throw UNSUPPORTED
  if (first === '{' || first === '[') return readFlow(text, start)
  if (first === "'" || first === '"') return readQuoted(text, start)
  if ('#&*!|>%@`,]}:?-'.includes(first)) throw UNSUPPORTED
  let i = start
  for (; i < text.length; i++) {
    const ch = text[i]!
    if (ch === ',' || ch === '[' || ch === ']' || ch === '{' || ch === '}') break
    if (ch === ':' && (i + 1 === text.length || ' ,[]{}'.includes(text[i + 1]!))) break
    if (ch === '#' && text[i - 1] === ' ') throw UNSUPPORTED
  }
  const plain = text.slice(start, i).trim()
  if (plain === '') throw UNSUPPORTED
  return { value: resolvePlain(plain), end: i }
}

function skipSpaces(text: string, from: number): number {
  let i = from
  while (text[i] === ' ') i++
  return i
}

function isExactSemver(version: string): boolean {
  return /^v?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/.test(version)
}

function isValidNpmName(name: string): boolean {
  return /^(?:@[a-z0-9][\w.-]*\/)?[a-z0-9_.][\w.-]*$/i.test(name) && name.length <= 214
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function asRecord(value: unknown): Record<string, unknown> {
  return isRecord(value) ? value : {}
}

function baseName(path: string): string {
  const slash = path.lastIndexOf('/')
  return slash < 0 ? path : path.slice(slash + 1)
}

function dirName(path: string): string {
  const slash = path.lastIndexOf('/')
  return slash < 0 ? '' : path.slice(0, slash)
}

function compare(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0
}
