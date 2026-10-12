/**
 * Dependency extraction from lock files and manifests. Parsers are tolerant:
 * a malformed file yields a warning and whatever could be read, never a throw.
 * Lock files win over their sibling manifests because they pin exact versions.
 */

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
}

const NPM_LOCKS = ['package-lock.json', 'npm-shrinkwrap.json', 'pnpm-lock.yaml', 'yarn.lock'] as const
const MAX_PARSE_CHARS = 32 * 1024 * 1024
const YIELD_EVERY = 50

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

  for (const file of snapshot.files.values()) {
    if (++count % YIELD_EVERY === 0) await yieldToEventLoop()
    const name = baseName(file.path)
    const dir = dirName(file.path)
    const sibling = (n: string): SnapshotFile | undefined => snapshot.files.get(dir === '' ? n : `${dir}/${n}`)
    const parser = pickParser(name, n => sibling(n) !== undefined)
    if (!parser) continue
    if (file.content.length > MAX_PARSE_CHARS) {
      warnings.push(`${file.path}: skipped, file too large to parse`)
      continue
    }
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
    }
    try {
      parser(ctx)
    } catch (error) {
      ctx.warn(`could not parse (${error instanceof Error ? error.message : String(error)})`)
    }
  }

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

function pickParser(name: string, sibling: (name: string) => boolean): ((ctx: ParseContext) => void) | undefined {
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

function parsePackageLock(ctx: ParseContext): void {
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
  const lines = new LineFinder(ctx.file.content)

  if (isRecord(json.packages)) {
    // lockfileVersion 2/3: flat map keyed by install path.
    for (const [key, raw] of Object.entries(json.packages)) {
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
  const visit = (deps: unknown, depth: number): void => {
    if (!isRecord(deps) || depth > 64) return
    for (const [name, raw] of Object.entries(deps)) {
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
      visit(raw.dependencies, depth + 1)
    }
  }
  if (!isRecord(json.dependencies)) {
    ctx.warn('no "packages" or "dependencies" section')
    return
  }
  visit(json.dependencies, 0)
}

function parsePnpmLock(ctx: ParseContext): void {
  const doc = parseYamlDoc(ctx)
  if (!isRecord(doc)) return
  const lines = new LineFinder(ctx.file.content)

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
  for (const [key, raw] of Object.entries(packages)) {
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
      line: lines.findLineStartingWith(key) ?? lines.findLineStartingWith(`'${key}'`),
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

function parseYarnLock(ctx: ParseContext): void {
  const content = ctx.file.content
  if (/^__metadata:/m.test(content)) {
    parseYarnBerry(ctx)
    return
  }
  // Classic v1: unindented `"a@^1", a@~1.2:` headers, indented `version "1.2.3"`.
  const declared = declaredNpmDeps(ctx)
  const lines = content.split(/\r?\n/)
  let specs: YarnSpec[] = []
  let headerLine = 0
  let found = 0
  for (let i = 0; i < lines.length; i++) {
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

function parseYarnBerry(ctx: ParseContext): void {
  const doc = parseYamlDoc(ctx)
  if (!isRecord(doc)) return
  const declared = declaredNpmDeps(ctx)
  const lines = new LineFinder(ctx.file.content)
  for (const [header, raw] of Object.entries(doc)) {
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
        line: lines.findLineStartingWith(`"${header}"`) ?? lines.findLineStartingWith(header),
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
  const lines = new LineFinder(ctx.file.content)
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

function parseRequirements(ctx: ParseContext): void {
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
    if (line === '' || line.startsWith('-')) continue // -r, -c, -e, --hash, --index-url …
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

function parsePipfileLock(ctx: ParseContext): void {
  const json = parseJson(ctx)
  if (!isRecord(json)) return
  const lines = new LineFinder(ctx.file.content)
  let found = false
  for (const [section, dev] of [
    ['default', false],
    ['develop', true],
  ] as const) {
    for (const [name, raw] of Object.entries(asRecord(json[section]))) {
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

function parseTomlPackages(kind: 'poetry' | 'uv' | 'cargo'): (ctx: ParseContext) => void {
  return ctx => {
    const packages = readTomlPackageBlocks(ctx.file.content)
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
function readTomlPackageBlocks(content: string): TomlPackage[] {
  const packages: TomlPackage[] = []
  let current: TomlPackage | undefined
  const lines = content.split(/\r?\n/)
  for (let i = 0; i < lines.length; i++) {
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

/** Finds the 1-based line of the first occurrence of a needle, caching line starts. */
class LineFinder {
  readonly #content: string
  #starts: number[] | undefined

  constructor(content: string) {
    this.#content = content
  }

  find(needle: string): number | undefined {
    const index = this.#content.indexOf(needle)
    return index < 0 ? undefined : this.#lineOf(index)
  }

  /** Line whose trimmed text starts with `prefix` (YAML mapping keys). */
  findLineStartingWith(prefix: string): number | undefined {
    let from = 0
    for (;;) {
      const index = this.#content.indexOf(prefix, from)
      if (index < 0) return undefined
      const lineStart = this.#content.lastIndexOf('\n', index - 1) + 1
      if (this.#content.slice(lineStart, index).trim() === '') return this.#lineOf(index)
      from = index + 1
    }
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

/** Parse a YAML lock; anything but a mapping root is a warning. */
function parseYamlDoc(ctx: ParseContext): Record<string, unknown> | undefined {
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
