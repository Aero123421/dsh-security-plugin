/**
 * Ground truth for the intentionally vulnerable fixture apps under
 * `tests/fixtures/apps/<app>/`. Each app's `expected.json` lists planted
 * findings (with the detectors expected to catch them) and negative controls
 * that look risky but are safe and must not be reported. The bench scans each
 * app directory as its own workspace and scores reported findings against
 * these entries with {@link matchesExpected}.
 */

import { cp, mkdir, readdir, readFile, writeFile } from 'node:fs/promises'
import { join, relative, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { FINDING_CATEGORIES, type FindingCategory, SEVERITIES, type Severity } from '../src/shared/domain.ts'

/** Analyzers a planted finding can be attributed to. `ai` covers logic flaws only a reviewer can see. */
export const FIXTURE_DETECTORS = ['sast', 'secrets', 'dependency', 'routes', 'ai'] as const
export type FixtureDetector = (typeof FIXTURE_DETECTORS)[number]

/** Directory holding one sub-directory per fixture app. */
export const FIXTURE_APPS_DIR = resolve(fileURLToPath(new URL('../tests/fixtures/apps', import.meta.url)))

/** A planted vulnerability. `path` is relative to the app directory. */
export interface FixtureFinding {
  readonly id: string
  readonly title: string
  readonly category: FindingCategory
  readonly cwe?: string
  readonly severity: Severity
  readonly path: string
  /** 1-based key line: the sink or the missing check. */
  readonly line: number
  /** Exact substring present on `line`. */
  readonly anchor: string
  readonly detectableBy: readonly FixtureDetector[]
  readonly notes: string
}

/** Code that looks risky but is safe; reporting it is a false positive. */
export interface FixtureNegative {
  readonly id: string
  readonly path: string
  readonly line: number
  readonly anchor: string
  readonly description: string
  readonly category: FindingCategory
}

export interface FixtureManifest {
  readonly app: string
  readonly language: string
  readonly frameworks: readonly string[]
  readonly findings: readonly FixtureFinding[]
  readonly negatives: readonly FixtureNegative[]
  /** Absolute path of the app directory (added by the loader, not stored in the JSON). */
  readonly dir: string
}

/** The location and classification of one reported finding, workspace-relative to the app directory. */
export interface ReportedLocation {
  readonly path: string
  readonly startLine: number
  readonly endLine: number
  readonly category: string
  readonly cwe?: string
}

const MANIFEST_FILE = 'expected.json'
const MANIFEST_FIELDS = ['app', 'language', 'frameworks', 'findings', 'negatives'] as const
const FINDING_FIELDS = [
  'id',
  'title',
  'category',
  'cwe',
  'severity',
  'path',
  'line',
  'anchor',
  'detectableBy',
  'notes',
] as const
const NEGATIVE_FIELDS = ['id', 'path', 'line', 'anchor', 'description', 'category'] as const
const ID_PATTERN = /^[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+$/
const CWE_PATTERN = /^CWE-[1-9]\d*$/

/**
 * Load and validate every `<root>/<app>/expected.json`, sorted by app name.
 * Directories without a manifest are skipped. Throws on unreadable or invalid
 * manifests (listing every problem) and on ids repeated across apps.
 */
export async function loadFixtures(root: string = FIXTURE_APPS_DIR): Promise<FixtureManifest[]> {
  const base = resolve(root)
  const entries = await readdir(base, { withFileTypes: true })
  const names = entries
    .filter(entry => entry.isDirectory())
    .map(entry => entry.name)
    .sort()
  const manifests: FixtureManifest[] = []
  for (const name of names) {
    const dir = join(base, name)
    const file = join(dir, MANIFEST_FILE)
    let text: string
    try {
      text = await readFile(file, 'utf8')
    } catch (error) {
      if (isNotFound(error)) continue
      throw error
    }
    let json: unknown
    try {
      json = JSON.parse(text)
    } catch (error) {
      throw new Error(`${file}: invalid JSON (${error instanceof Error ? error.message : String(error)})`)
    }
    manifests.push(parseFixtureManifest(json, dir, file))
  }
  const owners = new Map<string, string>()
  for (const manifest of manifests) {
    for (const entry of [...manifest.findings, ...manifest.negatives]) {
      const owner = owners.get(entry.id)
      if (owner !== undefined && owner !== manifest.app)
        throw new Error(`fixture id "${entry.id}" is used by both ${owner} and ${manifest.app}`)
      owners.set(entry.id, manifest.app)
    }
  }
  return manifests
}

/**
 * Validate one parsed manifest. `dir` is the app directory; its base name must
 * equal the manifest's `app`. Throws one error listing every problem.
 */
export function parseFixtureManifest(json: unknown, dir: string, source = join(dir, MANIFEST_FILE)): FixtureManifest {
  const problems: string[] = []
  if (!isRecord(json)) throw new Error(`${source}: invalid fixture manifest:\n  - expected a JSON object`)
  const top = new FieldReader(json, 'manifest', problems, MANIFEST_FIELDS)
  const app = top.string('app')
  const dirName = resolve(dir).split(/[\\/]/).pop() ?? ''
  if (app !== '' && app !== dirName) top.fail(`"app" is "${app}" but the directory is "${dirName}"`)
  const language = top.string('language')
  const frameworks = top.stringArray('frameworks')

  const findings = top.array('findings').map((raw, index): FixtureFinding => {
    const r = FieldReader.of(raw, `findings[${index}]`, problems, FINDING_FIELDS)
    const cwe = r.optionalString('cwe')
    if (cwe !== undefined && !CWE_PATTERN.test(cwe)) r.fail(`"cwe" must look like "CWE-79", got "${cwe}"`)
    const finding = {
      id: r.id(),
      title: r.string('title'),
      category: r.oneOf('category', FINDING_CATEGORIES),
      severity: r.oneOf('severity', SEVERITIES),
      path: r.path(),
      line: r.line(),
      anchor: r.string('anchor'),
      detectableBy: r.detectors(),
      notes: r.string('notes'),
    }
    return cwe === undefined ? finding : { ...finding, cwe }
  })

  const negatives = top.array('negatives').map((raw, index): FixtureNegative => {
    const r = FieldReader.of(raw, `negatives[${index}]`, problems, NEGATIVE_FIELDS)
    return {
      id: r.id(),
      path: r.path(),
      line: r.line(),
      anchor: r.string('anchor'),
      description: r.string('description'),
      category: r.oneOf('category', FINDING_CATEGORIES),
    }
  })

  const seen = new Set<string>()
  for (const entry of [...findings, ...negatives]) {
    if (entry.id === '') continue
    if (seen.has(entry.id)) problems.push(`duplicate id "${entry.id}"`)
    seen.add(entry.id)
  }

  if (problems.length > 0)
    throw new Error(`${source}: invalid fixture manifest:\n${problems.map(p => `  - ${p}`).join('\n')}`)
  return { app, language, frameworks, findings, negatives, dir: resolve(dir) }
}

/**
 * Whether a reported finding matches an expected entry (a planted finding or a
 * negative control): same path, the expected line within `tolerance` lines of
 * the reported start line or inside the reported range, and the same category
 * or the same CWE.
 */
export function matchesExpected(
  expected: Pick<FixtureFinding, 'path' | 'line' | 'category' | 'cwe'>,
  reported: ReportedLocation,
  tolerance = 3,
): boolean {
  if (normalizePath(expected.path) !== normalizePath(reported.path)) return false
  const start = Math.min(reported.startLine, reported.endLine)
  const end = Math.max(reported.startLine, reported.endLine)
  const near = Math.abs(reported.startLine - expected.line) <= tolerance
  const inside = expected.line >= start && expected.line <= end
  if (!near && !inside) return false
  if (reported.category === expected.category) return true
  return (
    expected.cwe !== undefined &&
    reported.cwe !== undefined &&
    normalizeCwe(expected.cwe) === normalizeCwe(reported.cwe)
  )
}

/**
 * Files in an app directory that describe the planted issues. They are left
 * out of every scanned copy so neither a model nor an analyzer can read the
 * answers.
 */
export const ANSWER_KEY_FILES: readonly string[] = [MANIFEST_FILE, 'README.md']

/**
 * Marker inside the fake credentials of the fixture apps. Provider-format
 * keys (`sk_live_…`) are stored split by this marker so the repository holds
 * no string in a real credential format; {@link materializeFixtureText}
 * removes it when a fixture is copied for scanning.
 */
export const FAKE_SECRET_SPLIT = '<<fake-split>>'

/** Fixture text as the scanners should see it (fake credentials joined). */
export function materializeFixtureText(text: string): string {
  return text.includes(FAKE_SECRET_SPLIT) ? text.split(FAKE_SECRET_SPLIT).join('') : text
}

/** Rewrite every file under `dir` that contains {@link FAKE_SECRET_SPLIT}. */
export async function materializeFixtureDir(dir: string): Promise<void> {
  for (const entry of await readdir(dir, { withFileTypes: true, recursive: true })) {
    if (!entry.isFile()) continue
    const file = join(entry.parentPath, entry.name)
    const text = await readFile(file, 'utf8')
    if (text.includes(FAKE_SECRET_SPLIT)) await writeFile(file, materializeFixtureText(text))
  }
}

/**
 * Copy one fixture app to `<destRoot>/<app>` without its answer keys, with
 * fake credentials materialized, and return the new directory. The copy is
 * what gets registered as a workspace.
 */
export async function copyFixtureApp(
  manifest: Pick<FixtureManifest, 'app' | 'dir'>,
  destRoot: string,
): Promise<string> {
  const dest = join(resolve(destRoot), manifest.app)
  await mkdir(dest, { recursive: true })
  await cp(manifest.dir, dest, {
    recursive: true,
    filter: source => !ANSWER_KEY_FILES.includes(normalizePath(relative(manifest.dir, source))),
  })
  await materializeFixtureDir(dest)
  return dest
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/** Reads typed fields from one JSON object, recording a problem for each invalid value. */
class FieldReader {
  readonly #obj: Readonly<Record<string, unknown>>
  readonly #where: string
  readonly #problems: string[]

  constructor(obj: Readonly<Record<string, unknown>>, where: string, problems: string[], allowed: readonly string[]) {
    this.#obj = obj
    this.#where = where
    this.#problems = problems
    for (const key of Object.keys(obj)) if (!allowed.includes(key)) this.fail(`unknown field "${key}"`)
  }

  /** A reader for an array element, which must itself be an object. */
  static of(raw: unknown, where: string, problems: string[], allowed: readonly string[]): FieldReader {
    if (isRecord(raw)) return new FieldReader(raw, where, problems, allowed)
    problems.push(`${where}: expected an object`)
    return new FieldReader({}, where, [], allowed)
  }

  fail(message: string): void {
    this.#problems.push(`${this.#where}: ${message}`)
  }

  string(key: string): string {
    const value = this.#obj[key]
    if (typeof value === 'string' && value.trim() !== '') return value
    this.fail(`"${key}" must be a non-empty string`)
    return ''
  }

  optionalString(key: string): string | undefined {
    return this.#obj[key] === undefined ? undefined : this.string(key)
  }

  id(): string {
    const id = this.string('id')
    if (id !== '' && !ID_PATTERN.test(id)) this.fail(`"id" must look like "ES-01" or "ES-N1", got "${id}"`)
    return id
  }

  /** A workspace-relative POSIX path that stays inside the app directory. */
  path(): string {
    const path = this.string('path')
    if (path === '') return path
    if (path.startsWith('/') || /^[A-Za-z]:/.test(path) || path.includes('\\'))
      this.fail(`"path" must be relative with "/" separators, got "${path}"`)
    else if (path.split('/').some(segment => segment === '' || segment === '.' || segment === '..'))
      this.fail(`"path" must be normalized and stay inside the app, got "${path}"`)
    return path
  }

  line(): number {
    const value = this.#obj.line
    if (typeof value === 'number' && Number.isInteger(value) && value >= 1) return value
    this.fail('"line" must be a positive integer')
    return 1
  }

  oneOf<T extends string>(key: string, values: readonly T[]): T {
    const value = this.#obj[key]
    if (typeof value === 'string' && (values as readonly string[]).includes(value)) return value as T
    this.fail(`"${key}" must be one of ${values.join(', ')}; got ${JSON.stringify(value)}`)
    return values[0]!
  }

  array(key: string): unknown[] {
    const value = this.#obj[key]
    if (Array.isArray(value)) return value
    this.fail(`"${key}" must be an array`)
    return []
  }

  stringArray(key: string): string[] {
    const items = this.array(key)
    if (items.some(item => typeof item !== 'string' || item.trim() === ''))
      this.fail(`"${key}" must contain only non-empty strings`)
    return items.filter((item): item is string => typeof item === 'string')
  }

  detectors(): FixtureDetector[] {
    const items = this.array('detectableBy')
    if (items.length === 0) this.fail('"detectableBy" must list at least one detector')
    const out: FixtureDetector[] = []
    for (const item of items) {
      if (typeof item !== 'string' || !(FIXTURE_DETECTORS as readonly string[]).includes(item)) {
        this.fail(`"detectableBy" entries must be one of ${FIXTURE_DETECTORS.join(', ')}; got ${JSON.stringify(item)}`)
        continue
      }
      if (out.includes(item as FixtureDetector)) this.fail(`"detectableBy" lists "${item}" twice`)
      else out.push(item as FixtureDetector)
    }
    return out
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function isNotFound(error: unknown): boolean {
  return isRecord(error) && error.code === 'ENOENT'
}

function normalizePath(path: string): string {
  return path.replace(/\\/g, '/').replace(/^(?:\.\/)+/, '')
}

function normalizeCwe(cwe: string): string {
  return cwe.trim().toUpperCase()
}
