/**
 * OSV.dev client. Only package ecosystems, names, and versions leave the
 * machine; never source code or file paths. Network problems degrade to
 * warnings so a scan still completes offline.
 */

import { z } from 'zod'
import type { Severity } from '../../shared/domain.ts'
import type { Dependency, Ecosystem, Signal } from './types.ts'
import { isSensitivePath } from './secrets.ts'

export interface OsvQueryOptions {
  /** Base URL, default `https://api.osv.dev`. */
  readonly endpoint: string
  readonly fetch: typeof fetch
  readonly signal?: AbortSignal
  /** Same gitignore-style disclosure policy as the workspace tools. */
  readonly withheldGlobs?: readonly string[]
  /** Queries per `querybatch` request (max 1000). */
  readonly batchSize?: number
  /** Per-request timeout. */
  readonly timeoutMs?: number
}

export interface OsvQueryResult {
  signals: Signal[]
  warnings: string[]
  /** Unique package versions for which OSV answered. */
  queried: number
  /** Eligible unique package versions, including requests that failed. */
  requested: number
  /** Dependency declarations excluded because versions are not exact or disclosure is withheld. */
  skipped: number
}

/** Where a vulnerable package was declared; the first entry becomes the signal location. */
export interface OsvPackageRef {
  readonly ecosystem: Ecosystem | string
  readonly name: string
  readonly version: string
  readonly manifest: string
  readonly line?: number
}

const DEFAULT_ENDPOINT = 'https://api.osv.dev'
const MAX_BATCH = 1000
const DETAIL_CONCURRENCY = 4
const MAX_DETAIL_FETCHES = 300
const MAX_PAGES_PER_QUERY = 10
const MAX_RESPONSE_BYTES = 32 * 1024 * 1024
const DEFAULT_TIMEOUT_MS = 30_000
const OSV_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._:-]{1,127}$/

// ---------------------------------------------------------------------------
// Response schemas (untrusted network input; unknown keys are dropped)
// ---------------------------------------------------------------------------

const osvEventSchema = z.object({
  introduced: z.string().optional(),
  fixed: z.string().optional(),
  last_affected: z.string().optional(),
  limit: z.string().optional(),
})

const osvAffectedSchema = z.object({
  package: z.object({ ecosystem: z.string().optional(), name: z.string().optional() }).optional(),
  ranges: z.array(z.object({ type: z.string().optional(), events: z.array(osvEventSchema).optional() })).optional(),
  database_specific: z.record(z.string(), z.unknown()).optional(),
  ecosystem_specific: z.record(z.string(), z.unknown()).optional(),
})

/** Subset of the OSV schema this module reads. */
export const osvVulnSchema = z.object({
  id: z.string(),
  summary: z.string().optional(),
  details: z.string().optional(),
  aliases: z.array(z.string()).optional(),
  withdrawn: z.string().optional(),
  severity: z.array(z.object({ type: z.string(), score: z.string() })).optional(),
  affected: z.array(osvAffectedSchema).optional(),
  references: z.array(z.object({ type: z.string().optional(), url: z.string() })).optional(),
  database_specific: z.record(z.string(), z.unknown()).optional(),
})
export type OsvVuln = z.infer<typeof osvVulnSchema>

const batchResponseSchema = z.object({
  results: z.array(
    z.object({
      vulns: z.array(z.object({ id: z.string() })).optional(),
      next_page_token: z.string().optional(),
    }),
  ),
})

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/** OSV ecosystem identifier for a dependency ecosystem (they share spelling). */
export function toOsvEcosystem(ecosystem: Ecosystem): string {
  return ecosystem
}

/**
 * Look up exact dependency versions in OSV and turn each known vulnerability
 * into a `dependency` signal. Ranges (`exact: false`) are not queried.
 */
export async function queryOsv(deps: readonly Dependency[], options: OsvQueryOptions): Promise<OsvQueryResult> {
  const endpoint = (options.endpoint || DEFAULT_ENDPOINT).replace(/\/+$/, '')
  const batchSize = Math.max(1, Math.min(MAX_BATCH, Math.floor(options.batchSize ?? MAX_BATCH)))
  const warnings: string[] = []
  const http = new OsvHttp(options, warnings)

  // One query per unique package version; remember every place it was declared.
  const queries = new Map<string, { ecosystem: string; name: string; version: string; refs: OsvPackageRef[] }>()
  let skipped = 0
  for (const dep of deps) {
    if (!dep.exact || isSensitivePath(dep.manifest, options.withheldGlobs ?? [])) {
      skipped++
      continue
    }
    const version = queryVersion(dep)
    if (!version) {
      skipped++
      continue
    }
    const ecosystem = toOsvEcosystem(dep.ecosystem)
    const key = `${ecosystem}\0${dep.name}\0${version}`
    const entry = queries.get(key) ?? { ecosystem, name: dep.name, version, refs: [] }
    entry.refs.push({ ecosystem, name: dep.name, version: dep.version, manifest: dep.manifest, line: dep.line })
    queries.set(key, entry)
  }
  const entries = [...queries.values()]
  const vulnIdsByEntry = new Map<number, Set<string>>()
  let queried = 0

  for (let offset = 0; offset < entries.length; offset += batchSize) {
    options.signal?.throwIfAborted()
    const batch = entries.slice(offset, offset + batchSize)
    const body = {
      queries: batch.map(e => ({ package: { name: e.name, ecosystem: e.ecosystem }, version: e.version })),
    }
    const response = await http.postJson(`${endpoint}/v1/querybatch`, body, batchResponseSchema)
    if (!response) continue
    if (response.results.length !== batch.length) {
      warnings.push(`OSV returned ${response.results.length} results for ${batch.length} queries; batch ignored`)
      continue
    }
    queried += batch.length
    for (let i = 0; i < batch.length; i++) {
      const result = response.results[i]!
      const index = offset + i
      const ids = new Set((result.vulns ?? []).map(v => v.id))
      let token = result.next_page_token
      for (let page = 1; token && page <= MAX_PAGES_PER_QUERY; page++) {
        const entry = entries[index]!
        const next = await http.postJson(
          `${endpoint}/v1/querybatch`,
          {
            queries: [
              { package: { name: entry.name, ecosystem: entry.ecosystem }, version: entry.version, page_token: token },
            ],
          },
          batchResponseSchema,
        )
        if (!next) break
        if (next.results.length !== 1) {
          warnings.push(`OSV returned ${next.results.length} results for 1 pagination query; page ignored`)
          break
        }
        const nextResult = next.results[0]!
        for (const v of nextResult.vulns ?? []) ids.add(v.id)
        token = nextResult.next_page_token
        if (token && page === MAX_PAGES_PER_QUERY) {
          warnings.push(`OSV pagination for ${entry.name}@${entry.version} stopped after ${page + 1} pages`)
        }
      }
      if (ids.size > 0) vulnIdsByEntry.set(index, ids)
    }
  }

  // Fetch each distinct advisory once, a few at a time, up to a fixed cap.
  const uniqueIds = [...new Set([...vulnIdsByEntry.values()].flatMap(ids => [...ids]))]
  const allIds = uniqueIds.filter(id => OSV_ID_RE.test(id))
  if (allIds.length < uniqueIds.length) {
    warnings.push(`OSV returned ${uniqueIds.length - allIds.length} malformed advisory id(s); ignored`)
  }
  const toFetch = allIds.slice(0, MAX_DETAIL_FETCHES)
  if (allIds.length > toFetch.length) {
    warnings.push(
      `OSV reported ${allIds.length} advisories; details were fetched for the first ${MAX_DETAIL_FETCHES} only`,
    )
  }
  const details = new Map<string, OsvVuln>()
  await mapConcurrent(toFetch, DETAIL_CONCURRENCY, async id => {
    const vuln = await http.getJson(`${endpoint}/v1/vulns/${encodeURIComponent(id)}`, osvVulnSchema)
    if (vuln) details.set(id, vuln)
  })

  const signals: Signal[] = []
  for (const [index, ids] of vulnIdsByEntry) {
    const entry = entries[index]!
    const refs = sortRefs(entry.refs)
    for (const id of [...ids].sort()) {
      if (!OSV_ID_RE.test(id)) continue
      const vuln = details.get(id) ?? { id }
      if (vuln.withdrawn) continue
      signals.push(osvVulnToSignal(vuln, refs, 'osv'))
    }
  }
  signals.sort((a, b) => compare(a.location.path, b.location.path) || compare(a.ruleId, b.ruleId))
  return { signals, warnings, queried, requested: entries.length, skipped }
}

/**
 * Map one OSV advisory affecting one package version to a signal. `refs`
 * lists every manifest declaring that version; the first is the location.
 */
export function osvVulnToSignal(
  vuln: OsvVuln,
  refs: readonly OsvPackageRef[],
  analyzer: 'osv' | 'osv-scanner',
): Signal {
  const primary = refs[0]
  if (!primary) throw new Error('osvVulnToSignal requires at least one package reference')
  const { ecosystem, name, version } = primary
  const alias = preferredAlias(vuln)
  const label = alias && alias !== vuln.id ? `${alias} / ${vuln.id}` : vuln.id
  const summary = oneLine(vuln.summary ?? firstSentence(vuln.details) ?? '')
  const fixed = fixedVersions(vuln, ecosystem, name)
  const { severity, score } = osvSeverity(vuln)
  const others = refs.slice(1).map(ref => ref.manifest)

  const message =
    `${name}@${version} (${ecosystem}) is listed as affected by ${label}` +
    (summary ? `: ${summary}` : '.') +
    (summary && !/[.!?]$/.test(summary) ? '.' : '') +
    ' This is a known, publicly documented weakness in a third-party package your project depends on. ' +
    'Whether your code actually reaches the vulnerable functionality was not analyzed.' +
    (others.length > 0 ? ` The same version is also declared in ${others.slice(0, 5).join(', ')}.` : '')

  const recommendation =
    fixed.length > 0
      ? `Upgrade ${name} to a fixed version (${fixed.slice(0, 6).join(', ')}) or later, then regenerate the lock file.`
      : `No fixed version is listed for ${name}. Check the advisory for workarounds, consider replacing the ` +
        'package, or document why the affected functionality is not used.'

  return {
    analyzer,
    ruleId: vuln.id,
    kind: 'dependency',
    title: `${name}@${version}: ${alias ?? vuln.id}${summary ? ` — ${truncate(summary, 120)}` : ''}`,
    category: 'dependency',
    severity,
    confidence: 'high',
    cwe: cweOf(vuln),
    location: { path: primary.manifest, startLine: primary.line ?? 1, endLine: primary.line ?? 1 },
    snippet: `${name}@${version}`,
    message,
    recommendation,
    fingerprintParts: ['osv', vuln.id, ecosystem, name, version],
    references: referencesOf(vuln),
    metadata: {
      ecosystem,
      package: name,
      version,
      ...(alias ? { alias } : {}),
      ...(score !== undefined ? { cvssScore: score } : {}),
      ...(fixed.length > 0 ? { fixedVersions: fixed.join(', ') } : {}),
      ...(others.length > 0 ? { alsoDeclaredIn: others.slice(0, 20).join(', ') } : {}),
      reachability: 'not-analyzed',
    },
  }
}

// ---------------------------------------------------------------------------
// Severity and CVSS
// ---------------------------------------------------------------------------

/** Pick a severity: GHSA-style database label, then a CVSS v3 vector or number, else `medium`. */
export function osvSeverity(vuln: OsvVuln): { severity: Severity; score?: number } {
  const labelled =
    labelSeverity(vuln.database_specific?.severity) ??
    vuln.affected
      ?.map(a => labelSeverity(a.database_specific?.severity ?? a.ecosystem_specific?.severity))
      .find(Boolean)
  let best: number | undefined
  for (const entry of vuln.severity ?? []) {
    const numeric = Number(entry.score)
    const score =
      Number.isFinite(numeric) && /^\d+(?:\.\d+)?$/.test(entry.score.trim()) ? numeric : cvss3BaseScore(entry.score)
    if (score !== undefined && score >= 0 && score <= 10 && (best === undefined || score > best)) best = score
  }
  if (labelled) return { severity: labelled, ...(best !== undefined ? { score: best } : {}) }
  if (best !== undefined) return { severity: severityFromScore(best), score: best }
  return { severity: 'medium' }
}

/** CVSS qualitative rating (v3.x) mapped to finding severities; 0.0 maps to `info`. */
export function severityFromScore(score: number): Severity {
  if (score >= 9) return 'critical'
  if (score >= 7) return 'high'
  if (score >= 4) return 'medium'
  if (score > 0) return 'low'
  return 'info'
}

const CVSS3_WEIGHTS = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  AC: { L: 0.77, H: 0.44 },
  UI: { N: 0.85, R: 0.62 },
  CIA: { H: 0.56, L: 0.22, N: 0 },
} as const

/**
 * CVSS v3.0/v3.1 base score from a vector such as
 * `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` (9.8). Returns `undefined`
 * for anything that is not a complete, valid v3 base vector.
 */
export function cvss3BaseScore(vector: string): number | undefined {
  const parts = vector.trim().split('/')
  if (!/^CVSS:3\.[01]$/.test(parts[0] ?? '')) return undefined
  const metrics = new Map<string, string>()
  for (const part of parts.slice(1)) {
    const [key, value, extra] = part.split(':')
    if (!key || !value || extra !== undefined || metrics.has(key)) return undefined
    metrics.set(key, value)
  }
  const get = <T extends Record<string, number>>(table: T, key: string): number | undefined => {
    const value = metrics.get(key)
    return value !== undefined && Object.hasOwn(table, value) ? table[value] : undefined
  }
  const scope = metrics.get('S')
  if (scope !== 'U' && scope !== 'C') return undefined
  const changed = scope === 'C'
  const av = get(CVSS3_WEIGHTS.AV, 'AV')
  const ac = get(CVSS3_WEIGHTS.AC, 'AC')
  const ui = get(CVSS3_WEIGHTS.UI, 'UI')
  const pr = get(changed ? { N: 0.85, L: 0.68, H: 0.5 } : { N: 0.85, L: 0.62, H: 0.27 }, 'PR')
  const c = get(CVSS3_WEIGHTS.CIA, 'C')
  const i = get(CVSS3_WEIGHTS.CIA, 'I')
  const a = get(CVSS3_WEIGHTS.CIA, 'A')
  if (av === undefined || ac === undefined || ui === undefined || pr === undefined) return undefined
  if (c === undefined || i === undefined || a === undefined) return undefined

  const iss = 1 - (1 - c) * (1 - i) * (1 - a)
  const impact = changed ? 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 : 6.42 * iss
  if (impact <= 0) return 0
  const exploitability = 8.22 * av * ac * pr * ui
  return roundUp1(Math.min(changed ? 1.08 * (impact + exploitability) : impact + exploitability, 10))
}

/** CVSS v3.1 "Roundup": smallest one-decimal number ≥ input, robust to float error. */
function roundUp1(value: number): number {
  const scaled = Math.round(value * 100_000)
  return scaled % 10_000 === 0 ? scaled / 100_000 : (Math.floor(scaled / 10_000) + 1) / 10
}

function labelSeverity(value: unknown): Severity | undefined {
  if (typeof value !== 'string') return undefined
  switch (value.trim().toUpperCase()) {
    case 'CRITICAL':
      return 'critical'
    case 'HIGH':
      return 'high'
    case 'MODERATE':
    case 'MEDIUM':
      return 'medium'
    case 'LOW':
      return 'low'
    default:
      return undefined
  }
}

// ---------------------------------------------------------------------------
// Advisory details
// ---------------------------------------------------------------------------

/** Versions that fix the advisory for this exact package (registry ranges only, not git commits). */
export function fixedVersions(vuln: OsvVuln, ecosystem: string, name: string): string[] {
  const wanted = normalizeName(ecosystem, name)
  const fixed = new Set<string>()
  for (const affected of vuln.affected ?? []) {
    const pkg = affected.package
    if (!pkg?.name || normalizeName(pkg.ecosystem ?? ecosystem, pkg.name) !== wanted) continue
    if (pkg.ecosystem && baseEcosystem(pkg.ecosystem) !== baseEcosystem(ecosystem)) continue
    for (const range of affected.ranges ?? []) {
      if (range.type === 'GIT') continue
      for (const event of range.events ?? []) if (event.fixed) fixed.add(event.fixed)
    }
  }
  return [...fixed]
}

function preferredAlias(vuln: OsvVuln): string | undefined {
  const ids = [vuln.id, ...(vuln.aliases ?? [])]
  return ids.find(id => id.startsWith('GHSA-')) ?? ids.find(id => id.startsWith('CVE-'))
}

function referencesOf(vuln: OsvVuln): string[] {
  const rank: Record<string, number> = { ADVISORY: 0, FIX: 1, REPORT: 2, WEB: 3, ARTICLE: 4, PACKAGE: 5 }
  const urls = (vuln.references ?? [])
    .filter(ref => /^https?:\/\/[^\s]+$/i.test(ref.url))
    .sort((a, b) => (rank[a.type ?? ''] ?? 9) - (rank[b.type ?? ''] ?? 9))
    .map(ref => ref.url)
  return [...new Set([`https://osv.dev/vulnerability/${encodeURIComponent(vuln.id)}`, ...urls])].slice(0, 5)
}

function cweOf(vuln: OsvVuln): string | undefined {
  const ids = vuln.database_specific?.cwe_ids
  if (Array.isArray(ids)) {
    const first = ids.find((id): id is string => typeof id === 'string' && /^CWE-\d+$/.test(id))
    if (first) return first
  }
  return undefined
}

// ---------------------------------------------------------------------------
// HTTP
// ---------------------------------------------------------------------------

class OsvHttp {
  readonly #options: OsvQueryOptions
  readonly #warnings: string[]
  #failures = 0

  constructor(options: OsvQueryOptions, warnings: string[]) {
    this.#options = options
    this.#warnings = warnings
  }

  postJson<T>(url: string, body: unknown, schema: z.ZodType<T>): Promise<T | undefined> {
    return this.#request(url, { method: 'POST', body: JSON.stringify(body) }, schema)
  }

  getJson<T>(url: string, schema: z.ZodType<T>): Promise<T | undefined> {
    return this.#request(url, { method: 'GET' }, schema)
  }

  async #request<T>(url: string, init: RequestInit, schema: z.ZodType<T>): Promise<T | undefined> {
    const outer = this.#options.signal
    outer?.throwIfAborted()
    const timeout = AbortSignal.timeout(this.#options.timeoutMs ?? DEFAULT_TIMEOUT_MS)
    const signal = outer ? AbortSignal.any([outer, timeout]) : timeout
    const what = describeRequest(url)
    try {
      const response = await this.#options.fetch(url, {
        ...init,
        signal,
        redirect: 'error',
        headers: { accept: 'application/json', ...(init.body ? { 'content-type': 'application/json' } : {}) },
      })
      if (!response.ok) {
        await response.body?.cancel().catch(() => undefined)
        this.#warn(`OSV ${what} failed with HTTP ${response.status}`)
        return undefined
      }
      const text = await readLimited(response, MAX_RESPONSE_BYTES)
      const parsed = schema.safeParse(JSON.parse(text))
      if (!parsed.success) {
        this.#warn(`OSV ${what} returned an unexpected response shape`)
        return undefined
      }
      return parsed.data
    } catch (error) {
      if (outer?.aborted) throw outer.reason
      const reason = timeout.aborted ? 'timed out' : error instanceof Error ? error.message : String(error)
      this.#warn(`OSV ${what} failed: ${reason}`)
      return undefined
    }
  }

  #warn(message: string): void {
    this.#failures++
    if (this.#failures <= 20) this.#warnings.push(message)
    else if (this.#failures === 21) this.#warnings.push('Further OSV request failures were not listed')
  }
}

function describeRequest(url: string): string {
  if (url.endsWith('/v1/querybatch')) return 'batch query'
  const id = /\/v1\/vulns\/([^/?#]+)$/.exec(url)?.[1]
  return id ? `details for ${decodeURIComponent(id)}` : 'request'
}

async function readLimited(response: Response, limit: number): Promise<string> {
  const declared = Number(response.headers.get('content-length'))
  if (Number.isFinite(declared) && declared > limit) throw new Error('response too large')
  if (!response.body) return await response.text()
  const reader = response.body.getReader()
  const chunks: Uint8Array[] = []
  let total = 0
  for (;;) {
    const { done, value } = await reader.read()
    if (done) break
    total += value.byteLength
    if (total > limit) {
      await reader.cancel().catch(() => undefined)
      throw new Error('response too large')
    }
    chunks.push(value)
  }
  return Buffer.concat(chunks, total).toString('utf8')
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Version string OSV expects: Go module versions without the leading `v`. */
function queryVersion(dep: Dependency): string | undefined {
  if (dep.ecosystem === 'Go') {
    if (dep.name === 'go' || dep.name === 'toolchain') return undefined
    return dep.version.replace(/^v/, '')
  }
  return dep.version
}

function normalizeName(ecosystem: string, name: string): string {
  return baseEcosystem(ecosystem) === 'PyPI' ? name.toLowerCase().replace(/[-_.]+/g, '-') : name
}

/** OSV ecosystems may carry a suffix such as `Debian:12`; compare the base. */
function baseEcosystem(ecosystem: string): string {
  return ecosystem.split(':')[0] ?? ecosystem
}

function sortRefs(refs: readonly OsvPackageRef[]): OsvPackageRef[] {
  // Prefer a lock file with a line number as the primary location.
  return [...refs].sort(
    (a, b) =>
      Number(b.line !== undefined) - Number(a.line !== undefined) ||
      a.manifest.split('/').length - b.manifest.split('/').length ||
      compare(a.manifest, b.manifest),
  )
}

async function mapConcurrent<T>(items: readonly T[], limit: number, fn: (item: T) => Promise<void>): Promise<void> {
  let next = 0
  const worker = async (): Promise<void> => {
    while (next < items.length) {
      const item = items[next++]!
      await fn(item)
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker))
}

function oneLine(text: string): string {
  return text.replace(/\s+/g, ' ').trim()
}

function firstSentence(text: string | undefined): string | undefined {
  if (!text) return undefined
  const line = oneLine(text.replace(/[#*`]/g, ''))
  const end = line.search(/[.!?](?:\s|$)/)
  return truncate(end > 0 ? line.slice(0, end + 1) : line, 200)
}

function truncate(text: string, max: number): string {
  return text.length <= max ? text : `${text.slice(0, max - 1)}…`
}

function compare(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0
}
