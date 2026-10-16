/**
 * Semgrep runner. Runs only with a local rules path supplied by the user or
 * the plugin: never `--config auto` or registry rules, metrics off, no
 * version check, so no code or telemetry leaves the machine. `--disable-nosem`
 * makes `nosemgrep` comments in the scanned repository ineffective, so its
 * author cannot silence a rule hit inline.
 */

import { stat } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { isAbsolute } from 'node:path'
import { z } from 'zod'
import type { FindingCategory, Severity } from '../../../shared/domain.ts'
import { redactText } from '../secrets.ts'
import type { AnalyzerRun, Signal } from '../types.ts'
import {
  completedRun,
  DEFAULT_EXTERNAL_TIMEOUT_MS,
  DEFAULT_MAX_OUTPUT_BYTES,
  type ExternalRunOptions,
  errorMessage,
  failedRun,
  firstLine,
  normalizeForFingerprint,
  snippetFor,
  toWorkspacePath,
  unavailableRun,
} from './common.ts'
import { runTool } from './process.ts'

export interface SemgrepRunOptions extends ExternalRunOptions {
  /** Absolute path to a local rules file or directory. Without it semgrep is not run. */
  readonly configPath?: string
}

const MAX_RESULTS = 5000

const resultSchema = z.object({
  check_id: z.string(),
  path: z.string(),
  start: z.object({ line: z.number().int(), col: z.number().int().optional() }),
  end: z.object({ line: z.number().int(), col: z.number().int().optional() }),
  extra: z
    .object({
      message: z.string().optional(),
      severity: z.string().optional(),
      lines: z.string().optional(),
      fingerprint: z.string().optional(),
      metadata: z.record(z.string(), z.unknown()).optional(),
    })
    .default({}),
})
const outputSchema = z.object({
  results: z.array(z.unknown()).default([]),
  errors: z.array(z.object({ message: z.string().optional(), level: z.string().optional() }).loose()).default([]),
})

/** Run semgrep with a local config and convert its results to signals. */
export async function runSemgrep(options: SemgrepRunOptions): Promise<AnalyzerRun> {
  const started = Date.now()
  const { tool, configPath } = options
  if (!tool) return unavailableRun('semgrep', 'semgrep is not installed', started)
  if (!configPath) return unavailableRun('semgrep', 'no local semgrep rules were configured', started)
  if (!isAbsolute(configPath) || !(await stat(configPath).catch(() => undefined))) {
    return unavailableRun('semgrep', 'the configured semgrep rules path does not exist', started)
  }
  options.signal?.throwIfAborted()

  const args = [
    'scan',
    '--json',
    '--metrics=off',
    '--disable-version-check',
    '--disable-nosem',
    '--quiet',
    '--config',
    configPath,
    '--max-target-bytes',
    '2000000',
    '--timeout',
    '30',
    options.root,
  ]
  let result: Awaited<ReturnType<typeof runTool>>
  try {
    result = await runTool(tool.path, args, {
      cwd: tmpdir(),
      timeoutMs: options.timeoutMs ?? DEFAULT_EXTERNAL_TIMEOUT_MS,
      maxOutputBytes: options.maxOutputBytes ?? DEFAULT_MAX_OUTPUT_BYTES,
      ...(options.signal ? { signal: options.signal } : {}),
      env: { SEMGREP_SEND_METRICS: 'off', SEMGREP_ENABLE_VERSION_CHECK: '0' },
    })
  } catch (error) {
    if (options.signal?.aborted) throw error
    return failedRun('semgrep', tool, `could not start semgrep: ${errorMessage(error)}`, started)
  }
  if (result.timedOut) return failedRun('semgrep', tool, 'semgrep timed out', started)
  if (result.truncated) return failedRun('semgrep', tool, 'semgrep output exceeded the size limit', started)
  // 0: no findings, 1: findings; JSON is still printed for some error codes.
  let raw: unknown
  try {
    raw = JSON.parse(result.stdout)
  } catch {
    const detail = firstLine(redactText(result.stderr)) || `exit code ${result.code ?? result.signal}`
    return failedRun('semgrep', tool, `semgrep failed: ${detail}`, started)
  }
  const warnings: string[] = []
  const signals = parseSemgrepOutput(raw, options, warnings)
  if (result.code !== 0 && result.code !== 1) warnings.push(`semgrep exited with code ${result.code}`)
  return completedRun('semgrep', tool, signals, started, warnings)
}

/** Convert semgrep `--json` output into signals. */
export function parseSemgrepOutput(
  raw: unknown,
  options: Pick<ExternalRunOptions, 'root' | 'snapshot' | 'redactor'>,
  warnings: string[],
): Signal[] {
  const parsed = outputSchema.safeParse(raw)
  if (!parsed.success) {
    warnings.push('semgrep output had an unexpected shape')
    return []
  }
  for (const error of parsed.data.errors.slice(0, 10)) {
    if (error.message) warnings.push(`semgrep: ${firstLine(redactText(error.message), 200)}`)
  }
  if (parsed.data.results.length > MAX_RESULTS) {
    warnings.push(`semgrep reported ${parsed.data.results.length} results; only ${MAX_RESULTS} kept`)
  }
  const cache = new Map<string, readonly string[]>()
  const signals: Signal[] = []
  for (const item of parsed.data.results.slice(0, MAX_RESULTS)) {
    const result = resultSchema.safeParse(item)
    if (!result.success) continue
    const r = result.data
    const path = toWorkspacePath(options.root, r.path, options.snapshot?.pathPrefix)
    if (!path) continue
    if (options.snapshot && !options.snapshot.files.has(path)) continue
    const startLine = Math.max(1, r.start.line)
    const endLine = Math.max(startLine, r.end.line)
    const snippet = snippetFor(options, path, startLine, endLine, r.extra.lines ?? '', cache)
    const metadata = r.extra.metadata ?? {}
    const cwe = cweOf(metadata.cwe)
    const message = redactText(r.extra.message ?? r.check_id)
    signals.push({
      analyzer: 'semgrep',
      ruleId: r.check_id,
      kind: 'vulnerability',
      title: truncate(firstLine(message, 160) || r.check_id, 160),
      category: categoryOf(r.check_id, metadata, cwe),
      severity: severityOf(r.extra.severity),
      confidence: confidenceOf(metadata.confidence),
      ...(cwe ? { cwe } : {}),
      location: { path, startLine, endLine },
      snippet,
      message,
      ...(typeof metadata.fix === 'string' ? { recommendation: redactText(metadata.fix) } : {}),
      fingerprintParts: ['semgrep', r.check_id, path, normalizeForFingerprint(snippet)],
      ...(referencesOf(metadata.references) ? { references: referencesOf(metadata.references) } : {}),
      metadata: {
        ...(r.start.col !== undefined ? { column: r.start.col } : {}),
        ...(typeof metadata.owasp === 'string' ? { owasp: metadata.owasp } : {}),
      },
    })
  }
  return signals
}

/** ERROR→high, WARNING→medium, INFO→low (also accepts semgrep's newer CRITICAL/HIGH/MEDIUM/LOW). */
function severityOf(value: string | undefined): Severity {
  switch ((value ?? '').toUpperCase()) {
    case 'CRITICAL':
      return 'critical'
    case 'ERROR':
    case 'HIGH':
      return 'high'
    case 'WARNING':
    case 'MEDIUM':
      return 'medium'
    case 'INFO':
    case 'LOW':
      return 'low'
    default:
      return 'medium'
  }
}

function confidenceOf(value: unknown): 'low' | 'medium' | 'high' {
  if (typeof value !== 'string') return 'medium'
  const upper = value.toUpperCase()
  return upper === 'HIGH' ? 'high' : upper === 'LOW' ? 'low' : 'medium'
}

/** First `CWE-<n>` from a string or a list like `["CWE-89: Improper Neutralization …"]`. */
function cweOf(value: unknown): string | undefined {
  const items = Array.isArray(value) ? value : [value]
  for (const item of items) {
    if (typeof item !== 'string') continue
    const match = /CWE-(\d{1,5})/i.exec(item)
    if (match) return `CWE-${match[1]}`
  }
  return undefined
}

const CWE_CATEGORIES: Readonly<Record<string, FindingCategory>> = {
  '22': 'path-traversal',
  '23': 'path-traversal',
  '73': 'path-traversal',
  '77': 'command-execution',
  '78': 'command-execution',
  '79': 'xss',
  '89': 'injection',
  '90': 'injection',
  '94': 'command-execution',
  '95': 'command-execution',
  '601': 'misconfiguration',
  '611': 'injection',
  '918': 'ssrf',
  '502': 'deserialization',
  '287': 'authn',
  '306': 'authn',
  '285': 'authz',
  '639': 'authz',
  '862': 'authz',
  '863': 'authz',
  '798': 'secrets',
  '321': 'secrets',
  '326': 'crypto',
  '327': 'crypto',
  '328': 'crypto',
  '330': 'crypto',
  '338': 'crypto',
  '200': 'data-exposure',
  '532': 'data-exposure',
  '362': 'race-condition',
  '367': 'race-condition',
  '16': 'misconfiguration',
  '693': 'misconfiguration',
  '1021': 'misconfiguration',
}

function categoryOf(checkId: string, metadata: Record<string, unknown>, cwe: string | undefined): FindingCategory {
  const byCwe = cwe ? CWE_CATEGORIES[cwe.slice(4)] : undefined
  if (byCwe) return byCwe
  const hint = `${checkId} ${Array.isArray(metadata.category) ? metadata.category.join(' ') : String(metadata.category ?? '')}`
  const lower = hint.toLowerCase()
  if (/sql|nosql|ldap|xpath|injection/.test(lower)) return 'injection'
  if (/xss|cross-site/.test(lower)) return 'xss'
  if (/ssrf/.test(lower)) return 'ssrf'
  if (/exec|command|shell|eval/.test(lower)) return 'command-execution'
  if (/path|traversal/.test(lower)) return 'path-traversal'
  if (/deserial|pickle|yaml\.load/.test(lower)) return 'deserialization'
  if (/crypto|hash|cipher|random/.test(lower)) return 'crypto'
  if (/secret|password|credential|token/.test(lower)) return 'secrets'
  return 'other'
}

function referencesOf(value: unknown): string[] | undefined {
  const items = Array.isArray(value) ? value : [value]
  const urls = items.filter((item): item is string => typeof item === 'string' && /^https?:\/\/\S+$/.test(item))
  return urls.length > 0 ? urls.slice(0, 5) : undefined
}

function truncate(text: string, max: number): string {
  return text.length <= max ? text : `${text.slice(0, max - 1)}…`
}
