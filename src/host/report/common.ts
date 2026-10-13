/**
 * Report input, ordering, counting, and naming shared by every report format.
 * Everything here is pure and deterministic: the same input renders the same
 * bytes.
 */

import type { FindingDetail, ReportFormat, ReportLanguage, ScanDetail } from '../../shared/contracts.ts'
import type { Closure, Severity, TriageState, Verification } from '../../shared/domain.ts'
import { SEVERITIES, severityRank, TRIAGE_STATES, VERIFICATIONS } from '../../shared/domain.ts'

/** Everything a report needs. Findings are full details of one scan. */
export interface ReportInput {
  readonly scan: ScanDetail
  readonly findings: readonly FindingDetail[]
  readonly workspaceTitle: string
  /** ISO timestamp of report generation. */
  readonly generatedAt: string
  readonly pluginVersion: string
  readonly language: ReportLanguage
}

/** Display name of the tool in every report. */
export const TOOL_NAME = 'DSH Security'
/** Project homepage used as SARIF `informationUri`. */
export const TOOL_INFORMATION_URI = 'https://github.com/dsh-security/dsh-security-plugin'

/** Closure groups in report order. */
export const CLOSURE_ORDER = ['confirmed', 'open_proof_gap', 'ruled_out'] as const satisfies readonly Closure[]

/** Total order for findings: severity, then verification strength, then title, location, and id. */
export function compareFindings(a: FindingDetail, b: FindingDetail): number {
  return (
    severityRank(a.severity) - severityRank(b.severity) ||
    VERIFICATIONS.indexOf(a.verification) - VERIFICATIONS.indexOf(b.verification) ||
    compareStrings(a.title, b.title) ||
    compareStrings(a.location?.path ?? '', b.location?.path ?? '') ||
    (a.location?.startLine ?? 0) - (b.location?.startLine ?? 0) ||
    compareStrings(a.id, b.id)
  )
}

function compareStrings(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0
}

/** Findings grouped by closure (in {@link CLOSURE_ORDER}), each group sorted with {@link compareFindings}. */
export function groupByClosure(findings: readonly FindingDetail[]): ReadonlyMap<Closure, readonly FindingDetail[]> {
  const groups = new Map<Closure, FindingDetail[]>(CLOSURE_ORDER.map(closure => [closure, []]))
  for (const finding of findings) groups.get(finding.closure)?.push(finding)
  for (const group of groups.values()) group.sort(compareFindings)
  return groups
}

/** Findings in report order: grouped by closure, then sorted within each group. */
export function orderedFindings(findings: readonly FindingDetail[]): FindingDetail[] {
  return [...groupByClosure(findings).values()].flat()
}

export interface FindingCounts {
  readonly total: number
  readonly byClosure: Readonly<Record<Closure, number>>
  readonly bySeverity: Readonly<Record<Severity, number>>
  /** Severity × closure matrix. */
  readonly matrix: Readonly<Record<Severity, Readonly<Record<Closure, number>>>>
  readonly byTriage: Readonly<Record<TriageState, number>>
  readonly byVerification: Readonly<Record<Verification, number>>
}

function zeroes<const K extends string>(keys: readonly K[]): Record<K, number> {
  return Object.fromEntries(keys.map(key => [key, 0])) as Record<K, number>
}

/** Count findings along every axis the reports show. */
export function countFindings(findings: readonly FindingDetail[]): FindingCounts {
  const byClosure = zeroes(CLOSURE_ORDER)
  const bySeverity = zeroes(SEVERITIES)
  const byTriage = zeroes(TRIAGE_STATES)
  const byVerification = zeroes(VERIFICATIONS)
  const matrix = Object.fromEntries(SEVERITIES.map(severity => [severity, zeroes(CLOSURE_ORDER)])) as Record<
    Severity,
    Record<Closure, number>
  >
  for (const finding of findings) {
    byClosure[finding.closure]++
    bySeverity[finding.severity]++
    byTriage[finding.triage]++
    byVerification[finding.verification]++
    matrix[finding.severity][finding.closure]++
  }
  return { total: findings.length, byClosure, bySeverity, matrix, byTriage, byVerification }
}

/** The numeric CWE id from `CWE-89`, `cwe-89`, or `89`. */
export function cweNumber(cwe: string | undefined): number | undefined {
  const match = cwe === undefined ? null : /^\s*(?:cwe[-_ ]?)?(\d{1,6})\s*$/i.exec(cwe)
  return match?.[1] === undefined ? undefined : Number(match[1])
}

/** MITRE definition URL for a CWE, when the id is well formed. */
export function cweUrl(cwe: string | undefined): string | undefined {
  const id = cweNumber(cwe)
  return id === undefined ? undefined : `https://cwe.mitre.org/data/definitions/${id}.html`
}

/** GitHub-compatible `security-severity` score per severity. */
export const SECURITY_SEVERITY: Readonly<Record<Severity, string>> = {
  critical: '9.0',
  high: '7.0',
  medium: '5.0',
  low: '3.0',
  info: '0.0',
}

// ---------------------------------------------------------------------------
// Filenames
// ---------------------------------------------------------------------------

const FORMAT_EXTENSIONS: Readonly<Record<ReportFormat, string>> = { markdown: 'md', json: 'json', sarif: 'sarif' }

/** MIME type of each report format. */
export const REPORT_MIME_TYPES: Readonly<Record<ReportFormat, string>> = {
  markdown: 'text/markdown; charset=utf-8',
  json: 'application/json',
  sarif: 'application/sarif+json',
}

const MAX_SLUG_LENGTH = 48

/**
 * ASCII-safe slug: Latin letters lose their accents, every other run of
 * characters becomes one hyphen. Titles with no ASCII letters or digits
 * (for example Japanese names) fall back to `workspace`.
 */
export function slugify(title: string): string {
  const slug = title
    .normalize('NFKD')
    .replace(/[̀-ͯ]/g, '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .slice(0, MAX_SLUG_LENGTH)
    .replace(/^-+|-+$/g, '')
  return slug === '' ? 'workspace' : slug
}

/** `yyyymmdd-hhmm` in UTC, or `undated` when the timestamp does not parse. */
function filenameStamp(iso: string): string {
  const date = new Date(iso)
  if (Number.isNaN(date.getTime())) return 'undated'
  const pad = (value: number) => String(value).padStart(2, '0')
  return (
    `${date.getUTCFullYear()}${pad(date.getUTCMonth() + 1)}${pad(date.getUTCDate())}` +
    `-${pad(date.getUTCHours())}${pad(date.getUTCMinutes())}`
  )
}

/** `dsh-security-<workspace-slug>-<yyyymmdd-hhmm>.<md|json|sarif>` (UTC). */
export function reportFilename(input: ReportInput, format: ReportFormat): string {
  return `dsh-security-${slugify(input.workspaceTitle)}-${filenameStamp(input.generatedAt)}.${FORMAT_EXTENSIONS[format]}`
}

// ---------------------------------------------------------------------------
// Small formatting helpers
// ---------------------------------------------------------------------------

/** ISO timestamp normalized to UTC, or undefined when it does not parse. */
export function isoOrUndefined(value: string | undefined): string | undefined {
  if (value === undefined) return undefined
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? undefined : date.toISOString()
}

/** Whether the report covers a scan that finished normally. */
export function scanSucceeded(scan: ScanDetail): boolean {
  return scan.summary.status === 'completed'
}
