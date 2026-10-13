/**
 * Reading the plugin's JSON report (`report-v1`, Export → JSON in DSH) for
 * scoring. Only the fields scoring needs are validated; anything else in the
 * report is ignored, so additive changes to the report do not break the
 * bench. An incompatible schema version is rejected with a clear message.
 */

import { z } from 'zod'
import type { Closure } from '../src/shared/domain.ts'
import { FIXTURE_DETECTORS, type FixtureDetector } from './fixtures.ts'
import { activeDetectorsOf, detectorsOf, type ReportedFinding } from './scoring.ts'

/** `$schema` of the report format this scorer understands. */
export const SUPPORTED_REPORT_SCHEMA = 'urn:dsh-security-plugin:report:v1'
/** `schemaVersion` this scorer understands; keep in step with `JSON_REPORT_SCHEMA_VERSION`. */
export const SUPPORTED_REPORT_VERSION = 1

const CLOSURES = ['confirmed', 'open_proof_gap', 'ruled_out'] as const satisfies readonly Closure[]

/** A report that cannot be scored: wrong format, wrong schema version, or malformed fields. */
export class ReportFormatError extends Error {
  override readonly name = 'ReportFormatError'
}

const codeRef = z.object({ path: z.string().min(1), startLine: z.number().int(), endLine: z.number().int() })

const findingSchema = z.object({
  id: z.string(),
  title: z.string(),
  category: z.string(),
  cwe: z.string().optional(),
  location: codeRef.optional(),
  verification: z.string(),
  closure: z.enum(CLOSURES),
  source: z.string(),
  createdBy: z.object({ role: z.string(), analyzer: z.string().optional() }),
  evidence: z.array(z.object({ originRole: z.string(), kind: z.string() })),
})

const reportSchema = z.object({
  generatedAt: z.string(),
  tool: z.object({ name: z.string(), version: z.string() }),
  workspace: z.object({ title: z.string() }),
  scan: z.object({
    summary: z.object({ mode: z.string(), status: z.string() }),
    usage: z.object({
      llmCalls: z.number(),
      inputTokens: z.number(),
      outputTokens: z.number(),
      toolCalls: z.number(),
      elapsedMs: z.number(),
    }),
    coverage: z
      .object({
        analyzers: z.array(z.object({ id: z.string(), available: z.boolean() })),
        discardedUnverifiable: z.number(),
      })
      .nullable(),
    models: z.record(z.string(), z.object({ provider: z.string(), model: z.string() }).optional()),
  }),
  findings: z.array(findingSchema),
})

/** What the bench reads from one exported report. */
export interface ParsedReport {
  readonly toolVersion: string
  readonly generatedAt: string
  readonly workspaceTitle: string
  readonly mode: string
  readonly status: string
  readonly usage: {
    readonly llmCalls: number
    readonly inputTokens: number
    readonly outputTokens: number
    readonly toolCalls: number
    readonly elapsedMs: number
  }
  /** Candidates dropped because none of their cited code matched the source; null when the scan has no coverage. */
  readonly discardedUnverifiable: number | null
  /** `provider/model` per role that had a model. */
  readonly models: Readonly<Record<string, string>>
  /** Whether an AI hunter model was configured for the scan. */
  readonly aiReview: boolean
  /** Detectors that ran, or undefined when the report has no coverage (scan did not finish). */
  readonly activeDetectors?: readonly FixtureDetector[]
  readonly findings: readonly ReportedFinding[]
}

/**
 * Validate and reduce one exported JSON report.
 * @throws ReportFormatError naming the problem: not a JSON report, unsupported version, or invalid fields.
 */
export function parseJsonReport(json: unknown): ParsedReport {
  if (typeof json !== 'object' || json === null || Array.isArray(json))
    throw new ReportFormatError('Not a DSH Security JSON report: expected a JSON object.')
  const record = json as Record<string, unknown>
  const schema = record.$schema
  const version = record.schemaVersion
  if (typeof schema === 'string' && /sarif/i.test(schema))
    throw new ReportFormatError('This is a SARIF report. Export the scan as JSON (Export → JSON) and score that file.')
  if (schema === undefined && version === undefined)
    throw new ReportFormatError(
      'Not a DSH Security JSON report: "$schema" and "schemaVersion" are missing. Export the scan as JSON (Export → JSON).',
    )
  if (version !== SUPPORTED_REPORT_VERSION || (schema !== undefined && schema !== SUPPORTED_REPORT_SCHEMA)) {
    throw new ReportFormatError(
      `Unsupported report schema: got schemaVersion ${JSON.stringify(version)} ($schema ${JSON.stringify(schema)}); ` +
        `this scorer reads schemaVersion ${SUPPORTED_REPORT_VERSION} (${SUPPORTED_REPORT_SCHEMA}). ` +
        'Use the bench from the same plugin release that produced the report.',
    )
  }
  const parsed = reportSchema.safeParse(json)
  if (!parsed.success) {
    const problems = parsed.error.issues
      .slice(0, 10)
      .map(issue => `  - ${issue.path.join('.') || '(root)'}: ${issue.message}`)
    throw new ReportFormatError(`Invalid report-v1 JSON:\n${problems.join('\n')}`)
  }
  const report = parsed.data
  const models: Record<string, string> = {}
  for (const [role, ref] of Object.entries(report.scan.models)) if (ref) models[role] = `${ref.provider}/${ref.model}`
  const aiReview = report.scan.models.hunter !== undefined
  const coverage = report.scan.coverage
  return {
    toolVersion: report.tool.version,
    generatedAt: report.generatedAt,
    workspaceTitle: report.workspace.title,
    mode: report.scan.summary.mode,
    status: report.scan.summary.status,
    usage: report.scan.usage,
    discardedUnverifiable: coverage ? coverage.discardedUnverifiable : null,
    models,
    aiReview,
    ...(coverage ? { activeDetectors: activeDetectorsOf(coverage.analyzers, aiReview) } : {}),
    findings: report.findings.map(
      (finding): ReportedFinding => ({
        id: finding.id,
        title: finding.title,
        category: finding.category,
        ...(finding.cwe ? { cwe: finding.cwe } : {}),
        ...(finding.location ? { location: finding.location } : {}),
        verification: finding.verification,
        // Closure is derived from verification in the plugin; never let a refuted report count as live.
        closure: finding.verification === 'refuted' ? 'ruled_out' : finding.closure,
        detectors: detectorsOf(finding),
      }),
    ),
  }
}

/** Detectors listed for display, in canonical order. */
export function formatDetectors(detectors: readonly FixtureDetector[]): string {
  return FIXTURE_DETECTORS.filter(d => detectors.includes(d)).join(',') || '-'
}
