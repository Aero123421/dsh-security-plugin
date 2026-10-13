/**
 * Machine-readable JSON report (`report-v1`). Field names and enum values
 * are the contract DTO names, so consumers can share types with the plugin.
 */

import type {
  Coverage,
  FindingDetail,
  ReportLanguage,
  ScanDetail,
  ScanSummary,
  ScanUsage,
  ThreatModelView,
} from '../../shared/contracts.ts'
import type { ReportInput } from './common.ts'
import { countFindings, orderedFindings, TOOL_INFORMATION_URI, TOOL_NAME } from './common.ts'

/** `$schema` of the JSON report. */
export const JSON_REPORT_SCHEMA_ID = 'https://dsh-security.dev/schemas/report-v1.json'
/** Bumped on incompatible changes to {@link JsonReport}. */
export const JSON_REPORT_SCHEMA_VERSION = 1

/** Shape of the JSON report. */
export interface JsonReport {
  readonly $schema: typeof JSON_REPORT_SCHEMA_ID
  readonly schemaVersion: typeof JSON_REPORT_SCHEMA_VERSION
  readonly generatedAt: string
  readonly language: ReportLanguage
  readonly tool: { readonly name: string; readonly version: string; readonly informationUri: string }
  readonly workspace: { readonly title: string }
  readonly scan: {
    readonly summary: ScanSummary
    readonly usage: ScanUsage
    readonly budget: ScanDetail['budget']
    readonly coverage: Coverage | null
    readonly models: ScanDetail['models']
    readonly threatModel: ThreatModelView | null
    readonly notices: ScanDetail['notices']
  }
  readonly counts: ReturnType<typeof countFindings>
  /** Grouped by closure (confirmed, open proof gap, ruled out), then by severity. */
  readonly findings: readonly FindingDetail[]
}

/** Build the JSON report object. */
export function buildJsonReport(input: ReportInput): JsonReport {
  const { scan } = input
  return {
    $schema: JSON_REPORT_SCHEMA_ID,
    schemaVersion: JSON_REPORT_SCHEMA_VERSION,
    generatedAt: input.generatedAt,
    language: input.language,
    tool: { name: TOOL_NAME, version: input.pluginVersion, informationUri: TOOL_INFORMATION_URI },
    workspace: { title: input.workspaceTitle },
    scan: {
      summary: scan.summary,
      usage: scan.usage,
      budget: scan.budget,
      coverage: scan.coverage ?? null,
      models: scan.models,
      threatModel: scan.threatModel ?? null,
      notices: scan.notices,
    },
    counts: countFindings(input.findings),
    findings: orderedFindings(input.findings),
  }
}

/** Pretty-printed JSON report with a trailing newline. */
export function renderJson(input: ReportInput): string {
  return `${JSON.stringify(buildJsonReport(input), null, 2)}\n`
}
