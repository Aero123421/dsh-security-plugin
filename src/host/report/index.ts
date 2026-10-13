/**
 * Report rendering: Markdown for people, JSON for tools, SARIF for
 * code-scanning dashboards. All renderers are pure functions of
 * {@link ReportInput}.
 */

import type { ReportFile, ReportFormat } from '../../shared/contracts.ts'
import type { ReportInput } from './common.ts'
import { REPORT_MIME_TYPES, reportFilename } from './common.ts'
import { renderJson } from './json.ts'
import { renderMarkdown } from './markdown.ts'
import { renderSarif } from './sarif.ts'

export type { ReportInput } from './common.ts'
export { REPORT_MIME_TYPES, reportFilename, slugify } from './common.ts'
export { buildJsonReport, JSON_REPORT_SCHEMA_ID, renderJson } from './json.ts'
export { renderMarkdown } from './markdown.ts'
export { buildSarif, renderSarif, SARIF_SCHEMA } from './sarif.ts'

const RENDERERS: Readonly<Record<ReportFormat, (input: ReportInput) => string>> = {
  markdown: renderMarkdown,
  json: renderJson,
  sarif: renderSarif,
}

/** Render one format as the `exportReport` response. */
export function renderReport(input: ReportInput, format: ReportFormat): ReportFile {
  return { filename: reportFilename(input, format), mime: REPORT_MIME_TYPES[format], content: RENDERERS[format](input) }
}
