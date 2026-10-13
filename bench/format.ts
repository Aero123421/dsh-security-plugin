/** Plain-text tables for the bench output. */

import type { AppScore, DetectorScore, ReportRow, ScoreTotals } from './scoring.ts'
import { formatDetectors } from './report.ts'

export interface Column<T> {
  readonly header: string
  readonly value: (row: T) => string
  readonly align?: 'left' | 'right'
  /** Truncate longer cells with an ellipsis. */
  readonly max?: number
}

/** Render rows as an aligned text table with a header rule. */
export function table<T>(columns: readonly Column<T>[], rows: readonly T[]): string {
  const cells = rows.map(row => columns.map(column => clip(column.value(row), column.max)))
  const widths = columns.map((column, i) => Math.max(column.header.length, ...cells.map(line => line[i]?.length ?? 0)))
  const render = (line: readonly string[]) =>
    line
      .map((cell, i) => (columns[i]?.align === 'right' ? cell.padStart(widths[i] ?? 0) : cell.padEnd(widths[i] ?? 0)))
      .join('  ')
      .trimEnd()
  const header = render(columns.map(c => c.header))
  return [header, render(widths.map(w => '-'.repeat(w))), ...cells.map(render)].join('\n')
}

export function pct(value: number | null): string {
  return value === null ? 'n/a' : `${(value * 100).toFixed(0)}%`
}

export function count(value: number | null | undefined): string {
  return value === null || value === undefined ? '-' : String(value)
}

export function tokens(value: number): string {
  if (value >= 1_000_000) return `${(value / 1_000_000).toFixed(1)}M`
  if (value >= 10_000) return `${Math.round(value / 1000)}k`
  return String(Math.round(value))
}

export function seconds(ms: number): string {
  return `${(ms / 1000).toFixed(1)}s`
}

function clip(text: string, max: number | undefined): string {
  return max === undefined || text.length <= max ? text : `${text.slice(0, max - 1)}…`
}

/** Totals columns shared by the run and score outputs. `T` supplies the row label and totals. */
export function totalsColumns<T>(
  label: string,
  name: (row: T) => string,
  totals: (row: T) => ScoreTotals,
): Column<T>[] {
  return [
    { header: label, value: name },
    { header: 'planted', value: r => String(totals(r).planted), align: 'right' },
    { header: 'TP', value: r => String(totals(r).truePositives), align: 'right' },
    { header: 'FN', value: r => String(totals(r).falseNegatives), align: 'right' },
    { header: 'recall', value: r => pct(totals(r).recall), align: 'right' },
    {
      header: 'in-scope',
      value: r => `${totals(r).inScopeTruePositives}/${totals(r).inScope} ${pct(totals(r).scopedRecall)}`,
      align: 'right',
    },
    { header: 'reports', value: r => String(totals(r).reports), align: 'right' },
    { header: 'FP', value: r => String(totals(r).falsePositives), align: 'right' },
    { header: 'on-neg', value: r => String(totals(r).negativeHits), align: 'right' },
    { header: 'dup', value: r => String(totals(r).duplicates), align: 'right' },
    { header: 'precision', value: r => pct(totals(r).precision), align: 'right' },
    {
      header: 'conf/proof/out',
      value: r => {
        const v = totals(r).verification
        return `${v.confirmed}/${v.needsProof}/${v.ruledOut}`
      },
      align: 'right',
    },
    { header: 'confTP', value: r => String(totals(r).confirmedTruePositives), align: 'right' },
    {
      header: 'out:neg/real',
      value: r => `${totals(r).ruledOut.onNegatives}/${totals(r).ruledOut.onPlanted}`,
      align: 'right',
    },
  ]
}

export function detectorTable(detectors: readonly DetectorScore[]): string {
  return table<DetectorScore>(
    [
      { header: 'detector', value: d => d.detector },
      { header: 'ran', value: d => (d.active ? 'yes' : 'no') },
      { header: 'planted', value: d => String(d.planted), align: 'right' },
      { header: 'TP', value: d => String(d.truePositives), align: 'right' },
      { header: 'FN', value: d => String(d.falseNegatives), align: 'right' },
      { header: 'recall', value: d => pct(d.recall), align: 'right' },
      { header: 'reports', value: d => String(d.reports), align: 'right' },
      { header: 'FP', value: d => String(d.falsePositives), align: 'right' },
      { header: 'on-neg', value: d => String(d.negativeHits), align: 'right' },
      { header: 'precision', value: d => pct(d.precision), align: 'right' },
      { header: 'bonus', value: d => String(d.bonus), align: 'right' },
    ],
    detectors,
  )
}

/** Per-finding detail of one app score: expected entries, negative controls, and unmatched or ruled-out reports. */
export function findingTables(score: AppScore): string {
  const out: string[] = []
  out.push('Planted findings')
  out.push(
    table(
      [
        { header: 'id', value: r => r.id },
        { header: 'expected by', value: r => formatDetectors(r.detectableBy) },
        { header: 'location', value: r => `${r.path}:${r.line}`, max: 48 },
        {
          header: 'result',
          value: r => (r.status === 'detected' ? 'found' : r.status === 'missed' ? 'MISSED' : 'RULED OUT'),
        },
        { header: 'matched report', value: r => (r.match ? r.match.title : ''), max: 60 },
        { header: 'verification', value: r => r.match?.verification ?? '' },
        { header: 'found by', value: r => (r.match ? formatDetectors(r.match.detectors) : '') },
        { header: 'n', value: r => (r.reports > 0 ? String(r.reports) : ''), align: 'right' },
      ],
      score.expected,
    ),
  )
  out.push('')
  out.push('Negative controls (must not be reported)')
  out.push(
    table(
      [
        { header: 'id', value: r => r.id },
        { header: 'location', value: r => `${r.path}:${r.line}`, max: 48 },
        { header: 'category', value: r => r.category },
        { header: 'result', value: r => (r.hits > 0 ? `HIT x${r.hits}` : 'ok') },
        { header: 'ruled out', value: r => (r.ruledOut > 0 ? String(r.ruledOut) : ''), align: 'right' },
      ],
      score.negatives,
    ),
  )
  const flagged = score.reports.filter(
    row => row.outcome === 'false-positive' || row.outcome === 'negative' || row.outcome === 'ruled-out',
  )
  out.push('')
  out.push(`Reports not matching a planted finding, and ruled-out reports (${flagged.length})`)
  out.push(flagged.length === 0 ? '(none)' : reportTable(flagged))
  return out.join('\n')
}

function reportTable(rows: readonly ReportRow[]): string {
  const label: Record<ReportRow['outcome'], string> = {
    'true-positive': 'TP',
    duplicate: 'dup',
    negative: 'FP:negative',
    'false-positive': 'FP:unmatched',
    'ruled-out': 'ruled out',
  }
  return table<ReportRow>(
    [
      { header: 'outcome', value: r => label[r.outcome] },
      { header: 'on', value: r => r.matchedId ?? '' },
      { header: 'title', value: r => r.finding.title, max: 56 },
      {
        header: 'location',
        value: r => (r.finding.location ? `${r.finding.location.path}:${r.finding.location.startLine}` : '(none)'),
        max: 44,
      },
      { header: 'category', value: r => r.finding.category + (r.finding.cwe ? ` ${r.finding.cwe}` : '') },
      { header: 'verification', value: r => r.finding.verification },
      { header: 'by', value: r => formatDetectors(r.finding.detectors) },
    ],
    rows,
  )
}
