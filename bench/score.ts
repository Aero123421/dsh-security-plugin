/**
 * Score a JSON report exported from a real DSH scan (Security → scan →
 * Export → JSON) against fixture ground truth, so maintainers can evaluate
 * real models (DeepSeek, Claude, …) end to end inside DSH.
 *
 *   node --experimental-strip-types bench/score.ts <report.json> <app-name | path/to/expected.json> [--json] [--tolerance <n>]
 *
 * The second argument is a fixture app name (e.g. `express-shop`) or the path
 * of an `expected.json`. Exits 0 after printing the score, 1 when the report
 * cannot be read or has an unsupported schema version, 2 on usage errors.
 */

import { readFile } from 'node:fs/promises'
import { basename, dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { parseArgs } from 'node:util'
import { FIXTURE_APPS_DIR, type FixtureManifest, loadFixtures, parseFixtureManifest } from './fixtures.ts'
import { count, detectorTable, findingTables, seconds, table, tokens, totalsColumns } from './format.ts'
import { formatDetectors, type ParsedReport, parseJsonReport, ReportFormatError } from './report.ts'
import { type AppScore, scoreApp } from './scoring.ts'

const USAGE = `Usage: node --experimental-strip-types bench/score.ts <report.json> <app-name | path/to/expected.json> [--json] [--tolerance <n>]

  report.json   a JSON report exported from DSH (Security → scan → Export → JSON)
  app-name      a fixture app under tests/fixtures/apps (or a path to its expected.json)
  --json        print the score as JSON instead of tables
  --tolerance   line tolerance when matching reports to ground truth (default 3)`

/** Thrown for problems the user can fix by changing the arguments. */
class UsageError extends Error {}

/** Resolve an app name or `expected.json` path to a validated manifest. */
export async function resolveManifest(target: string): Promise<FixtureManifest> {
  if (target.endsWith('.json')) {
    const file = resolve(target)
    let text: string
    try {
      text = await readFile(file, 'utf8')
    } catch {
      throw new UsageError(`Cannot read ground truth ${file}.`)
    }
    return parseFixtureManifest(JSON.parse(text), dirname(file), file)
  }
  const manifests = await loadFixtures()
  const manifest = manifests.find(m => m.app === target)
  if (!manifest)
    throw new UsageError(
      `Unknown fixture app "${target}". Known apps in ${FIXTURE_APPS_DIR}: ${manifests.map(m => m.app).join(', ')}.`,
    )
  return manifest
}

/** Read and score one exported report file. Throws ReportFormatError for unreadable or unsupported reports. */
export async function scoreReportFile(
  reportPath: string,
  manifest: FixtureManifest,
  tolerance = 3,
): Promise<{ readonly report: ParsedReport; readonly score: AppScore }> {
  let text: string
  try {
    text = await readFile(reportPath, 'utf8')
  } catch {
    throw new ReportFormatError(`Cannot read report ${resolve(reportPath)}.`)
  }
  let json: unknown
  try {
    json = JSON.parse(text)
  } catch {
    throw new ReportFormatError(
      `${basename(reportPath)} is not JSON. Export the scan as JSON (not Markdown or SARIF) and try again.`,
    )
  }
  const report = parseJsonReport(json)
  const score = scoreApp(manifest, report.findings, {
    tolerance,
    ...(report.activeDetectors ? { activeDetectors: report.activeDetectors } : {}),
  })
  return { report, score }
}

/** Human-readable score of one exported report. */
export function renderScore(report: ParsedReport, score: AppScore, manifest: FixtureManifest): string {
  const out: string[] = []
  const models = Object.entries(report.models)
    .map(([role, model]) => `${role}=${model}`)
    .join(', ')
  out.push(`Report: ${report.workspaceTitle} (${report.mode} scan, ${report.status}), plugin ${report.toolVersion}`)
  out.push(
    `Ground truth: ${manifest.app} (${manifest.findings.length} planted, ${manifest.negatives.length} negative controls)`,
  )
  out.push(`Models: ${models || 'none (built-in analyzers only)'}`)
  out.push(
    `Detectors that ran: ${report.activeDetectors ? formatDetectors(report.activeDetectors) : 'unknown (no coverage in report)'}`,
  )
  if (report.workspaceTitle !== manifest.app)
    out.push(`Note: the scanned workspace is "${report.workspaceTitle}", not "${manifest.app}"; check the pairing.`)
  if (report.status !== 'completed')
    out.push(`Warning: the scan did not complete (${report.status}); scores are partial.`)
  out.push('')
  out.push(
    table(
      [
        ...totalsColumns<AppScore>(
          'app',
          s => s.app,
          s => s.totals,
        ),
        { header: 'discarded', value: () => count(report.discardedUnverifiable), align: 'right' },
        { header: 'llm', value: () => String(report.usage.llmCalls), align: 'right' },
        {
          header: 'tokens in/out',
          value: () => `${tokens(report.usage.inputTokens)}/${tokens(report.usage.outputTokens)}`,
          align: 'right',
        },
        { header: 'scan time', value: () => seconds(report.usage.elapsedMs), align: 'right' },
      ],
      [score],
    ),
  )
  out.push('')
  out.push('Per detector')
  out.push(detectorTable(score.detectors))
  out.push('')
  out.push(findingTables(score))
  return out.join('\n')
}

async function main(): Promise<number> {
  let positionals: string[]
  let json = false
  let tolerance = 3
  try {
    const parsed = parseArgs({
      allowPositionals: true,
      strict: true,
      options: {
        json: { type: 'boolean', default: false },
        tolerance: { type: 'string', default: '3' },
        help: { type: 'boolean', short: 'h', default: false },
      },
    })
    if (parsed.values.help) {
      process.stdout.write(`${USAGE}\n`)
      return 0
    }
    positionals = parsed.positionals
    json = parsed.values.json === true
    tolerance = Number(parsed.values.tolerance)
    if (!Number.isInteger(tolerance) || tolerance < 0)
      throw new UsageError('--tolerance must be a non-negative integer')
    if (positionals.length !== 2) throw new UsageError('Expected exactly two arguments.')
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n\n${USAGE}\n`)
    return 2
  }
  const [reportPath, target] = positionals as [string, string]
  try {
    const manifest = await resolveManifest(target)
    const { report, score } = await scoreReportFile(reportPath, manifest, tolerance)
    if (json)
      process.stdout.write(`${JSON.stringify({ report: { ...report, findings: undefined }, score }, null, 2)}\n`)
    else process.stdout.write(`${renderScore(report, score, manifest)}\n`)
    return 0
  } catch (error) {
    if (error instanceof UsageError) {
      process.stderr.write(`${error.message}\n\n${USAGE}\n`)
      return 2
    }
    if (error instanceof ReportFormatError) {
      process.stderr.write(`score: ${error.message}\n`)
      return 1
    }
    throw error
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = await main()
}
