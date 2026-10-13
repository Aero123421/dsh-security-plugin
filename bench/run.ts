/**
 * `pnpm bench` — run the real scan pipeline in-process over every fixture app
 * and score the results against `tests/fixtures/apps/<app>/expected.json`.
 *
 *   pnpm bench [--app <name>] [--config deterministic|oracle|all] [--json] [--details] [--tolerance <n>]
 *
 * Configurations (see `bench/README.md`):
 *   deterministic          built-in analyzers + ast-grep, no model, no network
 *   deterministic-builtin  built-in analyzers with the fallback lexer
 *   oracle                 deep scan with the scripted fixture-aware model; a plumbing
 *                          test of tool calls, quote verification and review — NOT a
 *                          measure of any real model's quality
 *
 * Writes `bench/results/<timestamp>.json` (git-ignored) and exits non-zero
 * when any scan fails.
 */

import { mkdir, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { parseArgs } from 'node:util'
import type { BenchConfig, BenchRun } from './harness.ts'
import { loadFixtures } from './fixtures.ts'
import { count, detectorTable, findingTables, seconds, table, tokens, totalsColumns } from './format.ts'
import { registerTypeScriptTransform } from './hooks.ts'
import { type ScoreSummary, sumScores } from './scoring.ts'

const CONFIG_GROUPS = ['deterministic', 'oracle', 'all'] as const
type ConfigGroup = (typeof CONFIG_GROUPS)[number]

const RESULTS_DIR = fileURLToPath(new URL('./results/', import.meta.url))

const USAGE = `Usage: pnpm bench [--app <name>] [--config deterministic|oracle|all] [--json] [--details] [--save-reports] [--tolerance <n>]

  --app <name>      score one fixture app (default: every app)
  --config <group>  deterministic (with and without ast-grep), oracle, or all (default)
  --json            print the machine-readable result to stdout instead of tables
  --details         also print per-finding tables for every run
  --save-reports    also save each scan's exported JSON report under bench/results/<timestamp>/
                    (the same file bench/score.ts reads)
  --tolerance <n>   line tolerance when matching reports to ground truth (default 3)`

async function main(): Promise<number> {
  let args: ReturnType<typeof parse>
  try {
    args = parse()
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n\n${USAGE}\n`)
    return 2
  }
  if (args.help) {
    process.stdout.write(`${USAGE}\n`)
    return 0
  }

  registerTypeScriptTransform()
  const harness: typeof import('./harness.ts') = await import('./harness.ts')

  const manifests = await loadFixtures()
  const apps = args.app ? manifests.filter(m => m.app === args.app) : manifests
  if (apps.length === 0) {
    process.stderr.write(`Unknown app "${args.app}". Fixture apps: ${manifests.map(m => m.app).join(', ')}\n`)
    return 2
  }
  const configs = harness.BENCH_CONFIGS.filter(c => args.config === 'all' || c.group === args.config)

  const runs: BenchRun[] = []
  const log = (line: string) => process.stderr.write(`${line}\n`)
  for (const config of configs) {
    for (const manifest of apps) {
      const run = await harness.runBenchScan(manifest, config, { tolerance: args.tolerance })
      runs.push(run)
      const outcome =
        run.status === 'completed'
          ? `recall ${count(run.score?.totals.truePositives)}/${count(run.score?.totals.planted)}, ${count(run.score?.totals.falsePositives)} FP`
          : `${run.status.toUpperCase()}: ${run.reason ?? ''}`
      log(`[bench] ${config.name.padEnd(21)} ${manifest.app.padEnd(14)} ${seconds(run.wallMs).padStart(6)}  ${outcome}`)
    }
  }

  const result = buildResult(configs, runs, args.tolerance)
  await mkdir(RESULTS_DIR, { recursive: true })
  const stamp = result.generatedAt.replace(/[:.]/g, '-')
  const file = join(RESULTS_DIR, `${stamp}.json`)
  await writeFile(file, `${JSON.stringify(result, null, 2)}\n`)
  if (args.saveReports) {
    const dir = join(RESULTS_DIR, stamp)
    await mkdir(dir, { recursive: true })
    for (const run of runs) {
      if (run.reportJson) await writeFile(join(dir, `${run.config}-${run.app}.json`), run.reportJson)
    }
    log(`[bench] exported reports saved in ${dir}`)
  }

  if (args.json) process.stdout.write(`${JSON.stringify(result, null, 2)}\n`)
  else process.stdout.write(`${render(configs, runs, args.details)}\nResults written to ${file}\n`)
  return runs.some(run => run.status === 'failed') ? 1 : 0
}

function parse() {
  const { values } = parseArgs({
    options: {
      app: { type: 'string' },
      config: { type: 'string', default: 'all' },
      json: { type: 'boolean', default: false },
      details: { type: 'boolean', default: false },
      'save-reports': { type: 'boolean', default: false },
      tolerance: { type: 'string', default: '3' },
      help: { type: 'boolean', short: 'h', default: false },
    },
    strict: true,
    allowPositionals: false,
  })
  const config = values.config ?? 'all'
  if (!(CONFIG_GROUPS as readonly string[]).includes(config))
    throw new Error(`--config must be one of ${CONFIG_GROUPS.join(', ')}; got "${config}"`)
  const tolerance = Number(values.tolerance)
  if (!Number.isInteger(tolerance) || tolerance < 0) throw new Error('--tolerance must be a non-negative integer')
  return {
    app: values.app,
    config: config as ConfigGroup,
    json: values.json === true,
    details: values.details === true,
    saveReports: values['save-reports'] === true,
    tolerance,
    help: values.help === true,
  }
}

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------

interface Row {
  readonly label: string
  readonly run?: BenchRun
  readonly summary: ScoreSummary
}

function render(configs: readonly BenchConfig[], runs: readonly BenchRun[], details: boolean): string {
  const out: string[] = []
  for (const config of configs) {
    const own = runs.filter(run => run.config === config.name)
    const scored = own.filter(run => run.score !== undefined)
    out.push('')
    out.push(`== ${config.name}: ${config.description}`)
    if (scored.length === 0) {
      out.push(own.map(run => `   ${run.app}: ${run.status} (${run.reason ?? 'no result'})`).join('\n'))
      continue
    }
    const rows: Row[] = own.map(run => ({
      label: run.app,
      run,
      summary: run.score ?? sumScores([]),
    }))
    if (own.length > 1) rows.push({ label: 'ALL', summary: sumScores(scored.map(run => run.score!)) })
    const columns = [
      ...totalsColumns<Row>(
        'app',
        row => row.label,
        row => row.summary.totals,
      ),
      {
        header: 'discarded',
        value: (row: Row) =>
          count(row.run ? row.run.report?.discardedUnverifiable : sum(own, r => r.report?.discardedUnverifiable ?? 0)),
        align: 'right' as const,
      },
      {
        header: 'llm',
        value: (row: Row) =>
          count(row.run ? row.run.report?.usage.llmCalls : sum(own, r => r.report?.usage.llmCalls ?? 0)),
        align: 'right' as const,
      },
      {
        header: 'tokens in/out',
        value: (row: Row) => {
          const pick = (r: BenchRun) => r.report?.usage ?? { inputTokens: 0, outputTokens: 0 }
          const input = row.run ? pick(row.run).inputTokens : sum(own, r => pick(r).inputTokens)
          const output = row.run ? pick(row.run).outputTokens : sum(own, r => pick(r).outputTokens)
          return `${tokens(input)}/${tokens(output)}`
        },
        align: 'right' as const,
      },
      {
        header: 'wall',
        value: (row: Row) => seconds(row.run ? row.run.wallMs : sum(own, r => r.wallMs)),
        align: 'right' as const,
      },
      {
        header: 'status',
        value: (row: Row) => (row.run ? (row.run.status === 'completed' ? 'ok' : row.run.status) : ''),
      },
    ]
    out.push(table(columns, rows))
    out.push('')
    out.push(`Per detector (${config.name}, ${own.length > 1 ? 'all apps' : own[0]?.app})`)
    out.push(detectorTable(sumScores(scored.map(run => run.score!)).detectors))
    const failed = own.filter(run => run.status !== 'completed')
    for (const run of failed) out.push(`!! ${run.app}: ${run.status}: ${run.reason ?? ''}`)
    for (const run of own) {
      if (run.logged.errors.length > 0)
        out.push(`!! ${run.app}: plugin logged ${run.logged.errors.length} error(s): ${run.logged.errors[0]}`)
    }
    if (details) {
      for (const run of scored) {
        out.push('')
        out.push(`-- ${config.name} / ${run.app}`)
        out.push(findingTables(run.score!))
      }
    }
  }
  out.push('')
  out.push(LEGEND)
  return out.join('\n')
}

const LEGEND = `Legend: TP/FN/recall = planted findings detected/missed; in-scope = recall over findings an active detector
is expected to catch; reports = findings not ruled out; FP = reports matching no planted finding (on-neg = of those,
on documented negative controls); dup = extra reports of an already detected finding (count as correct for precision);
conf/proof/out = confirmed / needs proof / ruled out (all reports); confTP = planted findings with a confirmed report;
out:neg/real = ruled-out reports on negative controls (good) / on planted findings (verification loss); discarded =
AI candidates dropped because no cited quote matched the source. The oracle configuration is a plumbing test, not a
model-quality claim.`

function sum(runs: readonly BenchRun[], pick: (run: BenchRun) => number): number {
  return runs.reduce((n, run) => n + pick(run), 0)
}

// ---------------------------------------------------------------------------
// JSON result
// ---------------------------------------------------------------------------

function buildResult(configs: readonly BenchConfig[], runs: readonly BenchRun[], tolerance: number) {
  return {
    generatedAt: new Date().toISOString(),
    node: process.version,
    platform: `${process.platform}-${process.arch}`,
    tolerance,
    configs: configs.map(config => ({
      ...config,
      summary: sumScores(runs.filter(r => r.config === config.name && r.score).map(r => r.score!)),
    })),
    runs: runs.map(run => ({
      app: run.app,
      config: run.config,
      status: run.status,
      ...(run.reason ? { reason: run.reason } : {}),
      ...(run.scanStatus ? { scanStatus: run.scanStatus } : {}),
      engine: run.engine,
      wallMs: Math.round(run.wallMs),
      pluginErrors: run.logged.errors,
      pluginWarnings: run.logged.warnings,
      ...(run.report
        ? {
            pluginVersion: run.report.toolVersion,
            mode: run.report.mode,
            models: run.report.models,
            usage: run.report.usage,
            discardedUnverifiable: run.report.discardedUnverifiable,
          }
        : {}),
      ...(run.score ? { score: run.score } : {}),
    })),
  }
}

process.exitCode = await main()
