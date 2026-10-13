import { execFile } from 'node:child_process'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { loadFixtures } from '../../../bench/fixtures.ts'
import {
  parseJsonReport,
  ReportFormatError,
  SUPPORTED_REPORT_SCHEMA,
  SUPPORTED_REPORT_VERSION,
} from '../../../bench/report.ts'
import { resolveManifest, scoreReportFile } from '../../../bench/score.ts'
import { buildJsonReport, JSON_REPORT_SCHEMA_ID, JSON_REPORT_SCHEMA_VERSION } from '../../../src/host/report/json.ts'
import { finding, reportInput } from '../report/fixtures.ts'

const run = promisify(execFile)
const SCORE_CLI = fileURLToPath(new URL('../../../bench/score.ts', import.meta.url))
const REPO_ROOT = fileURLToPath(new URL('../../../', import.meta.url))

/** A real report-v1 object as `renderReport(…, 'json')` produces it. */
function exportedReport(findings = reportInput().findings) {
  return JSON.parse(JSON.stringify(buildJsonReport(reportInput({ findings })))) as Record<string, unknown>
}

describe('parseJsonReport', () => {
  it('tracks the plugin report schema', () => {
    expect(SUPPORTED_REPORT_SCHEMA).toBe(JSON_REPORT_SCHEMA_ID)
    expect(SUPPORTED_REPORT_VERSION).toBe(JSON_REPORT_SCHEMA_VERSION)
  })

  it('reads every finding of a real JSON report', () => {
    const input = reportInput()
    const parsed = parseJsonReport(exportedReport())
    expect(parsed.findings).toHaveLength(input.findings.length)
    expect(parsed.mode).toBe('deep')
    expect(parsed.aiReview).toBe(true)
    expect(parsed.models.hunter).toBe('deepseek/deepseek-chat')
    expect(parsed.discardedUnverifiable).toBe(4)
    expect(parsed.activeDetectors).toEqual(['secrets', 'ai'])
    const ruled = parsed.findings.find(f => f.id === 'f_ruled')
    expect(ruled).toMatchObject({ closure: 'ruled_out', verification: 'refuted', detectors: ['ai'] })
  })

  it('treats a refuted finding as ruled out even if its closure disagrees', () => {
    const report = exportedReport([finding({ id: 'x', verification: 'refuted', closure: 'open_proof_gap' })])
    expect(parseJsonReport(report).findings[0]?.closure).toBe('ruled_out')
  })

  it('rejects other schema versions with a clear message', () => {
    const v2 = { ...exportedReport(), schemaVersion: 2, $schema: 'urn:dsh-security-plugin:report:v2' }
    expect(() => parseJsonReport(v2)).toThrow(ReportFormatError)
    expect(() => parseJsonReport(v2)).toThrow(/Unsupported report schema: got schemaVersion 2.*reads schemaVersion 1/)
    expect(() => parseJsonReport({ ...exportedReport(), $schema: 'https://example.com/other.json' })).toThrow(
      /Unsupported report schema/,
    )
  })

  it('rejects SARIF, non-reports and malformed reports', () => {
    expect(() =>
      parseJsonReport({ $schema: 'https://json.schemastore.org/sarif-2.1.0.json', version: '2.1.0' }),
    ).toThrow(/SARIF/)
    expect(() => parseJsonReport([])).toThrow(/expected a JSON object/)
    expect(() => parseJsonReport({ findings: [] })).toThrow(/"\$schema" and "schemaVersion" are missing/)
    const broken = exportedReport()
    broken.findings = [{ id: 'x' }]
    expect(() => parseJsonReport(broken)).toThrow(/Invalid report-v1 JSON[\s\S]*findings\.0/)
  })
})

describe('bench/score.ts', () => {
  let dir: string
  beforeAll(async () => {
    dir = await mkdtemp(join(tmpdir(), 'dsh-security-score-'))
  })
  afterAll(async () => {
    await rm(dir, { recursive: true, force: true })
  })

  it('scores a report file against an app name or an expected.json path', async () => {
    const [shop] = (await loadFixtures()).filter(m => m.app === 'express-shop')
    if (!shop) throw new Error('express-shop fixture missing')
    const file = join(dir, 'report.json')
    const report = exportedReport([
      finding({
        id: 'hit',
        category: 'injection',
        cwe: 'CWE-89',
        verification: 'strong_static_evidence',
        location: { path: 'src/routes/products.ts', startLine: 27, endLine: 27 },
      }),
    ])
    await writeFile(file, JSON.stringify(report))
    const byName = await scoreReportFile(file, await resolveManifest('express-shop'))
    expect(byName.score.totals).toMatchObject({ planted: shop.findings.length, truePositives: 1, falsePositives: 0 })
    const byPath = await scoreReportFile(file, await resolveManifest(join(shop.dir, 'expected.json')))
    expect(byPath.score.totals).toEqual(byName.score.totals)
  })

  it('exits 1 with the schema-version message for an unsupported report', async () => {
    const file = join(dir, 'v2.json')
    await writeFile(file, JSON.stringify({ ...exportedReport(), schemaVersion: 2 }))
    const failure = await run(
      process.execPath,
      ['--experimental-strip-types', '--no-warnings', SCORE_CLI, file, 'express-shop'],
      {
        cwd: REPO_ROOT,
      },
    ).then(
      () => undefined,
      (error: unknown) => error as { code: number; stderr: string },
    )
    expect(failure?.code).toBe(1)
    expect(failure?.stderr).toMatch(/Unsupported report schema: got schemaVersion 2/)
  })

  it('prints the per-finding table for a supported report', async () => {
    const file = join(dir, 'ok.json')
    await writeFile(file, JSON.stringify(exportedReport()))
    const { stdout } = await run(
      process.execPath,
      ['--experimental-strip-types', '--no-warnings', SCORE_CLI, file, 'express-shop'],
      { cwd: REPO_ROOT },
    )
    expect(stdout).toContain('Planted findings')
    expect(stdout).toMatch(/ES-01 .*MISSED/)
    expect(stdout).toContain('Negative controls')
    expect(stdout).toContain('FP:unmatched')
  })
})
