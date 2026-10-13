import { describe, expect, it } from 'vitest'
import { renderReport } from '../../../src/host/report/index.ts'
import { reportFilename, slugify } from '../../../src/host/report/common.ts'
import type { JsonReport } from '../../../src/host/report/json.ts'
import { buildJsonReport, JSON_REPORT_SCHEMA_ID, renderJson } from '../../../src/host/report/json.ts'
import type { SarifLog } from '../../../src/host/report/sarif.ts'
import { renderSarif, sarifLevel } from '../../../src/host/report/sarif.ts'
import { finding, reportInput, scanDetail } from './fixtures.ts'

// ---------------------------------------------------------------------------
// Minimal hand-written SARIF 2.1.0 structural check
// ---------------------------------------------------------------------------

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

/** Returns a list of problems; empty means the log has the required SARIF shape. */
function sarifProblems(log: unknown): string[] {
  const problems: string[] = []
  const need = (condition: boolean, message: string) => {
    if (!condition) problems.push(message)
  }
  if (!isObject(log)) return ['log is not an object']
  need(log.version === '2.1.0', 'version must be 2.1.0')
  need(typeof log.$schema === 'string', '$schema missing')
  need(Array.isArray(log.runs) && log.runs.length === 1, 'exactly one run')
  const run = Array.isArray(log.runs) ? log.runs[0] : undefined
  if (!isObject(run)) return [...problems, 'run is not an object']
  const driver = isObject(run.tool) && isObject(run.tool.driver) ? run.tool.driver : undefined
  need(driver !== undefined && typeof driver.name === 'string', 'tool.driver.name required')
  const rules = driver !== undefined && Array.isArray(driver.rules) ? driver.rules : []
  const ruleIds = rules.map(rule => (isObject(rule) ? rule.id : undefined))
  need(new Set(ruleIds).size === ruleIds.length, 'rule ids must be unique')
  for (const rule of rules) {
    need(isObject(rule) && typeof rule.id === 'string', 'rule.id required')
    if (!isObject(rule)) continue
    need(
      isObject(rule.shortDescription) && typeof rule.shortDescription.text === 'string',
      'rule.shortDescription.text',
    )
    need(
      isObject(rule.defaultConfiguration) &&
        ['error', 'warning', 'note', 'none'].includes(String(rule.defaultConfiguration.level)),
      'rule.defaultConfiguration.level',
    )
    need(rule.helpUri === undefined || /^https:\/\//.test(String(rule.helpUri)), 'rule.helpUri must be absolute')
  }
  need(Array.isArray(run.results), 'results array required')
  for (const result of Array.isArray(run.results) ? run.results : []) {
    if (!isObject(result)) {
      problems.push('result is not an object')
      continue
    }
    need(isObject(result.message) && typeof result.message.text === 'string', 'result.message.text required')
    need(['error', 'warning', 'note', 'none'].includes(String(result.level)), 'result.level')
    need(typeof result.ruleId === 'string' && ruleIds.includes(result.ruleId), 'result.ruleId must name a rule')
    need(
      typeof result.ruleIndex === 'number' && ruleIds[result.ruleIndex] === result.ruleId,
      'result.ruleIndex must point at its rule',
    )
    const locations = Array.isArray(result.locations) ? result.locations : []
    for (const location of locations) checkLocation(location, need)
    for (const flow of Array.isArray(result.codeFlows) ? result.codeFlows : []) {
      const threadFlows = isObject(flow) && Array.isArray(flow.threadFlows) ? flow.threadFlows : []
      need(threadFlows.length > 0, 'codeFlow.threadFlows non-empty')
      for (const thread of threadFlows) {
        const steps = isObject(thread) && Array.isArray(thread.locations) ? thread.locations : []
        need(steps.length > 0, 'threadFlow.locations non-empty')
        for (const step of steps) checkLocation(isObject(step) ? step.location : undefined, need)
      }
    }
    for (const suppression of Array.isArray(result.suppressions) ? result.suppressions : []) {
      need(isObject(suppression) && ['inSource', 'external'].includes(String(suppression.kind)), 'suppression.kind')
    }
  }
  return problems
}

function checkLocation(location: unknown, need: (condition: boolean, message: string) => void): void {
  const physical = isObject(location) && isObject(location.physicalLocation) ? location.physicalLocation : undefined
  need(physical !== undefined, 'physicalLocation required')
  if (physical === undefined) return
  const artifact = isObject(physical.artifactLocation) ? physical.artifactLocation : undefined
  need(
    typeof artifact?.uri === 'string' && !String(artifact.uri).startsWith('/'),
    'artifactLocation.uri must be relative',
  )
  need(artifact?.uriBaseId === '%SRCROOT%', 'artifactLocation.uriBaseId must be %SRCROOT%')
  const region = isObject(physical.region) ? physical.region : undefined
  need(Number.isInteger(region?.startLine) && Number(region?.startLine) >= 1, 'region.startLine >= 1')
  need(Number(region?.endLine) >= Number(region?.startLine), 'region.endLine >= startLine')
}

function parseSarif(text: string): SarifLog {
  return JSON.parse(text) as SarifLog
}

describe('renderSarif', () => {
  const input = reportInput()
  const log = parseSarif(renderSarif(input))
  const run = log.runs[0]
  const byId = (id: string) => run.results.find(result => result.properties.id === id)!

  it('passes the structural check', () => {
    expect(sarifProblems(log)).toEqual([])
    expect(log.$schema).toBe('https://json.schemastore.org/sarif-2.1.0.json')
    expect(run.tool.driver).toMatchObject({ name: 'DSH Security', version: '0.1.0', semanticVersion: '0.1.0' })
    expect(run.tool.driver.informationUri).toMatch(/^https:\/\//)
  })

  it('emits one rule per ruleId or category with CWE metadata', () => {
    const ids = run.tool.driver.rules.map(rule => rule.id).sort()
    expect(ids).toEqual([
      'dsh-security/authz',
      'dsh-security/data-exposure',
      'dsh-security/injection',
      'dsh-security/xss',
      'secrets/generic-api-key',
    ])
    const injection = run.tool.driver.rules.find(rule => rule.id === 'dsh-security/injection')!
    expect(injection.helpUri).toBe('https://cwe.mitre.org/data/definitions/89.html')
    expect(injection.properties.tags).toEqual(['security', 'injection', 'external/cwe/cwe-89'])
    expect(injection.defaultConfiguration.level).toBe('error')
    expect(injection.properties['security-severity']).toBe('9.0')
    const exposure = run.tool.driver.rules.find(rule => rule.id === 'dsh-security/data-exposure')!
    expect(exposure.helpUri).toBeUndefined()
    expect(exposure.defaultConfiguration.level).toBe('note')
  })

  it('maps severity to level and security-severity', () => {
    expect(sarifLevel('critical')).toBe('error')
    expect(sarifLevel('high')).toBe('error')
    expect(sarifLevel('medium')).toBe('warning')
    expect(sarifLevel('low')).toBe('note')
    expect(sarifLevel('info')).toBe('note')
    expect(byId('f_conf').level).toBe('error')
    expect(byId('f_conf').properties['security-severity']).toBe('9.0')
    expect(byId('f_low').level).toBe('note')
    expect(byId('f_low').properties['security-severity']).toBe('3.0')
  })

  it('writes message, location, fingerprint, and properties', () => {
    const result = byId('f_conf')
    expect(result.message.text).toContain('User input reaches a SQL query')
    expect(result.message.text).toContain('Verification: strong static evidence.')
    expect(result.locations![0]!.physicalLocation).toEqual({
      artifactLocation: { uri: 'src/db/users.ts', uriBaseId: '%SRCROOT%' },
      region: { startLine: 10, endLine: 12 },
    })
    expect(result.partialFingerprints['dshSecurity/v1']).toMatch(/^fp/)
    expect(result.properties).toMatchObject({
      severity: 'critical',
      verification: 'strong_static_evidence',
      closure: 'confirmed',
      triage: 'open',
      source: 'ai',
    })
  })

  it('builds codeFlows from located attack steps only', () => {
    const flow = byId('f_conf').codeFlows![0]!.threadFlows[0]!.locations
    expect(flow).toHaveLength(2)
    expect(flow[0]!.location.physicalLocation.artifactLocation.uri).toBe('src/routes/users.ts')
    expect(flow[0]!.location.physicalLocation.region.snippet).toEqual({ text: 'const name = req.query.name' })
    expect(flow[1]!.location.physicalLocation.region.snippet).toBeUndefined()
    expect(flow.map(step => step.properties.order)).toEqual([1, 2])
    expect(byId('f_secret').codeFlows).toBeUndefined()
  })

  it('suppresses triaged-away and refuted findings', () => {
    expect(byId('f_conf').suppressions).toBeUndefined()
    expect(byId('f_gap').suppressions).toEqual([
      { kind: 'external', status: 'accepted', justification: 'Internal-only endpoint behind VPN' },
    ])
    expect(byId('f_secret').suppressions).toEqual([
      { kind: 'external', status: 'accepted', justification: 'triaged as a false positive' },
    ])
    expect(byId('f_ruled').suppressions).toEqual([
      { kind: 'external', status: 'accepted', justification: 'refuted by independent review' },
    ])
  })

  it('records run properties and invocation without host paths', () => {
    expect(run.invocations[0]).toMatchObject({
      executionSuccessful: true,
      startTimeUtc: '2026-10-12T09:00:05.000Z',
      endTimeUtc: '2026-10-12T09:41:30.000Z',
    })
    expect(run.invocations[0]!.toolExecutionNotifications).toEqual([
      { level: 'warning', message: { text: 'Token budget 90% used' } },
    ])
    expect(run.properties).toMatchObject({ scanId: 'scan_01', mode: 'deep', commit: input.scan.summary.commit })
    expect(run.properties.coverage).toMatchObject({ files: { total: 420 }, discardedUnverifiable: 4 })
    expect(run.originalUriBaseIds['%SRCROOT%']).not.toHaveProperty('uri')
    expect(renderSarif(input)).not.toMatch(/file:\/\//)
  })

  it('marks failed scans unsuccessful and normalizes odd paths', () => {
    const odd = finding({ location: { path: './dir with space/#file?.ts', startLine: 0, endLine: -1 } })
    const failed = parseSarif(renderSarif(reportInput({ scan: scanDetail({ status: 'failed' }), findings: [odd] })))
    expect(sarifProblems(failed)).toEqual([])
    expect(failed.runs[0].invocations[0]!.executionSuccessful).toBe(false)
    const physical = failed.runs[0].results[0]!.locations![0]!.physicalLocation
    expect(physical.artifactLocation.uri).toBe('dir%20with%20space/%23file%3F.ts')
    expect(physical.region).toEqual({ startLine: 1, endLine: 1 })
  })

  it('handles an empty scan', () => {
    const empty = parseSarif(renderSarif(reportInput({ findings: [] })))
    expect(sarifProblems(empty)).toEqual([])
    expect(empty.runs[0].results).toEqual([])
    expect(empty.runs[0].tool.driver.rules).toEqual([])
  })
})

describe('renderJson', () => {
  it('round-trips and carries the schema id, tool, scan, and full findings', () => {
    const input = reportInput()
    const text = renderJson(input)
    expect(text.endsWith('\n')).toBe(true)
    expect(text).toContain('\n  "schemaVersion": 1,')
    const parsed = JSON.parse(text) as JsonReport
    expect(parsed).toEqual(JSON.parse(JSON.stringify(buildJsonReport(input))))
    expect(parsed.$schema).toBe(JSON_REPORT_SCHEMA_ID)
    expect(parsed.$schema).toBe('urn:dsh-security-plugin:report:v1')
    expect(parsed.schemaVersion).toBe(1)
    expect(parsed.tool).toMatchObject({ name: 'DSH Security', version: '0.1.0' })
    expect(parsed.scan.summary.id).toBe('scan_01')
    expect(parsed.scan.usage.llmCalls).toBe(123)
    expect(parsed.scan.coverage?.gaps).toHaveLength(2)
    expect(parsed.scan.models.planner?.model).toBe('deepseek-reasoner')
    expect(parsed.counts.byClosure).toEqual({ confirmed: 1, open_proof_gap: 3, ruled_out: 1 })
    expect(parsed.findings.map(f => f.id)).toEqual(['f_conf', 'f_secret', 'f_gap', 'f_low', 'f_ruled'])
    const original = input.findings.find(f => f.id === 'f_conf')!
    expect(parsed.findings[0]).toEqual(JSON.parse(JSON.stringify(original)))
  })

  it('uses null for missing coverage and threat model', () => {
    const parsed = JSON.parse(
      renderJson(reportInput({ scan: scanDetail({}, { coverage: undefined, threatModel: undefined }) })),
    ) as JsonReport
    expect(parsed.scan.coverage).toBeNull()
    expect(parsed.scan.threatModel).toBeNull()
  })
})

describe('reportFilename', () => {
  it('builds dsh-security-<slug>-<yyyymmdd-hhmm>.<ext> in UTC', () => {
    const input = reportInput({ workspaceTitle: 'Acme API', generatedAt: '2026-10-12T09:45:07.000Z' })
    expect(reportFilename(input, 'markdown')).toBe('dsh-security-acme-api-20261012-0945.md')
    expect(reportFilename(input, 'json')).toBe('dsh-security-acme-api-20261012-0945.json')
    expect(reportFilename(input, 'sarif')).toBe('dsh-security-acme-api-20261012-0945.sarif')
    expect(reportFilename({ ...input, generatedAt: '2026-10-12T23:59:00+09:00' }, 'json')).toBe(
      'dsh-security-acme-api-20261012-1459.json',
    )
  })

  it('produces ASCII-safe slugs', () => {
    expect(slugify('日本語のプロジェクト')).toBe('workspace')
    expect(slugify('セキュリティ api v2')).toBe('api-v2')
    expect(slugify('Café Déjà-Vu')).toBe('cafe-deja-vu')
    expect(slugify('../../etc/passwd')).toBe('etc-passwd')
    expect(slugify('a\u0000b<>:"/\\|?*c')).toBe('a-b-c')
    expect(slugify('   ')).toBe('workspace')
    expect(slugify('x'.repeat(100))).toHaveLength(48)
    for (const title of ['日本語', 'ｆｕｌｌｗｉｄｔｈ', 'CON', 'a—b', 'emoji 🚀 app']) {
      expect(slugify(title)).toMatch(/^[a-z0-9]+(?:-[a-z0-9]+)*$/)
    }
    expect(slugify('ｆｕｌｌｗｉｄｔｈ')).toBe('fullwidth')
  })

  it('falls back to undated for an unparseable timestamp', () => {
    expect(reportFilename(reportInput({ generatedAt: 'nope' }), 'markdown')).toBe('dsh-security-acme-api-undated.md')
  })
})

describe('renderReport', () => {
  it('returns filename, mime, and content per format', () => {
    const input = reportInput({ workspaceTitle: 'プロジェクト' })
    const md = renderReport(input, 'markdown')
    expect(md.filename).toBe('dsh-security-workspace-20261012-0945.md')
    expect(md.mime).toBe('text/markdown; charset=utf-8')
    expect(md.content.startsWith('# DSH Security report: プロジェクト')).toBe(true)
    expect(renderReport(input, 'json').mime).toBe('application/json')
    const sarif = renderReport(input, 'sarif')
    expect(sarif.mime).toBe('application/sarif+json')
    expect(sarifProblems(JSON.parse(sarif.content))).toEqual([])
  })

  it('is deterministic', () => {
    const input = reportInput()
    for (const format of ['markdown', 'json', 'sarif'] as const) {
      expect(renderReport(input, format).content).toBe(renderReport(input, format).content)
    }
  })
})
