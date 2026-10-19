import { describe, expect, it } from 'vitest'
import type { Signal } from '../../../src/host/analysis/types.ts'
import { Config } from '../../../src/host/config.ts'
import { analyzeWorkspace, dedupeSignals } from '../../../src/host/scan/analysis.ts'
import { DEFAULT_SETTINGS } from '../../../src/shared/settings.ts'
import { signalOf } from '../core/factories.ts'
import { makeTempDir, writeTree } from './helpers.ts'
import { MODES } from './sast-helpers.ts'

const j = (...parts: string[]) => parts.join('')
const at = (path: string, line: number) => ({ path, startLine: line, endLine: line })

const settings = {
  ...DEFAULT_SETTINGS,
  privacy: { ...DEFAULT_SETTINGS.privacy, useExternalAnalyzers: false, allowDependencyLookup: false },
}

async function analyze(files: Record<string, string>, handle: (typeof MODES)[number][1]): Promise<Signal[]> {
  const { dir, cleanup } = await makeTempDir()
  try {
    await writeTree(dir, files)
    const analysis = await analyzeWorkspace({
      root: dir,
      settings,
      config: Config.parse({}),
      toolkit: undefined,
      fetch: (async () => {
        throw new Error('offline')
      }) as typeof fetch,
      astGrep: handle,
      signal: new AbortController().signal,
    })
    return [...analysis.signals]
  } finally {
    await cleanup()
  }
}

describe('signal de-duplication', () => {
  describe.each(MODES)('%s mode: distinct issues on one line all survive the scan', (_mode, handle) => {
    it('keeps the high JWT none-algorithm hit next to the low ignoreExpiration hit', async () => {
      const signals = await analyze(
        {
          'src/auth.js':
            "const jwt = require('jsonwebtoken')\nmodule.exports = t => jwt.verify(t, process.env.KEY, { algorithms: ['HS256', 'none'], ignoreExpiration: true })\n",
        },
        handle,
      )
      const line2 = signals.filter(s => s.location.path === 'src/auth.js' && s.location.startLine === 2)
      expect(line2.map(s => `${s.ruleId}/${s.severity}`).sort()).toEqual([
        'js.jwt-ignore-expiration/low',
        'js.jwt-none-algorithm/high',
      ])
    })

    it('keeps both cookie flags written on one line', async () => {
      const signals = await analyze(
        {
          'src/app.js':
            "const session = require('express-session')\napp.use(session({ secret: process.env.SESSION_SECRET, cookie: { httpOnly: false, secure: false } }))\n",
        },
        handle,
      )
      const rules = signals.filter(s => s.location.startLine === 2).map(s => s.ruleId)
      expect(rules.sort()).toEqual(['js.cookie-insecure', 'js.cookie-without-httponly'])
    })

    it('keeps an AWS key id and its secret key written on one line', async () => {
      const signals = await analyze(
        {
          'src/aws.js': `const s3 = new S3Client({ credentials: { accessKeyId: '${j('AKIA', 'Q4ZJX7MB2KRP5TNW')}', secretAccessKey: '${j('qX7f3kL9mN2pR8sT1vW4', 'yZ6bC0dE5gH7jK9lM3nP')}' } })\n`,
        },
        handle,
      )
      const secrets = signals.filter(s => s.kind === 'secret').map(s => `${s.ruleId}/${s.severity}`)
      expect(secrets.sort()).toEqual(['aws-access-key-id/high', 'aws-secret-access-key/critical'])
    })

    it('keeps a database URL and a Slack token written on one line', async () => {
      const signals = await analyze(
        {
          'src/notify.js': `const pg = 'postgres://billing:${j('7hQ2mZ9x', 'K4pL')}@billing-db.prod.acme-corp.net:5432/billing'; const slack = '${j('xoxb', '-2849571038-4729106385-', 'Kq8mZ2xP9vL4tR7wY3nB6cD1')}'\n`,
        },
        handle,
      )
      expect(
        signals
          .filter(s => s.kind === 'secret')
          .map(s => s.ruleId)
          .sort(),
      ).toEqual(['database-url', 'slack-token'])
    })
  })

  it('merges an external result into the built-in signal at the same place, keeping the higher severity', () => {
    const builtin = signalOf({ location: at('src/a.js', 3), severity: 'medium', cwe: 'CWE-89' })
    const semgrep = signalOf({
      analyzer: 'semgrep',
      ruleId: 'rules.sqli',
      location: at('src/a.js', 3),
      severity: 'high',
      cwe: 'CWE-89',
    })
    expect(dedupeSignals([semgrep, builtin])).toEqual([{ ...builtin, severity: 'high' }])
    // A lower external severity never lowers the built-in one.
    expect(dedupeSignals([builtin, { ...semgrep, severity: 'low' }])).toEqual([builtin])
  })

  it('merges an external result into the built-in hit with its CWE when one line has several', () => {
    const none = signalOf({
      ruleId: 'js.jwt-none-algorithm',
      category: 'authn',
      cwe: 'CWE-347',
      severity: 'high',
      location: at('src/a.js', 1),
      metadata: { column: 12 },
    })
    const expiry = signalOf({
      ruleId: 'js.jwt-ignore-expiration',
      category: 'authn',
      cwe: 'CWE-613',
      severity: 'low',
      location: at('src/a.js', 1),
      metadata: { column: 40 },
    })
    const semgrep = signalOf({
      analyzer: 'semgrep',
      ruleId: 'rules.jwt-expiry',
      category: 'authn',
      cwe: 'CWE-613',
      severity: 'medium',
      location: at('src/a.js', 1),
    })
    expect(dedupeSignals([none, expiry, semgrep])).toEqual([none, { ...expiry, severity: 'medium' }])
  })

  it('merges Gitleaks only into the built-in secret whose columns it overlaps', () => {
    const keyId = signalOf({
      analyzer: 'secrets',
      ruleId: 'aws-access-key-id',
      kind: 'secret',
      category: 'secrets',
      severity: 'high',
      location: at('src/aws.js', 1),
      metadata: { column: 55, secretStart: 54, secretEnd: 74 },
    })
    const secret = signalOf({
      analyzer: 'secrets',
      ruleId: 'aws-secret-access-key',
      kind: 'secret',
      category: 'secrets',
      severity: 'critical',
      location: at('src/aws.js', 1),
      metadata: { column: 95, secretStart: 94, secretEnd: 134 },
    })
    const gitleaks = (column: number, endColumn: number, severity: Signal['severity']) =>
      signalOf({
        analyzer: 'gitleaks',
        ruleId: 'generic-api-key',
        kind: 'secret',
        category: 'secrets',
        severity,
        location: at('src/aws.js', 1),
        metadata: { column, endColumn },
      })
    // Overlaps the key id only: merged there, and the secret key keeps its own finding.
    expect(dedupeSignals([keyId, secret, gitleaks(55, 75, 'critical')])).toEqual([
      { ...keyId, severity: 'critical' },
      secret,
    ])
    // A span on the same line that no built-in rule matched is a separate credential.
    const elsewhere = gitleaks(140, 170, 'medium')
    expect(dedupeSignals([keyId, secret, elsewhere])).toEqual([keyId, secret, elsewhere])
    // Without columns the external result is taken as a duplicate, as before.
    const noColumns = signalOf({ ...elsewhere, metadata: {} })
    expect(dedupeSignals([keyId, secret, noColumns])).toEqual([keyId, secret])
  })

  it('keeps different spans of one rule on one line and drops exact repeats', () => {
    const generic = (start: number) =>
      signalOf({
        analyzer: 'secrets',
        ruleId: 'generic-secret',
        kind: 'secret',
        category: 'secrets',
        severity: 'medium',
        location: at('src/c.js', 1),
        metadata: { column: start + 1, secretStart: start, secretEnd: start + 20 },
      })
    expect(dedupeSignals([generic(10), generic(40)])).toEqual([generic(10), generic(40)])
    expect(dedupeSignals([generic(10), generic(10)])).toEqual([generic(10)])
    const unguarded = signalOf({ analyzer: 'routes', ruleId: 'routes.unguarded', kind: 'sink' })
    expect(dedupeSignals([unguarded, { ...unguarded, fingerprintParts: ['other'] }])).toEqual([unguarded])
  })

  it('keeps one dependency advisory per package version with the higher severity', () => {
    const osv = signalOf({
      analyzer: 'osv',
      ruleId: 'GHSA-1',
      kind: 'dependency',
      category: 'dependency',
      severity: 'medium',
      snippet: 'lodash@4.17.20',
    })
    const scanner = { ...osv, analyzer: 'osv-scanner' as const, severity: 'high' as const }
    expect(dedupeSignals([osv, scanner])).toEqual([{ ...osv, severity: 'high' }])
    expect(dedupeSignals([osv, { ...osv, snippet: 'lodash@4.17.21' }])).toHaveLength(2)
  })
})
