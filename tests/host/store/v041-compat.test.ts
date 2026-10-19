import { mkdtempSync, rmSync } from 'node:fs'
import { DatabaseSync } from 'node:sqlite'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import { findingTitle } from '../../../src/client/localized.ts'
import { getTranslator } from '../../../src/client/i18n.ts'
import { builtinSecretRules } from '../../../src/host/analysis/secrets.ts'
import { renderJson } from '../../../src/host/report/json.ts'
import { renderSarif } from '../../../src/host/report/sarif.ts'
import { openSecurityStore } from '../../../src/host/store/sqlite.ts'
import {
  SECRET_RULE_DESCRIPTIONS,
  secretBody,
  secretMessage,
  secretTitle,
  SECRET_RECOMMENDATION,
} from '../../../src/shared/secret-copy.ts'
import { findingOf, scanOf } from './fixtures.ts'
import { finding, reportInput, scanDetail } from '../report/fixtures.ts'

describe('0.4.1 databases', () => {
  let dir: string | undefined

  afterEach(() => {
    if (dir) rmSync(dir, { recursive: true, force: true })
    dir = undefined
  })

  it('opens a secret finding written without a copy field and keeps English reports', () => {
    dir = mkdtempSync(join(tmpdir(), 'dsh-v041-'))
    const path = join(dir, 'security.db')
    const title = secretTitle('GitHub token')
    const impact = secretMessage({ description: 'GitHub token', preview: 'ghp_****…', inTest: false })
    const summary = secretBody('GitHub token', 'ghp_****…')
    const store = openSecurityStore(path)
    store.insertScan(scanOf({ id: 'scan_old', pluginVersion: '0.4.1', status: 'completed', phase: 'done' }))
    store.insertFinding(
      findingOf({
        id: 'f_old',
        scanId: 'scan_old',
        title,
        summary,
        impact,
        recommendation: SECRET_RECOMMENDATION,
        ruleId: 'github-token',
        category: 'secrets',
        source: 'secret',
        cwe: 'CWE-798',
      }),
    )
    store.close()

    const raw = new DatabaseSync(path, { readOnly: true })
    try {
      const row = raw.prepare('SELECT data FROM findings WHERE id = ?').get('f_old') as { data: string }
      const data = JSON.parse(row.data) as { title: string; copy?: unknown; ruleId: string }
      expect(data.copy).toBeUndefined()
      expect(data.title).toBe(title)
      expect(data.ruleId).toBe('github-token')
    } finally {
      raw.close()
    }

    const again = openSecurityStore(path)
    try {
      const saved = again.getFinding('scan_old', 'f_old')
      expect(saved?.copy).toBeUndefined()
      expect(saved?.title).toBe(title)
      const detail = finding({
        id: 'f_old',
        title,
        summary,
        impact,
        recommendation: SECRET_RECOMMENDATION,
        ruleId: 'github-token',
        category: 'secrets',
        source: 'secret',
        cwe: 'CWE-798',
      })
      const input = reportInput({
        scan: scanDetail({ id: 'scan_old' }),
        findings: [detail],
        pluginVersion: '0.4.2',
        language: 'en',
      })
      const json = renderJson(input)
      const parsedJson = JSON.parse(json) as {
        findings: { title: string; summary: string; recommendation: string; ruleId: string; copy?: unknown }[]
      }
      const reported = parsedJson.findings[0]
      expect(reported?.title).toBe(title)
      expect(reported?.summary).toBe(summary)
      expect(reported?.recommendation).toBe(SECRET_RECOMMENDATION)
      expect(reported?.ruleId).toBe('github-token')
      expect(reported?.copy).toBeUndefined()
      expect(json).not.toMatch(/[ぁ-んァ-ン]/)
      const sarif = JSON.parse(renderSarif(input)) as {
        runs: { results: { ruleId: string; message: { text: string } }[] }[]
      }
      expect(sarif.runs[0]?.results[0]?.ruleId).toBe('github-token')
      expect(sarif.runs[0]?.results[0]?.message.text).toContain(title)
      expect(findingTitle(getTranslator('ja'), { ...saved!, impact: saved!.impact })).toContain('GitHub トークン')
      expect(findingTitle(getTranslator('en'), saved!)).toBe(title)
    } finally {
      again.close()
    }
  })

  it('lists the same secret rules the display catalog translates', () => {
    expect(builtinSecretRules().map(rule => [rule.id, rule.description])).toEqual(
      Object.entries(SECRET_RULE_DESCRIPTIONS),
    )
  })
})
