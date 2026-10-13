import { describe, expect, it } from 'vitest'
import {
  DICTIONARIES,
  errorText,
  getTranslator,
  interpolate,
  type Language,
  noticeText,
  resolveLanguage,
} from '../../src/client/i18n.ts'
import { ERROR_CODES } from '../../src/shared/contracts.ts'
import {
  FINDING_SOURCES,
  ROLE_NAMES,
  SCAN_MODES,
  SCAN_PHASES,
  SCAN_STATUSES,
  SEVERITIES,
  TRIAGE_STATES,
  VERIFICATIONS,
} from '../../src/shared/domain.ts'

const LANGS: Language[] = ['en', 'ja', 'zh']

describe('dictionaries', () => {
  it('have identical key sets in en, ja and zh', () => {
    const en = Object.keys(DICTIONARIES.en).sort()
    for (const lang of LANGS) {
      expect(Object.keys(DICTIONARIES[lang]).sort(), lang).toEqual(en)
    }
  })

  it('have no empty strings', () => {
    for (const lang of LANGS) {
      for (const [key, value] of Object.entries(DICTIONARIES[lang])) {
        expect(value.trim(), `${lang}:${key}`).not.toBe('')
      }
    }
  })

  it('use the same {placeholders} in every language', () => {
    const placeholders = (s: string) => [...s.matchAll(/\{(\w+)\}/g)].map(m => m[1]).sort()
    for (const [key, value] of Object.entries(DICTIONARIES.en)) {
      for (const lang of ['ja', 'zh'] as const) {
        const other = (DICTIONARIES[lang] as Record<string, string>)[key] ?? ''
        expect(placeholders(other), `${lang}:${key}`).toEqual(placeholders(value))
      }
    }
  })

  it('cover every contract error code and every domain enum the UI shows', () => {
    const keys = new Set(Object.keys(DICTIONARIES.en))
    const required = [
      ...ERROR_CODES.map(code => `error.${code}`),
      'error.security/transport',
      ...SEVERITIES.map(v => `severity.${v}`),
      ...VERIFICATIONS.flatMap(v => [`verification.${v}`, `verification.${v}.explain`]),
      ...SCAN_STATUSES.map(v => `status.${v}`),
      ...SCAN_PHASES.map(v => `phase.${v}`),
      ...SCAN_MODES.flatMap(v => [`mode.${v}`, `mode.${v}.desc`]),
      ...TRIAGE_STATES.map(v => `triage.${v}`),
      ...FINDING_SOURCES.map(v => `source.${v}`),
      ...ROLE_NAMES.flatMap(v => [`role.${v}`, `role.${v}.desc`]),
    ]
    for (const key of required) expect(keys.has(key), key).toBe(true)
  })

  it('keep CWE jargon out of the Japanese beginner copy (only the detail label mentions it)', () => {
    const withCwe = Object.entries(DICTIONARIES.ja)
      .filter(([, v]) => v.includes('CWE'))
      .map(([k]) => k)
    expect(withCwe).toEqual(['detail.cwe'])
  })
})

describe('resolveLanguage', () => {
  it('uses the explicit setting', () => {
    expect(resolveLanguage('ja', 'en-US')).toBe('ja')
    expect(resolveLanguage('zh', 'ja')).toBe('zh')
    expect(resolveLanguage('en', 'zh-CN')).toBe('en')
  })

  it('follows DSH when auto', () => {
    expect(resolveLanguage('auto', 'ja')).toBe('ja')
    expect(resolveLanguage('auto', 'ja-JP')).toBe('ja')
    expect(resolveLanguage('auto', 'zh')).toBe('zh')
    expect(resolveLanguage('auto', 'zh-Hant-TW')).toBe('zh')
    expect(resolveLanguage('auto', 'fr')).toBe('en')
    expect(resolveLanguage(undefined, undefined)).toBe('en')
  })
})

describe('translator', () => {
  it('interpolates {name} params and leaves unknown ones', () => {
    expect(interpolate('Hello {name}, {missing}', { name: 'Ana' })).toBe('Hello Ana, {missing}')
    expect(getTranslator('en').t('detail.step', { n: 2 })).toBe('Step 2')
    expect(getTranslator('ja').t('detail.step', { n: 2 })).toBe('手順 2')
  })

  it('localizes known error codes and falls back to the server message', () => {
    const ja = getTranslator('ja')
    expect(errorText(ja, { code: 'security/busy', message: 'busy' })).toContain('すでに実行中か順番待ち')
    expect(errorText(ja, { code: 'x/unknown', message: 'Server says hi' })).toBe('Server says hi')
    expect(errorText(ja, { code: 'x/unknown', message: '' })).toBe(ja.t('error.generic'))
  })

  it('localizes known notice keys and falls back to the server text', () => {
    const zh = getTranslator('zh')
    expect(noticeText(zh, { key: 'budget-exhausted', text: 'Budget exhausted' })).toContain('预算')
    expect(noticeText(zh, { key: 'something-new', text: 'English fallback' })).toBe('English fallback')
  })
})
