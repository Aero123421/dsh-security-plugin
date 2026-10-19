import { describe, expect, it } from 'vitest'
import { DICTIONARIES, type Language } from '../../../src/client/i18n.ts'
import { labelsFor } from '../../../src/host/report/i18n.ts'

const LANGUAGES: Language[] = ['en', 'ja', 'zh']

/** The report and the results page describe the same coverage ledger, so they use the same words. */
describe.each(LANGUAGES)('coverage wording of the report matches the UI (%s)', language => {
  const ui = DICTIONARIES[language]
  const l = labelsFor(language).coverage

  it('names who added a part the same way', () => {
    expect(l.unitOrigin.critic).toBe(ui['coverage.unit.originCritic'])
    expect(l.unitOrigin.gap).toBe(ui['coverage.unit.originGap'])
  })

  it('uses the UI words for the part states', () => {
    expect(l.unitStatus['not-run']).toBe(ui['coverage.units.notRun'])
    expect(l.unitStatus.blocked).toBe(ui['coverage.units.blocked'])
    expect(l.unitStatus.finding).toBe(ui['coverage.units.finding'])
  })

  it('titles the parts the Host made like the UI does', () => {
    const fill = (template: string, values: Record<string, string>): string =>
      template.replace(/\{(\w+)\}/g, (_match, name: string) => values[name] ?? '')
    expect(l.unitTitles.endpoints('src/a.ts')).toBe(fill(ui['coverage.unit.title.endpoints'], { file: 'src/a.ts' }))
    expect(l.unitTitles.signals('src/a.ts')).toBe(fill(ui['coverage.unit.title.signals'], { file: 'src/a.ts' }))
    expect(l.unitTitles.triage('src/a.ts')).toBe(ui['coverage.unit.title.triage'])
    expect(l.unitTitles.sweep('3')).toBe(fill(ui['coverage.unit.title.sweep'], { count: '3' }))
    expect(l.unitTitles.file('src/a.ts')).toBe(fill(ui['coverage.unit.title.file'], { file: 'src/a.ts' }))
  })
})

describe('Japanese unassigned files', () => {
  it('do not read as excluded files', () => {
    const ja = DICTIONARIES.ja
    expect(ja['coverage.unassigned']).toBe('未割り当てのファイル')
    expect(ja['coverage.unassigned']).not.toContain('対象外')
    expect(ja['coverage.unassigned.value']).toContain('どの調査対象にも含まれない')
  })
})
