import { describe, expect, it } from 'vitest'
import {
  buildPatch,
  draftFromSettings,
  enforceHighRisk,
  isHighRiskLocked,
  modelRefOf,
  parseGlobs,
  rebaseDraft,
  type SettingsDraft,
  validateDraft,
} from '../../src/client/settingsForm.ts'
import { DEFAULT_SETTINGS, HIGH_RISK_SETTING_PATHS } from '../../src/shared/settings.ts'
import { makeBootstrap, makeSettings } from './helpers.tsx'

const base = draftFromSettings(DEFAULT_SETTINGS)

function withPrivacy(draft: SettingsDraft, privacy: Partial<SettingsDraft['privacy']>): SettingsDraft {
  return { ...draft, privacy: { ...draft.privacy, ...privacy } }
}

describe('high-risk settings rule', () => {
  const offBase = withPrivacy(base, {
    sendCodeToModel: false,
    allowDependencyLookup: false,
    useExternalAnalyzers: false,
  })
  const onBase = withPrivacy(base, { sendCodeToModel: true, allowDependencyLookup: true, useExternalAnalyzers: true })

  it('without permission, an OFF high-risk setting cannot be turned ON', () => {
    for (const path of HIGH_RISK_SETTING_PATHS) {
      expect(isHighRiskLocked(path, offBase, offBase, false), path).toBe(true)
    }
  })

  it('without permission, an ON high-risk setting can still be turned OFF (and back)', () => {
    for (const path of HIGH_RISK_SETTING_PATHS) {
      expect(isHighRiskLocked(path, onBase, onBase, false), path).toBe(false)
      const turnedOff = withPrivacy(onBase, {
        sendCodeToModel: false,
        allowDependencyLookup: false,
        useExternalAnalyzers: false,
      })
      expect(isHighRiskLocked(path, onBase, turnedOff, false), path).toBe(false)
    }
  })

  it('with permission nothing is locked', () => {
    for (const path of HIGH_RISK_SETTING_PATHS) expect(isHighRiskLocked(path, offBase, offBase, true)).toBe(false)
  })

  it('enforceHighRisk strips forbidden enables from the patch but keeps disables', () => {
    const sneaky = withPrivacy(offBase, { sendCodeToModel: true, allowDependencyLookup: true })
    expect(buildPatch(offBase, enforceHighRisk(offBase, sneaky, false))).toEqual({})
    expect(buildPatch(offBase, enforceHighRisk(offBase, sneaky, true))).toEqual({
      privacy: { sendCodeToModel: true, allowDependencyLookup: true },
    })
    const disable = withPrivacy(onBase, { useExternalAnalyzers: false })
    expect(buildPatch(onBase, enforceHighRisk(onBase, disable, false))).toEqual({
      privacy: { useExternalAnalyzers: false },
    })
  })
})

describe('buildPatch', () => {
  it('is empty when nothing changed', () => {
    expect(buildPatch(base, base)).toEqual({})
  })

  it('emits only changed leaves', () => {
    const draft: SettingsDraft = {
      ...base,
      scan: { ...base.scan, excludeGlobs: 'dist/\n\n  build/  \ndist/', parallelWorkers: '3' },
      budgets: { ...base.budgets, quick: { ...base.budgets.quick, maxTokens: '500000' } },
      ui: { language: 'ja' },
    }
    expect(buildPatch(base, draft)).toEqual({
      scan: { excludeGlobs: ['dist/', 'build/'], parallelWorkers: 3 },
      budgets: { quick: { maxTokens: 500_000 } },
      ui: { language: 'ja' },
    })
  })

  it('sets and clears model routes', () => {
    const withModel: SettingsDraft = {
      ...base,
      models: {
        ...base.models,
        hunter: { provider: 'deepseek', model: 'deepseek-chat', reasoningEffort: 'high', maxOutputTokens: '8000' },
      },
    }
    expect(buildPatch(base, withModel)).toEqual({
      models: {
        hunter: { provider: 'deepseek', model: 'deepseek-chat', reasoningEffort: 'high', maxOutputTokens: 8000 },
      },
    })
    expect(buildPatch(withModel, base)).toEqual({ models: { hunter: null } })
  })

  it('ignores whitespace-only glob edits', () => {
    const b = draftFromSettings(makeSettings({ scan: { ...DEFAULT_SETTINGS.scan, excludeGlobs: ['a', 'b'] } }))
    expect(buildPatch(b, { ...b, scan: { ...b.scan, excludeGlobs: ' a \n b \n' } })).toEqual({})
  })
})

describe('validateDraft', () => {
  const limits = makeBootstrap().limits

  it('checks ranges for edited numeric fields against operator limits', () => {
    const draft: SettingsDraft = {
      ...base,
      scan: { ...base.scan, parallelWorkers: '9' },
      budgets: { ...base.budgets, deep: { ...base.budgets.deep, maxLlmCalls: 'abc' } },
      storage: { ...base.storage, retentionDays: '-1' },
    }
    const errors = validateDraft(draft, base, limits)
    expect(errors['scan.parallelWorkers']).toEqual({ key: 'validation.range', params: { min: 1, max: 4 } })
    expect(errors['budgets.deep.maxLlmCalls']).toEqual({ key: 'validation.range', params: { min: 1, max: 2000 } })
    expect(errors['storage.retentionDays']?.key).toBe('validation.range')
  })

  it('requires a model once a provider is chosen', () => {
    const draft: SettingsDraft = {
      ...base,
      models: { ...base.models, planner: { provider: 'p', model: '', reasoningEffort: '', maxOutputTokens: '' } },
    }
    expect(validateDraft(draft, base, limits)['models.planner.model']).toBeDefined()
  })

  it('accepts unchanged values even if they are out of range', () => {
    const b = { ...base, scan: { ...base.scan, parallelWorkers: '50' } }
    expect(validateDraft(b, b, limits)).toEqual({})
  })
})

describe('misc', () => {
  it('parseGlobs trims and de-duplicates', () => {
    expect(parseGlobs(' a \r\n\nb\na ')).toEqual(['a', 'b'])
  })

  it('modelRefOf requires provider and model', () => {
    expect(modelRefOf({ provider: 'p', model: '', reasoningEffort: '', maxOutputTokens: '' })).toBeNull()
    expect(modelRefOf({ provider: 'p', model: 'm', reasoningEffort: '', maxOutputTokens: '' })).toEqual({
      provider: 'p',
      model: 'm',
    })
  })

  it('draftFromSettings tolerates garbage', () => {
    const draft = draftFromSettings({ scan: { parallelWorkers: 'x' }, budgets: null } as never)
    expect(draft.scan.parallelWorkers).toBe(String(DEFAULT_SETTINGS.scan.parallelWorkers))
    expect(draft.budgets.deep.maxTokens).toBe(String(DEFAULT_SETTINGS.budgets.deep.maxTokens))
  })

  it('rebaseDraft keeps user edits and takes other server changes', () => {
    const edited = { ...base, storage: { ...base.storage, retentionDays: '30' } }
    const server = draftFromSettings(makeSettings({ ui: { language: 'zh' } }))
    const merged = rebaseDraft(base, server, edited)
    expect(merged.storage.retentionDays).toBe('30')
    expect(merged.ui.language).toBe('zh')
  })
})
