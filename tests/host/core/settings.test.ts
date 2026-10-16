import { describe, expect, it } from 'vitest'
import { Config, operatorLimits } from '../../../src/host/config.ts'
import { RpcError } from '../../../src/host/rpc/errors.ts'
import {
  applySettingsPatch,
  clampSettings,
  enabledHighRiskPaths,
  readStoredSettings,
  roleRoute,
  SettingsService,
} from '../../../src/host/settings.ts'
import { openSecurityStore } from '../../../src/host/store/sqlite.ts'
import type { OperatorLimits } from '../../../src/shared/contracts.ts'
import { DEFAULT_SETTINGS, type SecuritySettings } from '../../../src/shared/settings.ts'
import { recordingLogger } from '../rpc/helpers.ts'

const LIMITS: OperatorLimits = operatorLimits(Config.parse({}))

function service(options: { allowRemoteHighRisk?: boolean; limits?: OperatorLimits } = {}) {
  const store = openSecurityStore(':memory:')
  const logger = recordingLogger()
  const settings = new SettingsService(store, options.limits ?? LIMITS, options.allowRemoteHighRisk ?? true, logger)
  return { store, logger, settings }
}

function rpcCode(fn: () => unknown): string | undefined {
  try {
    fn()
  } catch (error) {
    if (error instanceof RpcError) return error.code
    throw error
  }
  return undefined
}

describe('readStoredSettings', () => {
  it('returns the defaults for nothing stored', () => {
    expect(readStoredSettings(undefined)).toEqual(DEFAULT_SETTINGS)
    expect(readStoredSettings(null)).toEqual(DEFAULT_SETTINGS)
    expect(readStoredSettings({})).toEqual(DEFAULT_SETTINGS)
  })

  it.each([['garbage'], [42], [true], [['an', 'array']]])('repairs a non-object root (%j) to the defaults', value => {
    expect(readStoredSettings(value)).toEqual(DEFAULT_SETTINGS)
  })

  it('keeps valid fields and repairs invalid ones individually', () => {
    const settings = readStoredSettings({
      models: {
        default: { provider: 'deepseek', model: 'deepseek-chat', reasoningEffort: undefined },
        hunter: { provider: '', model: 'x' },
        skeptic: 'not a model',
        planner: { provider: 'p', model: 'm', maxOutputTokens: -5 },
      },
      scan: { defaultMode: 'turbo', excludeGlobs: ['dist/**', 7], includeTests: true, parallelWorkers: 0 },
      budgets: { quick: { maxLlmCalls: 5, maxTokens: 'lots' }, deep: 'nope' },
      privacy: { sendCodeToModel: 'yes', withheldGlobs: ['secrets/**'], allowDependencyLookup: true },
      storage: { retentionDays: -1, keepTranscripts: false },
      ui: { language: 'fr' },
      unknown: { field: true },
    })
    expect(settings.models).toEqual({ default: { provider: 'deepseek', model: 'deepseek-chat' } })
    expect(Object.keys(settings.models.default ?? {})).toEqual(['provider', 'model'])
    expect(settings.scan).toEqual({
      defaultMode: 'deep',
      excludeGlobs: [],
      includeTests: true,
      parallelWorkers: 2,
      reviewThreshold: 'medium',
    })
    expect(settings.budgets.quick).toEqual({ ...DEFAULT_SETTINGS.budgets.quick, maxLlmCalls: 5 })
    expect(settings.budgets.deep).toEqual(DEFAULT_SETTINGS.budgets.deep)
    expect(settings.budgets.research).toEqual(DEFAULT_SETTINGS.budgets.research)
    expect(settings.privacy).toEqual({
      sendCodeToModel: false,
      withheldGlobs: ['secrets/**'],
      allowDependencyLookup: true,
      useExternalAnalyzers: true,
    })
    expect(settings.storage).toEqual({ retentionDays: 90, keepTranscripts: false })
    expect(settings.ui).toEqual({ language: 'auto' })
    expect(settings).not.toHaveProperty('unknown')
  })

  it('round-trips a fully valid value unchanged', () => {
    const value: SecuritySettings = {
      ...DEFAULT_SETTINGS,
      models: {
        default: { provider: 'a', model: 'b', reasoningEffort: 'high', maxOutputTokens: 4096 },
        chain: { provider: 'c', model: 'd' },
      },
      scan: { ...DEFAULT_SETTINGS.scan, excludeGlobs: ['vendor/**'], reviewThreshold: 'high' },
      ui: { language: 'ja' },
    }
    expect(readStoredSettings(JSON.parse(JSON.stringify(value)))).toEqual(value)
  })
})

describe('applySettingsPatch', () => {
  const base: SecuritySettings = {
    ...DEFAULT_SETTINGS,
    models: { default: { provider: 'a', model: 'one' }, hunter: { provider: 'a', model: 'two' } },
    scan: { ...DEFAULT_SETTINGS.scan, excludeGlobs: ['dist/**', 'build/**'] },
  }

  it('replaces arrays instead of merging them', () => {
    const next = applySettingsPatch(base, { scan: { excludeGlobs: ['out/**'] } })
    expect(next.scan.excludeGlobs).toEqual(['out/**'])
    expect(applySettingsPatch(base, { scan: { excludeGlobs: [] } }).scan.excludeGlobs).toEqual([])
  })

  it('clears a role model with null and leaves the others', () => {
    const next = applySettingsPatch(base, { models: { hunter: null, skeptic: { provider: 'b', model: 'three' } } })
    expect(next.models).toEqual({
      default: { provider: 'a', model: 'one' },
      skeptic: { provider: 'b', model: 'three' },
    })
  })

  it('merges nested objects and ignores undefined values', () => {
    const next = applySettingsPatch(base, {
      scan: { parallelWorkers: 3, includeTests: undefined },
      budgets: { deep: { maxTasks: 7 } },
      privacy: { sendCodeToModel: true },
      ui: { language: 'zh' },
    })
    expect(next.scan).toEqual({ ...base.scan, parallelWorkers: 3 })
    expect(next.budgets.deep).toEqual({ ...DEFAULT_SETTINGS.budgets.deep, maxTasks: 7 })
    expect(next.budgets.quick).toEqual(DEFAULT_SETTINGS.budgets.quick)
    expect(next.privacy).toEqual({ ...DEFAULT_SETTINGS.privacy, sendCodeToModel: true })
    expect(next.storage).toEqual(DEFAULT_SETTINGS.storage)
    expect(next.ui.language).toBe('zh')
    // The input is not mutated.
    expect(base.scan.parallelWorkers).toBe(2)
    expect(base.models.hunter).toEqual({ provider: 'a', model: 'two' })
  })
})

describe('clampSettings', () => {
  it('clamps workers, calls, and tokens to the operator limits and keeps the rest', () => {
    const limits: OperatorLimits = { ...LIMITS, maxParallelWorkers: 3, maxLlmCallsPerScan: 50, maxTokensPerScan: 1000 }
    const wide = applySettingsPatch(DEFAULT_SETTINGS, {
      scan: { parallelWorkers: 16 },
      budgets: { quick: { maxLlmCalls: 10, maxTokens: 500 } },
    })
    const clamped = clampSettings(wide, limits)
    expect(clamped.scan.parallelWorkers).toBe(3)
    expect(clamped.budgets.quick).toEqual({ ...DEFAULT_SETTINGS.budgets.quick, maxLlmCalls: 10, maxTokens: 500 })
    expect(clamped.budgets.deep).toEqual({ ...DEFAULT_SETTINGS.budgets.deep, maxLlmCalls: 50, maxTokens: 1000 })
    expect(clamped.budgets.research.maxMinutes).toBe(DEFAULT_SETTINGS.budgets.research.maxMinutes)
    expect(clamped.budgets.research.maxTasks).toBe(DEFAULT_SETTINGS.budgets.research.maxTasks)
  })
})

describe('roleRoute and enabledHighRiskPaths', () => {
  it('uses the role override, then the default route', () => {
    const settings = applySettingsPatch(DEFAULT_SETTINGS, {
      models: { default: { provider: 'a', model: 'fallback' }, skeptic: { provider: 'b', model: 'strict' } },
    })
    expect(roleRoute(settings, 'skeptic')).toEqual({ provider: 'b', model: 'strict' })
    expect(roleRoute(settings, 'hunter')).toEqual({ provider: 'a', model: 'fallback' })
    expect(roleRoute(DEFAULT_SETTINGS, 'planner')).toBeUndefined()
  })

  it('lists only switches that go from off to on', () => {
    const on = applySettingsPatch(DEFAULT_SETTINGS, {
      privacy: { sendCodeToModel: true, allowDependencyLookup: true },
    })
    expect(enabledHighRiskPaths(DEFAULT_SETTINGS, on)).toEqual([
      'privacy.sendCodeToModel',
      'privacy.allowDependencyLookup',
    ])
    expect(enabledHighRiskPaths(on, on)).toEqual([])
    expect(enabledHighRiskPaths(on, DEFAULT_SETTINGS)).toEqual([])
    // External analyzers are on by default, so re-sending `true` enables nothing.
    const external = applySettingsPatch(DEFAULT_SETTINGS, { privacy: { useExternalAnalyzers: true } })
    expect(enabledHighRiskPaths(DEFAULT_SETTINGS, external)).toEqual([])
  })
})

describe('SettingsService', () => {
  it('starts at revision 0 with clamped defaults', () => {
    const { settings } = service({ limits: { ...LIMITS, maxParallelWorkers: 1 } })
    const current = settings.get()
    expect(current.revision).toBe(0)
    expect(current.settings).toEqual({ ...DEFAULT_SETTINGS, scan: { ...DEFAULT_SETTINGS.scan, parallelWorkers: 1 } })
  })

  it('applies a patch with compare-and-set and stores the clamped result', () => {
    const { settings, store } = service({ limits: { ...LIMITS, maxParallelWorkers: 4 } })
    const first = settings.update({ scan: { parallelWorkers: 32, excludeGlobs: ['tmp/**'] } }, 0, true)
    expect(first.revision).toBe(1)
    expect(first.settings.scan.parallelWorkers).toBe(4)
    expect(settings.get()).toEqual(first)
    expect((store.readSettings().value as SecuritySettings).scan.parallelWorkers).toBe(4)

    const second = settings.update({ scan: { excludeGlobs: [] } }, 1, false)
    expect(second.revision).toBe(2)
    expect(second.settings.scan.excludeGlobs).toEqual([])
  })

  it('rejects a stale revision with security/conflict and changes nothing', () => {
    const { settings } = service()
    settings.update({ ui: { language: 'ja' } }, 0, true)
    let failure: unknown
    try {
      settings.update({ ui: { language: 'zh' } }, 0, true)
    } catch (error) {
      failure = error
    }
    expect(failure).toBeInstanceOf(RpcError)
    expect((failure as RpcError).code).toBe('security/conflict')
    expect((failure as RpcError).details).toEqual({ revision: 1 })
    expect(settings.get().settings.ui.language).toBe('ja')
  })

  it('forbids a remote page from enabling high-risk switches when the operator reserved them', () => {
    const { settings } = service({ allowRemoteHighRisk: false })
    expect(settings.canEditHighRisk(false)).toBe(false)
    expect(settings.canEditHighRisk(true)).toBe(true)
    let failure: unknown
    try {
      settings.update({ privacy: { sendCodeToModel: true, allowDependencyLookup: true } }, 0, false)
    } catch (error) {
      failure = error
    }
    expect((failure as RpcError).code).toBe('security/forbidden-remote')
    expect((failure as RpcError).details).toEqual({
      paths: ['privacy.sendCodeToModel', 'privacy.allowDependencyLookup'],
    })
    expect(settings.get()).toEqual({ settings: DEFAULT_SETTINGS, revision: 0 })

    // Ordinary settings stay editable remotely.
    expect(settings.update({ scan: { includeTests: true } }, 0, false).revision).toBe(1)
  })

  it('allows enabling from loopback and turning switches off remotely', () => {
    const { settings } = service({ allowRemoteHighRisk: false })
    const enabled = settings.update({ privacy: { sendCodeToModel: true } }, 0, true)
    expect(enabled.settings.privacy.sendCodeToModel).toBe(true)
    // Already on: re-sending true from a remote page enables nothing new.
    expect(rpcCode(() => settings.update({ privacy: { sendCodeToModel: true } }, 1, false))).toBeUndefined()
    const disabled = settings.update({ privacy: { sendCodeToModel: false, useExternalAnalyzers: false } }, 2, false)
    expect(disabled.settings.privacy).toMatchObject({ sendCodeToModel: false, useExternalAnalyzers: false })
    // ...but turning them back on remotely is refused.
    expect(rpcCode(() => settings.update({ privacy: { useExternalAnalyzers: true } }, 3, false))).toBe(
      'security/forbidden-remote',
    )
  })

  it('reserves withheld changes and route changes while either side consents to upload', () => {
    const { settings } = service({ allowRemoteHighRisk: false })
    settings.update(
      {
        privacy: { sendCodeToModel: true, withheldGlobs: ['private/**'] },
        models: { default: { provider: 'a', model: 'b' } },
      },
      0,
      true,
    )
    for (const patch of [
      { privacy: { withheldGlobs: [] } },
      { privacy: { withheldGlobs: ['private/**', 'more/**'] } },
      { models: { default: { provider: 'other', model: 'b' } } },
      { models: { hunter: { provider: 'a', model: 'other' } } },
      { models: { default: null } },
      { privacy: { sendCodeToModel: false, withheldGlobs: [] } },
    ]) {
      expect(rpcCode(() => settings.update(patch, 1, false))).toBe('security/forbidden-remote')
      expect(settings.get().revision).toBe(1)
    }
    // Re-sending consent/routes and changing execution parameters do not redirect disclosure.
    settings.update(
      {
        models: { default: { provider: 'a', model: 'b', maxOutputTokens: 4096 } },
        privacy: { withheldGlobs: ['private/**'] },
      },
      1,
      false,
    )
    settings.update({ privacy: { withheldGlobs: [] }, models: { default: null } }, 2, true)
    settings.update({ privacy: { sendCodeToModel: false } }, 3, false)
    expect(
      settings.update(
        { privacy: { withheldGlobs: ['other/**'] }, models: { hunter: { provider: 'c', model: 'd' } } },
        4,
        false,
      ).revision,
    ).toBe(5)
  })

  it('lets remote pages enable high-risk switches when the operator allows it', () => {
    const { settings } = service({ allowRemoteHighRisk: true })
    expect(settings.canEditHighRisk(false)).toBe(true)
    expect(settings.update({ privacy: { allowDependencyLookup: true } }, 0, false).settings.privacy).toMatchObject({
      allowDependencyLookup: true,
    })
  })

  it('reads damaged stored settings as defaults', () => {
    const { settings, store } = service()
    store.writeSettings('not settings' as unknown as SecuritySettings, 0)
    expect(settings.get()).toEqual({ settings: DEFAULT_SETTINGS, revision: 1 })
    store.writeSettings({ scan: { parallelWorkers: 'many' }, ui: { language: 'ja' } } as unknown as SecuritySettings, 1)
    const repaired = settings.get()
    expect(repaired.revision).toBe(2)
    expect(repaired.settings.scan.parallelWorkers).toBe(2)
    expect(repaired.settings.ui.language).toBe('ja')
    // An update on top of damaged data writes a fully valid record.
    settings.update({ storage: { retentionDays: 7 } }, 2, true)
    expect(readStoredSettings(store.readSettings().value)).toEqual(settings.get().settings)
  })
})
