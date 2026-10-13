/**
 * Authoritative user settings: load (tolerating older or damaged stored
 * values), apply validated patches with optimistic concurrency, enforce the
 * remote-page rule for high-risk switches, and clamp to operator limits.
 */

import { z } from 'zod'
import type { OperatorLimits } from '../shared/contracts.ts'
import { ROLE_NAMES, type RoleName, SCAN_MODES, SEVERITIES } from '../shared/domain.ts'
import {
  DEFAULT_SETTINGS,
  HIGH_RISK_SETTING_PATHS,
  type ModelRef,
  type RoleModels,
  type ScanBudget,
  type SecuritySettings,
  type SettingsPatch,
} from '../shared/settings.ts'
import type { LoggerPort } from './dsh/ports.ts'
import { RpcError } from './rpc/errors.ts'
import type { SecurityStore } from './store/types.ts'

const modelRef = z
  .object({
    provider: z.string().min(1).max(200),
    model: z.string().min(1).max(200),
    reasoningEffort: z.string().min(1).max(200).optional(),
    maxOutputTokens: z.number().int().min(1).max(10_000_000).optional(),
  })
  .optional()
  .catch(undefined)

const budget = (fallback: ScanBudget) =>
  z
    .object({
      maxLlmCalls: z.number().int().min(1).catch(fallback.maxLlmCalls),
      maxTokens: z.number().int().min(1).catch(fallback.maxTokens),
      maxMinutes: z.number().int().min(1).catch(fallback.maxMinutes),
      maxTurnsPerWorker: z.number().int().min(1).max(500).catch(fallback.maxTurnsPerWorker),
      maxTasks: z.number().int().min(1).catch(fallback.maxTasks),
    })
    .catch(fallback)

const globs = z.array(z.string().min(1).max(300)).max(200).catch([])

const d = DEFAULT_SETTINGS

/** Lenient reader: every unreadable field falls back to its default. */
const storedSettings = z.object({
  models: z
    .object({
      default: modelRef,
      planner: modelRef,
      hunter: modelRef,
      skeptic: modelRef,
      chain: modelRef,
    })
    .catch({}),
  scan: z
    .object({
      defaultMode: z.enum(SCAN_MODES).catch(d.scan.defaultMode),
      excludeGlobs: globs,
      includeTests: z.boolean().catch(d.scan.includeTests),
      parallelWorkers: z.number().int().min(1).max(64).catch(d.scan.parallelWorkers),
      reviewThreshold: z.enum(SEVERITIES).catch(d.scan.reviewThreshold),
    })
    .catch({ ...d.scan, excludeGlobs: [...d.scan.excludeGlobs] }),
  budgets: z
    .object({
      quick: budget(d.budgets.quick),
      deep: budget(d.budgets.deep),
      research: budget(d.budgets.research),
    })
    .catch(d.budgets),
  privacy: z
    .object({
      sendCodeToModel: z.boolean().catch(d.privacy.sendCodeToModel),
      withheldGlobs: globs,
      allowDependencyLookup: z.boolean().catch(d.privacy.allowDependencyLookup),
      useExternalAnalyzers: z.boolean().catch(d.privacy.useExternalAnalyzers),
    })
    .catch({ ...d.privacy, withheldGlobs: [...d.privacy.withheldGlobs] }),
  storage: z
    .object({
      retentionDays: z.number().int().min(0).max(3650).catch(d.storage.retentionDays),
      keepTranscripts: z.boolean().catch(d.storage.keepTranscripts),
    })
    .catch(d.storage),
  ui: z.object({ language: z.enum(['auto', 'en', 'ja', 'zh']).catch('auto') }).catch(d.ui),
})

/** Parse a stored value, filling and repairing anything missing or invalid. */
export function readStoredSettings(value: unknown): SecuritySettings {
  // A root that is not a plain object (damaged JSON, an array) repairs to the defaults like any other field.
  const root = typeof value === 'object' && value !== null && !Array.isArray(value) ? value : {}
  const parsed = storedSettings.parse(root)
  const models: Record<string, ModelRef> = {}
  for (const key of ['default', ...ROLE_NAMES] as const) {
    const ref = parsed.models[key]
    if (ref) models[key] = stripUndefined(ref)
  }
  return { ...parsed, models: models as RoleModels }
}

/** Clamp preferences to operator ceilings. */
export function clampSettings(settings: SecuritySettings, limits: OperatorLimits): SecuritySettings {
  const clampBudget = (b: ScanBudget): ScanBudget => ({
    ...b,
    maxLlmCalls: Math.min(b.maxLlmCalls, limits.maxLlmCallsPerScan),
    maxTokens: Math.min(b.maxTokens, limits.maxTokensPerScan),
  })
  return {
    ...settings,
    scan: { ...settings.scan, parallelWorkers: Math.min(settings.scan.parallelWorkers, limits.maxParallelWorkers) },
    budgets: {
      quick: clampBudget(settings.budgets.quick),
      deep: clampBudget(settings.budgets.deep),
      research: clampBudget(settings.budgets.research),
    },
  }
}

/** Merge a validated patch into settings. Arrays replace; `null` clears a role model. */
export function applySettingsPatch(settings: SecuritySettings, patch: SettingsPatch): SecuritySettings {
  const models: Record<string, ModelRef> = { ...settings.models }
  for (const [key, value] of Object.entries(patch.models ?? {})) {
    if (value === null) delete models[key]
    else if (value !== undefined) models[key] = stripUndefined(value)
  }
  const mergeBudget = (mode: (typeof SCAN_MODES)[number]): ScanBudget => ({
    ...settings.budgets[mode],
    ...stripUndefined(patch.budgets?.[mode] ?? {}),
  })
  return {
    models: models as RoleModels,
    scan: { ...settings.scan, ...stripUndefined(patch.scan ?? {}) },
    budgets: { quick: mergeBudget('quick'), deep: mergeBudget('deep'), research: mergeBudget('research') },
    privacy: { ...settings.privacy, ...stripUndefined(patch.privacy ?? {}) },
    storage: { ...settings.storage, ...stripUndefined(patch.storage ?? {}) },
    ui: { ...settings.ui, ...stripUndefined(patch.ui ?? {}) },
  }
}

/** Paths of high-risk switches that the patch turns from off to on. */
export function enabledHighRiskPaths(before: SecuritySettings, after: SecuritySettings): string[] {
  return HIGH_RISK_SETTING_PATHS.filter(path => {
    const key = path.split('.')[1] as keyof SecuritySettings['privacy']
    return before.privacy[key] !== true && after.privacy[key] === true
  })
}

/** The model a role uses: its own override, else the default route. */
export function roleRoute(settings: SecuritySettings, role: RoleName): ModelRef | undefined {
  return settings.models[role] ?? settings.models.default
}

export class SettingsService {
  constructor(
    private readonly store: SecurityStore,
    private readonly limits: OperatorLimits,
    private readonly allowRemoteHighRisk: boolean,
    private readonly logger: LoggerPort,
  ) {}

  /** Current settings (clamped) and revision. */
  get(): { readonly settings: SecuritySettings; readonly revision: number } {
    const { value, revision } = this.store.readSettings()
    let settings: SecuritySettings
    try {
      settings = readStoredSettings(value)
    } catch (error) {
      this.logger.warn('dsh-security: stored settings unreadable, using defaults', error)
      settings = DEFAULT_SETTINGS
    }
    return { settings: clampSettings(settings, this.limits), revision }
  }

  /** Whether a page with this loopback status may turn high-risk switches on. */
  canEditHighRisk(loopback: boolean): boolean {
    return loopback || this.allowRemoteHighRisk
  }

  /**
   * Apply a patch with compare-and-set on `expectedRevision`.
   * @throws RpcError `security/conflict` on a stale revision,
   *   `security/forbidden-remote` when a remote page enables a high-risk switch the operator reserved.
   */
  update(
    patch: SettingsPatch,
    expectedRevision: number,
    loopback: boolean,
  ): { readonly settings: SecuritySettings; readonly revision: number } {
    const current = this.get()
    if (current.revision !== expectedRevision) {
      throw new RpcError('security/conflict', 'Settings were changed elsewhere. Reload and try again.', {
        revision: current.revision,
      })
    }
    const next = clampSettings(applySettingsPatch(current.settings, patch), this.limits)
    const enabled = enabledHighRiskPaths(current.settings, next)
    if (enabled.length > 0 && !this.canEditHighRisk(loopback)) {
      throw new RpcError(
        'security/forbidden-remote',
        'These settings can only be turned on from the machine running DSH.',
        { paths: enabled },
      )
    }
    const revision = this.store.writeSettings(next, expectedRevision)
    if (revision === undefined) {
      throw new RpcError('security/conflict', 'Settings were changed elsewhere. Reload and try again.', {
        revision: this.store.readSettings().revision,
      })
    }
    return { settings: next, revision }
  }
}

function stripUndefined<T extends object>(value: T): T {
  return Object.fromEntries(Object.entries(value).filter(([, v]) => v !== undefined)) as T
}
