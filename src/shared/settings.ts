/**
 * User-editable preferences. The Host owns the authoritative copy and clamps
 * every value to the operator ceilings declared in the plugin Config.
 */

import type { RoleName, ScanMode, Severity } from './domain.ts'

/** One provider/model route, as offered by DSH's LLM registry. */
export interface ModelRef {
  readonly provider: string
  readonly model: string
  /** Adapter-owned reasoning effort id; omitted uses the adapter default. */
  readonly reasoningEffort?: string
  /** Per-request output cap; omitted uses the adapter default. */
  readonly maxOutputTokens?: number
}

export type RoleModels = { readonly default?: ModelRef } & { readonly [R in RoleName]?: ModelRef }

/** Hard per-scan limits. The Host stops scheduling work once any is reached. */
export interface ScanBudget {
  /** Total model requests across all workers. */
  readonly maxLlmCalls: number
  /** Input + output tokens reported by the provider. */
  readonly maxTokens: number
  /** Wall-clock minutes from the first running moment. */
  readonly maxMinutes: number
  /** Model requests one worker may make before it must submit. */
  readonly maxTurnsPerWorker: number
  /** Upper bound on AI review tasks scheduled for one scan. */
  readonly maxTasks: number
}

export interface ScanPreferences {
  readonly defaultMode: ScanMode
  /** Extra gitignore-style patterns excluded from every scan. */
  readonly excludeGlobs: readonly string[]
  /** Include test and fixture directories in AI review (deterministic rules always see them). */
  readonly includeTests: boolean
  /** Concurrent AI workers per scan. */
  readonly parallelWorkers: number
  /** Findings at or above this severity get an independent skeptic review in Deep/Research. */
  readonly reviewThreshold: Severity
}

export interface PrivacyPreferences {
  /**
   * Allow sending (redacted) source code to the selected model providers.
   * Off by default: the first scan asks for explicit consent.
   */
  readonly sendCodeToModel: boolean
  /** Files never shown to a model, in addition to the built-in sensitive patterns. */
  readonly withheldGlobs: readonly string[]
  /**
   * Query the public OSV database for known-vulnerable dependencies. Sends
   * package names and versions only, never code. Off by default.
   */
  readonly allowDependencyLookup: boolean
  /** Use analyzers from the managed toolkit or PATH (gitleaks, osv-scanner, semgrep). */
  readonly useExternalAnalyzers: boolean
}

export interface StoragePreferences {
  /** Delete scans older than this many days at startup; 0 keeps everything. */
  readonly retentionDays: number
  /** Keep model transcripts for audit. */
  readonly keepTranscripts: boolean
}

export type UiLanguage = 'auto' | 'en' | 'ja' | 'zh'

export interface SecuritySettings {
  readonly models: RoleModels
  readonly scan: ScanPreferences
  readonly budgets: { readonly [M in ScanMode]: ScanBudget }
  readonly privacy: PrivacyPreferences
  readonly storage: StoragePreferences
  readonly ui: { readonly language: UiLanguage }
}

/** A deep-partial update. Arrays replace; objects merge. */
export type SettingsPatch = {
  readonly models?: { readonly [K in keyof RoleModels]?: ModelRef | null }
  readonly scan?: Partial<ScanPreferences>
  readonly budgets?: { readonly [M in ScanMode]?: Partial<ScanBudget> }
  readonly privacy?: Partial<PrivacyPreferences>
  readonly storage?: Partial<StoragePreferences>
  readonly ui?: { readonly language?: UiLanguage }
}

/**
 * Settings that widen what leaves the machine. When the operator does not
 * allow it, these can only be enabled from a loopback (same-machine) page.
 */
export const HIGH_RISK_SETTING_PATHS = [
  'privacy.sendCodeToModel',
  'privacy.allowDependencyLookup',
  'privacy.useExternalAnalyzers',
] as const

export const DEFAULT_BUDGETS: SecuritySettings['budgets'] = {
  quick: { maxLlmCalls: 120, maxTokens: 1_200_000, maxMinutes: 30, maxTurnsPerWorker: 36, maxTasks: 18 },
  deep: { maxLlmCalls: 900, maxTokens: 9_000_000, maxMinutes: 180, maxTurnsPerWorker: 72, maxTasks: 120 },
  research: { maxLlmCalls: 3600, maxTokens: 36_000_000, maxMinutes: 720, maxTurnsPerWorker: 120, maxTasks: 450 },
}

export const DEFAULT_SETTINGS: SecuritySettings = {
  models: {},
  scan: {
    defaultMode: 'deep',
    excludeGlobs: [],
    includeTests: false,
    parallelWorkers: 2,
    reviewThreshold: 'medium',
  },
  budgets: DEFAULT_BUDGETS,
  privacy: {
    sendCodeToModel: false,
    withheldGlobs: [],
    allowDependencyLookup: false,
    useExternalAnalyzers: true,
  },
  storage: { retentionDays: 90, keepTranscripts: true },
  ui: { language: 'auto' },
}
