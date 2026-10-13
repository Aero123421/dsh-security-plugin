/**
 * Settings form model. The form edits a string-friendly draft (numbers stay
 * text until saved so inline validation can show what the user typed); a
 * minimal `SettingsPatch` is computed against the last-known server copy.
 * Pure functions only; covered by tests.
 */

import type { OperatorLimits } from '../shared/contracts.ts'
import { ROLE_NAMES, type RoleName, SCAN_MODES, SEVERITIES, type ScanMode, type Severity } from '../shared/domain.ts'
import {
  DEFAULT_SETTINGS,
  HIGH_RISK_SETTING_PATHS,
  type ModelRef,
  type ScanBudget,
  type SecuritySettings,
  type SettingsPatch,
  type UiLanguage,
} from '../shared/settings.ts'
import type { MessageKey, MessageParams } from './i18n.ts'

export type ModelSlot = 'default' | RoleName
export const MODEL_SLOTS: readonly ModelSlot[] = ['default', ...ROLE_NAMES]

export const BUDGET_FIELDS = ['maxLlmCalls', 'maxTokens', 'maxMinutes', 'maxTurnsPerWorker', 'maxTasks'] as const
export type BudgetField = (typeof BUDGET_FIELDS)[number]

export const UI_LANGUAGES: readonly UiLanguage[] = ['auto', 'en', 'ja', 'zh']

export interface ModelDraft {
  /** Empty string: not set (the role falls back to the default model). */
  readonly provider: string
  readonly model: string
  /** Empty string: adapter default. */
  readonly reasoningEffort: string
  /** Raw input; empty: adapter default. */
  readonly maxOutputTokens: string
}

export interface SettingsDraft {
  readonly models: Readonly<Record<ModelSlot, ModelDraft>>
  readonly scan: {
    readonly defaultMode: ScanMode
    readonly excludeGlobs: string
    readonly includeTests: boolean
    readonly parallelWorkers: string
    readonly reviewThreshold: Severity
  }
  readonly budgets: Readonly<Record<ScanMode, Readonly<Record<BudgetField, string>>>>
  readonly privacy: {
    readonly sendCodeToModel: boolean
    readonly withheldGlobs: string
    readonly allowDependencyLookup: boolean
    readonly useExternalAnalyzers: boolean
  }
  readonly storage: { readonly retentionDays: string; readonly keepTranscripts: boolean }
  readonly ui: { readonly language: UiLanguage }
}

export interface FieldError {
  readonly key: MessageKey
  readonly params?: MessageParams
}

export type HighRiskPath = (typeof HIGH_RISK_SETTING_PATHS)[number]

const EMPTY_MODEL: ModelDraft = { provider: '', model: '', reasoningEffort: '', maxOutputTokens: '' }

// ---------------------------------------------------------------------------
// Settings → draft
// ---------------------------------------------------------------------------

function bool(value: unknown, fallback: boolean): boolean {
  return typeof value === 'boolean' ? value : fallback
}

function num(value: unknown, fallback: number): string {
  return String(typeof value === 'number' && Number.isFinite(value) ? value : fallback)
}

function oneOf<T extends string>(value: unknown, allowed: readonly T[], fallback: T): T {
  return typeof value === 'string' && (allowed as readonly string[]).includes(value) ? (value as T) : fallback
}

function lines(value: unknown): string {
  return Array.isArray(value) ? value.filter(v => typeof v === 'string').join('\n') : ''
}

export function modelDraftOf(ref: ModelRef | undefined | null): ModelDraft {
  if (!ref || typeof ref.provider !== 'string' || !ref.provider) return EMPTY_MODEL
  return {
    provider: ref.provider,
    model: typeof ref.model === 'string' ? ref.model : '',
    reasoningEffort: typeof ref.reasoningEffort === 'string' ? ref.reasoningEffort : '',
    maxOutputTokens:
      typeof ref.maxOutputTokens === 'number' && Number.isFinite(ref.maxOutputTokens)
        ? String(ref.maxOutputTokens)
        : '',
  }
}

export function draftFromSettings(settings: SecuritySettings | undefined): SettingsDraft {
  const s = (settings ?? DEFAULT_SETTINGS) as Partial<SecuritySettings>
  const d = DEFAULT_SETTINGS
  const models = (s.models ?? {}) as SecuritySettings['models']
  const scan = (s.scan ?? {}) as Partial<SecuritySettings['scan']>
  const budgets = (s.budgets ?? {}) as Partial<SecuritySettings['budgets']>
  const privacy = (s.privacy ?? {}) as Partial<SecuritySettings['privacy']>
  const storage = (s.storage ?? {}) as Partial<SecuritySettings['storage']>
  const budgetDraft = (mode: ScanMode): Record<BudgetField, string> => {
    const b = (budgets[mode] ?? {}) as Partial<ScanBudget>
    const fallback = d.budgets[mode]
    return {
      maxLlmCalls: num(b.maxLlmCalls, fallback.maxLlmCalls),
      maxTokens: num(b.maxTokens, fallback.maxTokens),
      maxMinutes: num(b.maxMinutes, fallback.maxMinutes),
      maxTurnsPerWorker: num(b.maxTurnsPerWorker, fallback.maxTurnsPerWorker),
      maxTasks: num(b.maxTasks, fallback.maxTasks),
    }
  }
  return {
    models: {
      default: modelDraftOf(models.default),
      planner: modelDraftOf(models.planner),
      hunter: modelDraftOf(models.hunter),
      skeptic: modelDraftOf(models.skeptic),
      chain: modelDraftOf(models.chain),
    },
    scan: {
      defaultMode: oneOf(scan.defaultMode, SCAN_MODES, d.scan.defaultMode),
      excludeGlobs: lines(scan.excludeGlobs),
      includeTests: bool(scan.includeTests, d.scan.includeTests),
      parallelWorkers: num(scan.parallelWorkers, d.scan.parallelWorkers),
      reviewThreshold: oneOf(scan.reviewThreshold, SEVERITIES, d.scan.reviewThreshold),
    },
    budgets: { quick: budgetDraft('quick'), deep: budgetDraft('deep'), research: budgetDraft('research') },
    privacy: {
      sendCodeToModel: bool(privacy.sendCodeToModel, d.privacy.sendCodeToModel),
      withheldGlobs: lines(privacy.withheldGlobs),
      allowDependencyLookup: bool(privacy.allowDependencyLookup, d.privacy.allowDependencyLookup),
      useExternalAnalyzers: bool(privacy.useExternalAnalyzers, d.privacy.useExternalAnalyzers),
    },
    storage: {
      retentionDays: num(storage.retentionDays, d.storage.retentionDays),
      keepTranscripts: bool(storage.keepTranscripts, d.storage.keepTranscripts),
    },
    ui: { language: oneOf(s.ui?.language, UI_LANGUAGES, d.ui.language) },
  }
}

// ---------------------------------------------------------------------------
// Parsing and validation
// ---------------------------------------------------------------------------

/** One pattern per line; blank lines dropped; duplicates removed. */
export function parseGlobs(textValue: string): string[] {
  const seen = new Set<string>()
  for (const line of textValue.split(/\r?\n/)) {
    const trimmed = line.trim()
    if (trimmed) seen.add(trimmed)
  }
  return [...seen]
}

export function parseInteger(raw: string): number | undefined {
  const trimmed = raw.trim()
  if (!/^-?\d+$/.test(trimmed)) return undefined
  const value = Number(trimmed)
  return Number.isSafeInteger(value) ? value : undefined
}

export interface Range {
  readonly min: number
  readonly max: number
}

function ceiling(value: unknown, fallback: number): number {
  return typeof value === 'number' && Number.isFinite(value) && value >= 1 ? Math.floor(value) : fallback
}

export function parallelRange(limits: OperatorLimits | undefined): Range {
  return { min: 1, max: ceiling(limits?.maxParallelWorkers, 8) }
}

export function budgetRange(field: BudgetField, limits: OperatorLimits | undefined): Range {
  switch (field) {
    case 'maxLlmCalls':
      return { min: 1, max: ceiling(limits?.maxLlmCallsPerScan, 100_000) }
    case 'maxTokens':
      return { min: 1000, max: ceiling(limits?.maxTokensPerScan, 1_000_000_000) }
    case 'maxMinutes':
      return { min: 1, max: 1440 }
    case 'maxTurnsPerWorker':
      return { min: 1, max: 500 }
    case 'maxTasks':
      return { min: 1, max: 1000 }
  }
}

export const RETENTION_RANGE: Range = { min: 0, max: 3650 }
export const MAX_OUTPUT_RANGE: Range = { min: 1, max: 1_000_000 }

function checkRange(raw: string, range: Range, optional = false): FieldError | undefined {
  if (optional && raw.trim() === '') return undefined
  const value = parseInteger(raw)
  if (value === undefined || value < range.min || value > range.max) {
    return { key: 'validation.range', params: { min: range.min, max: range.max } }
  }
  return undefined
}

/**
 * Inline validation, keyed by field path (`scan.parallelWorkers`,
 * `budgets.deep.maxTokens`, `models.hunter.maxOutputTokens`, …). Only fields
 * the user changed are checked, so an out-of-range value stored by an older
 * version never blocks an unrelated save (the Host clamps it anyway).
 */
export function validateDraft(
  draft: SettingsDraft,
  base: SettingsDraft,
  limits: OperatorLimits | undefined,
): Record<string, FieldError> {
  const errors: Record<string, FieldError> = {}
  const add = (path: string, error: FieldError | undefined) => {
    if (error) errors[path] = error
  }
  for (const slot of MODEL_SLOTS) {
    const m = draft.models[slot]
    const b = base.models[slot]
    if (m.provider && !m.model) add(`models.${slot}.model`, { key: 'settings.chooseModel' })
    if (m.maxOutputTokens !== b.maxOutputTokens) {
      add(`models.${slot}.maxOutputTokens`, checkRange(m.maxOutputTokens, MAX_OUTPUT_RANGE, true))
    }
  }
  if (draft.scan.parallelWorkers !== base.scan.parallelWorkers) {
    add('scan.parallelWorkers', checkRange(draft.scan.parallelWorkers, parallelRange(limits)))
  }
  for (const mode of SCAN_MODES) {
    for (const field of BUDGET_FIELDS) {
      if (draft.budgets[mode][field] !== base.budgets[mode][field]) {
        add(`budgets.${mode}.${field}`, checkRange(draft.budgets[mode][field], budgetRange(field, limits)))
      }
    }
  }
  if (draft.storage.retentionDays !== base.storage.retentionDays) {
    add('storage.retentionDays', checkRange(draft.storage.retentionDays, RETENTION_RANGE))
  }
  return errors
}

// ---------------------------------------------------------------------------
// High-risk rule
// ---------------------------------------------------------------------------

export function highRiskValue(source: SettingsDraft, path: HighRiskPath): boolean {
  switch (path) {
    case 'privacy.sendCodeToModel':
      return source.privacy.sendCodeToModel
    case 'privacy.allowDependencyLookup':
      return source.privacy.allowDependencyLookup
    case 'privacy.useExternalAnalyzers':
      return source.privacy.useExternalAnalyzers
  }
}

export function isHighRiskPath(path: string): path is HighRiskPath {
  return (HIGH_RISK_SETTING_PATHS as readonly string[]).includes(path)
}

/**
 * Whether the toggle for a high-risk setting must be disabled. Without
 * permission a high-risk setting can be turned OFF but never ON; a value that
 * is on at the server (or still on in the draft) stays operable so the user
 * can switch it off, and back to the server value.
 */
export function isHighRiskLocked(
  path: HighRiskPath,
  base: SettingsDraft,
  draft: SettingsDraft,
  canEditHighRisk: boolean,
): boolean {
  if (canEditHighRisk) return false
  return !highRiskValue(base, path) && !highRiskValue(draft, path)
}

/** Force any high-risk value the user may not enable back to off. */
export function enforceHighRisk(base: SettingsDraft, draft: SettingsDraft, canEditHighRisk: boolean): SettingsDraft {
  if (canEditHighRisk) return draft
  const privacy = { ...draft.privacy }
  if (!base.privacy.sendCodeToModel) privacy.sendCodeToModel = false
  if (!base.privacy.allowDependencyLookup) privacy.allowDependencyLookup = false
  if (!base.privacy.useExternalAnalyzers) privacy.useExternalAnalyzers = false
  return { ...draft, privacy }
}

// ---------------------------------------------------------------------------
// Draft → minimal patch
// ---------------------------------------------------------------------------

export function modelRefOf(draft: ModelDraft): ModelRef | null {
  if (!draft.provider || !draft.model) return null
  const maxOutputTokens = parseInteger(draft.maxOutputTokens)
  return {
    provider: draft.provider,
    model: draft.model,
    ...(draft.reasoningEffort ? { reasoningEffort: draft.reasoningEffort } : {}),
    ...(maxOutputTokens !== undefined ? { maxOutputTokens } : {}),
  }
}

function sameModel(a: ModelRef | null, b: ModelRef | null): boolean {
  if (a === null || b === null) return a === b
  return (
    a.provider === b.provider &&
    a.model === b.model &&
    (a.reasoningEffort ?? '') === (b.reasoningEffort ?? '') &&
    (a.maxOutputTokens ?? null) === (b.maxOutputTokens ?? null)
  )
}

function sameList(a: readonly string[], b: readonly string[]): boolean {
  return a.length === b.length && a.every((item, i) => item === b[i])
}

type Mutable<T> = { -readonly [K in keyof T]: T[K] }

/**
 * Smallest patch that turns `base` into `draft`. Unparseable numbers are left
 * out (validation reports them). Returns `{}` when nothing changed.
 */
export function buildPatch(base: SettingsDraft, draft: SettingsDraft): SettingsPatch {
  const patch: Mutable<SettingsPatch> = {}

  const models: Partial<Record<ModelSlot, ModelRef | null>> = {}
  for (const slot of MODEL_SLOTS) {
    const next = modelRefOf(draft.models[slot])
    if (!sameModel(modelRefOf(base.models[slot]), next)) models[slot] = next
  }
  if (Object.keys(models).length) patch.models = models

  const scan: Mutable<NonNullable<SettingsPatch['scan']>> = {}
  if (draft.scan.defaultMode !== base.scan.defaultMode) scan.defaultMode = draft.scan.defaultMode
  if (!sameList(parseGlobs(draft.scan.excludeGlobs), parseGlobs(base.scan.excludeGlobs))) {
    scan.excludeGlobs = parseGlobs(draft.scan.excludeGlobs)
  }
  if (draft.scan.includeTests !== base.scan.includeTests) scan.includeTests = draft.scan.includeTests
  numberChange(base.scan.parallelWorkers, draft.scan.parallelWorkers, v => {
    scan.parallelWorkers = v
  })
  if (draft.scan.reviewThreshold !== base.scan.reviewThreshold) scan.reviewThreshold = draft.scan.reviewThreshold
  if (Object.keys(scan).length) patch.scan = scan

  const budgets: Partial<Record<ScanMode, Partial<ScanBudget>>> = {}
  for (const mode of SCAN_MODES) {
    const change: Partial<Mutable<ScanBudget>> = {}
    for (const field of BUDGET_FIELDS) {
      numberChange(base.budgets[mode][field], draft.budgets[mode][field], v => {
        change[field] = v
      })
    }
    if (Object.keys(change).length) budgets[mode] = change
  }
  if (Object.keys(budgets).length) patch.budgets = budgets

  const privacy: Mutable<NonNullable<SettingsPatch['privacy']>> = {}
  if (draft.privacy.sendCodeToModel !== base.privacy.sendCodeToModel) {
    privacy.sendCodeToModel = draft.privacy.sendCodeToModel
  }
  if (!sameList(parseGlobs(draft.privacy.withheldGlobs), parseGlobs(base.privacy.withheldGlobs))) {
    privacy.withheldGlobs = parseGlobs(draft.privacy.withheldGlobs)
  }
  if (draft.privacy.allowDependencyLookup !== base.privacy.allowDependencyLookup) {
    privacy.allowDependencyLookup = draft.privacy.allowDependencyLookup
  }
  if (draft.privacy.useExternalAnalyzers !== base.privacy.useExternalAnalyzers) {
    privacy.useExternalAnalyzers = draft.privacy.useExternalAnalyzers
  }
  if (Object.keys(privacy).length) patch.privacy = privacy

  const storage: Mutable<NonNullable<SettingsPatch['storage']>> = {}
  numberChange(base.storage.retentionDays, draft.storage.retentionDays, v => {
    storage.retentionDays = v
  })
  if (draft.storage.keepTranscripts !== base.storage.keepTranscripts) {
    storage.keepTranscripts = draft.storage.keepTranscripts
  }
  if (Object.keys(storage).length) patch.storage = storage

  if (draft.ui.language !== base.ui.language) patch.ui = { language: draft.ui.language }

  return patch
}

function numberChange(baseRaw: string, draftRaw: string, apply: (value: number) => void): void {
  const next = parseInteger(draftRaw)
  if (next === undefined) return
  if (parseInteger(baseRaw) !== next) apply(next)
}

export function isPatchEmpty(patch: SettingsPatch): boolean {
  return Object.keys(patch).length === 0
}

/** Whether the draft differs from base in any way the user would notice (including invalid input). */
export function isDraftDirty(base: SettingsDraft, draft: SettingsDraft): boolean {
  return JSON.stringify(base) !== JSON.stringify(draft)
}

/**
 * Carry the user's unsaved edits onto a newer server copy: every leaf the
 * user changed (relative to `oldBase`) keeps its draft value; everything else
 * takes the new server value. Model routes are treated as single leaves.
 */
export function rebaseDraft(oldBase: SettingsDraft, newBase: SettingsDraft, draft: SettingsDraft): SettingsDraft {
  return rebase(oldBase, newBase, draft) as SettingsDraft
}

function isLeaf(value: unknown): boolean {
  return typeof value !== 'object' || value === null || Array.isArray(value) || 'provider' in value
}

function rebase(oldValue: unknown, newValue: unknown, current: unknown): unknown {
  if (isLeaf(current) || isLeaf(newValue) || isLeaf(oldValue)) {
    return JSON.stringify(current) === JSON.stringify(oldValue) ? newValue : current
  }
  const out: Record<string, unknown> = {}
  const o = oldValue as Record<string, unknown>
  const n = newValue as Record<string, unknown>
  const c = current as Record<string, unknown>
  for (const key of new Set([...Object.keys(n), ...Object.keys(c)])) {
    out[key] = rebase(o[key], n[key], c[key])
  }
  return out
}
