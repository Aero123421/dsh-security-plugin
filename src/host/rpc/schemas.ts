/**
 * Request validation for every RPC method. The browser is not trusted: every
 * payload is parsed with a strict schema (unknown keys rejected, every string
 * and array bounded, every number finite and range-checked) before a handler
 * sees it.
 */

import { z } from 'zod'
import type { FindingFilter, ReportFormat, RpcMethodName, RpcRequest, ToolkitEntry } from '../../shared/contracts.ts'
import type { Closure, ScanMode } from '../../shared/domain.ts'
import { FINDING_SOURCES, SCAN_MODES, SEVERITIES, TRIAGE_STATES } from '../../shared/domain.ts'
import type {
  PrivacyPreferences,
  RoleModels,
  ScanBudget,
  ScanPreferences,
  SettingsPatch,
  StoragePreferences,
  UiLanguage,
} from '../../shared/settings.ts'

/** Upper bounds applied by the request schemas. */
export const REQUEST_LIMITS = {
  idLength: 64,
  noteLength: 2000,
  textFilterLength: 200,
  globCount: 200,
  globLength: 300,
  modelIdLength: 200,
  maxBudgetValue: 1e9,
  maxOutputTokens: 10_000_000,
  maxRetentionDays: 3650,
  minParallelWorkers: 1,
  maxParallelWorkers: 64,
  maxListLimit: 1000,
  maxFilterValues: 32,
} as const

// ---------------------------------------------------------------------------
// Closed vocabularies not exported as arrays by the shared modules
// ---------------------------------------------------------------------------

const CLOSURES = ['confirmed', 'open_proof_gap', 'ruled_out'] as const satisfies readonly Closure[]
const REPORT_FORMATS = ['markdown', 'json', 'sarif'] as const satisfies readonly ReportFormat[]
const UI_LANGUAGES = ['auto', 'en', 'ja', 'zh'] as const satisfies readonly UiLanguage[]
const TOOLKIT_IDS = ['gitleaks', 'osv-scanner', 'semgrep'] as const satisfies readonly ToolkitEntry['id'][]

/** `true` only when the tuple `A` lists every member of the union `T`. */
type Covers<T, A extends readonly unknown[]> = [Exclude<T, A[number]>] extends [never] ? true : false
const _vocabulariesCovered: [
  Covers<Closure, typeof CLOSURES>,
  Covers<ReportFormat, typeof REPORT_FORMATS>,
  Covers<UiLanguage, typeof UI_LANGUAGES>,
  Covers<ToolkitEntry['id'], typeof TOOLKIT_IDS>,
] = [true, true, true, true]
void _vocabulariesCovered

// ---------------------------------------------------------------------------
// Primitives
// ---------------------------------------------------------------------------

/** C0 controls and DEL; single-line fields reject all of them. */
const SINGLE_LINE_RE = /^[^\u0000-\u001f\u007f]*$/
/** Multi-line fields allow tab, LF, and CR only. */
const MULTI_LINE_RE = /^[^\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]*$/

/** Opaque identifiers (workspace, scan, finding). */
export const idSchema = z
  .string()
  .regex(/^[A-Za-z0-9_-]{1,64}$/, { error: 'Expected an id of 1-64 characters [A-Za-z0-9_-]' })

function singleLine(max: number, min = 0): z.ZodString {
  return z.string().min(min).max(max).regex(SINGLE_LINE_RE, { error: 'Control characters are not allowed' })
}

const modelIdSchema = singleLine(REQUEST_LIMITS.modelIdLength, 1)
const globSchema = singleLine(REQUEST_LIMITS.globLength, 1)
const globListSchema = z.array(globSchema).max(REQUEST_LIMITS.globCount)
const budgetValueSchema = z.int().min(1).max(REQUEST_LIMITS.maxBudgetValue)
const nonNegativeIntSchema = z.int().min(0).max(Number.MAX_SAFE_INTEGER)
const listLimitSchema = z.int().min(1).max(REQUEST_LIMITS.maxListLimit)
const scanModeSchema = z.enum(SCAN_MODES)
const severitySchema = z.enum(SEVERITIES)

// ---------------------------------------------------------------------------
// Settings patch
// ---------------------------------------------------------------------------

/** One provider/model route. */
export const modelRefSchema = z.strictObject({
  provider: modelIdSchema,
  model: modelIdSchema,
  reasoningEffort: modelIdSchema.optional(),
  maxOutputTokens: z.int().min(1).max(REQUEST_LIMITS.maxOutputTokens).optional(),
})

/** `null` clears a role's model so it falls back to the default route. */
const roleModelPatchSchema = modelRefSchema.nullable().optional()
const modelsPatchShape = {
  default: roleModelPatchSchema,
  planner: roleModelPatchSchema,
  hunter: roleModelPatchSchema,
  skeptic: roleModelPatchSchema,
  chain: roleModelPatchSchema,
} satisfies Record<keyof RoleModels, z.ZodType>

const scanPatchShape = {
  defaultMode: scanModeSchema.optional(),
  excludeGlobs: globListSchema.optional(),
  includeTests: z.boolean().optional(),
  parallelWorkers: z.int().min(REQUEST_LIMITS.minParallelWorkers).max(REQUEST_LIMITS.maxParallelWorkers).optional(),
  reviewThreshold: severitySchema.optional(),
} satisfies Record<keyof ScanPreferences, z.ZodType>

const budgetPatchShape = {
  maxLlmCalls: budgetValueSchema.optional(),
  maxTokens: budgetValueSchema.optional(),
  maxMinutes: budgetValueSchema.optional(),
  maxTurnsPerWorker: budgetValueSchema.optional(),
  maxTasks: budgetValueSchema.optional(),
} satisfies Record<keyof ScanBudget, z.ZodType>
const budgetPatchSchema = z.strictObject(budgetPatchShape).optional()

const budgetsPatchShape = {
  quick: budgetPatchSchema,
  deep: budgetPatchSchema,
  research: budgetPatchSchema,
} satisfies Record<ScanMode, z.ZodType>

const privacyPatchShape = {
  sendCodeToModel: z.boolean().optional(),
  withheldGlobs: globListSchema.optional(),
  allowDependencyLookup: z.boolean().optional(),
  useExternalAnalyzers: z.boolean().optional(),
} satisfies Record<keyof PrivacyPreferences, z.ZodType>

const storagePatchShape = {
  retentionDays: z.int().min(0).max(REQUEST_LIMITS.maxRetentionDays).optional(),
  keepTranscripts: z.boolean().optional(),
} satisfies Record<keyof StoragePreferences, z.ZodType>

const settingsPatchShape = {
  models: z.strictObject(modelsPatchShape).optional(),
  scan: z.strictObject(scanPatchShape).optional(),
  budgets: z.strictObject(budgetsPatchShape).optional(),
  privacy: z.strictObject(privacyPatchShape).optional(),
  storage: z.strictObject(storagePatchShape).optional(),
  ui: z.strictObject({ language: z.enum(UI_LANGUAGES).optional() }).optional(),
} satisfies Record<keyof SettingsPatch, z.ZodType>

/** Deep-partial settings update; arrays replace, objects merge. */
export const settingsPatchSchema: z.ZodType<SettingsPatch> = z.strictObject(settingsPatchShape)

// ---------------------------------------------------------------------------
// Findings filter
// ---------------------------------------------------------------------------

function enumList<const T extends readonly [string, ...string[]]>(values: T) {
  return z.array(z.enum(values)).max(REQUEST_LIMITS.maxFilterValues).optional()
}

const findingFilterShape = {
  severities: enumList(SEVERITIES),
  closures: enumList(CLOSURES),
  sources: enumList(FINDING_SOURCES),
  triage: enumList(TRIAGE_STATES),
  text: singleLine(REQUEST_LIMITS.textFilterLength).optional(),
} satisfies Record<keyof FindingFilter, z.ZodType>

/** Findings list filter. */
export const findingFilterSchema: z.ZodType<FindingFilter> = z.strictObject(findingFilterShape)

// ---------------------------------------------------------------------------
// Method map
// ---------------------------------------------------------------------------

/** One request schema per RPC method. */
export type RequestSchemas = { readonly [M in RpcMethodName]: z.ZodType<RpcRequest<M>> }

const emptyRequestSchema = z.strictObject({})
const scanRefSchema = z.strictObject({ scanId: idSchema })
const findingRefSchema = z.strictObject({ scanId: idSchema, findingId: idSchema })
const workspaceModeSchema = z.strictObject({ workspaceId: idSchema, mode: scanModeSchema })

/** Strict request schemas for every method; a missing method is a type error. */
export const requestSchemas = {
  getBootstrap: emptyRequestSchema,
  listWorkspaces: emptyRequestSchema,
  listModels: emptyRequestSchema,
  updateSettings: z.strictObject({ patch: settingsPatchSchema, expectedRevision: nonNegativeIntSchema }),
  estimateScan: workspaceModeSchema,
  createScan: workspaceModeSchema,
  listScans: z.strictObject({ workspaceId: idSchema.optional(), limit: listLimitSchema.optional() }),
  getScan: scanRefSchema,
  pauseScan: scanRefSchema,
  resumeScan: scanRefSchema,
  cancelScan: scanRefSchema,
  deleteScan: scanRefSchema,
  listFindings: z.strictObject({ scanId: idSchema, filter: findingFilterSchema.optional() }),
  getFinding: findingRefSchema,
  setTriage: z.strictObject({
    scanId: idSchema,
    findingId: idSchema,
    triage: z.enum(TRIAGE_STATES),
    note: z
      .string()
      .max(REQUEST_LIMITS.noteLength)
      .regex(MULTI_LINE_RE, { error: 'Control characters are not allowed' })
      .optional(),
  }),
  getFixPrompt: findingRefSchema,
  exportReport: z.strictObject({ scanId: idSchema, format: z.enum(REPORT_FORMATS) }),
  listEvents: z.strictObject({
    scanId: idSchema,
    afterSeq: nonNegativeIntSchema.optional(),
    limit: listLimitSchema.optional(),
  }),
  listToolkit: emptyRequestSchema,
  installTool: z.strictObject({ toolId: z.enum(TOOLKIT_IDS), acceptLicense: z.literal(true) }),
} satisfies RequestSchemas

/** The schema for one method, typed by the method name. */
export function requestSchemaFor<M extends RpcMethodName>(method: M): z.ZodType<RpcRequest<M>> {
  const schemas: RequestSchemas = requestSchemas
  return schemas[method]
}
