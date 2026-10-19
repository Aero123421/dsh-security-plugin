/**
 * Planner (reconnaissance): maps the repository in any language, builds a
 * compact threat model, and plans the review as explicit coverage units that
 * become hunter tasks. Runs once per AI scan, briefly in Quick mode. The
 * same unit schema serves the coverage critic.
 */

import { z } from 'zod'
import type { ReportLanguage } from '../../../shared/contracts.ts'
import type { Endpoint, Inventory, Signal } from '../../analysis/types.ts'
import type { PlanUnitRecord } from '../../core/model.ts'
import type { RawUnit, UnitResolution } from '../../scan/units.ts'
import { describeUnresolved } from '../../scan/units.ts'
import { coerceArgs, type Fixup } from '../runtime/lenient.ts'
import { defineTool, type WorkerTool } from '../runtime/tool.ts'
import { bullets, categorySchema, clipLine, ENUM_ALIASES, submitCoercion, systemPreamble } from './common.ts'

/** A string fixup that shortens over-long text instead of rejecting the submission. */
function clipTo(max: number): Fixup {
  return value => (typeof value === 'string' && value.length > max ? `${value.slice(0, max - 1)}…` : value)
}

const unitTitleSchema = z
  .string()
  .min(1)
  .max(200)
  .describe('Short name of the slice, e.g. "Order API: read and update".')
const unitRationaleSchema = z
  .string()
  .min(1)
  .max(800)
  .describe('Why this slice matters and what the reviewer must verify (who may call it, what it protects).')
const unitHypothesisSchema = z
  .string()
  .max(800)
  .optional()
  .describe('A specific flaw you suspect here, if any (unverified).')
const unitFocusSchema = z
  .array(categorySchema)
  .min(1)
  .max(6)
  .describe('Finding categories to examine, e.g. ["authz", "injection"].')
const unitPrioritySchema = z
  .enum(['critical', 'high', 'medium', 'low'])
  .default('medium')
  .describe('How much this slice matters for security.')

export const unitSchema = z.object({
  title: unitTitleSchema,
  component: z.string().max(120).optional().describe('Component or subsystem, as named in components.'),
  surface: z
    .string()
    .max(200)
    .optional()
    .describe(
      'The entry surface, e.g. "POST /api/orders/:id", "GraphQL mutation updateUser", "CLI arguments", "queue consumer", "file import"; omit for internal mechanisms.',
    ),
  focus: unitFocusSchema,
  target_paths: z
    .array(z.string().min(1).max(400))
    .min(1)
    .max(8)
    .describe('1-8 workspace-relative files (or a directory) where the reviewer starts.'),
  priority: unitPrioritySchema,
  rationale: unitRationaleSchema,
  hypothesis: unitHypothesisSchema,
})

const reconSchema = z.object({
  summary: z
    .string()
    .min(1)
    .max(1500)
    .describe(
      'What the application does, who uses it, how authentication and authorization are enforced, and where the security-relevant logic lives.',
    ),
  assets: z.array(z.string().min(1).max(200)).max(15).default([]).describe('Valuable data or capabilities.'),
  actors: z
    .array(z.string().min(1).max(200))
    .max(10)
    .default([])
    .describe('Who interacts with the system and with which privileges.'),
  trust_boundaries: z
    .array(z.string().min(1).max(300))
    .max(15)
    .default([])
    .describe('Where untrusted data or requests enter, and where privilege changes.'),
  components: z
    .array(
      z.object({
        name: z.string().min(1).max(120),
        paths: z.array(z.string().min(1).max(400)).max(10).default([]).describe('Main files or directories.'),
      }),
    )
    .max(30)
    .default([])
    .describe('Main components or subsystems.'),
  units: z.array(unitSchema).max(120).default([]).describe('Coverage units, most important first.'),
  excluded: z
    .array(z.object({ path: z.string().min(1).max(400), reason: z.string().min(1).max(200) }))
    .max(50)
    .default([])
    .describe('Only vendored third-party code, generated code, documentation or test fixtures, with that reason.'),
})

type ReconSubmission = z.output<typeof reconSchema>

/** What reconnaissance produced, with units already resolved and validated by the host. */
export interface ReconOutput {
  readonly summary: string
  readonly assets: readonly string[]
  readonly actors: readonly string[]
  readonly trustBoundaries: readonly string[]
  readonly components: readonly { readonly name: string; readonly paths: readonly string[] }[]
  readonly units: readonly PlanUnitRecord[]
  readonly excluded: readonly { readonly path: string; readonly reason: string }[]
  /** Units dropped by validation (beyond the limit, duplicate, unresolved or out of scope). */
  readonly dropped: number
}

export interface ReconInput {
  readonly language: ReportLanguage
  readonly mode: 'quick' | 'deep' | 'research'
  readonly inventory: Inventory
  readonly fileCount: number
  /** Directory overview rows (see `directoryTree`). */
  readonly tree: readonly string[]
  readonly endpoints: readonly Endpoint[]
  readonly signals: readonly Signal[]
  readonly maxUnits: number
}

export function plannerSystem(language: ReportLanguage): string {
  return systemPreamble('planner', language)
}

/** Lenient repairs shared by every tool that submits units. */
export function unitFixups(): (readonly [z.ZodType, Fixup])[] {
  return [
    [unitTitleSchema, clipTo(200)],
    [unitRationaleSchema, clipTo(800)],
    [unitHypothesisSchema, clipTo(800)],
    [unitFocusSchema, keepCategories],
    [unitPrioritySchema, normalizePriority],
  ]
}

/** The categories in a focus list the schema knows (aliases applied); `other` when none is left. */
function keepCategories(value: unknown): unknown {
  if (value === null || value === undefined) return ['other']
  const list = Array.isArray(value) ? value : typeof value === 'string' ? value.split(/[,;]/) : [value]
  const kept = [
    ...new Set(
      list.flatMap(item => {
        const parsed = categorySchema.safeParse(coerceArgs(categorySchema, item, { aliases: ENUM_ALIASES }))
        return parsed.success ? [parsed.data] : []
      }),
    ),
  ].slice(0, 6)
  return kept.length > 0 ? kept : ['other']
}

/** `P1`, `1`, `"Critical risk"` and the like as one of the four priorities; anything else is `medium`. */
function normalizePriority(value: unknown): unknown {
  if (value === null || value === undefined) return undefined
  if (typeof value === 'number') return value <= 1 ? 'critical' : value <= 2 ? 'high' : value <= 3 ? 'medium' : 'low'
  if (typeof value !== 'string') return 'medium'
  const text = value.toLowerCase()
  if (/crit|p0|urgent/.test(text)) return 'critical'
  if (/high|p1|important/.test(text)) return 'high'
  if (/low|p3|p4|minor/.test(text)) return 'low'
  return 'medium'
}

export function plannerTask(input: ReconInput): string {
  const endpoints = input.endpoints
    .slice(0, 60)
    .map(
      e =>
        `${e.method} ${clipLine(e.route, 120)}  ${e.declaredAt.path}:${e.declaredAt.startLine}${e.handler && e.handler.path !== e.declaredAt.path ? ` → ${e.handler.path}` : ''}  auth=[${e.authHints.map(m => clipLine(m, 40)).join(', ')}]`,
    )
  const hits = new Map<string, { count: number; rules: Set<string> }>()
  for (const signal of input.signals) {
    if (signal.kind !== 'vulnerability' && signal.kind !== 'sink') continue
    const entry = hits.get(signal.location.path) ?? { count: 0, rules: new Set<string>() }
    entry.count++
    entry.rules.add(signal.ruleId)
    hits.set(signal.location.path, entry)
  }
  const ruleHits = [...hits.entries()]
    .sort((a, b) => b[1].count - a[1].count || (a[0] < b[0] ? -1 : 1))
    .slice(0, 30)
    .map(([path, { count, rules }]) => `${path}: ${count} (${[...rules].slice(0, 4).join(', ')})`)
  const languages = input.inventory.languages
    .slice(0, 10)
    .map(l => `${l.language} (${l.files} files)`)
    .join(', ')
  const quick = input.mode === 'quick'
  return `Map this repository and plan its security review as coverage units. Each unit is one slice that one reviewer examines next: an entry surface or a security mechanism, with the files that implement it. A coverage ledger reports which units were examined, so what no unit covers is at most skimmed by a broad sweep.

Facts from deterministic analysis (may be incomplete; route and rule detection know some languages and frameworks better than others):
- Files in scope: ${input.fileCount} (test files: ${input.inventory.testFiles})
- Languages: ${languages || 'unknown'}
- Frameworks: ${input.inventory.frameworks.join(', ') || 'none detected'}
- Manifests: ${input.inventory.manifests.slice(0, 15).join(', ') || 'none'}
- Directory overview (files per directory, main languages, markers):
${bullets(input.tree.map(row => clipLine(row, 160)))}
- HTTP endpoints detected (${input.endpoints.length}${input.endpoints.length > 60 ? ', first 60 shown' : ''}):
${bullets(endpoints)}
- Pattern-rule hits per file (hints, often false positives; ${hits.size} file(s)):
${bullets(ruleHits)}

Steps:
1. ${quick ? 'Read the few files that decide the structure (entry point, routing, authentication setup); you have only a few replies, so rely on the overview above.' : 'Explore with list_files, read the entry points, routing, configuration and authentication setup, and use search_code to find entry points the analyzers missed.'} Entry points can be in any language or framework: HTTP handlers and controllers, RPC or GraphQL resolvers, CLI arguments, message or queue consumers, scheduled jobs, webhooks, file imports and uploads.
2. Identify assets, actors with their privileges, trust boundaries and the main components.
3. Plan up to ${input.maxUnits} coverage units, most important first. Cover every entry surface and trust boundary first. Then cover sensitive internals: authentication and sessions, authorization and tenant isolation, cryptography and secret handling, file uploads and file paths, deserialization, templates and HTML rendering, shell and process execution, SQL and other queries, and outbound requests. Group related endpoints into one unit; split a large area so that each unit fits one reviewer (1-8 files).
4. For each unit give a title, the component, the surface (for entry points), focus categories, target_paths, priority, a rationale saying what to verify, and a hypothesis when you suspect a specific flaw.
5. In excluded, list only directories or files that are vendored third-party code, generated code, documentation or test fixtures, with that reason. Never exclude application code.
6. Submit with submit_review_plan. Do not try to find and prove vulnerabilities yourself.`
}

/**
 * Terminal tool for reconnaissance. `resolve` validates the submitted units
 * (see `resolveUnits`); a submission with units whose targets name no file is
 * sent back once with suggestions, and on acceptance such units are dropped.
 */
export function plannerSubmitTool(
  maxUnits: number,
  resolve: (units: readonly RawUnit[]) => UnitResolution,
): WorkerTool<ReconSubmission, ReconOutput> {
  let asked = false
  return defineTool<ReconSubmission, ReconOutput>({
    name: 'submit_review_plan',
    description: `Submit the threat model and up to ${maxUnits} coverage units, most important first. This ends your work.`,
    input: reconSchema,
    coerce: submitCoercion(reconSchema, unitFixups()),
    terminal: {
      validate: (args, context) => {
        if (asked || context.final) return undefined
        const message = describeUnresolved(resolve(args.units).unresolved, 'submit_review_plan')
        if (message !== undefined) asked = true
        return message
      },
      toOutput: args => {
        const resolution = resolve(args.units)
        return {
          summary: args.summary,
          assets: args.assets,
          actors: args.actors,
          trustBoundaries: args.trust_boundaries,
          components: args.components,
          units: resolution.units,
          excluded: args.excluded,
          dropped: resolution.dropped,
        }
      },
    },
  })
}
