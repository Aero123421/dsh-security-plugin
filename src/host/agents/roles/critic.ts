/**
 * Coverage critic: after a hunt wave, reads the coverage ledger, the source
 * files no reviewer opened and the endpoints no reviewer was given, and
 * proposes new coverage units for real gaps, or stops. Uses the planner's
 * model route; the host validates its units like reconnaissance units.
 */

import { z } from 'zod'
import type { CoverageUnit, ReportLanguage } from '../../../shared/contracts.ts'
import type { Endpoint } from '../../analysis/types.ts'
import type { PlanUnitRecord } from '../../core/model.ts'
import type { RawUnit, UnitResolution } from '../../scan/units.ts'
import { describeUnresolved } from '../../scan/units.ts'
import { defineTool, type WorkerTool } from '../runtime/tool.ts'
import { bullets, clipLine, submitCoercion, systemPreamble } from './common.ts'
import { unitFixups, unitSchema } from './planner.ts'

const criticSchema = z.object({
  done: z
    .boolean()
    .default(false)
    .describe('true when coverage is adequate and nothing needs to be added (submit no units then).'),
  units: z.array(unitSchema).max(40).default([]).describe('New coverage units for real gaps, most important first.'),
  note: z.string().max(600).optional().describe('One or two sentences on what you checked.'),
})

type CriticSubmission = z.output<typeof criticSchema>

export interface CriticOutput {
  readonly done: boolean
  readonly units: readonly PlanUnitRecord[]
  readonly dropped: number
}

export interface CriticInput {
  /** The ledger so far (without the unassigned-files row). */
  readonly ledger: readonly CoverageUnit[]
  /** In-scope source files no worker read, best first (bounded by the caller). */
  readonly unread: readonly { readonly path: string; readonly language: string; readonly lines: number }[]
  /** How many unread files there are in all. */
  readonly unreadTotal: number
  /** Endpoints no finished task reviewed. */
  readonly endpoints: readonly Endpoint[]
  readonly maxUnits: number
  readonly pass: number
}

const MAX_LEDGER_ROWS = 80
const MAX_ENDPOINT_ROWS = 40

export function criticSystem(language: ReportLanguage): string {
  return systemPreamble('coverage critic', language)
}

export function criticTask(input: CriticInput): string {
  const ledger = input.ledger.slice(0, MAX_LEDGER_ROWS).map(unit => {
    const paths = unit.paths.slice(0, 3).join(', ') + (unit.paths.length > 3 ? ` (+${unit.paths.length - 3})` : '')
    const status = unit.reason ? `${unit.status}: ${unit.reason.code}` : unit.status
    return `[${status}] ${clipLine(unit.title, 100)}${unit.surface ? ` — ${clipLine(unit.surface, 80)}` : ''} — ${paths}`
  })
  const endpoints = input.endpoints
    .slice(0, MAX_ENDPOINT_ROWS)
    .map(e => `${e.method} ${clipLine(e.route, 120)}  ${e.handler?.path ?? e.declaredAt.path}`)
  const unread = input.unread.map(f => `${f.path}  (${f.language}, ${f.lines} lines)`)
  return `You are checking the coverage of a security review in progress (critic pass ${input.pass}); you do not look for vulnerabilities yourself. Reviewers examined the units below. Decide whether important attack surface or security-sensitive logic is still unexamined.

Coverage ledger (${input.ledger.length} units${input.ledger.length > MAX_LEDGER_ROWS ? `, first ${MAX_LEDGER_ROWS} shown` : ''}; covered = examined without findings, finding = examined with findings, blocked = examined but undecided, not-run = not examined):
${bullets(ledger)}

Source files no reviewer opened (${input.unreadTotal}${input.unreadTotal > unread.length ? `, ${unread.length} most review-worthy shown` : ''}):
${bullets(unread)}

Detected endpoints no reviewer was given (${input.endpoints.length}${input.endpoints.length > MAX_ENDPOINT_ROWS ? `, first ${MAX_ENDPOINT_ROWS} shown` : ''}):
${bullets(endpoints)}

Look for: entry surfaces and trust boundaries no unit covers; sensitive internals nobody read (authentication and sessions, authorization and tenant isolation, cryptography, uploads and file paths, deserialization, templates, shell execution, SQL and other queries, outbound requests); blocked units that a narrower follow-up could settle. Use list_files, read_file and search_code to check quickly.

Then call submit_coverage_review: propose up to ${input.maxUnits} new units for real gaps (most important first, 1-8 files each, not repeating a unit above), or set done to true with no units when coverage is adequate.`
}

/** Terminal tool for the critic; units are validated like reconnaissance units (unresolved ones are asked about once). */
export function criticSubmitTool(
  maxUnits: number,
  resolve: (units: readonly RawUnit[]) => UnitResolution,
): WorkerTool<CriticSubmission, CriticOutput> {
  let asked = false
  return defineTool<CriticSubmission, CriticOutput>({
    name: 'submit_coverage_review',
    description: `Propose up to ${maxUnits} new coverage units for real gaps, or set done to true. This ends your work.`,
    input: criticSchema,
    coerce: submitCoercion(criticSchema, unitFixups()),
    terminal: {
      validate: (args, context) => {
        if (asked || context.final || args.units.length === 0) return undefined
        const message = describeUnresolved(resolve(args.units).unresolved, 'submit_coverage_review')
        if (message !== undefined) asked = true
        return message
      },
      toOutput: args => {
        const resolution = resolve(args.units)
        return {
          done: args.done || resolution.units.length === 0,
          units: resolution.units,
          dropped: resolution.dropped,
        }
      },
    },
  })
}
