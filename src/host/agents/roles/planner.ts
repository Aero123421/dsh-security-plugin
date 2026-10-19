/**
 * Planner: builds a compact threat model and proposes concrete hypotheses
 * that become additional hunter tasks. Runs once per Deep/Research scan.
 */

import { z } from 'zod'
import type { ReportLanguage } from '../../../shared/contracts.ts'
import type { Endpoint, Inventory, Signal } from '../../analysis/types.ts'
import { defineTool, type WorkerTool } from '../runtime/tool.ts'
import { bullets, categorySchema, clipLine, submitCoercion, systemPreamble } from './common.ts'

export const hypothesisSchema = z.object({
  title: z.string().min(1).max(200).describe('Short name of what might be wrong.'),
  category: categorySchema,
  target_paths: z
    .array(z.string().min(1).max(400))
    .min(1)
    .max(6)
    .describe('Workspace-relative files where a reviewer should start.'),
  rationale: z.string().min(1).max(1000).describe('Why this place is worth checking and what to verify.'),
})

export const threatModelSchema = z.object({
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
  priorities: z
    .array(z.object({ target: z.string().min(1).max(300), reason: z.string().min(1).max(400) }))
    .max(20)
    .default([])
    .describe('Entry points or files that deserve the closest review, most important first.'),
  hypotheses: z.array(hypothesisSchema).max(20).default([]),
})

export type ThreatModelOutput = z.output<typeof threatModelSchema>

export interface PlannerInput {
  readonly language: ReportLanguage
  readonly inventory: Inventory
  readonly fileCount: number
  readonly endpoints: readonly Endpoint[]
  readonly signals: readonly Signal[]
  readonly maxHypotheses: number
}

export function plannerSystem(language: ReportLanguage): string {
  return systemPreamble('planner', language)
}

export function plannerTask(input: PlannerInput): string {
  const endpoints = input.endpoints
    .slice(0, 60)
    .map(
      e =>
        `${e.method} ${clipLine(e.route, 120)}  ${e.declaredAt.path}:${e.declaredAt.startLine}  middleware=[${e.middleware.map(m => clipLine(m, 40)).join(', ')}] auth=[${e.authHints.map(m => clipLine(m, 40)).join(', ')}]`,
    )
  const signals = input.signals
    .filter(s => s.kind === 'vulnerability' || s.kind === 'sink')
    .slice(0, 40)
    .map(s => `${s.ruleId} (${s.severity}) ${s.location.path}:${s.location.startLine} — ${clipLine(s.title, 100)}`)
  const languages = input.inventory.languages
    .slice(0, 8)
    .map(l => `${l.language} (${l.files} files)`)
    .join(', ')
  return `Build a threat model for this application so that the following review can focus on what matters.

Facts from deterministic analysis (may be incomplete):
- Files in scope: ${input.fileCount}
- Languages: ${languages || 'unknown'}
- Frameworks: ${input.inventory.frameworks.join(', ') || 'none detected'}
- Manifests: ${input.inventory.manifests.slice(0, 15).join(', ') || 'none'}
- HTTP endpoints detected (${input.endpoints.length}${input.endpoints.length > 60 ? ', first 60 shown' : ''}):
${bullets(endpoints)}
- Pattern-rule hits (hints, often false positives; ${signals.length} shown):
${bullets(signals)}

Steps:
1. Skim the structure (list_files), the application entry point, how authentication and authorization are set up, the data model, and multi-tenant or role logic.
2. Identify assets, actors with their privilege levels, and trust boundaries.
3. Propose up to ${input.maxHypotheses} concrete hypotheses: specific places where authorization, tenant isolation, input handling, business rules, or state changes could fail. Prefer logic flaws that pattern rules cannot see. Each hypothesis names 1-6 files to start from.
4. Submit with submit_threat_model. Keep it focused; do not try to find and prove vulnerabilities yourself.`
}

/**
 * Terminal tool for the planner. Hypotheses beyond `maxHypotheses` are cut
 * (the planner lists them most important first) instead of sending the
 * whole threat model back.
 */
export function plannerSubmitTool(maxHypotheses: number): WorkerTool<ThreatModelOutput, ThreatModelOutput> {
  return defineTool<ThreatModelOutput, ThreatModelOutput>({
    name: 'submit_threat_model',
    description: `Submit the threat model and up to ${maxHypotheses} hypotheses, most important first. This ends your work.`,
    input: threatModelSchema,
    coerce: submitCoercion(threatModelSchema),
    terminal: {
      toOutput: args => ({ ...args, hypotheses: args.hypotheses.slice(0, Math.max(0, maxHypotheses)) }),
    },
  })
}
