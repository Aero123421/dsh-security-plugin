/**
 * Hunter: investigates one slice of the application (an endpoint group, a set
 * of rule hits, a sensitive file, or a planner hypothesis) and submits
 * findings whose attack paths cite exact code. The host verifies every quote
 * before anything is stored.
 */

import { z } from 'zod'
import type { ReportLanguage } from '../../../shared/contracts.ts'
import { type FindingCategory, isQuoteVerified } from '../../../shared/domain.ts'
import type { Endpoint, Signal } from '../../analysis/types.ts'
import type { TaskKind } from '../../core/model.ts'
import { normalizeForMatch } from '../../evidence/normalize.ts'
import type { QuoteSource } from '../../evidence/quote.ts'
import { defineTool, type WorkerTool } from '../runtime/tool.ts'
import {
  bullets,
  type Citation,
  categorySchema,
  citationSchema,
  clipLine,
  cweSchema,
  defenseSchema,
  describeCommentOnly,
  describeMismatches,
  isVerifiedCode,
  MAX_CITATIONS,
  normalizeShortId,
  severitySchema,
  submitCoercion,
  systemPreamble,
  type VerifiedCitation,
  verifyCitation,
} from './common.ts'

const referenceSchema = z.url().max(300)
const referencesSchema = z
  .array(referenceSchema)
  .max(5)
  .optional()
  .describe('Reference URLs (http or https); anything that is not a URL is ignored.')

const findingSchema = z.object({
  title: z
    .string()
    .min(1)
    .max(160)
    .describe('Specific title, e.g. "Any logged-in user can read other users\' orders".'),
  category: categorySchema,
  cwe: cweSchema,
  severity: severitySchema,
  summary: z.string().min(1).max(700).describe('One or two plain sentences: what is wrong.'),
  impact: z.string().min(1).max(900).describe('What an attacker gains, in concrete terms.'),
  preconditions: z
    .array(z.string().min(1).max(300))
    .max(6)
    .default([])
    .describe('What must be true for the attack (e.g. "attacker has any user account").'),
  attack_path: z
    .array(citationSchema)
    .min(1)
    .max(MAX_CITATIONS)
    .describe('Ordered steps from the entry point to the harmful effect, each citing exact code.'),
  defenses_checked: z
    .array(defenseSchema)
    .max(6)
    .default([])
    .describe('Protections you looked for and why they do not stop the attack.'),
  recommendation: z.string().min(1).max(1500).describe('How to fix it in this codebase, concretely.'),
  references: referencesSchema,
})

const signalIdSchema = z.string().min(1).max(20).describe('Signal id from the task, e.g. "S2".')
const assessmentSchema = z.object({
  id: signalIdSchema,
  verdict: z.enum(['true_positive', 'false_positive', 'uncertain']),
  reason: z.string().min(1).max(800),
  evidence: citationSchema.optional().describe('Code that proves the verdict (the vulnerable flow, or the defense).'),
})

const coverageSchema = z
  .enum(['complete', 'partial', 'needs-runtime'])
  .optional()
  .describe(
    'How completely you examined the part described in the task: complete; partial (you could not finish); needs-runtime (the outcome depends on deployment or runtime state you cannot see in the source).',
  )
const coverageNoteSchema = z.string().max(400).optional().describe('One sentence on what is left open, if anything.')

const submissionSchema = z.object({
  findings: z.array(findingSchema).max(10).describe('Verified vulnerabilities. An empty list is a valid result.'),
  signal_assessments: z
    .array(assessmentSchema)
    .max(40)
    .default([])
    .describe('A verdict for every rule hit (S1, S2, …) listed in the task.'),
  coverage: coverageSchema,
  coverage_note: coverageNoteSchema,
})

type Submission = z.output<typeof submissionSchema>
type RawFinding = z.output<typeof findingSchema>
type RawAssessment = z.output<typeof assessmentSchema>

export interface HunterFinding {
  readonly title: string
  readonly category: FindingCategory
  readonly cwe?: string
  readonly severity: RawFinding['severity']
  readonly summary: string
  readonly impact: string
  readonly preconditions: readonly string[]
  readonly attackPath: readonly VerifiedCitation[]
  readonly defenses: readonly VerifiedCitation[]
  readonly recommendation: string
  readonly references: readonly string[]
}

export interface HunterAssessment {
  readonly id: string
  readonly verdict: 'true_positive' | 'false_positive' | 'uncertain'
  readonly reason: string
  readonly evidence?: VerifiedCitation
}

export interface HunterOutput {
  readonly findings: readonly HunterFinding[]
  readonly assessments: readonly HunterAssessment[]
  /** The hunter's own verdict on how completely it examined its part; absent when not given. */
  readonly coverage?: { readonly verdict: 'complete' | 'partial' | 'needs-runtime'; readonly note?: string }
}

/** A deterministic hit shown to the hunter with a short id for its verdict. */
export interface TaskSignal {
  readonly id: string
  readonly signal: Signal
}

export interface HunterTaskInput {
  readonly kind: TaskKind
  readonly focus: readonly FindingCategory[]
  readonly targetPaths: readonly string[]
  readonly endpoints: readonly Endpoint[]
  readonly signals: readonly TaskSignal[]
  readonly hypothesis?: string
  /** The coverage unit this task examines (plan, critic or gap units). */
  readonly unit?: {
    readonly title: string
    readonly component?: string
    readonly surface?: string
    readonly rationale?: string
  }
  readonly threatModelSummary?: string
  /** The planner's actors (who uses the system, with which privileges). */
  readonly actors?: readonly string[]
  /** The planner's trust boundaries. */
  readonly trustBoundaries?: readonly string[]
  /** Issues already reported by analyzers in these files (to avoid duplicates). */
  readonly known: readonly string[]
  readonly frameworks: readonly string[]
}

const FOCUS_TEXT: Record<FindingCategory, string> = {
  injection: 'injection into SQL/NoSQL/template/LDAP interpreters',
  authz:
    'authorization: missing checks, IDOR (object access by id without ownership checks), privilege escalation, tenant isolation',
  authn: 'authentication, sessions, tokens and JWT handling',
  secrets: 'secret handling',
  dependency: 'dependency usage',
  crypto: 'cryptography and randomness',
  ssrf: 'server-side request forgery',
  xss: 'cross-site scripting and unsafe HTML rendering',
  'path-traversal': 'file path handling and traversal',
  deserialization: 'unsafe deserialization',
  'command-execution': 'OS command execution',
  'business-logic': 'business rules and workflows that can be abused',
  'race-condition': 'race conditions and check-then-act on shared state',
  misconfiguration: 'security-relevant configuration',
  'data-exposure': 'exposure of sensitive data in responses, logs or errors',
  other: 'other security issues',
}

export function hunterSystem(language: ReportLanguage): string {
  return systemPreamble('hunter', language)
}

export function hunterTask(input: HunterTaskInput): string {
  const sections: string[] = []
  sections.push(
    'Investigate the part of the application described below for exploitable security vulnerabilities, then call submit_findings.',
  )
  if (input.focus.length > 0) {
    sections.push(`Focus areas:\n${bullets(input.focus.map(f => FOCUS_TEXT[f]))}`)
  }
  if (input.frameworks.length > 0) sections.push(`Frameworks in use: ${input.frameworks.join(', ')}`)
  if (input.threatModelSummary) {
    const context = [`Threat model summary:\n${input.threatModelSummary}`]
    if (input.actors && input.actors.length > 0) {
      context.push(`Actors:\n${bullets(input.actors.slice(0, 8).map(actor => clipLine(actor, 160)))}`)
    }
    if (input.trustBoundaries && input.trustBoundaries.length > 0) {
      context.push(
        `Trust boundaries:\n${bullets(input.trustBoundaries.slice(0, 8).map(boundary => clipLine(boundary, 200)))}`,
      )
    }
    sections.push(`${context.join('\n')}\n(The threat model is the planner's reading of the code, not verified facts.)`)
  }
  if (input.unit) {
    const rows = [
      `Unit: ${clipLine(input.unit.title, 200)}`,
      ...(input.unit.component ? [`Component: ${clipLine(input.unit.component, 120)}`] : []),
      ...(input.unit.surface ? [`Entry surface: ${clipLine(input.unit.surface, 200)}`] : []),
      ...(input.unit.rationale ? [`What to verify (planner's view): ${clipLine(input.unit.rationale, 800)}`] : []),
    ]
    sections.push(
      `The part of the application assigned to you (a coverage unit of the review plan; examine all of it, following calls into other files as needed):\n${rows.join('\n')}`,
    )
  }
  if (input.hypothesis) {
    sections.push(`Hypothesis from the planner (unverified — check it, do not assume it):\n${input.hypothesis}`)
  }
  if (input.endpoints.length > 0) {
    const rows = input.endpoints.map(
      e =>
        `${e.method} ${clipLine(e.route, 120)}  declared at ${e.declaredAt.path}:${e.declaredAt.startLine}${e.handler ? `, handler ${e.handler.path}:${e.handler.startLine}-${e.handler.endLine}` : ''}  middleware=[${e.middleware.map(m => clipLine(m, 40)).join(', ')}]  auth hints=[${e.authHints.map(m => clipLine(m, 40)).join(', ')}]`,
    )
    sections.push(
      `Endpoints in scope (detected statically; middleware applied when routers are mounted elsewhere may be missing from this list, so check how and where these routes are mounted):\n${bullets(rows)}\n\nFor each endpoint ask: who can call it? Is authentication enforced (including app- or router-level middleware)? Is access to the specific object or tenant checked against the caller? What happens to user input?`,
    )
  }
  const reportable = input.signals.filter(({ signal }) => signal.kind !== 'sink')
  const sinks = input.signals.filter(({ signal }) => signal.kind === 'sink')
  if (sinks.length > 0) {
    sections.push(
      `Review steering observations (not findings; missing static auth hints do not prove missing protection):\n${bullets(sinks.map(({ signal }) => `${signal.ruleId} — ${clipLine(signal.title, 100)} at ${signal.location.path}:${signal.location.startLine}\n    ${clipLine(signal.snippet, 240)}`))}\nCheck reachability, inherited protections and intended public access; do not assess these as rule-hit findings.`,
    )
  }
  if (reportable.length > 0) {
    const rows = reportable.map(
      ({ id, signal }) =>
        `${id}: ${signal.ruleId} — ${clipLine(signal.title, 100)} at ${signal.location.path}:${signal.location.startLine}-${signal.location.endLine} (rule confidence ${signal.confidence})\n    ${clipLine(signal.snippet, 240)}`,
    )
    sections.push(
      `Pattern-rule hits to verify (hints only; many are false positives):\n${rows.join('\n')}\n\nFor each hit, decide whether attacker-controlled data really reaches the sink without effective sanitization, and give a verdict for every id in signal_assessments (cite the code that proves it). Report confirmed ones as findings with a full attack path.`,
    )
  }
  if (input.targetPaths.length > 0) {
    sections.push(`Start with these files:\n${bullets(input.targetPaths.slice(0, 30))}`)
  }
  if (input.known.length > 0) {
    sections.push(
      `Already reported by other analyzers in these files (no need to report these same issues again; do report any other issue you find, also in the same code):\n${bullets(input.known.slice(0, 20))}`,
    )
  }
  sections.push(`Rules for submit_findings:
- Report only issues you verified by reading the code. Each finding needs an attack_path of 1-8 steps from the entry point to the harmful effect, each citing exact code.
- Use defenses_checked to show which protections you looked for and why they do not stop the attack.
- If, after checking the code, nothing is exploitable, submit an empty findings list.
- Optionally set coverage: complete, partial (you could not examine all of it), or needs-runtime (the outcome depends on deployment or runtime state the source does not show), with a short coverage_note.`)
  return sections.join('\n\n')
}

/** Options for {@link hunterSubmitTool}. */
export interface HunterSubmitOptions {
  /** Submissions sent back before one is accepted as it is. Default 3. */
  readonly maxRejections?: number
  /** Rule-hit ids listed in the task (`S1`, …); a submission missing verdicts for some is sent back once. */
  readonly signalIds?: readonly string[]
}

/**
 * Terminal tool for hunters. Citations are verified while validating. Findings
 * with verified code are saved across resubmissions, so a model only resends
 * what it must fix; a submission with unverifiable findings, assessments with
 * unverifiable evidence, or (once) missing verdicts is sent back with the
 * reasons and the file's actual lines, up to `maxRejections` times. A
 * submission on the worker's last request is accepted as it is. Accepted
 * output holds the saved findings plus the final submission's; the host
 * drops (and counts) findings without verified code.
 */
export function hunterSubmitTool(
  source: QuoteSource,
  options: HunterSubmitOptions = {},
): WorkerTool<Submission, HunterOutput> {
  const maxRejections = options.maxRejections ?? 3
  const signalIds = [...new Set((options.signalIds ?? []).map(id => id.trim().toUpperCase()))]
  const saved = new Map<string, RawFinding>()
  const assessed = new Map<string, RawAssessment>()
  let rejections = 0
  let emptyBounced = false
  let missingAsked = false

  const save = (finding: RawFinding): boolean => {
    const key = findingKey(
      finding,
      finding.attack_path.map(step => verifyCitation(source, step)),
    )
    if (key === undefined) return false
    saved.set(key, finding)
    return true
  }

  return defineTool<Submission, HunterOutput>({
    name: 'submit_findings',
    description:
      'Submit your verified findings (possibly none) and a verdict for every listed rule hit. Findings that pass verification are saved; this ends your work once nothing needs fixing.',
    input: submissionSchema,
    coerce: submitCoercion(submissionSchema, [
      [referencesSchema, keepUrls],
      [signalIdSchema, normalizeShortId('S')],
      [coverageSchema, normalizeCoverage],
      [coverageNoteSchema, value => (typeof value === 'string' ? value.slice(0, 400) : undefined)],
    ]),
    terminal: {
      validate: (args, context) => {
        if (context.final) return undefined
        if (!emptyBounced && args.findings.length === 0 && saved.size === 0 && context.toolCalls === 0) {
          emptyBounced = true
          return 'You submitted without reading any code. Investigate the files and rule hits listed in the task first (for example read_file on the starting files, in one reply), then call submit_findings. An empty findings list is a fine result once you have checked the code.'
        }
        if (rejections >= maxRejections) return undefined
        const hints = { hints: 6 }
        const problems: string[] = []
        const kept: number[] = []
        args.findings.forEach((finding, index) => {
          const verified = finding.attack_path.map(step => verifyCitation(source, step))
          if (verified.some(isVerifiedCode)) {
            if (save(finding)) kept.push(index + 1)
            return
          }
          problems.push(
            `- Finding ${index + 1} ("${clipLine(finding.title, 80)}"): none of its quotes is verified code.`,
            ...describeMismatches('step', verified, finding.attack_path, hints).map(line => `  ${line}`),
            ...describeCommentOnly('step', verified, finding.attack_path).map(line => `  ${line}`),
          )
        })
        for (const assessment of args.signal_assessments) {
          assessed.set(assessment.id.trim().toUpperCase(), assessment)
          if (!assessment.evidence) continue
          const evidence = verifyCitation(source, assessment.evidence)
          if (isQuoteVerified(evidence.quoteCheck)) continue
          problems.push(
            `- Verdict ${assessment.id} (${assessment.verdict}): its evidence could not be verified, so it does not count.`,
            ...describeMismatches('evidence', [evidence], [assessment.evidence], hints).map(line => `  ${line}`),
          )
        }
        const missing = signalIds.filter(id => !assessed.has(id))
        if (missing.length > 0 && !missingAsked) {
          missingAsked = true
          problems.push(
            `- No verdict yet for ${missing.join(', ')}: give one in signal_assessments for every listed rule hit.`,
          )
        }
        if (problems.length === 0) return undefined
        rejections++
        return [
          kept.length > 0
            ? `Saved: finding${kept.length === 1 ? '' : 's'} ${kept.join(', ')} (verified; no need to send ${kept.length === 1 ? 'it' : 'them'} again).`
            : '',
          'Not accepted yet:',
          ...problems,
          'Fix these and call submit_findings again with only the corrected findings and verdicts; saved findings and verdicts are kept. Re-read the code with read_file and copy the exact lines (without line-number prefixes). Drop a finding you cannot support with code you read; an empty findings list finishes with what is saved.',
        ]
          .filter(line => line !== '')
          .join('\n')
      },
      toOutput: args => {
        const unverified: RawFinding[] = []
        for (const finding of args.findings) if (!save(finding)) unverified.push(finding)
        for (const assessment of args.signal_assessments) assessed.set(assessment.id.trim().toUpperCase(), assessment)
        return toHunterOutput(
          source,
          [...saved.values(), ...unverified],
          [...assessed.values()],
          args.coverage ? { verdict: args.coverage, note: args.coverage_note } : undefined,
        )
      },
    },
  })
}

/** Identity of a finding with verified code: category and its key (last verified code) step. */
function findingKey(finding: RawFinding, verified: readonly VerifiedCitation[]): string | undefined {
  for (let i = verified.length - 1; i >= 0; i--) {
    const step = verified[i]
    if (step && isVerifiedCode(step) && step.location) {
      return `${finding.category}\0${step.location.path}\0${normalizeForMatch(step.quote)}`
    }
  }
  return undefined
}

/**
 * A coverage verdict in the model's words mapped onto the three values; an
 * unknown one is dropped (the verdict is optional), never sent back.
 */
function normalizeCoverage(value: unknown): unknown {
  if (typeof value !== 'string') return undefined
  const text = value.toLowerCase()
  if (/runtime|deploy|config|environment|depends/.test(text)) return 'needs-runtime'
  if (/partial|incomplete|unfinished|limited/.test(text)) return 'partial'
  if (/complete|full|done|finished/.test(text)) return 'complete'
  return undefined
}

/** References that are URLs; other text (an OWASP label, a CWE id) is dropped instead of failing the call. */
function keepUrls(value: unknown): unknown {
  if (value === null || value === undefined) return undefined
  const list = Array.isArray(value) ? value : [value]
  return list.filter(item => referenceSchema.safeParse(item).success).slice(0, 5)
}

function toHunterOutput(
  source: QuoteSource,
  findings: readonly RawFinding[],
  assessments: readonly RawAssessment[],
  coverage: { readonly verdict: NonNullable<Submission['coverage']>; readonly note?: string | undefined } | undefined,
): HunterOutput {
  const verify = (citations: readonly Citation[]) => citations.map(c => verifyCitation(source, c))
  return {
    findings: findings.map(f => ({
      title: f.title,
      category: f.category,
      ...(f.cwe ? { cwe: f.cwe } : {}),
      severity: f.severity,
      summary: f.summary,
      impact: f.impact,
      preconditions: f.preconditions,
      attackPath: verify(f.attack_path),
      defenses: verify(f.defenses_checked),
      recommendation: f.recommendation,
      references: f.references ?? [],
    })),
    assessments: assessments.map(a => ({
      id: a.id,
      verdict: a.verdict,
      reason: a.reason,
      ...(a.evidence ? { evidence: verifyCitation(source, a.evidence) } : {}),
    })),
    ...(coverage
      ? { coverage: { verdict: coverage.verdict, ...(coverage.note?.trim() ? { note: coverage.note.trim() } : {}) } }
      : {}),
  }
}
