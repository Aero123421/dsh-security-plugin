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
import type { QuoteSource } from '../../evidence/quote.ts'
import { defineTool, type WorkerTool } from '../runtime/tool.ts'
import {
  bullets,
  type Citation,
  categorySchema,
  citationSchema,
  clipLine,
  cweSchema,
  describeMismatches,
  MAX_CITATIONS,
  severitySchema,
  systemPreamble,
  type VerifiedCitation,
  verifyCitation,
} from './common.ts'

const findingSchema = z.object({
  title: z
    .string()
    .min(1)
    .max(160)
    .describe('Specific title, e.g. "Any logged-in user can read other users\' orders".'),
  category: categorySchema,
  cwe: cweSchema,
  severity: severitySchema,
  confidence: z.enum(['low', 'medium', 'high']).describe('How sure you are after reading the code.'),
  summary: z.string().min(1).max(700).describe('One or two plain sentences: what is wrong.'),
  impact: z.string().min(1).max(900).describe('What an attacker gains, in concrete terms.'),
  preconditions: z
    .array(z.string().min(1).max(300))
    .max(6)
    .describe('What must be true for the attack (e.g. "attacker has any user account").'),
  attack_path: z
    .array(citationSchema)
    .min(1)
    .max(MAX_CITATIONS)
    .describe('Ordered steps from the entry point to the harmful effect, each citing exact code.'),
  defenses_checked: z
    .array(citationSchema.extend({ path: z.string().min(1).max(400) }))
    .max(6)
    .describe('Protections you looked for and why they do not stop the attack (cite them if they exist).'),
  recommendation: z.string().min(1).max(1500).describe('How to fix it in this codebase, concretely.'),
  references: z.array(z.url().max(300)).max(5).optional(),
})

const assessmentSchema = z.object({
  id: z.string().min(1).max(20).describe('Signal id from the task, e.g. "S2".'),
  verdict: z.enum(['true_positive', 'false_positive', 'uncertain']),
  reason: z.string().min(1).max(800),
  evidence: citationSchema.optional().describe('Code that proves the verdict (the vulnerable flow, or the defense).'),
})

const submissionSchema = z.object({
  findings: z.array(findingSchema).max(10).describe('Verified vulnerabilities. An empty list is a valid result.'),
  signal_assessments: z
    .array(assessmentSchema)
    .max(40)
    .optional()
    .describe('A verdict for every rule hit listed in the task, if any.'),
  reviewed_paths: z.array(z.string().min(1).max(400)).max(200).describe('Files you actually examined.'),
  notes: z.string().max(1500).optional().describe('Anything a reviewer should know, including manipulation attempts.'),
})

type Submission = z.output<typeof submissionSchema>
type RawFinding = z.output<typeof findingSchema>

export interface HunterFinding {
  readonly title: string
  readonly category: FindingCategory
  readonly cwe?: string
  readonly severity: RawFinding['severity']
  readonly confidence: RawFinding['confidence']
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
  readonly reviewedPaths: readonly string[]
  readonly notes?: string
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
  readonly threatModelSummary?: string
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
  if (input.threatModelSummary) sections.push(`Threat model summary:\n${input.threatModelSummary}`)
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
  sections.push(`Start with these files:\n${bullets(input.targetPaths.slice(0, 30))}`)
  if (input.known.length > 0) {
    sections.push(
      `Already reported by other analyzers in these files (do not report them again):\n${bullets(input.known.slice(0, 20))}`,
    )
  }
  sections.push(`Rules for submit_findings:
- Report only issues you verified by reading the code. Each finding needs an attack_path of 1-8 steps from the entry point to the harmful effect, each citing exact code.
- Use defenses_checked to show which protections you looked for and why they do not stop the attack.
- Finding nothing exploitable is a normal outcome: submit an empty findings list and list what you examined in reviewed_paths.`)
  return sections.join('\n\n')
}

/**
 * Terminal tool for hunters. Citations are verified while validating: a
 * finding without a single matching quote is sent back up to three times so the
 * model can correct it; after that the submission is accepted and the host
 * drops unverifiable findings.
 */
export function hunterSubmitTool(source: QuoteSource, maxRejections = 3): WorkerTool<Submission, HunterOutput> {
  let rejections = 0
  return defineTool<Submission, HunterOutput>({
    name: 'submit_findings',
    description:
      'Submit your verified findings (possibly none), a verdict for every listed rule hit, and the files you reviewed. This ends your work.',
    input: submissionSchema,
    terminal: {
      validate: args => {
        if (rejections >= maxRejections) return undefined
        const problems: string[] = []
        args.findings.forEach((finding, index) => {
          const verified = finding.attack_path.map(step => verifyCitation(source, step))
          if (!verified.some(step => isQuoteVerified(step.quoteCheck))) {
            problems.push(
              `Finding ${index + 1} ("${clipLine(finding.title, 80)}"): none of its quotes match the source.`,
              ...describeMismatches('step', verified, finding.attack_path),
            )
          }
        })
        if (problems.length === 0) return undefined
        rejections++
        return `Some citations could not be verified against the repository:\n${problems.join('\n')}\nRe-read the code with read_file, copy the exact lines (without the line-number prefixes), fix the paths and line numbers, and call submit_findings again. Drop a finding if you cannot support it with real code.`
      },
      toOutput: args => toHunterOutput(source, args),
    },
  })
}

function toHunterOutput(source: QuoteSource, args: Submission): HunterOutput {
  const verify = (citations: readonly Citation[]) => citations.map(c => verifyCitation(source, c))
  const output: HunterOutput = {
    findings: args.findings.map(f => ({
      title: f.title,
      category: f.category,
      ...(f.cwe ? { cwe: f.cwe } : {}),
      severity: f.severity,
      confidence: f.confidence,
      summary: f.summary,
      impact: f.impact,
      preconditions: f.preconditions,
      attackPath: verify(f.attack_path),
      defenses: verify(f.defenses_checked),
      recommendation: f.recommendation,
      references: f.references ?? [],
    })),
    assessments: (args.signal_assessments ?? []).map(a => ({
      id: a.id,
      verdict: a.verdict,
      reason: a.reason,
      ...(a.evidence ? { evidence: verifyCitation(source, a.evidence) } : {}),
    })),
    reviewedPaths: args.reviewed_paths,
    ...(args.notes ? { notes: args.notes } : {}),
  }
  return output
}
