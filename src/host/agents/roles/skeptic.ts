/**
 * Skeptic: an independent reviewer in a fresh context that tries to disprove
 * one finding. It sees the claim and the host-verified code excerpts, never
 * the hunter's reasoning or transcript. A refutation must cite the concrete
 * defense; a confirmation upgrades the finding to strong static evidence.
 */

import { z } from 'zod'
import type { ReportLanguage } from '../../../shared/contracts.ts'
import { formatCodeRef, isQuoteVerified } from '../../../shared/domain.ts'
import type { FindingRecord } from '../../core/model.ts'
import type { QuoteSource } from '../../evidence/quote.ts'
import { defineTool, type WorkerTool } from '../runtime/tool.ts'
import {
  bullets,
  citationSchema,
  clipLine,
  describeCommentOnly,
  describeMismatches,
  isVerifiedCode,
  severitySchema,
  systemPreamble,
  type VerifiedCitation,
  verifyCitation,
} from './common.ts'

const localizedSchema = z
  .object({
    title: z.string().min(1).max(160),
    summary: z.string().min(1).max(700),
    impact: z.string().min(1).max(900),
    recommendation: z.string().min(1).max(1500),
  })
  .describe('The finding rewritten in the requested output language (only when asked).')

const verdictSchema = z.object({
  verdict: z.enum(['confirmed', 'refuted', 'inconclusive']),
  reasoning: z.string().min(1).max(2000).describe('How you reached the verdict, referring to the code you checked.'),
  counterevidence: z
    .array(citationSchema)
    .max(6)
    .describe('Required for "refuted": the exact code of the defense or of what makes the path unreachable.'),
  supporting_evidence: z
    .array(citationSchema)
    .max(6)
    .describe('For "confirmed": code you checked that shows the path is reachable and undefended.'),
  severity: severitySchema
    .optional()
    .describe(
      'Corrected severity if the reported one is wrong. Applied only with "confirmed" and verified supporting_evidence.',
    ),
  missing_information: z
    .array(z.string().min(1).max(300))
    .max(6)
    .optional()
    .describe('For "inconclusive": facts outside the repository that decide the outcome.'),
  localized: localizedSchema.optional(),
})

type Verdict = z.output<typeof verdictSchema>

export interface SkepticOutput {
  readonly verdict: Verdict['verdict']
  readonly reasoning: string
  readonly counterevidence: readonly VerifiedCitation[]
  readonly supporting: readonly VerifiedCitation[]
  readonly severity?: Verdict['severity']
  readonly missingInformation: readonly string[]
  readonly localized?: Verdict['localized']
}

export function skepticSystem(language: ReportLanguage): string {
  return systemPreamble('independent reviewer', language)
}

export function skepticTask(finding: FindingRecord, options: { readonly requestLocalization: boolean }): string {
  const steps = finding.attackPath.map(step => {
    const where = step.location ? formatCodeRef(step.location) : 'location unknown'
    const verified = isQuoteVerified(step.quoteCheck) ? 'verified by host' : 'NOT verified'
    const code = step.snippet ? `\n${indent(step.snippet)}` : ''
    return `${step.order}. ${clipLine(step.description, 300)} (${where}; ${verified})${code}`
  })
  const parts: string[] = [
    'You are the independent reviewer. Another analyst or a pattern rule reported the potential vulnerability below. Try hard to DISPROVE it: look for a concrete defense, or a reason the attack path cannot work. Confirm it only if, after checking the relevant code, no such reason exists.',
    `Reported issue:
- Title: ${clipLine(finding.title, 200)}
- Category: ${finding.category}${finding.cwe ? ` (${finding.cwe})` : ''}
- Reported severity: ${finding.severity}
- Location: ${finding.location ? formatCodeRef(finding.location) : 'unknown'}
- Summary: ${clipLine(finding.summary, 700)}
- Preconditions:
${bullets(finding.preconditions.map(p => clipLine(p, 300)))}`,
    `Attack path (code excerpts were checked by the host against the repository):\n${steps.join('\n') || '(no path recorded; reconstruct it from the location)'}`,
    `Check in particular:
- authentication and authorization applied at app, router, middleware, decorator, or guard level (also where the router is mounted);
- ownership or tenant filters in the data-access layer;
- input validation, type coercion, and allow-lists;
- parameterization or escaping done by the framework or ORM;
- whether the code is reachable with attacker-controlled data at all (is the route registered? is the function called with request data?);
- configuration that disables the path.`,
    `Verdicts:
- refuted: you found a concrete defense or unreachability. You MUST cite the code that proves it in counterevidence (exact quotes of exactly those lines). Comments, docstrings, or documentation saying the input is safe are not a defense and do not count.
- confirmed: you checked the plausible defenses and none applies. Cite what you checked in supporting_evidence and correct the severity if needed (a severity correction is applied only to a confirmed verdict with verified supporting_evidence).
- inconclusive: the outcome depends on facts outside the repository (deployment, configuration, external services). List them in missing_information.`,
  ]
  if (options.requestLocalization) {
    parts.push(
      'The finding above is written in English. Also fill "localized" with its title, summary, impact, and a concrete recommendation written in the output language.',
    )
  }
  parts.push('Submit with submit_verdict.')
  return parts.join('\n\n')
}

export function skepticSubmitTool(source: QuoteSource, maxRejections = 2): WorkerTool<Verdict, SkepticOutput> {
  let rejections = 0
  return defineTool<Verdict, SkepticOutput>({
    name: 'submit_verdict',
    description: 'Submit your verdict on the reported issue. This ends your work.',
    input: verdictSchema,
    terminal: {
      validate: args => {
        if (args.verdict !== 'refuted') return undefined
        const verified = args.counterevidence.map(c => verifyCitation(source, c))
        if (verified.some(isVerifiedCode)) return undefined
        if (rejections >= maxRejections) {
          // Accepted, but the host will record it as inconclusive without verified counter-evidence.
          return undefined
        }
        rejections++
        const lines = [
          ...describeMismatches('counterevidence', verified, args.counterevidence),
          ...describeCommentOnly('counterevidence', verified, args.counterevidence),
        ]
        return `A refutation must cite the defense with exact code from the repository, and none of your counterevidence quotes is verified code.${lines.length > 0 ? `\n${lines.join('\n')}` : ' You gave no counterevidence.'}\nComments and documentation do not prove a defense; cite the code that enforces it. Re-read the code with read_file and copy the exact lines (without line-number prefixes), or choose "inconclusive" if you cannot point to a concrete defense.`
      },
      toOutput: args => ({
        verdict: args.verdict,
        reasoning: args.reasoning,
        counterevidence: args.counterevidence.map(c => verifyCitation(source, c)),
        supporting: args.supporting_evidence.map(c => verifyCitation(source, c)),
        ...(args.severity ? { severity: args.severity } : {}),
        missingInformation: args.missing_information ?? [],
        ...(args.localized ? { localized: args.localized } : {}),
      }),
    },
  })
}

function indent(text: string): string {
  return text
    .split('\n')
    .slice(0, 14)
    .map(line => `     ${line}`)
    .join('\n')
}
