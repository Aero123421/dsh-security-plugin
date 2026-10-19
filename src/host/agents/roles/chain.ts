/**
 * Chain researcher (Research mode): looks for combinations of findings that
 * together enable a stronger attack. Each chain needs its own verified path.
 */

import { z } from 'zod'
import type { ReportLanguage } from '../../../shared/contracts.ts'
import { formatCodeRef, isQuoteVerified } from '../../../shared/domain.ts'
import type { FindingRecord } from '../../core/model.ts'
import type { QuoteSource } from '../../evidence/quote.ts'
import { defineTool, type WorkerTool } from '../runtime/tool.ts'
import {
  categorySchema,
  citationSchema,
  clipLine,
  cweSchema,
  describeMismatches,
  MAX_CITATIONS,
  normalizeShortId,
  severitySchema,
  submitCoercion,
  systemPreamble,
  type VerifiedCitation,
  verifyCitation,
} from './common.ts'

const findingIdSchema = z.string().min(1).max(20)
const chainSchema = z.object({
  title: z.string().min(1).max(160),
  finding_ids: z.array(findingIdSchema).min(2).max(5).describe('Ids (F1, F2, …) of the combined findings.'),
  category: categorySchema,
  cwe: cweSchema,
  severity: severitySchema.describe('Severity of the combined attack.'),
  summary: z.string().min(1).max(900),
  impact: z.string().min(1).max(900),
  attack_path: z.array(citationSchema).min(1).max(MAX_CITATIONS),
  recommendation: z.string().min(1).max(1500),
})

const submissionSchema = z.object({ chains: z.array(chainSchema).max(5) })
type Submission = z.output<typeof submissionSchema>

export interface ChainProposal {
  readonly title: string
  readonly findingIds: readonly string[]
  readonly category: z.output<typeof categorySchema>
  readonly cwe?: string
  readonly severity: z.output<typeof severitySchema>
  readonly summary: string
  readonly impact: string
  readonly attackPath: readonly VerifiedCitation[]
  readonly recommendation: string
}

export function chainSystem(language: ReportLanguage): string {
  return systemPreamble('attack-chain researcher', language)
}

export function chainTask(findings: readonly { readonly id: string; readonly finding: FindingRecord }[]): string {
  const rows = findings.map(
    ({ id, finding }) =>
      `${id}: [${finding.severity}, ${finding.verification}] ${clipLine(finding.title, 140)} at ${finding.location ? formatCodeRef(finding.location) : 'unknown'} — ${clipLine(finding.summary, 260)}`,
  )
  return `Below are the issues found so far in this application. Look for combinations where one issue enables or amplifies another — for example an information leak that reveals identifiers used by an IDOR, an open redirect that steals an OAuth code, or SSRF that reaches an internal admin API.

Findings:
${rows.join('\n')}

Rules:
- Propose a chain only if you can support every step with code you read; each chain needs its own attack_path with exact quotes.
- Do not repeat a single finding as a chain. An empty list is a fine result.
Submit with submit_chains.`
}

export function chainSubmitTool(source: QuoteSource, maxRejections = 1): WorkerTool<Submission, ChainProposal[]> {
  let rejections = 0
  return defineTool<Submission, ChainProposal[]>({
    name: 'submit_chains',
    description: 'Submit attack chains (possibly none). This ends your work.',
    input: submissionSchema,
    coerce: submitCoercion(submissionSchema, [[findingIdSchema, normalizeShortId('F')]]),
    terminal: {
      validate: (args, context) => {
        if (rejections >= maxRejections || context.final) return undefined
        const problems: string[] = []
        args.chains.forEach((chain, index) => {
          const verified = chain.attack_path.map(c => verifyCitation(source, c))
          if (!verified.some(c => isQuoteVerified(c.quoteCheck))) {
            problems.push(
              `Chain ${index + 1}: no quote matches the source.`,
              ...describeMismatches('step', verified, chain.attack_path),
            )
          }
        })
        if (problems.length === 0) return undefined
        rejections++
        return `Some citations could not be verified:\n${problems.join('\n')}\nCopy exact lines from read_file and submit again, or drop the chain.`
      },
      toOutput: args =>
        args.chains.map(chain => ({
          title: chain.title,
          findingIds: chain.finding_ids,
          category: chain.category,
          ...(chain.cwe ? { cwe: chain.cwe } : {}),
          severity: chain.severity,
          summary: chain.summary,
          impact: chain.impact,
          attackPath: chain.attack_path.map(c => verifyCitation(source, c)),
          recommendation: chain.recommendation,
        })),
    },
  })
}
