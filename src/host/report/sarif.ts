/**
 * SARIF 2.1.0 export for code-scanning dashboards (GitHub, Azure DevOps,
 * IDE viewers). Locations are relative to `%SRCROOT%`, which is deliberately
 * left without a URI so no Host path ends up in the file.
 */

import type { AttackStepView, FindingDetail } from '../../shared/contracts.ts'
import type { CodeRef, FindingCategory, Severity } from '../../shared/domain.ts'
import { isQuoteVerified, severityRank } from '../../shared/domain.ts'
import type { ReportInput } from './common.ts'
import {
  cweNumber,
  cweUrl,
  isoOrUndefined,
  orderedFindings,
  SECURITY_SEVERITY,
  scanSucceeded,
  TOOL_INFORMATION_URI,
  TOOL_NAME,
} from './common.ts'

/** SARIF JSON schema location. */
export const SARIF_SCHEMA = 'https://json.schemastore.org/sarif-2.1.0.json'
/** Base id every location is relative to. */
export const SRCROOT = '%SRCROOT%'
/** Key of the stable fingerprint in `partialFingerprints`. */
export const FINGERPRINT_KEY = 'dshSecurity/v1'

/** SARIF `level` values used here. */
export type SarifLevel = 'error' | 'warning' | 'note'

// Minimal structural SARIF types: only what this exporter writes.
interface SarifMessage {
  readonly text: string
}
interface SarifPhysicalLocation {
  readonly artifactLocation: { readonly uri: string; readonly uriBaseId: string }
  readonly region: { readonly startLine: number; readonly endLine: number; readonly snippet?: SarifMessage }
}
interface SarifLocation {
  readonly physicalLocation: SarifPhysicalLocation
  readonly message?: SarifMessage
}
interface SarifSuppression {
  readonly kind: 'external'
  readonly status: 'accepted'
  readonly justification: string
}
interface SarifRule {
  readonly id: string
  readonly name?: string
  readonly shortDescription: SarifMessage
  readonly helpUri?: string
  readonly defaultConfiguration: { readonly level: SarifLevel }
  readonly properties: { readonly tags: readonly string[]; readonly 'security-severity': string }
}
interface SarifResult {
  readonly ruleId: string
  readonly ruleIndex: number
  readonly level: SarifLevel
  readonly message: SarifMessage
  readonly locations?: readonly SarifLocation[]
  readonly partialFingerprints: { readonly [FINGERPRINT_KEY]: string }
  readonly codeFlows?: readonly {
    readonly threadFlows: readonly {
      readonly locations: readonly {
        readonly location: SarifLocation
        readonly properties: { readonly order: number; readonly quoteCheck: string }
      }[]
    }[]
  }[]
  readonly suppressions?: readonly SarifSuppression[]
  readonly properties: Readonly<Record<string, unknown>>
}

/** The SARIF log written by {@link renderSarif}. */
export interface SarifLog {
  readonly $schema: typeof SARIF_SCHEMA
  readonly version: '2.1.0'
  readonly runs: readonly [
    {
      readonly tool: {
        readonly driver: {
          readonly name: string
          readonly version: string
          readonly semanticVersion?: string
          readonly informationUri: string
          readonly rules: readonly SarifRule[]
        }
      }
      readonly originalUriBaseIds: { readonly [SRCROOT]: { readonly description: SarifMessage } }
      readonly invocations: readonly {
        readonly executionSuccessful: boolean
        readonly startTimeUtc?: string
        readonly endTimeUtc?: string
        readonly toolExecutionNotifications?: readonly { readonly level: SarifLevel; readonly message: SarifMessage }[]
      }[]
      readonly results: readonly SarifResult[]
      readonly properties: Readonly<Record<string, unknown>>
    },
  ]
}

/** SARIF level for a severity: critical/high → error, medium → warning, low/info → note. */
export function sarifLevel(severity: Severity): SarifLevel {
  switch (severity) {
    case 'critical':
    case 'high':
      return 'error'
    case 'medium':
      return 'warning'
    case 'low':
    case 'info':
      return 'note'
  }
}

const CATEGORY_DESCRIPTIONS: Readonly<Record<FindingCategory, string>> = {
  injection: 'Injection',
  authz: 'Broken authorization',
  authn: 'Broken authentication',
  secrets: 'Exposed secret',
  dependency: 'Vulnerable dependency',
  crypto: 'Weak cryptography',
  ssrf: 'Server-side request forgery',
  xss: 'Cross-site scripting',
  'path-traversal': 'Path traversal',
  deserialization: 'Unsafe deserialization',
  'command-execution': 'Command execution',
  'business-logic': 'Business logic flaw',
  'race-condition': 'Race condition',
  misconfiguration: 'Security misconfiguration',
  'data-exposure': 'Sensitive data exposure',
  other: 'Security issue',
}

const VERIFICATION_TEXT: Readonly<Record<FindingDetail['verification'], string>> = {
  proven_dynamic: 'proven (dynamic)',
  strong_static_evidence: 'strong static evidence',
  potential: 'potential (not yet confirmed)',
  inconclusive: 'inconclusive',
  refuted: 'refuted by independent review',
}

/** `Broken authorization` → `BrokenAuthorization`. */
function pascalCase(text: string): string {
  return text
    .split(/[^A-Za-z0-9]+/)
    .filter(word => word !== '')
    .map(word => word[0]!.toUpperCase() + word.slice(1))
    .join('')
}

/** Rule id for a finding: its own `ruleId`, else one per category. */
export function sarifRuleId(finding: FindingDetail): string {
  return finding.ruleId ?? `dsh-security/${finding.category}`
}

/** A relative URI reference for a workspace-relative POSIX path. */
function relativeUri(path: string): string {
  return path
    .replace(/\\/g, '/')
    .replace(/^(?:\.\/|\/)+/, '')
    .split('/')
    .map(segment => encodeURIComponent(segment))
    .join('/')
}

function physicalLocation(ref: CodeRef, snippet?: string): SarifPhysicalLocation {
  const startLine = Math.max(1, Math.trunc(ref.startLine))
  const endLine = Math.max(startLine, Math.trunc(ref.endLine))
  return {
    artifactLocation: { uri: relativeUri(ref.path), uriBaseId: SRCROOT },
    region: { startLine, endLine, ...(snippet === undefined ? {} : { snippet: { text: snippet } }) },
  }
}

function cweTag(cwe: string | undefined): string | undefined {
  const id = cweNumber(cwe)
  return id === undefined ? undefined : `external/cwe/cwe-${id}`
}

interface RuleDraft {
  readonly id: string
  readonly name?: string
  readonly description: string
  helpUri?: string
  severity: Severity
  readonly tags: Set<string>
}

function buildRules(findings: readonly FindingDetail[]): { rules: SarifRule[]; index: Map<string, number> } {
  const drafts = new Map<string, RuleDraft>()
  for (const finding of findings) {
    const id = sarifRuleId(finding)
    let draft = drafts.get(id)
    if (draft === undefined) {
      draft = {
        id,
        ...(finding.ruleId === undefined ? { name: pascalCase(CATEGORY_DESCRIPTIONS[finding.category]) } : {}),
        description: finding.ruleId === undefined ? CATEGORY_DESCRIPTIONS[finding.category] : finding.title,
        severity: finding.severity,
        tags: new Set(['security']),
      }
      drafts.set(id, draft)
    }
    draft.tags.add(finding.category)
    const tag = cweTag(finding.cwe)
    if (tag !== undefined) draft.tags.add(tag)
    if (draft.helpUri === undefined) draft.helpUri = cweUrl(finding.cwe)
    if (severityRank(finding.severity) < severityRank(draft.severity)) draft.severity = finding.severity
  }
  const rules: SarifRule[] = []
  const index = new Map<string, number>()
  for (const draft of drafts.values()) {
    index.set(draft.id, rules.length)
    rules.push({
      id: draft.id,
      ...(draft.name === undefined ? {} : { name: draft.name }),
      shortDescription: { text: draft.description },
      ...(draft.helpUri === undefined ? {} : { helpUri: draft.helpUri }),
      defaultConfiguration: { level: sarifLevel(draft.severity) },
      properties: { tags: [...draft.tags], 'security-severity': SECURITY_SEVERITY[draft.severity] },
    })
  }
  return { rules, index }
}

function codeFlowOf(steps: readonly AttackStepView[]): SarifResult['codeFlows'] {
  const located = [...steps]
    .sort((a, b) => a.order - b.order)
    .flatMap(step => {
      if (step.location === undefined) return []
      const snippet = step.snippet !== undefined && isQuoteVerified(step.quoteCheck) ? step.snippet : undefined
      return [
        {
          location: { physicalLocation: physicalLocation(step.location, snippet), message: { text: step.description } },
          properties: { order: step.order, quoteCheck: step.quoteCheck },
        },
      ]
    })
  return located.length === 0 ? undefined : [{ threadFlows: [{ locations: located }] }]
}

function suppressionsOf(finding: FindingDetail): SarifSuppression[] {
  const out: SarifSuppression[] = []
  if (finding.triage === 'false_positive' || finding.triage === 'accepted_risk') {
    const note = finding.triageNote?.trim()
    const fallback = finding.triage === 'false_positive' ? 'triaged as a false positive' : 'risk accepted during triage'
    out.push({
      kind: 'external',
      status: 'accepted',
      justification: note === undefined || note === '' ? fallback : note,
    })
  }
  if (finding.verification === 'refuted') {
    out.push({ kind: 'external', status: 'accepted', justification: 'refuted by independent review' })
  }
  return out
}

function resultOf(finding: FindingDetail, ruleIndex: number): SarifResult {
  const codeFlows = codeFlowOf(finding.attackPath)
  const suppressions = suppressionsOf(finding)
  const verification = VERIFICATION_TEXT[finding.verification]
  return {
    ruleId: sarifRuleId(finding),
    ruleIndex,
    level: sarifLevel(finding.severity),
    message: { text: `${finding.title}: ${finding.summary.trim()}\nVerification: ${verification}.` },
    ...(finding.location === undefined
      ? {}
      : { locations: [{ physicalLocation: physicalLocation(finding.location) }] }),
    partialFingerprints: { [FINGERPRINT_KEY]: finding.fingerprint },
    ...(codeFlows === undefined ? {} : { codeFlows }),
    ...(suppressions.length === 0 ? {} : { suppressions }),
    properties: {
      id: finding.id,
      title: finding.title,
      severity: finding.severity,
      verification: finding.verification,
      closure: finding.closure,
      triage: finding.triage,
      source: finding.source,
      category: finding.category,
      ...(finding.cwe === undefined ? {} : { cwe: finding.cwe }),
      isNew: finding.isNew,
      'security-severity': SECURITY_SEVERITY[finding.severity],
    },
  }
}

const SEMVER_RE = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/

/** Build the SARIF log object. */
export function buildSarif(input: ReportInput): SarifLog {
  const { scan } = input
  const summary = scan.summary
  const findings = orderedFindings(input.findings)
  const { rules, index } = buildRules(findings)
  const results = findings.map(finding => resultOf(finding, index.get(sarifRuleId(finding)) ?? 0))

  const startTimeUtc = isoOrUndefined(summary.startedAt)
  const endTimeUtc = isoOrUndefined(summary.finishedAt)
  const notifications = scan.notices
    .filter(notice => notice.level !== 'info')
    .map(notice => ({
      level: notice.level === 'error' ? ('error' as const) : ('warning' as const),
      message: { text: notice.text },
    }))
  const coverage = scan.coverage

  return {
    $schema: SARIF_SCHEMA,
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: TOOL_NAME,
            version: input.pluginVersion,
            ...(SEMVER_RE.test(input.pluginVersion) ? { semanticVersion: input.pluginVersion } : {}),
            informationUri: TOOL_INFORMATION_URI,
            rules,
          },
        },
        originalUriBaseIds: { [SRCROOT]: { description: { text: 'Root of the scanned workspace.' } } },
        invocations: [
          {
            executionSuccessful: scanSucceeded(scan),
            ...(startTimeUtc === undefined ? {} : { startTimeUtc }),
            ...(endTimeUtc === undefined ? {} : { endTimeUtc }),
            ...(notifications.length === 0 ? {} : { toolExecutionNotifications: notifications }),
          },
        ],
        results,
        properties: {
          scanId: summary.id,
          mode: summary.mode,
          status: summary.status,
          ...(summary.commit === undefined ? {} : { commit: summary.commit }),
          ...(summary.dirty === undefined ? {} : { dirty: summary.dirty }),
          generatedAt: input.generatedAt,
          coverage:
            coverage === undefined
              ? null
              : {
                  files: coverage.files,
                  endpoints: coverage.endpoints,
                  tasks: coverage.tasks,
                  discardedUnverifiable: coverage.discardedUnverifiable,
                  gaps: coverage.gaps,
                },
        },
      },
    ],
  }
}

/** Pretty-printed SARIF 2.1.0 with a trailing newline. */
export function renderSarif(input: ReportInput): string {
  return `${JSON.stringify(buildSarif(input), null, 2)}\n`
}
