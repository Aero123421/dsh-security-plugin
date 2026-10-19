/**
 * Rule vocabulary shared by the SAST engine and the language rule sets.
 * Kept free of rule imports so rule modules can depend on it without cycles.
 */

import type { FindingCategory, Severity } from '../../../shared/domain.ts'
import type { SnapshotFile } from '../types.ts'
import type { Charset } from './guards.ts'
import type { Span } from './model.ts'
import type { Taint, TaintOrigin } from './taint.ts'

export type Confidence = 'low' | 'medium' | 'high'

/** Static description of one rule. */
export interface RuleMeta {
  /** Stable id such as `js.sql-injection`. */
  readonly id: string
  /** Title of the `vulnerability` variant. */
  readonly title: string
  /** Title of the `sink` variant. */
  readonly sinkTitle?: string
  readonly category: FindingCategory
  readonly cwe: string
  /** Severity when user input visibly reaches the sink (or the issue is certain). */
  readonly severity: Severity
  /** Severity of the `sink` variant; rules without one never emit sinks from dynamic values. */
  readonly sinkSeverity?: Severity
  /** Plain-English explanation for beginners. */
  readonly message: string
  /** Explanation for the `sink` variant (defaults to `message`). */
  readonly sinkMessage?: string
  readonly recommendation: string
  readonly references: readonly string[]
  /** Taint origins that make a `vulnerability`; others become a `sink`. Default: `request`. */
  readonly origins?: readonly TaintOrigin[]
}

/** One rule match before it becomes a signal. */
export interface Hit {
  readonly rule: RuleMeta
  readonly kind: 'vulnerability' | 'sink'
  /** The matched expression; drives location, snippet and fingerprint. */
  readonly span: Span
  readonly confidence: Confidence
  /** Overrides the rule's severity for this match. */
  readonly severity?: Severity
  readonly taint?: Taint
  /** Extra sentence appended to the message. */
  readonly note?: string
  /** Spans (e.g. hard-coded secret literals) masked in the snippet and fingerprint. */
  readonly mask?: readonly Span[]
  readonly metadata?: Readonly<Record<string, string | number | boolean>>
}

/** Context passed to every rule set. */
export interface FileContext {
  readonly file: SnapshotFile
  readonly report: (hit: Hit) => void
  /**
   * Function name → parameters every route fills through a numeric or UUID converter (Django
   * `<int:id>` in a URLconf of another file), so they never hold attacker-chosen text.
   */
  readonly scalarParams?: ReadonlyMap<string, ReadonlySet<string>>
}

/** Common reference URLs. */
export const REF = {
  injection: 'https://owasp.org/Top10/A03_2021-Injection/',
  accessControl: 'https://owasp.org/Top10/A01_2021-Broken_Access_Control/',
  crypto: 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/',
  design: 'https://owasp.org/Top10/A04_2021-Insecure_Design/',
  misconfig: 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/',
  components: 'https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/',
  authn: 'https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/',
  integrity: 'https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/',
  ssrf: 'https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/',
} as const

/** MITRE CWE definition URL. */
export function cweUrl(cwe: string): string {
  return `https://cwe.mitre.org/data/definitions/${cwe.replace(/^CWE-/, '')}.html`
}

export interface Classification {
  readonly kind: 'vulnerability' | 'sink'
  readonly confidence: Confidence
  readonly taint?: Taint
  readonly note?: string
}

/** Note for a value that passed an allow-list pattern check before the sink. */
export const GUARDED_NOTE =
  'The value is checked against an allow-list pattern before this call, which keeps out the characters this sink needs; confirm the check runs on every path to it.'

/** Note for a path checked against an allow-list that admits dots but no separators. */
export const DOT_SEGMENT_NOTE =
  'The value is checked against an allow-list pattern first, but the pattern admits `.`, so `..` can still reach the parent folder; check how the path is used.'

/**
 * Whether an allow-list check admitting `charset` makes request data harmless for this rule's sink: only shell
 * syntax matters for command execution, and `..` and separators for file paths. Other sinks keep the taint
 * (an allow-listed host name is still an SSRF target).
 */
export function sanitizedBy(rule: RuleMeta, charset: Charset | undefined): boolean {
  if (!charset) return false
  if (rule.category === 'command-execution') return charset.shellSafe
  if (rule.category === 'path-traversal') return charset.pathSafe
  return false
}

/**
 * Decide the kind and confidence of a match from the taint of its dangerous
 * value. `dynamic` says the value is not a constant. Returns `undefined`
 * when nothing should be reported.
 */
export function classify(rule: RuleMeta, taint: Taint | undefined, dynamic: boolean): Classification | undefined {
  if (taint && sanitizedBy(rule, taint.guard)) {
    return dynamic && rule.sinkSeverity ? { kind: 'sink', confidence: 'low', note: GUARDED_NOTE } : undefined
  }
  if (taint) {
    const origins = rule.origins ?? ['request']
    if (origins.includes(taint.origin)) {
      return { kind: 'vulnerability', confidence: taint.direct ? 'high' : 'medium', taint }
    }
    if (!rule.sinkSeverity) return undefined
    const note =
      taint.origin === 'cli'
        ? 'The value comes from command-line arguments or standard input, so it only matters if untrusted people can run this program or control its input.'
        : 'The value comes from the browser (for example the page URL), so the impact depends on where this code runs.'
    return { kind: 'sink', confidence: 'low', taint, note }
  }
  if (dynamic && rule.sinkSeverity) return { kind: 'sink', confidence: 'low' }
  return undefined
}
