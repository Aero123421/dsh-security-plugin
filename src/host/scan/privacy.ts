/**
 * The privacy boundary for text the host writes into model requests (task
 * messages). The workspace tools already hide withheld files and redact what
 * they return; this module does the same for everything the pipeline builds
 * from analyzer signals, findings and endpoints:
 *
 * - content from withheld files (built-in credential files plus the user's
 *   `withheldGlobs`) is replaced by {@link WITHHELD_PLACEHOLDER}, keeping
 *   only the path and rule id so a reviewer knows the signal exists;
 * - every other excerpt passes through the scan's `Redactor` (known secret
 *   values from the secret scan, wherever they occur) and the stateless
 *   high-confidence patterns, and the absolute root is masked.
 */

import type { FindingRecord } from '../core/model.ts'
import { isSensitivePath, type Redactor, redactKnownSecrets } from '../analysis/secrets.ts'
import { type Endpoint, isEndpointVisible, type Signal, type Snapshot } from '../analysis/types.ts'
import { maskRoot } from '../evidence/text.ts'

/** Neutral stand-in for code or text that comes from a withheld file. */
export const WITHHELD_PLACEHOLDER = '[content withheld by privacy settings]'

export interface ModelPrivacyOptions {
  readonly snapshot: Snapshot
  readonly redactor: Redactor
  readonly withheldGlobs: readonly string[]
}

/**
 * Whether `finding` has any evidence location outside withheld files (its
 * attack-path steps and its own location). A finding without any location
 * has nothing withheld.
 */
export function hasVisibleEvidence(finding: FindingRecord, isWithheld: (path: string) => boolean): boolean {
  const paths = [
    ...finding.attackPath.flatMap(step => (step.location ? [step.location.path] : [])),
    ...(finding.location ? [finding.location.path] : []),
  ]
  return paths.length === 0 || paths.some(path => !isWithheld(path))
}

/** Model-bound text policy for one scan. */
export class ModelPrivacy {
  readonly #snapshot: Snapshot
  readonly #redactor: Redactor
  readonly #globs: readonly string[]
  readonly #withheld = new Map<string, boolean>()
  #secrets: { readonly value: string; readonly ruleId: string }[] | undefined
  #shortSecrets: { readonly value: string; readonly ruleId: string }[] | undefined

  constructor(options: ModelPrivacyOptions) {
    this.#snapshot = options.snapshot
    this.#redactor = options.redactor
    this.#globs = options.withheldGlobs
  }

  /** Whether a workspace-relative path must never be shown to a model. */
  isWithheld(path: string): boolean {
    let withheld = this.#withheld.get(path)
    if (withheld === undefined) {
      withheld = isSensitivePath(path, this.#globs)
      this.#withheld.set(path, withheld)
    }
    return withheld
  }

  /** Redact known secret values and high-confidence patterns, and mask the absolute root. */
  scrub(text: string): string {
    if (text === '') return text
    this.#secrets ??= this.#redactor.secretValues(path => this.#snapshot.files.get(path)?.content)
    this.#shortSecrets ??= this.#secrets.filter(secret => secret.value.length >= 4 && secret.value.length < 8)
    // Keep the pre-existing short-value protection for task text; tools deliberately use the eight-character floor.
    let safe = redactKnownSecrets(this.#redactor.scrub(text, this.#snapshot), this.#shortSecrets)
    // Preserve the clipped-excerpt backstop without scanning a potentially large value list for every task.
    if (/…\s*$/.test(safe)) safe = redactKnownSecrets(safe, this.#secrets)
    return maskRoot(safe, [this.#snapshot.workspaceRoot ?? this.#snapshot.root, this.#snapshot.registeredWorkspaceRoot])
  }

  /** An excerpt taken from `path`: the placeholder when the file is withheld, otherwise scrubbed. */
  excerpt(path: string | undefined, text: string): string {
    if (path !== undefined && this.isWithheld(path)) return WITHHELD_PLACEHOLDER
    return this.scrub(text)
  }

  /** A copy of `signal` that is safe to describe to a model. */
  signal(signal: Signal): Signal {
    if (this.isWithheld(signal.location.path)) {
      const { metadata: _metadata, recommendation: _recommendation, ...rest } = signal
      return {
        ...rest,
        title: `Rule hit in a withheld file ${WITHHELD_PLACEHOLDER}`,
        snippet: WITHHELD_PLACEHOLDER,
        message: WITHHELD_PLACEHOLDER,
      }
    }
    return {
      ...signal,
      title: this.scrub(signal.title),
      snippet: this.scrub(signal.snippet),
      message: this.scrub(signal.message),
      ...(signal.metadata
        ? {
            metadata: Object.fromEntries(
              Object.entries(signal.metadata).map(([key, value]) => [
                key,
                typeof value === 'string' ? this.scrub(value) : value,
              ]),
            ),
          }
        : {}),
    }
  }

  /** Endpoints whose declaration, handler and contributing mounts are all outside withheld files (route text is file content). */
  endpointVisible(endpoint: Endpoint): boolean {
    return isEndpointVisible(endpoint, path => this.isWithheld(path))
  }

  /** Whether a reviewer could see any of the finding's evidence. */
  reviewable(finding: FindingRecord): boolean {
    return hasVisibleEvidence(finding, path => this.isWithheld(path))
  }

  /**
   * A copy of `finding` that is safe to describe to a model: steps in
   * withheld files show the placeholder, and text derived from a withheld
   * location (rule messages quote code) is replaced.
   */
  finding(finding: FindingRecord): FindingRecord {
    const hidden = finding.location !== undefined && this.isWithheld(finding.location.path)
    return {
      ...finding,
      title: hidden ? `Finding in a withheld file ${WITHHELD_PLACEHOLDER}` : this.scrub(finding.title),
      summary: hidden ? WITHHELD_PLACEHOLDER : this.scrub(finding.summary),
      impact: hidden ? WITHHELD_PLACEHOLDER : this.scrub(finding.impact),
      preconditions: hidden ? [] : finding.preconditions.map(p => this.scrub(p)),
      recommendation: hidden ? WITHHELD_PLACEHOLDER : this.scrub(finding.recommendation),
      attackPath: finding.attackPath.map(step => {
        const path = step.location?.path
        const withheld = path !== undefined && this.isWithheld(path)
        return {
          ...step,
          description: withheld ? WITHHELD_PLACEHOLDER : this.scrub(step.description),
          ...(step.snippet !== undefined ? { snippet: this.excerpt(path, step.snippet) } : {}),
          ...(step.quote !== undefined ? { quote: this.excerpt(path, step.quote) } : {}),
        }
      }),
    }
  }
}
