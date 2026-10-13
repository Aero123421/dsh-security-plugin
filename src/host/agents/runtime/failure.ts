/**
 * Classification of failed provider attempts. One DSH `ctx.llm.stream()` call
 * is exactly one provider attempt with no retries inside, so the worker loop
 * decides per failure whether to back off and retry, shrink the request,
 * surface a provider-side refusal, or give up.
 */

import type { LlmFailure } from '../../dsh/ports.ts'

/** How the worker loop reacts to one failed provider attempt. */
export type FailureClass = 'retryable' | 'blocked_by_provider' | 'context_overflow' | 'aborted' | 'fatal'

/** DSH's default transient failure codes; the worker retries these with backoff. */
export const RETRYABLE_CODES: ReadonlySet<string> = new Set([
  'EMPTY_RESPONSE',
  'RATE_LIMIT',
  'SERVER',
  'TIMEOUT',
  'TRANSPORT',
])

/** Codes whose request was rejected generically; the message tells a content refusal apart. */
const MESSAGE_CLASSIFIED_CODES: ReadonlySet<string> = new Set(['INVALID_REQUEST', 'UNSUPPORTED_CONTENT'])
const BLOCKED_CODE = /CONTENT|SAFETY|POLICY|FILTER/
const BLOCKED_MESSAGE = /content|safety|policy|risk|moderation|filter/i

/**
 * Classify a provider failure.
 *
 * - `aborted`: `ABORTED`.
 * - `context_overflow`: `CONTEXT_WINDOW_EXCEEDED`.
 * - `blocked_by_provider`: codes containing `CONTENT`/`SAFETY`/`POLICY`/`FILTER`, or
 *   `INVALID_REQUEST`/`UNSUPPORTED_CONTENT` whose message mentions content, safety,
 *   policy, risk, moderation, or filtering. Never retried and never re-routed.
 * - `retryable`: {@link RETRYABLE_CODES}.
 * - `fatal`: everything else, including `AUTH`, credential, adapter, and quota codes
 *   and unknown codes such as `INTERNAL`.
 */
export function classifyFailure(failure: LlmFailure): FailureClass {
  const code = String(failure.code).toUpperCase()
  if (code === 'ABORTED') return 'aborted'
  if (code === 'CONTEXT_WINDOW_EXCEEDED') return 'context_overflow'
  if (MESSAGE_CLASSIFIED_CODES.has(code)) {
    return BLOCKED_MESSAGE.test(String(failure.message)) ? 'blocked_by_provider' : 'fatal'
  }
  if (BLOCKED_CODE.test(code)) return 'blocked_by_provider'
  if (RETRYABLE_CODES.has(code)) return 'retryable'
  return 'fatal'
}
