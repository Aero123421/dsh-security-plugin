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
  'STREAM_CLOSED',
])

/** Codes whose request was rejected generically; the message tells a content refusal apart. */
const MESSAGE_CLASSIFIED_CODES: ReadonlySet<string> = new Set(['INVALID_REQUEST', 'UNSUPPORTED_CONTENT', 'PI_AI_ERROR'])
const BLOCKED_CODE = /CONTENT|SAFETY|POLICY|FILTER/
// Bundled pi-ai: Anthropic refusal; OpenAI content_filter; Gemini terminal safety reasons.
// A structural error such as messages[0].content is not a content-policy refusal.
const BLOCKED_MESSAGE =
  /\bthe model refused\b|\bcontent exists risk\b|\bcontent (?:was )?(?:rejected|blocked|filtered)\b|\bcontent[_ -](?:filter|policy)\b|\b(?:flagged by )?moderation\b|\b(?:safety guidelines|usage policy|policy violation)\b|\b(?:output|response) (?:was )?filtered\b|^(?:Provider stopped with: )?(?:SAFETY|IMAGE_SAFETY|BLOCKLIST|PROHIBITED_CONTENT|IMAGE_PROHIBITED_CONTENT|SPII|RECITATION|IMAGE_RECITATION)$/i

/**
 * Classify a provider failure.
 *
 * - `aborted`: `ABORTED`.
 * - `context_overflow`: `CONTEXT_WINDOW_EXCEEDED`.
 * - `blocked_by_provider`: codes containing `CONTENT`/`SAFETY`/`POLICY`/`FILTER`, or
 *   generic request/pi-ai errors with refusal-shaped messages from the bundled adapters.
 *   Bare field names such as `content` are not refusal evidence. Never retried or re-routed.
 * - `retryable`: {@link RETRYABLE_CODES} and the worker's exact finish-less-stream diagnostic.
 * - `fatal`: everything else, including `AUTH`, credential, adapter, and quota codes
 *   and unknown codes such as `INTERNAL`.
 */
export function classifyFailure(failure: LlmFailure): FailureClass {
  const code = String(failure.code).toUpperCase()
  if (code === 'ABORTED') return 'aborted'
  if (code === 'CONTEXT_WINDOW_EXCEEDED') return 'context_overflow'
  if (code === 'INTERNAL' && failure.message === 'The model stream ended without a finish chunk') return 'retryable'
  if (MESSAGE_CLASSIFIED_CODES.has(code)) {
    return BLOCKED_MESSAGE.test(String(failure.message)) ? 'blocked_by_provider' : 'fatal'
  }
  if (BLOCKED_CODE.test(code)) return 'blocked_by_provider'
  if (RETRYABLE_CODES.has(code)) return 'retryable'
  return 'fatal'
}
