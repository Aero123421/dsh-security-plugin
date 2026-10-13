import { describe, expect, it } from 'vitest'
import { classifyFailure, type FailureClass } from '../../../../src/host/agents/runtime/failure.ts'
import { unlimitedBudget } from '../../../../src/host/agents/runtime/budget.ts'

describe('classifyFailure', () => {
  const table: [code: string, message: string, expected: FailureClass][] = [
    // DSH default retryable codes
    ['EMPTY_RESPONSE', 'empty', 'retryable'],
    ['RATE_LIMIT', 'slow down', 'retryable'],
    ['SERVER', '500', 'retryable'],
    ['TIMEOUT', 'timed out', 'retryable'],
    ['TRANSPORT', 'socket hang up', 'retryable'],
    // Context window
    ['CONTEXT_WINDOW_EXCEEDED', 'too many tokens', 'context_overflow'],
    // Aborted
    ['ABORTED', 'aborted', 'aborted'],
    // Provider refusals by code
    ['CONTENT_FILTER', 'x', 'blocked_by_provider'],
    ['CONTENT_POLICY', 'x', 'blocked_by_provider'],
    ['SAFETY', 'x', 'blocked_by_provider'],
    ['SAFETY_BLOCK', 'x', 'blocked_by_provider'],
    ['POLICY_VIOLATION', 'x', 'blocked_by_provider'],
    ['RESPONSE_FILTERED', 'x', 'blocked_by_provider'],
    ['content_filter', 'lower-case code', 'blocked_by_provider'],
    // Provider refusals by message
    ['INVALID_REQUEST', 'Content Exists Risk', 'blocked_by_provider'],
    ['INVALID_REQUEST', 'flagged by moderation', 'blocked_by_provider'],
    ['INVALID_REQUEST', 'violates SAFETY guidelines', 'blocked_by_provider'],
    ['INVALID_REQUEST', 'usage policy', 'blocked_by_provider'],
    ['INVALID_REQUEST', 'output was filtered', 'blocked_by_provider'],
    ['UNSUPPORTED_CONTENT', 'content rejected', 'blocked_by_provider'],
    // Generic invalid requests stay fatal
    ['INVALID_REQUEST', 'unknown parameter "foo"', 'fatal'],
    ['UNSUPPORTED_CONTENT', 'images are not supported by this model', 'fatal'],
    // Fatal
    ['AUTH', 'unauthorized', 'fatal'],
    ['INVALID_CREDENTIAL', 'bad key', 'fatal'],
    ['MISSING_CREDENTIAL', 'no key', 'fatal'],
    ['NO_ADAPTER', 'no adapter', 'fatal'],
    ['QUOTA', 'quota', 'fatal'],
    ['ACCOUNT_QUOTA', 'account quota', 'fatal'],
    ['INTERNAL', 'bug', 'fatal'],
    ['SOMETHING_NEW', 'future code', 'fatal'],
    // Codes are classified on their own; a scary message on a retryable code stays retryable.
    ['SERVER', 'content moderation service down', 'retryable'],
  ]

  it.each(table)('%s (%s) → %s', (code, message, expected) => {
    expect(classifyFailure({ code, message })).toBe(expected)
  })
})

describe('unlimitedBudget', () => {
  it('admits everything', () => {
    const budget = unlimitedBudget()
    for (let i = 0; i < 1000; i++) {
      budget.record({ inputTokens: 1e9, outputTokens: 1e9 })
      expect(budget.admit()).toEqual({ ok: true })
    }
  })
})
