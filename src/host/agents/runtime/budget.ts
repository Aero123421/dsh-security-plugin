/**
 * Budget gates bound what a worker may spend. The worker asks the gate before
 * every model request (retries included) and reports usage after every
 * admitted request, so one gate can be shared by many workers of a run.
 */

import type { LlmTokenUsage } from '../../dsh/ports.ts'

/** Admission control for a worker's model requests. */
export interface BudgetGate {
  /** Called before each model request; return a reason to stop instead. */
  admit(): { readonly ok: true } | { readonly ok: false; readonly reason: 'calls' | 'tokens' | 'time' | 'cancelled' }
  /**
   * Called after each request with the reported usage (zero usage when absent).
   * Every admitted request is recorded exactly once, including failed ones.
   */
  record(usage: LlmTokenUsage): void
}

/** A gate that admits every request and ignores usage. */
export function unlimitedBudget(): BudgetGate {
  return {
    admit: () => ({ ok: true }),
    record: () => {},
  }
}
