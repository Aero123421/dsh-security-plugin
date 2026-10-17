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

/**
 * Fraction of a cache-read token charged against token budgets.
 *
 * Budgets are a cost guardrail, and providers price cache reads far below
 * fresh input (typically around a tenth). Charging them at full rate made
 * token budgets drain roughly ten times faster than the underlying spend
 * once a worker's context was mostly served from cache, which is the normal
 * case for multi-turn workers that resend their history every turn.
 */
export const CACHE_READ_CHARGE_RATE = 0.1

/** Budget charge for a reported cache-read count (never rounds down to zero). */
export function chargedCacheReadTokens(cacheReadTokens: number): number {
  return cacheReadTokens > 0 ? Math.ceil(cacheReadTokens * CACHE_READ_CHARGE_RATE) : 0
}

/** A gate that admits every request and ignores usage. */
export function unlimitedBudget(): BudgetGate {
  return {
    admit: () => ({ ok: true }),
    record: () => {},
  }
}
