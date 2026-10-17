import type { Coverage, ScanSummary } from './contracts.ts'
import type { ModelRef } from './settings.ts'

/** Completion of scheduled work, never a statement that the project is safe. */
export function reviewOutcome(input: {
  readonly models?: { readonly hunter?: ModelRef }
  readonly coverage?: Coverage
}): NonNullable<ScanSummary['review']> {
  const tasks = input.coverage?.tasks
  const completed = tasks?.completed ?? 0
  const planned = tasks?.planned ?? 0
  if (!input.models?.hunter) return { state: 'builtin', completed, planned }
  if (!tasks) return { state: 'unknown', completed, planned }
  if (planned === 0) return { state: 'not-run', completed, planned }
  if (tasks.failed > 0 && completed === 0) return { state: 'failed', completed, planned }
  if (tasks.failed > 0 || tasks.skipped > 0 || completed < planned) return { state: 'partial', completed, planned }
  return { state: 'complete', completed, planned }
}
