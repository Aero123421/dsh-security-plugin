import type { Coverage, ScanSummary } from './contracts.ts'
import type { ModelRef } from './settings.ts'

/**
 * Completion of scheduled work, never a statement that the project is safe.
 *
 * Tasks skipped because their targets no longer exist (a resumed scan whose
 * files were deleted, reported as the `stale-tasks` gap) are not missing
 * review: they are left out of both the planned and the skipped counts.
 */
export function reviewOutcome(input: {
  readonly models?: { readonly hunter?: ModelRef }
  readonly coverage?: Coverage
}): NonNullable<ScanSummary['review']> {
  const tasks = input.coverage?.tasks
  const obsolete = obsoleteTasks(input.coverage)
  const completed = tasks?.completed ?? 0
  const planned = Math.max(0, (tasks?.planned ?? 0) - obsolete)
  if (!input.models?.hunter) return { state: 'builtin', completed, planned }
  if (!tasks) return { state: 'unknown', completed, planned }
  if (planned === 0) return { state: 'not-run', completed, planned }
  const skipped = Math.max(0, tasks.skipped - obsolete)
  if (tasks.failed > 0 && completed === 0) return { state: 'failed', completed, planned }
  if (tasks.failed > 0 || skipped > 0 || completed < planned) return { state: 'partial', completed, planned }
  return { state: 'complete', completed, planned }
}

function obsoleteTasks(coverage: Coverage | undefined): number {
  const count = coverage?.gapDetails?.find(gap => gap.code === 'stale-tasks')?.params?.count
  return typeof count === 'number' && Number.isFinite(count) && count > 0 ? count : 0
}
