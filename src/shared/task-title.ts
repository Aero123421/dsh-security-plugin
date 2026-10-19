/**
 * Structured titles for the two built-in hunt tasks whose English wording is
 * `Review … in <path>`. The stored task title stays that English sentence
 * (models, transcripts, and 0.4.1 rows). The client translates `titleCopy`
 * or, for older rows, the same sentence.
 */

export type TaskTitleCopy =
  | { readonly kind: 'review-endpoints'; readonly count: number; readonly path: string }
  | { readonly kind: 'review-sensitive'; readonly path: string }

export function reviewEndpointsTitle(count: number, path: string): string {
  const noun = count === 1 ? 'endpoint' : 'endpoints'
  return `Review ${count} ${noun} in ${path}`
}

export function reviewSensitiveTitle(path: string): string {
  return `Review security-sensitive logic in ${path}`
}

const ENDPOINT_TITLE = /^Review (\d+) endpoint(s)? in (.+)$/
const SENSITIVE_TITLE = /^Review security-sensitive logic in (.+)$/

export function taskTitleCopyFromUnknown(value: unknown): TaskTitleCopy | undefined {
  if (typeof value !== 'object' || value === null) return undefined
  const record = value as Record<string, unknown>
  if (record.kind === 'review-endpoints') {
    if (typeof record.count !== 'number' || !Number.isInteger(record.count) || record.count < 1) return undefined
    if (typeof record.path !== 'string' || record.path.trim() === '') return undefined
    return { kind: 'review-endpoints', count: record.count, path: record.path }
  }
  if (record.kind === 'review-sensitive') {
    if (typeof record.path !== 'string' || record.path.trim() === '') return undefined
    return { kind: 'review-sensitive', path: record.path }
  }
  return undefined
}

/** Recover a 0.4.1 task title. Other hunt titles stay as stored. */
export function recoverTaskTitle(title: string): TaskTitleCopy | undefined {
  const endpoints = ENDPOINT_TITLE.exec(title)
  if (endpoints) {
    const count = Number(endpoints[1])
    const plural = endpoints[2] === 's'
    const path = endpoints[3]
    if (!Number.isInteger(count) || count < 1 || path === undefined || path.trim() === '') return undefined
    if (plural !== (count !== 1)) return undefined
    return { kind: 'review-endpoints', count, path }
  }
  const sensitive = SENSITIVE_TITLE.exec(title)
  if (sensitive?.[1] && sensitive[1].trim() !== '') return { kind: 'review-sensitive', path: sensitive[1] }
  return undefined
}

export function displayTaskTitle(task: {
  readonly title: string
  readonly titleCopy?: unknown
}): TaskTitleCopy | undefined {
  const stored = taskTitleCopyFromUnknown(task.titleCopy)
  if (stored?.kind === 'review-endpoints' && task.title === reviewEndpointsTitle(stored.count, stored.path))
    return stored
  if (stored?.kind === 'review-sensitive' && task.title === reviewSensitiveTitle(stored.path)) return stored
  return recoverTaskTitle(task.title)
}
