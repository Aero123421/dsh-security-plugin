/**
 * Path utilities for the workspace tools: directory filters and "did you
 * mean" suggestions for unknown paths.
 */

import { normalizePath } from '../../evidence/normalize.ts'

/**
 * Normalize a model-supplied directory. `''`, `.` and `./` mean the workspace
 * root and yield `''`; everything else goes through {@link normalizePath}, so
 * absolute, escaping, and NUL-containing input yields `undefined`.
 */
export function normalizeDir(dir: string): string | undefined {
  const trimmed = dir.trim()
  if (trimmed === '' || trimmed === '.' || trimmed === './' || trimmed === '.\\') return ''
  return normalizePath(trimmed)
}

/** Whether `path` is `dir` itself or lies below it. `''` is the workspace root. */
export function isUnder(path: string, dir: string): boolean {
  return dir === '' || path === dir || path.startsWith(`${dir}/`)
}

/** Last path segment. */
export function baseName(path: string): string {
  return path.slice(path.lastIndexOf('/') + 1)
}

/**
 * Edit distance between `a` and `b`, or `cap + 1` as soon as it is certain to
 * exceed `cap`. O(|a| × |b|) time, O(|b|) memory.
 */
export function levenshtein(a: string, b: string, cap = Number.POSITIVE_INFINITY): number {
  if (a === b) return 0
  if (Math.abs(a.length - b.length) > cap) return cap + 1
  let previous = new Array<number>(b.length + 1)
  let current = new Array<number>(b.length + 1)
  for (let j = 0; j <= b.length; j++) previous[j] = j
  for (let i = 1; i <= a.length; i++) {
    current[0] = i
    let rowMin = i
    for (let j = 1; j <= b.length; j++) {
      const cost = a.charCodeAt(i - 1) === b.charCodeAt(j - 1) ? 0 : 1
      const value = Math.min((previous[j] ?? 0) + 1, (current[j - 1] ?? 0) + 1, (previous[j - 1] ?? 0) + cost)
      current[j] = value
      if (value < rowMin) rowMin = value
    }
    if (rowMin > cap) return cap + 1
    ;[previous, current] = [current, previous]
  }
  return previous[b.length] ?? 0
}

/**
 * Up to `max` candidate paths that look like what `target` meant, best first:
 * a case-insensitive exact match, then paths where one is a suffix of the
 * other (a missing or extra directory prefix), then paths with the same file
 * name, then file names within a small edit distance. Ties break on full-path
 * edit distance, then path order, so the result is deterministic.
 */
export function suggestPaths(target: string, candidates: Iterable<string>, max = 5): string[] {
  const wanted = target.toLowerCase()
  const wantedBase = baseName(wanted)
  const wantedStem = stem(wantedBase)
  const baseCap = Math.max(2, Math.floor(wantedBase.length / 3))
  const scored: { path: string; rank: number; distance: number }[] = []
  for (const path of candidates) {
    const lower = path.toLowerCase()
    const base = baseName(lower)
    let rank: number
    if (lower === wanted) rank = 0
    else if (lower.endsWith(`/${wanted}`) || wanted.endsWith(`/${lower}`)) rank = 1
    else if (base === wantedBase) rank = 2
    else if (wantedStem !== '' && stem(base) === wantedStem) rank = 3
    else {
      const distance = levenshtein(base, wantedBase, baseCap)
      if (distance > baseCap) continue
      rank = 3 + distance
    }
    scored.push({ path, rank, distance: 0 })
  }
  scored.sort((a, b) => a.rank - b.rank || (a.path < b.path ? -1 : a.path > b.path ? 1 : 0))
  // Refine only the head of the list; full-path distance is the costly part.
  const head = scored.slice(0, Math.max(max * 4, 20))
  for (const entry of head) entry.distance = levenshtein(entry.path.toLowerCase(), wanted, 200)
  head.sort((a, b) => a.rank - b.rank || a.distance - b.distance || (a.path < b.path ? -1 : a.path > b.path ? 1 : 0))
  return head.slice(0, max).map(entry => entry.path)
}

/** File name without its last extension (`app.test.ts` → `app.test`). */
function stem(name: string): string {
  const dot = name.lastIndexOf('.')
  return dot > 0 ? name.slice(0, dot) : name
}
