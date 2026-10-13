/**
 * A small, dependency-free glob matcher for model-supplied file filters.
 *
 * Supported syntax: `*` (any run of characters except `/`), `?` (one
 * character except `/`), `**` as a whole segment (zero or more directories),
 * and `{a,b}` alternation (nestable). Everything else is literal, including
 * `[` and `]` so Next.js-style paths such as `app/[id]/page.tsx` match
 * themselves. `*` also matches leading dots. Matching is case-sensitive.
 *
 * A pattern (or brace alternative) without `/` matches the file name at any
 * depth, so `*.ts` behaves like `**\/*.ts`. A trailing `/` matches everything
 * below that directory.
 *
 * Matching runs in O(pattern × path) per alternative with no regular
 * expressions, so hostile patterns cannot cause catastrophic backtracking.
 */

/** Longest accepted glob, in characters. */
export const MAX_GLOB_LENGTH = 300
/** Most alternatives one glob may expand to through `{a,b}` groups. */
export const MAX_GLOB_ALTERNATIVES = 256

/** Tests a normalized, workspace-relative POSIX path. */
export type GlobMatcher = (path: string) => boolean

const GLOBSTAR = Symbol('globstar')
type Segment = string | typeof GLOBSTAR

/**
 * Normalize a model-supplied glob: trim, turn backslashes into `/`, drop `.`
 * and empty segments, and turn a trailing `/` into `/**`. Returns `undefined`
 * for globs that are empty, too long, absolute (`/x`, `C:/x`), contain NUL or
 * a `..` segment.
 */
export function normalizeGlob(glob: string): string | undefined {
  if (typeof glob !== 'string' || glob.includes('\0')) return undefined
  const slashed = glob.trim().replace(/\\/g, '/')
  if (slashed === '' || slashed.length > MAX_GLOB_LENGTH) return undefined
  if (slashed.startsWith('/') || /^[A-Za-z]:/.test(slashed)) return undefined
  const segments: string[] = []
  for (const segment of slashed.split('/')) {
    if (segment === '' || segment === '.') continue
    if (segment === '..') return undefined
    segments.push(segment)
  }
  if (segments.length === 0) return undefined
  if (slashed.endsWith('/') && segments.at(-1) !== '**') segments.push('**')
  return segments.join('/')
}

/**
 * Compile a glob into a matcher. The glob should already be normalized with
 * {@link normalizeGlob}.
 * @throws RangeError when `{a,b}` groups expand to more than
 *   {@link MAX_GLOB_ALTERNATIVES} alternatives.
 */
export function compileGlob(glob: string): GlobMatcher {
  const alternatives = expandBraces(glob)
  if (alternatives === undefined) {
    throw new RangeError(`Glob expands to more than ${MAX_GLOB_ALTERNATIVES} alternatives`)
  }
  const compiled = alternatives.map(compileAlternative)
  return path => {
    const segments = path.split('/')
    return compiled.some(pattern => matchSegments(pattern, segments))
  }
}

/** One-shot convenience: whether `path` matches `glob` (`false` for invalid globs). */
export function matchGlob(glob: string, path: string): boolean {
  const normalized = normalizeGlob(glob)
  if (normalized === undefined) return false
  try {
    return compileGlob(normalized)(path)
  } catch {
    return false
  }
}

/**
 * Expand `{a,b}` groups (nested groups too) into brace-free alternatives,
 * de-duplicated in first-seen order. A group without a top-level comma or
 * without a closing brace stays literal. Returns `undefined` when the
 * expansion exceeds `limit` alternatives.
 */
export function expandBraces(pattern: string, limit = MAX_GLOB_ALTERNATIVES): string[] | undefined {
  const out = new Set<string>()
  return expandInto(pattern, out, limit) ? [...out] : undefined
}

function expandInto(pattern: string, out: Set<string>, limit: number): boolean {
  const group = findBraceGroup(pattern)
  if (!group) {
    out.add(pattern)
    return out.size <= limit
  }
  const head = pattern.slice(0, group.start)
  const tail = pattern.slice(group.end + 1)
  for (const option of group.options) {
    if (!expandInto(head + option + tail, out, limit)) return false
  }
  return true
}

/** The first `{…}` group with a matching `}` and at least one top-level comma. */
function findBraceGroup(pattern: string): { start: number; end: number; options: string[] } | undefined {
  for (let start = pattern.indexOf('{'); start >= 0; start = pattern.indexOf('{', start + 1)) {
    let depth = 0
    const commas: number[] = []
    for (let i = start; i < pattern.length; i++) {
      const ch = pattern[i]
      if (ch === '{') depth++
      else if (ch === ',' && depth === 1) commas.push(i)
      else if (ch === '}' && --depth === 0) {
        if (commas.length === 0) break
        const bounds = [start, ...commas, i]
        const options: string[] = []
        for (let k = 0; k + 1 < bounds.length; k++) options.push(pattern.slice((bounds[k] ?? 0) + 1, bounds[k + 1]))
        return { start, end: i, options }
      }
    }
  }
  return undefined
}

function compileAlternative(alternative: string): Segment[] {
  const parts = alternative.split('/').filter(part => part !== '' && part !== '.')
  const segments: Segment[] = parts.map(part => (part === '**' ? GLOBSTAR : part))
  // A pattern without a slash matches the file name at any depth.
  if (!alternative.includes('/') && segments[0] !== GLOBSTAR) segments.unshift(GLOBSTAR)
  return segments
}

/**
 * Greedy wildcard matching with single-point backtracking, over path
 * segments: `**` plays the role of `*` and every other pattern segment
 * consumes exactly one path segment. Linear in practice, O(n × m) worst case.
 */
function matchSegments(pattern: readonly Segment[], path: readonly string[]): boolean {
  let p = 0
  let s = 0
  let starP = -1
  let starS = 0
  while (s < path.length) {
    const segment = pattern[p]
    if (segment !== undefined && segment !== GLOBSTAR && matchSegment(segment, path[s] ?? '')) {
      p++
      s++
    } else if (segment === GLOBSTAR) {
      starP = p++
      starS = s
    } else if (starP >= 0) {
      p = starP + 1
      s = ++starS
    } else {
      return false
    }
  }
  while (pattern[p] === GLOBSTAR) p++
  return p === pattern.length
}

/** The same greedy algorithm over characters, for `*` and `?` within one segment. */
function matchSegment(pattern: string, text: string): boolean {
  if (!pattern.includes('*') && !pattern.includes('?')) return pattern === text
  let p = 0
  let t = 0
  let starP = -1
  let starT = 0
  while (t < text.length) {
    const ch = pattern[p]
    if (ch !== undefined && ch !== '*' && (ch === '?' || ch === text[t])) {
      p++
      t++
    } else if (ch === '*') {
      starP = p++
      starT = t
    } else if (starP >= 0) {
      p = starP + 1
      t = ++starT
    } else {
      return false
    }
  }
  while (pattern[p] === '*') p++
  return p === pattern.length
}
