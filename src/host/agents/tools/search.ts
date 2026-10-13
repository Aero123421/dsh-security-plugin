/**
 * Line matching for `search_code`.
 *
 * Literal patterns are matched case-insensitively with plain string search.
 * Regular expressions come from a model and are hostile by assumption, so
 * they are bounded four ways: the source is at most {@link MAX_PATTERN_LENGTH}
 * characters, each regex runs against one line at a time (never multiline),
 * callers cap scanned bytes per call, and every batch of lines runs inside a
 * `node:vm` script with a timeout, so even a catastrophically backtracking
 * pattern (`(a+)+$`, `.*.*.*x`) is interrupted once the per-call time budget
 * is spent. The script is fixed; the pattern is only ever passed to
 * `new RegExp` as data.
 */

import vm from 'node:vm'

/** Longest accepted search pattern, in characters. */
export const MAX_PATTERN_LENGTH = 200
/** Default per-call time budget for executing a regular expression. */
export const DEFAULT_REGEX_TIME_BUDGET_MS = 2_000

/** One matching line. */
export interface LineHit {
  /** Index into the `texts` passed to {@link LineMatcher.scan}. */
  readonly text: number
  /** 0-based line index within that text. */
  readonly line: number
  /** UTF-16 column of the match within the line (CR stripped), best effort. */
  readonly column: number
}

/** Result of one {@link LineMatcher.scan}. */
export interface ScanOutcome {
  readonly hits: LineHit[]
  /** The regex time budget ran out; `hits` holds what was found before that. */
  readonly timedOut: boolean
}

/** A compiled search pattern. Keeps its regex time budget across `scan` calls. */
export interface LineMatcher {
  readonly kind: 'literal' | 'regex'
  /** Matches lines of each text (LF-separated, trailing CR ignored) in order, stopping after `maxHits`. */
  scan(texts: readonly string[], maxHits: number): ScanOutcome
}

/** Options for {@link compileLineMatcher}. */
export interface LineMatcherOptions {
  readonly regex?: boolean
  readonly caseSensitive?: boolean
  /** Total regex execution time allowed across all `scan` calls. */
  readonly timeBudgetMs?: number
}

/**
 * Validate and compile a pattern. Errors are English sentences meant for the
 * model: empty, multi-line, or overlong patterns and invalid regex syntax.
 */
export function compileLineMatcher(
  pattern: string,
  options: LineMatcherOptions = {},
): { readonly ok: true; readonly matcher: LineMatcher } | { readonly ok: false; readonly error: string } {
  if (pattern.length === 0) return { ok: false, error: 'The pattern is empty.' }
  if (pattern.length > MAX_PATTERN_LENGTH) {
    return {
      ok: false,
      error: `The pattern is ${pattern.length} characters long; the limit is ${MAX_PATTERN_LENGTH}. Search for a shorter, distinctive fragment.`,
    }
  }
  if (/[\r\n]/.test(pattern)) {
    return { ok: false, error: 'search_code matches one line at a time; the pattern must not contain line breaks.' }
  }
  const caseSensitive = options.caseSensitive === true
  if (options.regex !== true) return { ok: true, matcher: new LiteralMatcher(pattern, caseSensitive) }
  const flags = caseSensitive ? '' : 'i'
  try {
    new RegExp(pattern, flags)
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error)
    return {
      ok: false,
      error: `Invalid regular expression: ${detail}. Fix the pattern, or set regex to false for a literal search.`,
    }
  }
  const budget = options.timeBudgetMs ?? DEFAULT_REGEX_TIME_BUDGET_MS
  return { ok: true, matcher: new RegexMatcher(pattern, flags, budget) }
}

// ---------------------------------------------------------------------------
// Literal
// ---------------------------------------------------------------------------

class LiteralMatcher implements LineMatcher {
  readonly kind = 'literal'
  readonly #needle: string
  readonly #caseSensitive: boolean

  constructor(needle: string, caseSensitive: boolean) {
    this.#caseSensitive = caseSensitive
    this.#needle = caseSensitive ? needle : needle.toLowerCase()
  }

  scan(texts: readonly string[], maxHits: number): ScanOutcome {
    const hits: LineHit[] = []
    const fold = (s: string): string => (this.#caseSensitive ? s : s.toLowerCase())
    for (let t = 0; t < texts.length && hits.length < maxHits; t++) {
      const text = texts[t] ?? ''
      // Whole-text prefilter: most files have no match at all.
      if (!fold(text).includes(this.#needle)) continue
      const lines = text.split('\n')
      const last = lines.length > 1 && lines[lines.length - 1] === '' ? lines.length - 1 : lines.length
      for (let i = 0; i < last && hits.length < maxHits; i++) {
        const raw = lines[i] ?? ''
        const line = raw.endsWith('\r') ? raw.slice(0, -1) : raw
        const column = fold(line).indexOf(this.#needle)
        if (column >= 0) hits.push({ text: t, line: i, column })
      }
    }
    return { hits, timedOut: false }
  }
}

// ---------------------------------------------------------------------------
// Regex (time-bounded)
// ---------------------------------------------------------------------------

/**
 * Runs inside the sandbox context. Reads `source`, `flags`, `texts`, `limit`
 * from the context's globals and returns a flat `[text, line, column, …]`.
 */
const SCAN_SCRIPT = new vm.Script(
  `(function () {
  'use strict'
  var re = new RegExp(source, flags)
  var out = []
  for (var t = 0; t < texts.length; t++) {
    var lines = texts[t].split('\\n')
    var count = lines.length > 1 && lines[lines.length - 1] === '' ? lines.length - 1 : lines.length
    for (var i = 0; i < count; i++) {
      var line = lines[i]
      if (line.length > 0 && line.charCodeAt(line.length - 1) === 13) line = line.slice(0, -1)
      var m = re.exec(line)
      if (m !== null) {
        out.push(t, i, m.index)
        if (out.length >= limit * 3) return out
      }
    }
  }
  return out
})()`,
  { filename: 'search-code-regex.vm.js' },
)

interface Sandbox {
  source: string
  flags: string
  texts: readonly string[]
  limit: number
}

class RegexMatcher implements LineMatcher {
  readonly kind = 'regex'
  readonly #sandbox: Sandbox
  readonly #context: vm.Context
  #remainingMs: number

  constructor(source: string, flags: string, budgetMs: number) {
    this.#sandbox = { source, flags, texts: [], limit: 0 }
    this.#context = vm.createContext(this.#sandbox)
    this.#remainingMs = Math.max(1, budgetMs)
  }

  scan(texts: readonly string[], maxHits: number): ScanOutcome {
    if (texts.length === 0 || maxHits <= 0) return { hits: [], timedOut: false }
    if (this.#remainingMs <= 0) return { hits: [], timedOut: true }
    this.#sandbox.texts = texts
    this.#sandbox.limit = maxHits
    const started = performance.now()
    let raw: unknown
    try {
      raw = SCAN_SCRIPT.runInContext(this.#context, { timeout: Math.max(1, Math.ceil(this.#remainingMs)) })
    } catch (error) {
      if ((error as { code?: unknown } | null)?.code === 'ERR_SCRIPT_EXECUTION_TIMEOUT') {
        this.#remainingMs = 0
        return { hits: [], timedOut: true }
      }
      throw error
    } finally {
      this.#remainingMs -= performance.now() - started
      this.#sandbox.texts = []
    }
    // The array comes from the sandbox realm: read it by index only.
    const flat = raw as ArrayLike<number>
    const hits: LineHit[] = []
    for (let k = 0; k + 2 < flat.length; k += 3) {
      hits.push({ text: Number(flat[k]), line: Number(flat[k + 1]), column: Number(flat[k + 2]) })
    }
    return { hits, timedOut: false }
  }
}
