/**
 * Host-side verification of model-cited quotes: the anti-hallucination
 * check that every piece of AI evidence passes before it is trusted.
 *
 * A model cites `{ path, startLine, endLine, quote }`. The quote is compared
 * with the REDACTED snapshot content after collapsing whitespace on both sides,
 * so indentation and line wrapping never matter, quotes may span several
 * lines, and `[REDACTED:…]` markers the model saw in tool output still match.
 * A quote holding a raw secret cannot match redacted content; that is
 * intended. Nothing here touches the filesystem.
 */

import type { CodeRef, QuoteCheck } from '../../shared/domain.ts'
import type { Redactor } from '../analysis/secrets.ts'
import { isSensitivePath } from '../analysis/secrets.ts'
import type { Snapshot } from '../analysis/types.ts'
import { commentMask, isCommentOnlyRange } from './comments.ts'
import { type NormalizedText, normalizeForMatch, normalizePath, normalizeWithOffsets } from './normalize.ts'
import { clipText, countLines, lineOfOffset, lineStarts, numberLines, stripCr } from './text.ts'

/** Outcome of {@link verifyQuote}. */
export interface QuoteVerification {
  readonly check: QuoteCheck
  /**
   * For `match` and `relocated`: the lines the quote actually occupies (never
   * the wider cited range). Absent otherwise.
   */
  readonly location?: CodeRef
  /** Redacted source lines at `location`: at most 12 lines and 1500 characters. */
  readonly snippet?: string
  /**
   * `true` when the matched text lies entirely in comments, docstrings, or
   * documentation prose. Such a quote is real but shows no code; callers must
   * not treat it as proof of a defense. Absent otherwise.
   */
  readonly commentOnly?: true
  /**
   * English reason for `mismatch`, written for the model that cited it:
   * `file not in snapshot` (also for paths that are not plain relative paths),
   * `withheld file`, `lines out of range`, `quote not found`, `quote ambiguous`
   * (several places in the file, or in a loose cited range), `cited range too
   * wide: …`, or `quote too short`.
   */
  readonly reason?: string
}

/** Snapshot access needed to verify quotes. */
export interface QuoteSource {
  /** Snapshot lookup by normalized workspace-relative path. */
  file(path: string): { readonly content: string; readonly sha256: string } | undefined
  /** Redact file content exactly as tools showed it to the model. */
  redact(path: string, content: string): string
  /** Files that are never shown to a model and therefore cannot be quoted. */
  isWithheld(path: string): boolean
}

/** A model's citation. Lines are 1-based and inclusive. */
export interface CitedQuote {
  readonly path: string
  readonly startLine: number
  readonly endLine: number
  readonly quote: string
}

/** Tuning for {@link verifyQuote}. */
export interface VerifyQuoteOptions {
  /** Lines of tolerance around the cited range that still count as `match`. Default 3. */
  readonly slackLines?: number
  /** Minimum normalized quote length, unless the whole cited range is shorter. Default 8. */
  readonly minQuoteChars?: number
  /**
   * Cited lines allowed beyond the quote's own line count before the citation
   * is rejected as `cited range too wide`. Default {@link MAX_EXTRA_CITED_LINES}.
   */
  readonly maxExtraLines?: number
}

/** Maximum lines in {@link QuoteVerification.snippet}. */
export const SNIPPET_MAX_LINES = 12
/** Maximum characters in {@link QuoteVerification.snippet}. */
export const SNIPPET_MAX_CHARS = 1500
/** Default for {@link VerifyQuoteOptions.maxExtraLines}: a citation may span at most the quote's lines + 40. */
export const MAX_EXTRA_CITED_LINES = 40

const DEFAULT_SLACK_LINES = 3
const DEFAULT_MIN_QUOTE_CHARS = 8
const DEFAULT_EXCERPT_LINES = 12
const PREPARED_CACHE_SIZE = 8
const NUMBERED_LINE = /^[ \t]*\d+\|/
/** Occurrences collected inside one cited window; more only matter as "ambiguous". */
const MAX_WINDOW_HITS = 64

/**
 * Check a cited quote against the snapshot.
 *
 * - A cited range wider than the quote's own lines + `maxExtraLines` is a
 *   `mismatch` (`cited range too wide`), so "lines 1 to the end" can never
 *   turn any quote anywhere in the file into a match.
 * - `match`: the quote occurs exactly once within lines
 *   `[start - slack, end + slack]`. Several occurrences there are accepted
 *   only when the cited range is tight (at most the quote's lines +
 *   `2 × slack`), taking the one nearest the cited lines; otherwise the
 *   result is `quote ambiguous`.
 * - `relocated`: no occurrence within that window, but exactly one elsewhere
 *   in the file (also when the cited lines are out of range).
 * - `mismatch` otherwise, with a `reason`; several occurrences elsewhere are
 *   `quote ambiguous`.
 *
 * For `match` and `relocated`, `location` and `snippet` are those of the
 * occurrence itself, never the cited range. Quotes shorter than
 * `minQuoteChars` after normalization are rejected unless the cited range
 * itself is that short and contains them; they are never relocated. A quote
 * copied with `N| ` line-number prefixes (the format of `read_file` output) is
 * retried without them. Never throws for malformed citations.
 */
export function verifyQuote(
  source: QuoteSource,
  cited: CitedQuote,
  options: VerifyQuoteOptions = {},
): QuoteVerification {
  const path = normalizePath(String(cited.path))
  if (path === undefined) return mismatch('file not in snapshot')
  if (source.isWithheld(path)) return mismatch('withheld file')
  const file = source.file(path)
  if (!file) return mismatch('file not in snapshot')

  const limits: Limits = {
    slack: nonNegativeInt(options.slackLines, DEFAULT_SLACK_LINES),
    minChars: nonNegativeInt(options.minQuoteChars, DEFAULT_MIN_QUOTE_CHARS),
    maxExtraLines: nonNegativeInt(options.maxExtraLines, MAX_EXTRA_CITED_LINES),
  }
  const prepared = prepare(source, path, file)
  const quote = typeof cited.quote === 'string' ? cited.quote : ''
  const first = verifyPrepared(prepared, path, cited, quote, limits)
  if (first.check !== 'mismatch') return first
  const stripped = stripLineNumbers(quote)
  return stripped === undefined ? first : verifyPrepared(prepared, path, cited, stripped, limits)
}

/**
 * Redacted lines of `ref` with `N| ` line-number prefixes, for display. The
 * range is clamped to the file and cut after `maxLines` lines (default 12)
 * with a `… (N more lines)` note. `undefined` for an invalid, withheld, or
 * unknown path, or a range that does not overlap the file.
 */
export function excerpt(source: QuoteSource, ref: CodeRef, maxLines = DEFAULT_EXCERPT_LINES): string | undefined {
  const path = normalizePath(String(ref.path))
  if (path === undefined || source.isWithheld(path)) return undefined
  const file = source.file(path)
  if (!file) return undefined
  const prepared = prepare(source, path, file)
  const wanted = Math.trunc(ref.startLine)
  const wantedEnd = Math.trunc(ref.endLine)
  if (!Number.isFinite(wanted) || !Number.isFinite(wantedEnd)) return undefined
  const start = Math.max(1, wanted)
  const end = Math.min(prepared.lineCount, wantedEnd)
  if (start > end) return undefined
  const limit = Math.max(1, Math.trunc(Number.isFinite(maxLines) ? maxLines : DEFAULT_EXCERPT_LINES))
  const shownEnd = Math.min(end, start + limit - 1)
  const text = numberLines(linesOf(prepared, start, shownEnd), start)
  return shownEnd < end ? `${text}\n… (${end - shownEnd} more lines)` : text
}

/**
 * Compare a file's current hash with the hash recorded in the snapshot. A
 * missing current hash (deleted or unreadable file) is `stale`.
 */
export function checkStaleness(currentSha: string | undefined, snapshotSha: string): 'same' | 'stale' {
  return currentSha !== undefined && currentSha.toLowerCase() === snapshotSha.toLowerCase() ? 'same' : 'stale'
}

/**
 * A {@link QuoteSource} over a snapshot: files are redacted with `redactor`
 * and withheld when {@link isSensitivePath} says so for `withheldGlobs`.
 */
export function snapshotQuoteSource(
  snapshot: Snapshot,
  redactor: Pick<Redactor, 'redactFile'>,
  withheldGlobs: readonly string[] = [],
): QuoteSource {
  return {
    file: path => snapshot.files.get(path),
    redact: (path, content) => redactor.redactFile(path, content),
    isWithheld: path => isSensitivePath(path, withheldGlobs),
  }
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

interface PreparedFile {
  readonly redacted: string
  /** UTF-16 offset of each LF-separated line of `redacted`. */
  readonly starts: readonly number[]
  readonly lineCount: number
  readonly norm: NormalizedText
}

/** Per-source cache of redacted, normalized files, keyed by path and content hash. */
const preparedCache = new WeakMap<QuoteSource, Map<string, PreparedFile>>()

function prepare(
  source: QuoteSource,
  path: string,
  file: { readonly content: string; readonly sha256: string },
): PreparedFile {
  let cache = preparedCache.get(source)
  if (!cache) {
    cache = new Map()
    preparedCache.set(source, cache)
  }
  const key = `${path}\0${file.sha256}`
  const hit = cache.get(key)
  if (hit) return hit
  const redacted = source.redact(path, file.content)
  const prepared: PreparedFile = {
    redacted,
    starts: lineStarts(redacted),
    lineCount: countLines(redacted),
    norm: normalizeWithOffsets(redacted),
  }
  if (cache.size >= PREPARED_CACHE_SIZE) {
    const oldest = cache.keys().next().value
    if (oldest !== undefined) cache.delete(oldest)
  }
  cache.set(key, prepared)
  return prepared
}

interface Limits {
  readonly slack: number
  readonly minChars: number
  readonly maxExtraLines: number
}

function verifyPrepared(
  prepared: PreparedFile,
  path: string,
  cited: CitedQuote,
  quote: string,
  { slack, minChars, maxExtraLines }: Limits,
): QuoteVerification {
  const needle = normalizeForMatch(quote)
  const { startLine: start, endLine: end } = cited
  const inRange = Number.isInteger(start) && Number.isInteger(end) && 1 <= start && start <= end
  const valid = inRange && end <= prepared.lineCount
  const haystack = prepared.norm.text

  if (needle.length === 0) return mismatch('quote too short')
  // Non-blank lines only: matching collapses whitespace, so padding a quote with blank lines must not widen
  // the range it may cite.
  const quoteLines = Math.max(1, quote.split('\n').filter(line => line.trim() !== '').length)
  const span = inRange ? end - start + 1 : 0
  if (span > quoteLines + maxExtraLines) {
    return mismatch(
      `cited range too wide: lines ${start}-${end} (${span} lines) for a ${quoteLines}-line quote; cite only the lines the quote is on`,
    )
  }
  if (needle.length < minChars) {
    if (!valid) return mismatch('quote too short')
    const [from, to] = normalizedRange(prepared, start, end)
    if (haystack.slice(from, to).trim().length >= minChars) return mismatch('quote too short')
    const [hit] = occurrencesWithin(haystack, needle, from, to)
    if (hit === undefined) return mismatch('quote not found')
    return found(prepared, path, 'match', hit, needle.length)
  }

  if (valid) {
    const low = Math.max(1, start - slack)
    const high = Math.min(prepared.lineCount, end + slack)
    const [from, to] = normalizedRange(prepared, low, high)
    const hits = occurrencesWithin(haystack, needle, from, to)
    const [only] = hits
    if (hits.length === 1 && only !== undefined) return found(prepared, path, 'match', only, needle.length)
    if (hits.length > 1) {
      const spans = hits.map(index => linesOfOccurrence(prepared, index, needle.length))
      const occupied = Math.max(quoteLines, Math.min(...spans.map(s => s.endLine - s.startLine + 1)))
      if (span > occupied + 2 * slack) {
        return mismatch(
          `quote ambiguous: it occurs ${hits.length === MAX_WINDOW_HITS ? 'many' : hits.length} times in lines ${low}-${high}; candidate lines: ${formatOccurrenceLines(spans)}; cite the exact lines of one occurrence`,
        )
      }
      // A tight citation names one occurrence: take the one nearest the cited lines (first on a tie).
      let best = 0
      let bestDistance = Number.POSITIVE_INFINITY
      spans.forEach((lines, index) => {
        const distance = Math.max(0, lines.startLine - end, start - lines.endLine)
        if (distance < bestDistance) {
          best = index
          bestDistance = distance
        }
      })
      return found(prepared, path, 'match', hits[best] ?? 0, needle.length)
    }
  }

  // No occurrence inside the window, so every occurrence lies elsewhere.
  const first = haystack.indexOf(needle)
  if (first < 0) return mismatch(valid ? 'quote not found' : 'lines out of range')
  if (haystack.indexOf(needle, first + 1) >= 0) {
    const hits = occurrencesWithin(haystack, needle, 0, haystack.length)
    const spans = hits.map(index => linesOfOccurrence(prepared, index, needle.length))
    return mismatch(
      `quote ambiguous; candidate lines: ${formatOccurrenceLines(spans)}; cite the exact lines of one occurrence`,
    )
  }
  return found(prepared, path, 'relocated', first, needle.length)
}

function formatOccurrenceLines(spans: readonly { readonly startLine: number; readonly endLine: number }[]): string {
  const lines = spans.map(s => (s.startLine === s.endLine ? `${s.startLine}` : `${s.startLine}-${s.endLine}`))
  return `${[...new Set(lines)].join(', ')}${spans.length === MAX_WINDOW_HITS ? ' (first candidates only)' : ''}`
}

/** Start indices of every occurrence of `needle` lying entirely within `haystack[from, to)` (capped). */
function occurrencesWithin(haystack: string, needle: string, from: number, to: number): number[] {
  const hits: number[] = []
  for (let index = haystack.indexOf(needle, from); index >= 0; index = haystack.indexOf(needle, index + 1)) {
    if (index + needle.length > to || hits.length >= MAX_WINDOW_HITS) break
    hits.push(index)
  }
  return hits
}

/** 1-based line range covered by normalized characters `[index, index + length)`. */
function linesOfOccurrence(
  prepared: PreparedFile,
  index: number,
  length: number,
): {
  readonly startLine: number
  readonly endLine: number
} {
  const { offsets } = prepared.norm
  return {
    startLine: lineOfOffset(prepared.starts, offsets[index] ?? 0),
    endLine: lineOfOffset(prepared.starts, offsets[index + length - 1] ?? 0),
  }
}

/** Half-open range of normalized indices whose characters lie on lines `start..end`. */
function normalizedRange(prepared: PreparedFile, start: number, end: number): [number, number] {
  const from = prepared.starts[start - 1] ?? prepared.redacted.length
  const to = prepared.starts[end] ?? prepared.redacted.length
  return [lowerBound(prepared.norm.offsets, from), lowerBound(prepared.norm.offsets, to)]
}

/** First index whose value is `>= target` (array length when none). */
function lowerBound(values: Int32Array, target: number): number {
  let lo = 0
  let hi = values.length
  while (lo < hi) {
    const mid = (lo + hi) >>> 1
    if ((values[mid] ?? 0) < target) lo = mid + 1
    else hi = mid
  }
  return lo
}

/** A verified occurrence at normalized `[index, index + length)`: its own lines, snippet, and comment status. */
function found(
  prepared: PreparedFile,
  path: string,
  check: 'match' | 'relocated',
  index: number,
  length: number,
): QuoteVerification {
  const location: CodeRef = { path, ...linesOfOccurrence(prepared, index, length) }
  const { offsets } = prepared.norm
  const from = offsets[index] ?? 0
  const to = (offsets[index + length - 1] ?? from) + 1
  const commentOnly = isCommentOnlyRange(prepared.redacted, maskOf(prepared, path), from, to)
  return {
    check,
    location,
    snippet: snippetOf(prepared, location.startLine, location.endLine),
    ...(commentOnly ? { commentOnly: true as const } : {}),
  }
}

/** Comment mask per prepared file, computed on first use. */
const masks = new WeakMap<PreparedFile, Uint8Array>()

function maskOf(prepared: PreparedFile, path: string): Uint8Array {
  let mask = masks.get(prepared)
  if (!mask) {
    mask = commentMask(prepared.redacted, path)
    masks.set(prepared, mask)
  }
  return mask
}

function mismatch(reason: string): QuoteVerification {
  return { check: 'mismatch', reason }
}

function snippetOf(prepared: PreparedFile, start: number, end: number): string {
  const last = Math.min(end, start + SNIPPET_MAX_LINES - 1)
  const text = linesOf(prepared, start, last).join('\n')
  return clipText(last < end ? `${text} …` : text, SNIPPET_MAX_CHARS)
}

/** Redacted lines `start..end` (1-based, inclusive, assumed in range) without CRs. */
function linesOf(prepared: PreparedFile, start: number, end: number): string[] {
  const { redacted, starts } = prepared
  const from = starts[start - 1] ?? redacted.length
  const next = starts[end]
  const to = next === undefined ? redacted.length : next - 1
  return redacted.slice(from, Math.max(from, to)).split('\n').map(stripCr)
}

/** The quote without `N| ` prefixes when every non-blank line carries one; otherwise `undefined`. */
function stripLineNumbers(quote: string): string | undefined {
  const lines = quote.split('\n')
  const content = lines.filter(line => line.trim() !== '')
  if (content.length === 0 || !content.every(line => NUMBERED_LINE.test(line))) return undefined
  return lines.map(line => line.replace(NUMBERED_LINE, '')).join('\n')
}

function nonNegativeInt(value: number | undefined, fallback: number): number {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0 ? Math.floor(value) : fallback
}
