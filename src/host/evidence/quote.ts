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
 *
 * Models copy code imperfectly in harmless ways. When the exact quote is not
 * found, cleaned-up variants are tried: without code fences or line-number
 * prefixes (`12| `, `12: `, `12 | `, `12→`, `L12: `, `path:12: `, on any of
 * its lines), with HTML entities and backslash-escaped quotes undone, without
 * one added trailing `;` or `,`, and with compatibility forms (full-width
 * punctuation, typographic quotes, `'` for `"`) folded on both sides. A quote
 * that elides code with `...` or `…` is accepted when every fragment of at
 * least {@link MIN_GAP_FRAGMENT_CHARS} characters occurs, in order, within the
 * cited window. In every case the host stores its own contiguous text, never
 * the model's: the stored quote and snippet are the file's lines.
 */

import type { CodeRef, QuoteCheck } from '../../shared/domain.ts'
import type { Redactor } from '../analysis/secrets.ts'
import { isSensitivePath } from '../analysis/secrets.ts'
import type { Snapshot } from '../analysis/types.ts'
import { commentMask, isCommentOnlyRange } from './comments.ts'
import { isWhitespace, normalizeForMatch, normalizePath, normalizeWithOffsets } from './normalize.ts'
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
  /** Exact redacted matched text, without model/tool line-number prefixes. */
  readonly quote?: string
  /**
   * `true` when the matched text is non-code evidence: prose, literal text,
   * punctuation alone, or a comment-led mixed citation. Such a quote is real
   * but must not count as verified code. Absent otherwise.
   */
  readonly commentOnly?: true
  /**
   * English reason for `mismatch`, written for the model that cited it:
   * `file not in snapshot` (also for paths that are not plain relative paths),
   * `withheld file`, `lines out of range`, `quote not found`, `quote ambiguous`
   * (several places in the file, or in a loose cited range), `cited range too
   * wide: …` (a wide citation verifies only a quote that occurs once in the
   * file), or `quote too short`.
   */
  readonly reason?: string
  /**
   * With {@link VerifyQuoteOptions.feedback}, for a `mismatch` in a readable
   * file: what went wrong and the redacted lines at the cited range ±2, for
   * the model to correct its citation. Never stored.
   */
  readonly hint?: string
}

/** Snapshot access needed to verify quotes. */
export interface QuoteSource {
  /** Snapshot lookup by normalized workspace-relative path. */
  file(path: string): { readonly content: string; readonly sha256: string } | undefined
  /** Redact file content exactly as tools showed it to the model. */
  redact(path: string, content: string): string
  /** Files that are never shown to a model and therefore cannot be quoted. */
  isWithheld(path: string): boolean
  /** Every snapshot path, for "did you mean" suggestions; optional. */
  paths?(): Iterable<string>
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
   * counts as `cited range too wide` and can only be `relocated`. Default
   * {@link MAX_EXTRA_CITED_LINES}.
   */
  readonly maxExtraLines?: number
  /** Add a {@link QuoteVerification.hint} to mismatches. Default false. */
  readonly feedback?: boolean
}

/** Maximum lines in {@link QuoteVerification.snippet}. */
export const SNIPPET_MAX_LINES = 12
/** Maximum characters in {@link QuoteVerification.snippet}. */
export const SNIPPET_MAX_CHARS = 1500
/** Default for {@link VerifyQuoteOptions.maxExtraLines}: a citation may span at most the quote's lines + 40. */
export const MAX_EXTRA_CITED_LINES = 40
/** Shortest normalized fragment of a `...`-elided quote that has to be found; shorter ones are ignored. */
export const MIN_GAP_FRAGMENT_CHARS = 12
/** Lines a `...` gap may skip beyond the quote's own lines. */
export const MAX_GAP_LINES = 20

const DEFAULT_SLACK_LINES = 3
const DEFAULT_MIN_QUOTE_CHARS = 8
const DEFAULT_EXCERPT_LINES = 12
const PREPARED_CACHE_SIZE = 8
/** Occurrences collected inside one cited window; more only matter as "ambiguous". */
const MAX_WINDOW_HITS = 64
/** Context lines shown around the cited range in a mismatch hint, and the most lines shown. */
const HINT_CONTEXT_LINES = 2
const HINT_MAX_LINES = 12
const HINT_LINE_CHARS = 160

/** A line-number prefix as tools and editors print them: `12| `, `12: `, `12 | `, `12\t`, `12→`, `L12: `. */
const LINE_PREFIX = /^[ \t]*L?\d{1,7}(?:[ \t]*[|:→]|\t)[ \t]?/
/** The `path:line: ` prefix of search_code results. */
const SEARCH_PREFIX = /^[ \t]*[^\s:|]+:\d{1,7}:[ \t]?/
const FENCE_OPEN = /^\s*(?:```|~~~)[\w+#.-]*\s*$/
const FENCE_CLOSE = /^\s*(?:```|~~~)\s*$/
/** `...` or `…` used to skip code, alone or behind a comment marker. */
const GAP = /(?:\/\/|#|\/\*|<!--)?[ \t]*(?:\.{3,}|…+)[ \t]*(?:\*\/|-->)?/g
const ENTITY = /&(?:lt|gt|amp|quot|apos|#39|#x27);/g
const ENTITIES: Record<string, string> = {
  '&lt;': '<',
  '&gt;': '>',
  '&amp;': '&',
  '&quot;': '"',
  '&apos;': "'",
  '&#39;': "'",
  '&#x27;': "'",
}
/** Quote characters folded into `'`, so `"`/`'`/backtick and typographic quotes compare equal. */
const QUOTES = new Set(["'", '"', '`', '‘', '’', '‚', '‛', '“', '”', '„', '‟', '′', '″', '＇', '＂', '｀'])

/**
 * Check a cited quote against the snapshot.
 *
 * - `match`: exactly one occurrence lies on the cited lines, or the quote's
 *   only occurrence in the file lies within `slack` lines of them. A quote
 *   that occurs several times on the cited lines, or only near them while
 *   it repeats in the file, is `quote ambiguous`: binding it to a nearby
 *   identical line would be a guess.
 * - `relocated`: no occurrence within that window, but exactly one elsewhere
 *   in the file (also when the cited lines are out of range, or the cited
 *   range is wider than the quote's own lines + `maxExtraLines`: such a range
 *   names no place, so only a quote that is unique in the file verifies).
 * - `mismatch` otherwise, with a `reason`; several occurrences elsewhere are
 *   `quote ambiguous`.
 *
 * Exact quotes are tried first, then the cleaned-up variants described in
 * the module comment; the first variant that verifies wins, and a mismatch
 * reports the most informative reason any variant produced. For `match` and
 * `relocated`, `location` and `snippet` are those of the occurrence itself,
 * never the cited range. Quotes shorter than `minQuoteChars` after
 * normalization are rejected unless the cited range itself is that short and
 * contains them; they are never relocated. Never throws for malformed
 * citations.
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
  const variants = quoteVariants(quote)
  let best: Attempt | undefined
  const settle = (attempt: Attempt): QuoteVerification | undefined => {
    if (attempt.result.check !== 'mismatch') return attempt.result
    if (!best || RANK[attempt.kind] > RANK[best.kind]) best = attempt
    return undefined
  }
  for (const variant of variants) {
    const done = settle(verifyPrepared(prepared, path, cited, variant, quote, limits, prepared.norm, normalizeForMatch))
    if (done) return done
  }
  const folded = foldedOf(prepared)
  for (const variant of variants) {
    const done = settle(verifyPrepared(prepared, path, cited, variant, quote, limits, folded, foldForMatch))
    if (done) return done
  }
  const gap = verifyGap(prepared, path, cited, variants.at(-1) ?? quote, quote, limits, folded)
  if (gap) {
    const done = settle(gap)
    if (done) return done
  }
  const result = best?.result ?? mismatch('quote not found')
  if (!options.feedback) return result
  const hint = mismatchHint(prepared, cited, variants.at(-1) ?? quote, folded, limits.slack)
  return hint ? { ...result, hint } : result
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
    paths: () => snapshot.files.keys(),
  }
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

/** Normalized text with, per character, the half-open range of source offsets it came from. */
interface Haystack {
  readonly text: string
  readonly starts: Int32Array
  /** Absent when every character maps to one UTF-16 unit (end = start + 1). */
  readonly ends?: Int32Array
}

interface PreparedFile {
  readonly redacted: string
  /** UTF-16 offset of each LF-separated line of `redacted`. */
  readonly starts: readonly number[]
  readonly lineCount: number
  /** Whitespace-collapsed text. */
  readonly norm: Haystack
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
  const norm = normalizeWithOffsets(redacted)
  const prepared: PreparedFile = {
    redacted,
    starts: lineStarts(redacted),
    lineCount: countLines(redacted),
    norm: { text: norm.text, starts: norm.offsets },
  }
  if (cache.size >= PREPARED_CACHE_SIZE) {
    const oldest = cache.keys().next().value
    if (oldest !== undefined) cache.delete(oldest)
  }
  cache.set(key, prepared)
  return prepared
}

/** Folded text per prepared file, computed only when an exact quote failed. */
const foldedCache = new WeakMap<PreparedFile, Haystack>()

function foldedOf(prepared: PreparedFile): Haystack {
  let folded = foldedCache.get(prepared)
  if (!folded) {
    folded = foldWithOffsets(prepared.redacted)
    foldedCache.set(prepared, folded)
  }
  return folded
}

interface Limits {
  readonly slack: number
  readonly minChars: number
  readonly maxExtraLines: number
}

type MismatchKind = 'not-found' | 'ambiguous' | 'too-short'
/** Which mismatch reason is worth reporting when variants disagree. */
const RANK: Record<MismatchKind | 'verified', number> = { 'too-short': 0, 'not-found': 1, ambiguous: 2, verified: 3 }

interface Attempt {
  readonly kind: MismatchKind | 'verified'
  readonly result: QuoteVerification
}

function verifyPrepared(
  prepared: PreparedFile,
  path: string,
  cited: CitedQuote,
  quote: string,
  original: string,
  { slack, minChars, maxExtraLines }: Limits,
  hay: Haystack,
  normalize: (text: string) => string,
): Attempt {
  const needle = normalize(quote)
  const { startLine: start, endLine: end } = cited
  const inRange = Number.isInteger(start) && Number.isInteger(end) && 1 <= start && start <= end
  const haystack = hay.text

  if (needle.length === 0) return miss('too-short', 'quote too short')
  // Non-blank lines only: matching collapses whitespace, so padding a quote with blank lines must not widen
  // the range it may cite.
  const quoteLines = Math.max(1, original.split('\n').filter(line => line.trim() !== '').length)
  const span = inRange ? end - start + 1 : 0
  const tooWide = span > quoteLines + maxExtraLines
  const wide = `cited range too wide: lines ${start}-${end} (${span} lines) for a ${quoteLines}-line quote`
  // A range much wider than the quote names no place: it is treated like wrong lines (relocation only).
  const valid = inRange && end <= prepared.lineCount && !tooWide
  if (needle.length < minChars) {
    if (!valid) return miss('too-short', tooWide ? `${wide}; cite only the lines the quote is on` : 'quote too short')
    const [from, to] = normalizedRange(prepared, hay, start, end)
    if (haystack.slice(from, to).trim().length >= minChars) return miss('too-short', 'quote too short')
    const [hit] = occurrencesWithin(haystack, needle, from, to)
    if (hit === undefined) return miss('not-found', 'quote not found')
    return verified(found(prepared, path, 'match', hit, needle.length, hay))
  }

  if (valid) {
    const low = Math.max(1, start - slack)
    const high = Math.min(prepared.lineCount, end + slack)
    const [from, to] = normalizedRange(prepared, hay, low, high)
    const hits = occurrencesWithin(haystack, needle, from, to)
    if (hits.length > 0) {
      const spans = hits.map(index => linesOfOccurrence(prepared, hay, index, needle.length))
      const pick = closest(spans, start, end)
      const hit = pick ? hits[pick.index] : undefined
      if (pick && hit !== undefined) {
        // On the cited lines, or the file's only copy: anything else would guess between identical lines.
        if (pick.distance === 0 || (hits.length === 1 && uniqueAt(haystack, needle, hit))) {
          return verified(found(prepared, path, 'match', hit, needle.length, hay))
        }
        if (hits.length === 1) {
          const all = occurrencesWithin(haystack, needle, 0, haystack.length)
          const lines = all.map(index => linesOfOccurrence(prepared, hay, index, needle.length))
          return miss(
            'ambiguous',
            `quote ambiguous: it is not on lines ${start}-${end}, and it occurs ${all.length === MAX_WINDOW_HITS ? 'many' : all.length} times in the file; candidate lines: ${formatOccurrenceLines(lines)}; cite the exact lines of one occurrence`,
          )
        }
      }
      return miss(
        'ambiguous',
        `quote ambiguous: it occurs ${hits.length === MAX_WINDOW_HITS ? 'many' : hits.length} times in lines ${low}-${high}; candidate lines: ${formatOccurrenceLines(spans)}; cite the exact lines of one occurrence`,
      )
    }
  }

  // No occurrence inside the window, so every occurrence lies elsewhere.
  const first = haystack.indexOf(needle)
  if (first < 0) {
    if (tooWide)
      return miss('not-found', `${wide}, and the quote was not found in the file; cite only the lines the quote is on`)
    return miss('not-found', inRange && end <= prepared.lineCount ? 'quote not found' : 'lines out of range')
  }
  if (haystack.indexOf(needle, first + 1) >= 0) {
    const hits = occurrencesWithin(haystack, needle, 0, haystack.length)
    const spans = hits.map(index => linesOfOccurrence(prepared, hay, index, needle.length))
    return miss(
      'ambiguous',
      `${tooWide ? `${wide}, and the ` : ''}quote ${tooWide ? 'is ' : ''}ambiguous; candidate lines: ${formatOccurrenceLines(spans)}; cite the exact lines of one occurrence`,
    )
  }
  return verified(found(prepared, path, 'relocated', first, needle.length, hay))
}

/**
 * Verify a quote that elides code with `...`/`…`: its fragments of at least
 * {@link MIN_GAP_FRAGMENT_CHARS} normalized characters must occur in order
 * within the cited window, spanning at most the quote's own lines +
 * {@link MAX_GAP_LINES}. `undefined` when the quote has no gap marker.
 */
function verifyGap(
  prepared: PreparedFile,
  path: string,
  cited: CitedQuote,
  quote: string,
  original: string,
  { slack, maxExtraLines }: Limits,
  hay: Haystack,
): Attempt | undefined {
  GAP.lastIndex = 0
  if (!GAP.test(quote)) return undefined
  const parts = quote
    .split(GAP)
    .map(foldForMatch)
    .filter(part => part.length >= MIN_GAP_FRAGMENT_CHARS)
  if (parts.length === 0) {
    return miss(
      'too-short',
      `quote too short: every part between "..." has fewer than ${MIN_GAP_FRAGMENT_CHARS} characters`,
    )
  }
  const { startLine: start, endLine: end } = cited
  const quoteLines = Math.max(1, original.split('\n').filter(line => line.trim() !== '').length)
  const span = end - start + 1
  if (
    !Number.isInteger(start) ||
    !Number.isInteger(end) ||
    start < 1 ||
    start > end ||
    end > prepared.lineCount ||
    span > quoteLines + maxExtraLines
  ) {
    return miss('not-found', 'quote not found: a quote with "..." must cite the lines it spans')
  }
  const low = Math.max(1, start - slack)
  const high = Math.min(prepared.lineCount, end + slack)
  const [from, to] = normalizedRange(prepared, hay, low, high)
  const text = hay.text
  const [head, ...rest] = parts as [string, ...string[]]
  const candidates: { readonly index: number; readonly length: number }[] = []
  for (
    let index = text.indexOf(head, from);
    index >= 0 && index + head.length <= to;
    index = text.indexOf(head, index + 1)
  ) {
    let cursor = index + head.length
    let complete = true
    for (const part of rest) {
      const next = text.indexOf(part, cursor)
      if (next < 0 || next + part.length > to) {
        complete = false
        break
      }
      cursor = next + part.length
    }
    if (complete) candidates.push({ index, length: cursor - index })
    if (candidates.length >= MAX_WINDOW_HITS) break
  }
  const spans = candidates
    .map(candidate => ({ candidate, lines: linesOfOccurrence(prepared, hay, candidate.index, candidate.length) }))
    .filter(({ lines }) => lines.endLine - lines.startLine + 1 <= quoteLines + MAX_GAP_LINES)
  const [only] = spans
  if (!only) return miss('not-found', 'quote not found')
  // One candidate in the window, or a single one on the cited lines; otherwise picking one would be a guess.
  const pick =
    spans.length === 1
      ? { index: 0, distance: 0 }
      : closest(
          spans.map(s => s.lines),
          start,
          end,
        )
  const chosen = pick && pick.distance === 0 ? spans[pick.index] : undefined
  if (!chosen) {
    return miss(
      'ambiguous',
      `quote ambiguous: its parts occur ${spans.length} times in lines ${low}-${high}; candidate lines: ${formatOccurrenceLines(spans.map(s => s.lines))}; cite the exact lines of one occurrence`,
    )
  }
  return verified(found(prepared, path, 'match', chosen.candidate.index, chosen.candidate.length, hay))
}

/**
 * The span nearest the cited lines and its distance in lines (0 when it
 * overlaps them); `undefined` when two spans are equally near.
 */
function closest(
  spans: readonly { readonly startLine: number; readonly endLine: number }[],
  start: number,
  end: number,
): { readonly index: number; readonly distance: number } | undefined {
  let best: { index: number; distance: number } | undefined
  let tied = false
  spans.forEach((lines, index) => {
    const distance = Math.max(0, lines.startLine - end, start - lines.endLine)
    if (!best || distance < best.distance) {
      best = { index, distance }
      tied = false
    } else if (distance === best.distance) {
      tied = true
    }
  })
  return tied ? undefined : best
}

/** Whether `needle` occurs in `haystack` only at `index`. */
function uniqueAt(haystack: string, needle: string, index: number): boolean {
  return haystack.indexOf(needle) === index && haystack.indexOf(needle, index + 1) < 0
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

/** First source offset at or after the normalized character `k`, and the end of the character `k`. */
function startOf(hay: Haystack, k: number): number {
  return hay.starts[k] ?? 0
}
function endOf(hay: Haystack, k: number): number {
  return hay.ends ? (hay.ends[k] ?? 0) : startOf(hay, k) + 1
}

/** 1-based line range covered by normalized characters `[index, index + length)`. */
function linesOfOccurrence(
  prepared: PreparedFile,
  hay: Haystack,
  index: number,
  length: number,
): {
  readonly startLine: number
  readonly endLine: number
} {
  return {
    startLine: lineOfOffset(prepared.starts, startOf(hay, index)),
    endLine: lineOfOffset(prepared.starts, Math.max(startOf(hay, index), endOf(hay, index + length - 1) - 1)),
  }
}

/** Half-open range of normalized indices whose characters lie on lines `start..end`. */
function normalizedRange(prepared: PreparedFile, hay: Haystack, start: number, end: number): [number, number] {
  const from = prepared.starts[start - 1] ?? prepared.redacted.length
  const to = prepared.starts[end] ?? prepared.redacted.length
  return [lowerBound(hay.starts, from), lowerBound(hay.starts, to)]
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
  hay: Haystack,
): QuoteVerification {
  const location: CodeRef = { path, ...linesOfOccurrence(prepared, hay, index, length) }
  const from = startOf(hay, index)
  const to = Math.max(from + 1, endOf(hay, index + length - 1))
  const commentOnly = isCommentOnlyRange(prepared.redacted, maskOf(prepared, path), from, to)
  return {
    check,
    location,
    quote: prepared.redacted.slice(from, to),
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

function miss(kind: MismatchKind, reason: string): Attempt {
  return { kind, result: mismatch(reason) }
}

function verified(result: QuoteVerification): Attempt {
  return { kind: 'verified', result }
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

// ---------------------------------------------------------------------------
// Variants and folding
// ---------------------------------------------------------------------------

/**
 * The quote, then each cleaned-up variant that differs from the previous one:
 * without code fences, without line-number prefixes, with entities and
 * escaped quotes undone, and without one added trailing `;`/`,`.
 */
function quoteVariants(quote: string): string[] {
  const out = [quote]
  const add = (next: string): string => {
    if (next !== out.at(-1) && next.trim() !== '') out.push(next)
    return out.at(-1) ?? quote
  }
  let current = add(stripFences(quote))
  current = add(stripLinePrefixes(current))
  current = add(unescapeQuote(current))
  add(current.replace(/[;,]\s*$/, ''))
  return out
}

/** Without a surrounding Markdown code fence or a pair of single backticks around the whole quote. */
function stripFences(quote: string): string {
  const lines = quote.split('\n')
  while (lines.length > 0 && (lines[0] ?? '').trim() === '') lines.shift()
  while (lines.length > 0 && (lines.at(-1) ?? '').trim() === '') lines.pop()
  if (lines.length >= 2 && FENCE_OPEN.test(lines[0] ?? '') && FENCE_CLOSE.test(lines.at(-1) ?? '')) {
    return lines.slice(1, -1).join('\n')
  }
  const single = /^\s*`([^`\n]+)`\s*$/.exec(quote)
  return single?.[1] ?? quote
}

/** Every line without a line-number or `path:line:` prefix (lines without one are kept as they are). */
function stripLinePrefixes(quote: string): string {
  return quote
    .split('\n')
    .map(line => line.replace(SEARCH_PREFIX, '').replace(LINE_PREFIX, ''))
    .join('\n')
}

/** HTML entities and backslash-escaped quotes, as models sometimes double-escape code. */
function unescapeQuote(quote: string): string {
  return quote.replace(ENTITY, entity => ENTITIES[entity] ?? entity).replace(/\\(["'`])/g, '$1')
}

/** {@link normalizeForMatch} plus the per-character folding of {@link foldWithOffsets}. */
function foldForMatch(text: string): string {
  return foldWithOffsets(text).text
}

/**
 * Whitespace-collapsed text with compatibility forms folded: each code point
 * is decomposed (NFKD, so full-width punctuation becomes ASCII and composed
 * letters match decomposed ones) and quote characters become `'`. Per
 * output character it records the source range it came from.
 */
function foldWithOffsets(text: string): Haystack {
  const n = text.length
  const parts: string[] = []
  let starts = new Int32Array(n + 16)
  let ends = new Int32Array(n + 16)
  let length = 0
  const push = (unit: string, start: number, end: number): void => {
    if (length === starts.length) {
      const grown = new Int32Array(starts.length * 2)
      grown.set(starts)
      starts = grown
      const grownEnds = new Int32Array(ends.length * 2)
      grownEnds.set(ends)
      ends = grownEnds
    }
    parts.push(unit)
    starts[length] = start
    ends[length] = end
    length++
  }
  let pendingSpace = -1
  let i = 0
  while (i < n) {
    const code = text.charCodeAt(i)
    if (isWhitespace(code)) {
      if (pendingSpace < 0 && length > 0) pendingSpace = i
      i++
      continue
    }
    const width = code >= 0xd800 && code <= 0xdbff && i + 1 < n ? 2 : 1
    const folded = foldChar(text.slice(i, i + width))
    if (folded !== '') {
      if (pendingSpace >= 0) {
        push(' ', pendingSpace, pendingSpace + 1)
        pendingSpace = -1
      }
      // One code point can decompose into several UTF-16 units; each maps back to the whole code point.
      for (let k = 0; k < folded.length; k++) push(folded.charAt(k), i, i + width)
    }
    i += width
  }
  return { text: parts.join(''), starts: starts.subarray(0, length), ends: ends.subarray(0, length) }
}

function foldChar(char: string): string {
  if (char.length === 1 && char.charCodeAt(0) < 0x80) return QUOTES.has(char) ? "'" : char
  let out = ''
  for (const part of char.normalize('NFKD')) {
    const code = part.charCodeAt(0)
    if (part.length === 1 && isWhitespace(code)) continue
    out += QUOTES.has(part) ? "'" : part
  }
  return out
}

// ---------------------------------------------------------------------------
// Feedback for the model
// ---------------------------------------------------------------------------

/**
 * What the file holds at the cited range ±2 lines (at most 12 lines) and,
 * when the start of the quote matches there, where it stops matching.
 */
function mismatchHint(
  prepared: PreparedFile,
  cited: CitedQuote,
  quote: string,
  folded: Haystack,
  slack: number,
): string | undefined {
  const { startLine: start, endLine: end } = cited
  if (!Number.isInteger(start) || !Number.isInteger(end) || start < 1 || end < start) return undefined
  if (prepared.lineCount === 0) return 'The file is empty.'
  if (start > prepared.lineCount) {
    return `The file has only ${prepared.lineCount} lines; read it again to find the right lines.`
  }
  const low = Math.max(1, start - HINT_CONTEXT_LINES)
  const high = Math.min(prepared.lineCount, end + HINT_CONTEXT_LINES, low + HINT_MAX_LINES - 1)
  const lines = numberLines(
    linesOf(prepared, low, high).map(line => clipText(line, HINT_LINE_CHARS)),
    low,
  )
  const shown = `The file has at lines ${low}-${high}:\n${lines}`
  const needle = foldForMatch(quote)
  if (needle.length === 0) return shown
  const [from, to] = normalizedRange(
    prepared,
    folded,
    Math.max(1, start - slack),
    Math.min(prepared.lineCount, end + slack),
  )
  const window = folded.text.slice(from, to)
  // Longest prefix of the quote that occurs near the cited lines (binary search: occurrence is monotonic).
  let lo = 0
  let hi = needle.length
  while (lo < hi) {
    const mid = (lo + hi + 1) >>> 1
    if (window.includes(needle.slice(0, mid))) lo = mid
    else hi = mid - 1
  }
  // The whole quote occurs here: the reason (ambiguity, a range too wide) says what to fix.
  if (lo === needle.length) return shown
  if (lo < MIN_GAP_FRAGMENT_CHARS) return `None of the quote's text appears near these lines. ${shown}`
  const at = from + window.indexOf(needle.slice(0, lo))
  const matchedFrom = startOf(folded, Math.max(at, at + lo - 40))
  const matchedTo = endOf(folded, at + lo - 1)
  const matched = oneLine(prepared.redacted.slice(matchedFrom, matchedTo))
  const text = prepared.redacted
  const lineEnd = text.indexOf('\n', matchedTo)
  const rest = oneLine(text.slice(matchedTo, lineEnd < 0 ? text.length : lineEnd)).slice(0, 40)
  const nextEnd = lineEnd < 0 ? -1 : text.indexOf('\n', lineEnd + 1)
  const nextLine = lineEnd < 0 ? '' : oneLine(text.slice(lineEnd + 1, nextEnd < 0 ? text.length : nextEnd)).slice(0, 40)
  const continues = rest
    ? `the file continues with "${rest}"`
    : nextLine
      ? `the line ends there and the next line is "${nextLine}"`
      : 'the file ends there'
  return `The quote matches the file up to "…${matched}" and then differs; ${continues}. ${shown}`
}

function oneLine(text: string): string {
  return text.replace(/\s+/g, ' ').trim()
}

function nonNegativeInt(value: number | undefined, fallback: number): number {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0 ? Math.floor(value) : fallback
}
