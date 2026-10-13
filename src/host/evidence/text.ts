/**
 * Line helpers shared by evidence verification and the workspace tools.
 * Lines are split on LF only (CR stays on the line and is stripped for
 * display), matching how the Redactor and the analyzers count lines.
 */

/**
 * The lines of `text`. A trailing newline does not start an extra line and
 * empty text has no lines, so `'a\nb\n'` has 2 lines and `''` has 0.
 */
export function splitLines(text: string): string[] {
  if (text === '') return []
  const lines = text.split('\n')
  if (lines.length > 1 && lines[lines.length - 1] === '') lines.pop()
  return lines
}

/** Number of lines as counted by {@link splitLines}, without allocating them. */
export function countLines(text: string): number {
  if (text === '') return 0
  let count = 1
  for (let i = text.indexOf('\n'); i >= 0; i = text.indexOf('\n', i + 1)) count++
  return text.endsWith('\n') ? count - 1 : count
}

/** UTF-16 offset of the first character of every LF-separated line. */
export function lineStarts(text: string): number[] {
  const starts = [0]
  for (let i = text.indexOf('\n'); i >= 0; i = text.indexOf('\n', i + 1)) starts.push(i + 1)
  return starts
}

/** 1-based line containing UTF-16 `offset`, given {@link lineStarts}. */
export function lineOfOffset(starts: readonly number[], offset: number): number {
  let lo = 0
  let hi = starts.length - 1
  while (lo < hi) {
    const mid = (lo + hi + 1) >>> 1
    if ((starts[mid] ?? 0) <= offset) lo = mid
    else hi = mid - 1
  }
  return lo + 1
}

/** Drops one trailing CR (CRLF files). */
export function stripCr(line: string): string {
  return line.endsWith('\r') ? line.slice(0, -1) : line
}

/**
 * Cut `text` to at most `max` UTF-16 units (never inside a surrogate pair),
 * appending `…` when anything was removed. The result never exceeds `max`.
 */
export function clipText(text: string, max: number): string {
  if (text.length <= max) return text
  if (max <= 1) return '…'.slice(0, Math.max(0, max))
  let cut = max - 1
  const code = text.charCodeAt(cut - 1)
  if (code >= 0xd800 && code <= 0xdbff) cut--
  return `${text.slice(0, cut)}…`
}

/** Placeholder that replaces the absolute snapshot root in text shown to models. */
export const ROOT_PLACEHOLDER = '<root>'

/**
 * Replace every occurrence of the absolute workspace `root` (in its own,
 * forward-slash and backslash spellings) with {@link ROOT_PLACEHOLDER}, so
 * text shown to a model never reveals where the workspace lives.
 *
 * An occurrence must start at a path boundary (`src/home/u/x` is a relative
 * path, not the root). A root with two or more segments (`/home/u/proj`) is
 * specific enough to mask wherever a path starts with it, so
 * `/home/u/proj-old` becomes `<root>-old`; a single-segment root (`/app`,
 * `C:\work`) must also end at a boundary so `/apple` stays intact. Roots
 * shorter than 2 characters after trimming separators (`/`, `C:`) are left
 * alone. Never changes line structure.
 */
export function maskRoot(text: string, root: string): string {
  const trimmed = root.replace(/[\\/]+$/, '')
  if (trimmed.length < 2 || /^[A-Za-z]:$/.test(trimmed)) return text
  const segments = trimmed
    .replace(/^[A-Za-z]:/, '')
    .split(/[\\/]/)
    .filter(Boolean).length
  const needsEndBoundary = segments < 2
  const spellings = [...new Set([trimmed, trimmed.replace(/\\/g, '/'), trimmed.replace(/\//g, '\\')])]
  let out = text
  for (const spelling of spellings) {
    if (!out.includes(spelling)) continue
    let result = ''
    let cursor = 0
    for (let i = out.indexOf(spelling); i >= 0; i = out.indexOf(spelling, i + 1)) {
      if (i < cursor) continue
      if (i > 0 && isPathChar(out.charCodeAt(i - 1))) continue
      const after = i + spelling.length
      if (needsEndBoundary && after < out.length && isPathChar(out.charCodeAt(after))) continue
      result += out.slice(cursor, i) + ROOT_PLACEHOLDER
      cursor = after
    }
    out = result + out.slice(cursor)
  }
  return out
}

/** Characters that continue a file-name segment (so the root match is not at a boundary). */
function isPathChar(code: number): boolean {
  return (
    (code >= 0x30 && code <= 0x39) ||
    (code >= 0x41 && code <= 0x5a) ||
    (code >= 0x61 && code <= 0x7a) ||
    code === 0x5f || // _
    code === 0x2d || // -
    code === 0x2e || // .
    code > 0x7f
  )
}

/**
 * Render lines with right-aligned `N| ` prefixes, starting at line number
 * `firstLine`. CRs are stripped; lines longer than `maxLineChars` are clipped
 * with a note saying how much was cut.
 */
export function numberLines(lines: readonly string[], firstLine: number, maxLineChars = 2_000): string {
  const width = String(firstLine + Math.max(0, lines.length - 1)).length
  return lines
    .map((raw, index) => {
      const line = stripCr(raw)
      const body =
        line.length > maxLineChars
          ? `${clipText(line, maxLineChars)} [line clipped: ${line.length - maxLineChars + 1} more chars]`
          : line
      const prefix = `${String(firstLine + index).padStart(width, ' ')}|`
      return body === '' ? prefix : `${prefix} ${body}`
    })
    .join('\n')
}
