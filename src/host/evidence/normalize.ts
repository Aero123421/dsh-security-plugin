/**
 * Text and path normalization shared by evidence verification and the
 * workspace tools. Pure functions only.
 */

/**
 * Collapse every whitespace run (the JavaScript `\s` set, line breaks
 * included) to a single space and trim both ends, so indentation and line
 * wrapping differences do not affect quote matching.
 */
export function normalizeForMatch(text: string): string {
  return text.replace(/\s+/g, ' ').trim()
}

/** {@link normalizeForMatch} output plus, per normalized character, its offset in the original text. */
export interface NormalizedText {
  readonly text: string
  /**
   * `offsets[k]` is the UTF-16 index in the original text of `text[k]`. A
   * collapsed space maps to the first whitespace character of its run.
   */
  readonly offsets: Int32Array
}

/** Same result as {@link normalizeForMatch}, with an offset map back into `text`. */
export function normalizeWithOffsets(text: string): NormalizedText {
  const n = text.length
  const offsets = new Int32Array(n)
  const parts: string[] = []
  let length = 0
  let i = 0
  while (i < n && isWhitespace(text.charCodeAt(i))) i++
  while (i < n) {
    const start = i
    while (i < n && !isWhitespace(text.charCodeAt(i))) offsets[length++] = i++
    parts.push(text.slice(start, i))
    const run = i
    while (i < n && isWhitespace(text.charCodeAt(i))) i++
    if (i < n && i > run) {
      parts.push(' ')
      offsets[length++] = run
    }
  }
  return { text: parts.join(''), offsets: offsets.subarray(0, length) }
}

/**
 * Exactly the characters matched by the JavaScript `\s` class: ECMAScript
 * WhiteSpace (TAB, VT, FF, ZWNBSP and the Unicode `Zs` category) plus
 * LineTerminator (LF, CR, LS, PS).
 */
export function isWhitespace(code: number): boolean {
  if (code <= 0x20) return code === 0x20 || (code >= 0x09 && code <= 0x0d)
  if (code < 0xa0) return false
  return (
    code === 0xa0 ||
    code === 0x1680 ||
    (code >= 0x2000 && code <= 0x200a) ||
    code === 0x2028 ||
    code === 0x2029 ||
    code === 0x202f ||
    code === 0x205f ||
    code === 0x3000 ||
    code === 0xfeff
  )
}

/**
 * Normalize a path supplied by a model to the snapshot's POSIX relative form.
 * Backslashes become `/`, surrounding whitespace, `.` segments, empty segments
 * and a trailing `/` are dropped. Returns `undefined` for anything that is not
 * a plain relative path: absolute paths (`/x`, `C:\x`, `C:x`, UNC `\\host`),
 * URLs (`file://…`), any `..` segment, NUL characters, and empty input.
 */
export function normalizePath(path: string): string | undefined {
  if (typeof path !== 'string' || path.includes('\0')) return undefined
  const slashed = path.trim().replace(/\\/g, '/')
  if (slashed === '' || slashed.startsWith('/')) return undefined
  if (/^[A-Za-z]:/.test(slashed) || /^[A-Za-z][A-Za-z0-9+.-]*:\/\//.test(slashed)) return undefined
  const out: string[] = []
  for (const segment of slashed.split('/')) {
    if (segment === '' || segment === '.') continue
    if (segment === '..') return undefined
    out.push(segment)
  }
  return out.length === 0 ? undefined : out.join('/')
}
