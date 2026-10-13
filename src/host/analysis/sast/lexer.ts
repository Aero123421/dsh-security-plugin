/**
 * Small, forgiving tokenizers for JavaScript/TypeScript and Python.
 *
 * They are the precision floor of the code analyzers: the regex/line fallback
 * when the native AST engine is unavailable, and the expression scanner used
 * by taint analysis in both modes. They never throw; malformed input yields
 * best-effort tokens. String literals that are not closed end at the line
 * break, so one stray quote (e.g. in JSX text) cannot swallow a whole file.
 *
 * Template literals and f-strings are flattened: each literal chunk is a
 * `str` token with `interp` set when the literal has substitutions, and each
 * substitution is delimited by `punct` tokens with `sub: 'open' | 'close'`.
 */

export type TokenType = 'ident' | 'num' | 'str' | 'punct' | 'regex'

export interface Token {
  readonly type: TokenType
  /** Raw text (strings keep their quotes and prefix). */
  readonly value: string
  /** UTF-16 offsets into the source; `end` is exclusive. */
  readonly start: number
  readonly end: number
  /** A line break separates this token from the previous one. */
  readonly nl: boolean
  /** `str`: a template literal or f-string chunk of a literal that has substitutions. */
  readonly interp?: boolean
  /** `str` chunk position inside an interpolated literal: holds the opening quote, the closing quote, or neither. */
  readonly part?: 'head' | 'middle' | 'tail'
  /** `punct`: opens (`${`, `{`) or closes (`}`) a substitution. */
  readonly sub?: 'open' | 'close'
}

interface MutableToken {
  type: TokenType
  value: string
  start: number
  end: number
  nl: boolean
  interp?: boolean
  part?: 'head' | 'middle' | 'tail'
  sub?: 'open' | 'close'
}

/** Mark the chunks of one literal: `interp` when it has substitutions, plus each chunk's position. */
function markChunks(chunks: MutableToken[], closed: boolean): void {
  if (chunks.length <= 1) return
  for (let i = 0; i < chunks.length; i++) {
    const chunk = chunks[i]!
    chunk.interp = true
    chunk.part = i === 0 ? 'head' : i === chunks.length - 1 && closed ? 'tail' : 'middle'
  }
}

const JS_PUNCT = [
  '>>>=',
  '...',
  '===',
  '!==',
  '**=',
  '<<=',
  '>>=',
  '>>>',
  '&&=',
  '||=',
  '??=',
  '=>',
  '==',
  '!=',
  '<=',
  '>=',
  '&&',
  '||',
  '??',
  '?.',
  '++',
  '--',
  '+=',
  '-=',
  '*=',
  '/=',
  '%=',
  '&=',
  '|=',
  '^=',
  '**',
  '<<',
  '>>',
]

const PY_PUNCT = [
  '**=',
  '//=',
  '>>=',
  '<<=',
  '...',
  '**',
  '//',
  '==',
  '!=',
  '<=',
  '>=',
  '->',
  '+=',
  '-=',
  '*=',
  '/=',
  '%=',
  '&=',
  '|=',
  '^=',
  '@=',
  ':=',
  '<<',
  '>>',
]

/** Keywords after which a `/` starts a regular expression rather than a division. */
const REGEX_AFTER_KEYWORDS: ReadonlySet<string> = new Set([
  'return',
  'typeof',
  'instanceof',
  'in',
  'of',
  'new',
  'delete',
  'void',
  'throw',
  'case',
  'do',
  'else',
  'yield',
  'await',
])

/** JavaScript reserved words that never name a value or a callable. */
export const JS_KEYWORDS: ReadonlySet<string> = new Set([
  'break',
  'case',
  'catch',
  'class',
  'const',
  'continue',
  'debugger',
  'default',
  'delete',
  'do',
  'else',
  'export',
  'extends',
  'finally',
  'for',
  'function',
  'if',
  'import',
  'in',
  'instanceof',
  'let',
  'new',
  'return',
  'switch',
  'throw',
  'try',
  'typeof',
  'var',
  'void',
  'while',
  'with',
  'yield',
  'await',
  'async',
  'of',
  'static',
  'get',
  'set',
])

/** Python keywords that never name a callable. */
export const PY_KEYWORDS: ReadonlySet<string> = new Set([
  'and',
  'as',
  'assert',
  'async',
  'await',
  'break',
  'class',
  'continue',
  'def',
  'del',
  'elif',
  'else',
  'except',
  'finally',
  'for',
  'from',
  'global',
  'if',
  'import',
  'in',
  'is',
  'lambda',
  'nonlocal',
  'not',
  'or',
  'pass',
  'raise',
  'return',
  'try',
  'while',
  'with',
  'yield',
])

// ---------------------------------------------------------------------------
// JavaScript / TypeScript
// ---------------------------------------------------------------------------

/**
 * Tokenize JavaScript or TypeScript (JSX tolerated). Comments are dropped.
 * `start`/`end` limit lexing to a slice; offsets stay absolute.
 */
export function lexJs(source: string, start = 0, end = source.length): Token[] {
  const out: MutableToken[] = []
  const lexer = new JsLexer(source, out, Math.min(end, source.length))
  let pos = start
  if (start === 0 && source.startsWith('#!')) {
    const eol = source.indexOf('\n')
    pos = eol < 0 ? source.length : eol
  }
  lexer.run(pos, false)
  return out
}

class JsLexer {
  readonly #src: string
  readonly #out: MutableToken[]
  readonly #limit: number
  #nl = false

  constructor(src: string, out: MutableToken[], limit: number) {
    this.#src = src
    this.#out = out
    this.#limit = limit
  }

  /** Lex from `pos`. In `sub` mode, stop at the `}` closing a `${` and return its offset. */
  run(pos: number, sub: boolean): number {
    const src = this.#src
    const n = this.#limit
    let depth = 0
    let i = pos
    while (i < n) {
      const c = src.charCodeAt(i)
      // whitespace
      if (c === 10 || c === 13 || c === 0x2028 || c === 0x2029) {
        this.#nl = true
        i++
        continue
      }
      if (c === 32 || c === 9 || c === 11 || c === 12 || c === 0xa0 || c === 0xfeff) {
        i++
        continue
      }
      // comments
      if (c === 47 /* / */) {
        const d = src.charCodeAt(i + 1)
        if (d === 47) {
          i = skipToEol(src, i)
          continue
        }
        if (d === 42) {
          const close = src.indexOf('*/', i + 2)
          const end = close < 0 ? n : close + 2
          if (src.slice(i, end).includes('\n')) this.#nl = true
          i = end
          continue
        }
        if (this.#regexAllowed()) {
          const end = scanRegex(src, i, n)
          if (end > 0) {
            this.#push('regex', i, end)
            i = end
            continue
          }
        }
      }
      if (c === 60 /* < */ && src.startsWith('<!--', i)) {
        i = skipToEol(src, i)
        continue
      }
      // strings
      if (c === 39 || c === 34) {
        const end = scanQuoted(src, i, c, n)
        this.#push('str', i, end)
        i = end
        continue
      }
      if (c === 96 /* ` */) {
        i = this.#template(i)
        continue
      }
      // numbers
      if (isDigit(c) || (c === 46 && isDigit(src.charCodeAt(i + 1)))) {
        let j = i + 1
        while (j < n) {
          const d = src.charCodeAt(j)
          if (isIdentPart(d) || d === 46) j++
          else if ((d === 43 || d === 45) && (src[j - 1] === 'e' || src[j - 1] === 'E') && !src.startsWith('0x', i)) j++
          else break
        }
        this.#push('num', i, j)
        i = j
        continue
      }
      // identifiers (including `#private`)
      if (isIdentStart(c) || (c === 35 && isIdentStart(src.charCodeAt(i + 1)))) {
        let j = i + 1
        while (j < n && isIdentPart(src.charCodeAt(j))) j++
        this.#push('ident', i, j)
        i = j
        continue
      }
      if (c === 92 /* backslash: unicode escape in identifier, rare */) {
        i++
        continue
      }
      // punctuation
      if (sub) {
        if (c === 123) depth++
        else if (c === 125) {
          if (depth === 0) return i
          depth--
        }
      }
      const op = matchPunct(src, i, JS_PUNCT)
      this.#push('punct', i, i + op.length)
      i += op.length
    }
    return n
  }

  #template(start: number): number {
    const src = this.#src
    const n = this.#limit
    const chunks: MutableToken[] = []
    let chunkStart = start
    let i = start + 1
    while (i < n) {
      const c = src.charCodeAt(i)
      if (c === 92) {
        i += 2
        continue
      }
      if (c === 96) {
        chunks.push(this.#push('str', chunkStart, i + 1))
        i++
        this.#finishTemplate(chunks)
        return i
      }
      if (c === 36 && src.charCodeAt(i + 1) === 123) {
        chunks.push(this.#push('str', chunkStart, i))
        const open = this.#push('punct', i, i + 2)
        open.sub = 'open'
        const close = this.run(i + 2, true)
        if (close >= n) {
          this.#finishTemplate(chunks, false)
          return n
        }
        const closer = this.#push('punct', close, close + 1)
        closer.sub = 'close'
        // The next chunk continues the same literal; it never starts a new line.
        this.#nl = false
        i = close + 1
        chunkStart = i
        continue
      }
      i++
    }
    chunks.push(this.#push('str', chunkStart, n))
    this.#finishTemplate(chunks, false)
    return n
  }

  #finishTemplate(chunks: MutableToken[], closed = true): void {
    markChunks(chunks, closed)
  }

  #regexAllowed(): boolean {
    const prev = this.#out[this.#out.length - 1]
    if (!prev) return true
    if (prev.type === 'num' || prev.type === 'str' || prev.type === 'regex') return false
    if (prev.type === 'ident') return REGEX_AFTER_KEYWORDS.has(prev.value)
    if (prev.sub === 'close') return false
    return prev.value !== ')' && prev.value !== ']' && prev.value !== '}' && prev.value !== '++' && prev.value !== '--'
  }

  #push(type: TokenType, start: number, end: number): MutableToken {
    const token: MutableToken = { type, value: this.#src.slice(start, end), start, end, nl: this.#nl }
    this.#nl = false
    this.#out.push(token)
    return token
  }
}

/** Offset just past a `/regex/flags` literal starting at `start`, or -1 when it is not one. */
function scanRegex(src: string, start: number, n: number): number {
  let i = start + 1
  let inClass = false
  while (i < n) {
    const c = src.charCodeAt(i)
    if (c === 10 || c === 13) return -1
    if (c === 92) {
      i += 2
      continue
    }
    if (c === 91) inClass = true
    else if (c === 93) inClass = false
    else if (c === 47 && !inClass) {
      i++
      while (i < n && isIdentPart(src.charCodeAt(i))) i++
      return i
    }
    i++
  }
  return -1
}

// ---------------------------------------------------------------------------
// Python
// ---------------------------------------------------------------------------

/**
 * Tokenize Python. Comments and line continuations are dropped. `start`/`end`
 * limit lexing to a slice; offsets stay absolute.
 */
export function lexPython(source: string, start = 0, end = source.length): Token[] {
  const out: MutableToken[] = []
  new PyLexer(source, out).run(start, Math.min(end, source.length), false)
  return out
}

class PyLexer {
  readonly #src: string
  readonly #out: MutableToken[]
  #nl = true

  constructor(src: string, out: MutableToken[]) {
    this.#src = src
    this.#out = out
  }

  /**
   * Lex `[pos, limit)`. In `sub` mode (inside an f-string `{...}`), stop at a
   * depth-0 `}`, `!` (conversion) or `:` (format spec) and return its offset.
   */
  run(pos: number, limit: number, sub: boolean): number {
    const src = this.#src
    let depth = 0
    let i = pos
    while (i < limit) {
      const c = src.charCodeAt(i)
      if (c === 10 || c === 13) {
        if (!sub) this.#nl = true
        i++
        continue
      }
      if (c === 32 || c === 9 || c === 12 || c === 0xfeff) {
        i++
        continue
      }
      if (c === 92 /* backslash continuation */) {
        i++
        if (src.charCodeAt(i) === 13) i++
        if (src.charCodeAt(i) === 10) i++
        continue
      }
      if (c === 35 /* # */) {
        i = skipToEol(src, i)
        continue
      }
      if (isIdentStart(c)) {
        let j = i + 1
        while (j < limit && isIdentPart(src.charCodeAt(j))) j++
        const q = src.charCodeAt(j)
        if (
          (q === 39 || q === 34) &&
          j - i <= 2 &&
          /^(?:[rRuUbBfFtT]|[rR][bBfFtT]|[bBfFtT][rR])$/.test(src.slice(i, j))
        ) {
          const prefix = src.slice(i, j).toLowerCase()
          i = this.#string(i, j, prefix.includes('f') || prefix.includes('t'), limit)
          continue
        }
        this.#push('ident', i, j)
        i = j
        continue
      }
      if (c === 39 || c === 34) {
        i = this.#string(i, i, false, limit)
        continue
      }
      if (isDigit(c) || (c === 46 && isDigit(src.charCodeAt(i + 1)))) {
        let j = i + 1
        while (j < limit) {
          const d = src.charCodeAt(j)
          if (isIdentPart(d) || d === 46) j++
          else if ((d === 43 || d === 45) && (src[j - 1] === 'e' || src[j - 1] === 'E')) j++
          else break
        }
        this.#push('num', i, j)
        i = j
        continue
      }
      if (sub) {
        if (c === 40 || c === 91 || c === 123) depth++
        else if (c === 41 || c === 93) depth = Math.max(0, depth - 1)
        else if (c === 125) {
          if (depth === 0) return i
          depth--
        } else if (depth === 0 && c === 33 && src.charCodeAt(i + 1) !== 61) return i
        else if (depth === 0 && c === 58 && src.charCodeAt(i + 1) !== 61) return i
      }
      const op = matchPunct(src, i, PY_PUNCT)
      this.#push('punct', i, i + op.length)
      i += op.length
    }
    return limit
  }

  /** Lex a string whose prefix starts at `start` and opening quote is at `quoteAt`. */
  #string(start: number, quoteAt: number, fstring: boolean, limit: number): number {
    const src = this.#src
    const q = src[quoteAt]!
    const triple = src.startsWith(q.repeat(3), quoteAt)
    const close = triple ? q.repeat(3) : q
    const chunks: MutableToken[] = []
    let chunkStart = start
    let i = quoteAt + close.length
    while (i < limit) {
      const c = src.charCodeAt(i)
      if (c === 92) {
        i += 2
        continue
      }
      if (!triple && (c === 10 || c === 13)) break
      if (src.startsWith(close, i)) {
        i += close.length
        chunks.push(this.#push('str', chunkStart, i))
        markChunks(chunks, true)
        return i
      }
      if (fstring && c === 123) {
        if (src.charCodeAt(i + 1) === 123) {
          i += 2
          continue
        }
        chunks.push(this.#push('str', chunkStart, i))
        const open = this.#push('punct', i, i + 1)
        open.sub = 'open'
        // A non-triple f-string expression cannot cross a line break.
        const innerLimit = triple ? limit : Math.min(limit, eolOf(src, i))
        let end = this.run(i + 1, innerLimit, true)
        if (end < innerLimit && src.charCodeAt(end) !== 125) end = skipFormatSpec(src, end, innerLimit)
        if (end >= innerLimit) {
          markChunks(chunks, false)
          return innerLimit
        }
        const closer = this.#push('punct', end, end + 1)
        closer.sub = 'close'
        this.#nl = false
        i = end + 1
        chunkStart = i
        continue
      }
      i++
    }
    chunks.push(this.#push('str', chunkStart, i))
    markChunks(chunks, false)
    return i
  }

  #push(type: TokenType, start: number, end: number): MutableToken {
    const token: MutableToken = { type, value: this.#src.slice(start, end), start, end, nl: this.#nl }
    this.#nl = false
    this.#out.push(token)
    return token
  }
}

/** Skip an f-string conversion/format spec (which may nest `{}`) to its closing `}`. */
function skipFormatSpec(src: string, i: number, limit: number): number {
  let depth = 0
  while (i < limit) {
    const c = src.charCodeAt(i)
    if (c === 123) depth++
    else if (c === 125) {
      if (depth === 0) return i
      depth--
    }
    i++
  }
  return limit
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/**
 * For every bracket token index, the index of its partner (`(`↔`)`, `[`↔`]`,
 * `{`/`${`↔`}`); -1 when unbalanced. Mismatched closers are ignored.
 */
export function matchBrackets(tokens: readonly Token[]): Int32Array {
  const match = new Int32Array(tokens.length).fill(-1)
  const stack: number[] = []
  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i]!
    if (t.type !== 'punct') continue
    const v = t.value
    if (v === '(' || v === '[' || v === '{' || t.sub === 'open') {
      stack.push(i)
      continue
    }
    if (v !== ')' && v !== ']' && v !== '}') continue
    const want = v === ')' ? '(' : v === ']' ? '[' : '{'
    for (let s = stack.length - 1; s >= 0; s--) {
      const open = tokens[stack[s]!]!
      const kind = open.sub === 'open' ? '{' : open.value
      if (kind === want) {
        match[stack[s]!] = i
        match[i] = stack[s]!
        stack.length = s
        break
      }
    }
  }
  return match
}

/** Index of the first token whose start is `>= offset` (binary search). */
export function tokenAt(tokens: readonly Token[], offset: number): number {
  let lo = 0
  let hi = tokens.length
  while (lo < hi) {
    const mid = (lo + hi) >>> 1
    if (tokens[mid]!.start < offset) lo = mid + 1
    else hi = mid
  }
  return lo
}

/** Token index range `[from, to)` of the tokens fully inside `[start, end)`. */
export function tokenRange(tokens: readonly Token[], start: number, end: number): [number, number] {
  const from = tokenAt(tokens, start)
  let to = tokenAt(tokens, end)
  while (to > from && tokens[to - 1]!.end > end) to--
  return [from, to]
}

/** Decoded-enough content of a string token: quotes and prefixes stripped, escapes left as is. */
export function stringContent(token: Token): string {
  let v = token.value
  const head = token.part === undefined || token.part === 'head'
  const tail = token.part === undefined || token.part === 'tail'
  if (head) {
    const prefix = /^[rRuUbBfFtT]{0,2}(?=['"])/.exec(v)?.[0] ?? ''
    v = v.slice(prefix.length)
    if (v.startsWith('"""') || v.startsWith("'''")) v = v.slice(3)
    else if (v.startsWith('`') || v.startsWith('"') || v.startsWith("'")) v = v.slice(1)
  }
  if (tail && v.length > 0) {
    if (v.endsWith('"""') || v.endsWith("'''")) v = v.slice(0, -3)
    else if (v.endsWith('`') || v.endsWith('"') || v.endsWith("'")) v = v.slice(0, -1)
  }
  return v
}

/** Offsets where each line starts. */
export function lineStarts(text: string): number[] {
  const starts = [0]
  for (let i = text.indexOf('\n'); i >= 0; i = text.indexOf('\n', i + 1)) starts.push(i + 1)
  return starts
}

/** 1-based line containing `offset`. */
export function lineOf(starts: readonly number[], offset: number): number {
  let lo = 0
  let hi = starts.length - 1
  while (lo < hi) {
    const mid = (lo + hi + 1) >>> 1
    if (starts[mid]! <= offset) lo = mid
    else hi = mid - 1
  }
  return lo + 1
}

function matchPunct(src: string, i: number, table: readonly string[]): string {
  for (const op of table) if (src.startsWith(op, i)) return op
  return src[i]!
}

function scanQuoted(src: string, start: number, quote: number, n: number): number {
  let i = start + 1
  while (i < n) {
    const c = src.charCodeAt(i)
    if (c === 92) {
      i += 2
      continue
    }
    if (c === quote) return i + 1
    if (c === 10 || c === 13) return i
    i++
  }
  return n
}

function skipToEol(src: string, i: number): number {
  const eol = src.indexOf('\n', i)
  return eol < 0 ? src.length : eol
}

function eolOf(src: string, i: number): number {
  const eol = src.indexOf('\n', i)
  return eol < 0 ? src.length : eol
}

function isDigit(c: number): boolean {
  return c >= 48 && c <= 57
}

function isIdentStart(c: number): boolean {
  return (
    (c >= 65 && c <= 90) ||
    (c >= 97 && c <= 122) ||
    c === 95 ||
    c === 36 ||
    (c > 0x7f && c !== 0xa0 && c !== 0x2028 && c !== 0x2029 && c !== 0xfeff && !Number.isNaN(c))
  )
}

function isIdentPart(c: number): boolean {
  return isIdentStart(c) || isDigit(c)
}
