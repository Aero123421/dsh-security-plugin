/**
 * Comment detection for evidence. A quote that is only a comment (or prose
 * documentation) states a claim about the code; it does not show code doing
 * anything. Such quotes may be displayed as context but never count as
 * verified counter-evidence, because a hostile repository can write
 * `// input sanitized upstream` anywhere.
 *
 * The scanner is a small, string-aware lexer per comment family chosen by
 * file extension. It errs towards "comment" only for text that sits inside a
 * recognized comment, string literal, or documentation file; everything it cannot
 * classify counts as code.
 */

import { isWhitespace } from './normalize.ts'

interface CommentSyntax {
  /** Markers that start a comment running to the end of the line, anywhere on the line. */
  readonly line: readonly string[]
  /** Line-comment markers recognized only as the first non-blank text of a line. */
  readonly lineAtStart: readonly string[]
  /** `[open, close]` block-comment delimiters. */
  readonly block: readonly (readonly [string, string])[]
  /** Whether block comments of the same kind can nest. */
  readonly nestedBlocks: boolean
  /** Single-character string delimiters whose interiors are non-code evidence. */
  readonly quotes: string
  /** Python-style triple-quoted strings; one in statement position is a docstring. */
  readonly tripleQuotes: boolean
  /** The whole file is prose (documentation), so all of it counts as comment. */
  readonly prose: boolean
}

const syntax = (overrides: Partial<CommentSyntax>): CommentSyntax => ({
  line: [],
  lineAtStart: [],
  block: [],
  nestedBlocks: false,
  quotes: '',
  tripleQuotes: false,
  prose: false,
  ...overrides,
})

const C_BLOCK = ['/*', '*/'] as const
const HTML_BLOCKS = [
  ['<!--', '-->'],
  ['{{!--', '--}}'],
  ['{#', '#}'],
  ['<%#', '%>'],
] as const

const C_LIKE = syntax({ line: ['//'], block: [C_BLOCK], quotes: '"\'`' })
const NESTED_C = syntax({ ...C_LIKE, nestedBlocks: true })
const CSS = syntax({ block: [C_BLOCK], quotes: '"\'' })
const PHP = syntax({ line: ['//', '#'], block: [C_BLOCK], quotes: '"\'`' })
const HASH = syntax({ line: ['#'], quotes: '"\'' })
const RUBY = syntax({ line: ['#'], block: [['=begin', '=end']], quotes: '"\'' })
const PYTHON = syntax({ line: ['#'], quotes: '"\'', tripleQuotes: true })
const INI = syntax({ line: ['#'], lineAtStart: [';'], quotes: '"\'' })
const SQL = syntax({ line: ['--'], block: [C_BLOCK], quotes: '"\'' })
const LUA = syntax({ line: ['--'], block: [['--[[', ']]']], quotes: '"\'' })
const HASKELL = syntax({ line: ['--'], block: [['{-', '-}']], nestedBlocks: true, quotes: '"' })
const HTML = syntax({ lineAtStart: ['//'], block: HTML_BLOCKS })
const COMPONENT = syntax({ lineAtStart: ['//'], block: [...HTML_BLOCKS, C_BLOCK] })
const PROSE = syntax({ prose: true })
const GENERIC = syntax({ lineAtStart: ['//', '#'], block: [C_BLOCK, ['<!--', '-->']], quotes: '"\'' })

const BY_EXTENSION: Readonly<Record<string, CommentSyntax>> = {
  ...family(
    C_LIKE,
    'js jsx ts tsx mjs cjs mts cts java go c h cc cpp cxx hpp hh cs dart groovy gradle sol proto m mm zig scss less',
  ),
  ...family(NESTED_C, 'rs swift kt kts scala sc'),
  ...family(CSS, 'css'),
  ...family(PHP, 'php phtml'),
  ...family(PYTHON, 'py pyi pyw'),
  ...family(
    HASH,
    'sh bash zsh fish ksh yml yaml toml pl pm r ex exs tf tfvars hcl conf cfg env properties nix cmake mk coffee cr jl ps1',
  ),
  ...family(RUBY, 'rb rake gemspec'),
  ...family(INI, 'ini'),
  ...family(SQL, 'sql'),
  ...family(LUA, 'lua'),
  ...family(HASKELL, 'hs elm'),
  ...family(HTML, 'html htm xhtml xml svg jsp erb ejs hbs handlebars mustache njk j2 jinja jinja2 twig liquid'),
  ...family(COMPONENT, 'vue svelte astro'),
  ...family(PROSE, 'md markdown mdx txt text rst adoc asciidoc org'),
}

const BY_BASENAME: Readonly<Record<string, CommentSyntax>> = {
  dockerfile: HASH,
  makefile: HASH,
  gemfile: RUBY,
  rakefile: RUBY,
  readme: PROSE,
  license: PROSE,
  licence: PROSE,
  copying: PROSE,
  notice: PROSE,
  authors: PROSE,
  changelog: PROSE,
  changes: PROSE,
  contributing: PROSE,
  procfile: HASH,
  '.gitignore': HASH,
  '.dockerignore': HASH,
}

function family(value: CommentSyntax, extensions: string): Record<string, CommentSyntax> {
  return Object.fromEntries(extensions.split(' ').map(ext => [ext, value]))
}

function syntaxOf(path: string): CommentSyntax {
  const base = (path.slice(path.lastIndexOf('/') + 1) || path).toLowerCase()
  const named = BY_BASENAME[base]
  if (named) return named
  if (base === '.env' || base.startsWith('.env.') || base.startsWith('dockerfile.')) return HASH
  const dot = base.lastIndexOf('.')
  return (dot > 0 ? BY_EXTENSION[base.slice(dot + 1)] : undefined) ?? GENERIC
}

/**
 * Per UTF-16 index of `text`, 1 when the character lies inside a comment,
 * docstring, or documentation prose for the language implied by `path`, and
 * 2 for string literals, and 0 for code. Literal text is not executable
 * evidence, but code surrounding a literal (such as a comparison) still is.
 */
export function commentMask(text: string, path: string): Uint8Array {
  const mask = new Uint8Array(text.length)
  const lang = syntaxOf(path)
  if (lang.prose) return mask.fill(1)
  const n = text.length
  // Whether only blanks precede `i` on its line.
  let blank = true
  let i = 0
  while (i < n) {
    const c = text[i] ?? ''
    if (c === '\n') {
      blank = true
      i++
      continue
    }
    if (c === ' ' || c === '\t' || c === '\r' || c === '\f' || c === '\v') {
      i++
      continue
    }
    const atLineStart = blank
    blank = false
    const block = lang.block.find(([open]) => text.startsWith(open, i))
    if (block) {
      const end = blockEnd(text, i, block, lang.nestedBlocks)
      mask.fill(1, i, end)
      i = end
      continue
    }
    if (
      lang.line.some(m => text.startsWith(m, i)) ||
      (atLineStart && lang.lineAtStart.some(m => text.startsWith(m, i)))
    ) {
      const end = lineEnd(text, i)
      mask.fill(1, i, end)
      i = end
      continue
    }
    if (lang.tripleQuotes && (text.startsWith('"""', i) || text.startsWith("'''", i))) {
      const close = text.indexOf(text.slice(i, i + 3), i + 3)
      const end = close < 0 ? n : close + 3
      mask.fill(atLineStart && isStatementPosition(text, i) && endsStatement(text, end) ? 1 : 2, i, end)
      i = end
      continue
    }
    if (lang.quotes.includes(c)) {
      const end = skipString(text, i)
      mask.fill(2, i, end)
      i = end
    } else i++
  }
  return mask
}

/**
 * Compatibility name: true means the quote is non-code evidence. Require an
 * identifier/number outside comments and literals; punctuation alone is not
 * behaviour. In mixed citations, code must contribute at least as many
 * non-whitespace characters as comments. Literal contents contribute to
 * neither side, so `if (x === "admin")` remains code, not string prose.
 *
 * This lexical majority rule blocks a defensive prose claim padded with a
 * short adjacent sink, without guessing whether an expression is a guard.
 * A code-led guard plus a short explanatory comment still qualifies. This
 * is not semantic proof of a defense: the independent reviewer must assess
 * whether that code actually defends the path.
 */
export function isCommentOnlyRange(text: string, mask: Uint8Array, from: number, to: number): boolean {
  let comments = 0
  let code = 0
  let substantive = false
  let nonblank = false
  for (let i = Math.max(0, from); i < Math.min(to, text.length); i++) {
    if (isWhitespace(text.charCodeAt(i))) continue
    nonblank = true
    if (mask[i] === 1) comments++
    else if (mask[i] !== 2) {
      code++
      if (/[\p{L}\p{N}_$]/u.test(text[i] ?? '')) substantive = true
    }
  }
  return nonblank && (!substantive || comments > code)
}

/** Scan each character once, including nested blocks only where the language allows them. */
function blockEnd(text: string, start: number, [open, close]: readonly [string, string], nested: boolean): number {
  let depth = 1
  let i = start + open.length
  while (i < text.length) {
    if (text.startsWith(close, i)) {
      i += close.length
      if (--depth === 0) return i
    } else if (nested && text.startsWith(open, i)) {
      depth++
      i += open.length
    } else i++
  }
  return text.length
}

function lineEnd(text: string, from: number): number {
  const end = text.indexOf('\n', from)
  return end < 0 ? text.length : end
}

/** End of the string literal opened at `start` (unterminated ones stop at the line end, except backticks). */
function skipString(text: string, start: number): number {
  const delimiter = text[start]
  const multiline = delimiter === '`'
  let i = start + 1
  while (i < text.length) {
    const c = text[i]
    if (c === '\\') i += 2
    else if (c === delimiter) return i + 1
    else if (c === '\n' && !multiline) return i
    else i++
  }
  return text.length
}

/** A triple-quoted string not preceded by an operator that would make it part of an expression. */
function isStatementPosition(text: string, start: number): boolean {
  let i = start - 1
  while (i >= 0 && isWhitespace(text.charCodeAt(i))) i--
  return i < 0 || !'=([{,+%\\'.includes(text[i] ?? '')
}

/** Only blanks or a `#` comment follow `end` on its line. */
function endsStatement(text: string, end: number): boolean {
  let i = end
  while (i < text.length && (text[i] === ' ' || text[i] === '\t' || text[i] === '\r')) i++
  return i >= text.length || text[i] === '\n' || text[i] === '#'
}
