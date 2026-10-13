/**
 * Markdown building blocks for untrusted text. Finding titles, summaries,
 * snippets, and paths come from models and scanned code, so none of them may
 * change the report's structure: no headings, list items, tables, code
 * fences, links, or raw HTML may appear unless this module emits them.
 *
 * `<`, `>`, and entity-looking `&` become HTML entities rather than
 * backslash escapes, because some Markdown renderers do not honor `\<` and
 * would pass the tag through.
 */

/** Bidirectional controls (Trojan Source); shown as visible code points instead. */
const BIDI_RE = /[‪-‮⁦-⁩‎‏؜]/g
/** C0/C1 controls except tab and line feed. */
const CONTROL_RE = /[\u0000-\u0008\u000b-\u001f\u007f-\u009f]/g

function visibleCodePoint(char: string): string {
  return `⟨U+${(char.codePointAt(0) ?? 0).toString(16).toUpperCase().padStart(4, '0')}⟩`
}

/** Normalize newlines, drop control characters, and make bidi controls visible. */
export function sanitizeText(text: string): string {
  return text.replace(/\r\n?/g, '\n').replace(CONTROL_RE, '').replace(BIDI_RE, visibleCodePoint)
}

const WORD_CHAR_RE = /[\p{L}\p{N}]/u

/**
 * Escape characters that can start inline structure. `_` between two word
 * characters (as in `user_id`) cannot open emphasis, so it is left alone to
 * keep identifiers readable.
 */
function escapeInlineChars(text: string): string {
  let out = ''
  for (let index = 0; index < text.length; index++) {
    const char = text[index]!
    switch (char) {
      case '<':
        out += '&lt;'
        break
      case '>':
        out += '&gt;'
        break
      case '&':
        out += /^&(?:#[0-9]{1,7}|#[xX][0-9a-fA-F]{1,6}|[A-Za-z][A-Za-z0-9]{0,31});/.test(text.slice(index, index + 40))
          ? '&amp;'
          : '&'
        break
      case '_': {
        const before = text[index - 1] ?? ''
        const after = text[index + 1] ?? ''
        out += WORD_CHAR_RE.test(before) && WORD_CHAR_RE.test(after) ? '_' : '\\_'
        break
      }
      case '\\':
      case '`':
      case '*':
      case '[':
      case ']':
      case '|':
      case '#':
      case '~':
      case '$':
        out += `\\${char}`
        break
      default:
        out += char
    }
  }
  return out
}

/**
 * Escape a marker that would start a block (list item, ordered list item,
 * setext underline) when it begins a line. Applied after inline escaping.
 */
function escapeLineStart(line: string): string {
  if (/^[-+=]/.test(line)) return `\\${line}`
  return line.replace(/^(\d{1,9})([.)])/, '$1\\$2')
}

/** One line of inline text: whitespace (including newlines) collapsed, every structural character escaped. */
export function inline(text: string): string {
  const flat = sanitizeText(text).replace(/\s+/g, ' ').trim()
  return escapeLineStart(escapeInlineChars(flat))
}

/**
 * Multi-line prose as Markdown paragraphs. Line breaks are kept, blank-line
 * runs collapse to one paragraph break, and each line is escaped and trimmed
 * so indentation cannot create code blocks. Returns `''` for blank input.
 */
export function paragraphs(text: string): string {
  const lines = sanitizeText(text)
    .split('\n')
    .map(line => line.replace(/\s+/g, ' ').trim())
  const out: string[] = []
  for (const line of lines) {
    if (line === '') {
      if (out.length > 0 && out.at(-1) !== '') out.push('')
      continue
    }
    out.push(escapeLineStart(escapeInlineChars(line)))
  }
  while (out.at(-1) === '') out.pop()
  return out.join('\n')
}

function longestBacktickRun(text: string): number {
  let longest = 0
  for (const match of text.matchAll(/`+/g)) longest = Math.max(longest, match[0].length)
  return longest
}

/**
 * An inline code span whose delimiter is longer than any backtick run in the
 * content. Inside a table cell, `|` is escaped as GFM requires. Returns `''`
 * for empty content.
 */
export function codeSpan(text: string, inTable = false): string {
  let content = sanitizeText(text).replace(/\s+/g, ' ')
  if (content.trim() === '') return ''
  if (inTable) content = content.replace(/\|/g, '\\|')
  const fence = '`'.repeat(longestBacktickRun(content) + 1)
  const pad = /^[` ]|[` ]$/.test(content) ? ' ' : ''
  return `${fence}${pad}${content}${pad}${fence}`
}

const LANGUAGE_BY_EXTENSION: Readonly<Record<string, string>> = {
  c: 'c',
  cc: 'cpp',
  cpp: 'cpp',
  cs: 'csharp',
  css: 'css',
  go: 'go',
  h: 'c',
  hpp: 'cpp',
  html: 'html',
  java: 'java',
  js: 'javascript',
  json: 'json',
  jsx: 'jsx',
  kt: 'kotlin',
  mjs: 'javascript',
  cjs: 'javascript',
  php: 'php',
  py: 'python',
  rb: 'ruby',
  rs: 'rust',
  scala: 'scala',
  sh: 'bash',
  sql: 'sql',
  swift: 'swift',
  toml: 'toml',
  ts: 'typescript',
  tsx: 'tsx',
  mts: 'typescript',
  cts: 'typescript',
  vue: 'vue',
  xml: 'xml',
  yaml: 'yaml',
  yml: 'yaml',
}

/** A highlight language for a path, from a fixed allowlist (never untrusted text). */
export function languageForPath(path: string | undefined): string {
  const extension = path === undefined ? undefined : /\.([A-Za-z0-9]+)$/.exec(path)?.[1]?.toLowerCase()
  return extension === undefined ? '' : (LANGUAGE_BY_EXTENSION[extension] ?? '')
}

/**
 * A fenced code block whose fence is longer than any backtick run in the
 * code, so the code cannot close it early. `indent` prefixes every line so the
 * block stays inside a list item.
 */
export function fencedCode(code: string, language = '', indent = ''): string {
  const body = sanitizeText(code).replace(/\n+$/, '')
  const fence = '`'.repeat(Math.max(3, longestBacktickRun(body) + 1))
  const info = /^[a-z0-9+-]*$/.test(language) ? language : ''
  const lines = [`${fence}${info}`, ...body.split('\n'), fence]
  return lines.map(line => (line === '' ? '' : `${indent}${line}`)).join('\n')
}

/** One GFM table row from already-escaped cells. */
export function tableRow(cells: readonly string[]): string {
  return `| ${cells.map(cell => (cell === '' ? ' ' : cell)).join(' | ')} |`
}

/** A GFM table: header, alignment row, body rows. `right` marks numeric columns. */
export function table(
  header: readonly string[],
  rows: readonly (readonly string[])[],
  right: readonly boolean[] = [],
): string {
  const align = header.map((_, index) => (right[index] === true ? '---:' : '---'))
  return [tableRow(header), tableRow(align), ...rows.map(tableRow)].join('\n')
}

/** An autolink for a plain http(s) URL, or escaped text for anything else. */
export function linkOrText(reference: string): string {
  const trimmed = sanitizeText(reference).trim()
  if (/^https?:\/\/[^\s<>"`]+$/i.test(trimmed)) {
    try {
      const url = new URL(trimmed)
      if (url.protocol === 'http:' || url.protocol === 'https:') return `<${trimmed}>`
    } catch {
      // fall through to text
    }
  }
  return inline(trimmed)
}
