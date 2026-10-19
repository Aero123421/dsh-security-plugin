/**
 * Allow-list validation that constrains a value before it reaches a sink, recognized syntactically:
 *
 * - an anchored character-class pattern checked with an early exit:
 *   `if (!/^[\w.-]+$/.test(branch)) return …`, `if not re.fullmatch(r"[\w.-]+", branch): abort(400)`;
 * - the positive form wrapping the sink: `if (/^\d+$/.test(id)) { … }`;
 * - Python digit/letter tests: `if not page.isdigit(): return …`.
 *
 * Guards only say which characters can get through (`Charset`); each rule decides whether that is enough for
 * its sink (a host name made of `[\w.-]` is still an SSRF target, a shell argument is not an injection).
 */

import { stringContent, type Token } from './lexer.ts'
import { type FileModel, type FnFact, fnChain, innermostFn } from './model.ts'

/** What an allow-list lets through. */
export interface Charset {
  /** No whitespace or shell metacharacters (`;&|$\`'"<>(){}*?!#~\\`). */
  readonly shellSafe: boolean
  /** Also no path separators or dots, so the value cannot be `..` or an absolute path. */
  readonly pathSafe: boolean
  /** No path separators (a single path segment, possibly `..`). */
  readonly segmentSafe: boolean
}

export interface Guard {
  /** The tested value as written, whitespace removed (`branch`, `req.query.id`, `request.form["b"]`). */
  readonly subject: string
  readonly fn: FnFact | undefined
  /** Offsets `[from, to)` where the guard holds. */
  readonly from: number
  readonly to: number
  readonly charset: Charset
}

/** Punctuation an allow-list may admit without letting shell syntax through. */
const SHELL_SAFE_PUNCT: ReadonlySet<string> = new Set(['.', '-', '_', ':', '@', '+', ',', '/'])
/** Punctuation that cannot form `..`, an absolute path or a separator. */
const PATH_SAFE_PUNCT: ReadonlySet<string> = new Set(['-', '_', ':', '@', '+', ','])
/** Punctuation that stays within one path segment. */
const SEGMENT_SAFE_PUNCT: ReadonlySet<string> = new Set(['.', '-', '_', ':', '@', '+', ','])

/**
 * The characters an anchored allow-list pattern body admits, or `undefined` when the body is not made only of
 * character classes, `\w`/`\d`, literal characters, groups and quantifiers (alternation, `.`, `\s`, negated
 * classes and anything else give up).
 */
export function patternCharset(body: string): Charset | undefined {
  const punct = new Set<string>()
  let i = 0
  const n = body.length
  if (n === 0) return undefined
  while (i < n) {
    const c = body[i]!
    if (c === '[') {
      if (body[i + 1] === '^') return undefined
      let j = i + 1
      let closed = false
      while (j < n) {
        const d = body[j]!
        if (d === ']' && j > i + 1) {
          closed = true
          break
        }
        if (d === '\\') {
          const e = body[j + 1]
          if (e === 'w' || e === 'd') j += 2
          else if (e !== undefined && /[.\-_:@+,/]/.test(e)) {
            punct.add(e)
            j += 2
          } else return undefined
          continue
        }
        if (/[A-Za-z0-9]/.test(d) && body[j + 1] === '-' && /[A-Za-z0-9]/.test(body[j + 2] ?? '')) {
          const from = d
          const to = body[j + 2]!
          const sameKind =
            (/[a-z]/.test(from) && /[a-z]/.test(to)) ||
            (/[A-Z]/.test(from) && /[A-Z]/.test(to)) ||
            (/[0-9]/.test(from) && /[0-9]/.test(to))
          if (!sameKind || from > to) return undefined
          j += 3
          continue
        }
        if (/[A-Za-z0-9_]/.test(d)) {
          j++
          continue
        }
        if (/[.\-:@+,/]/.test(d)) {
          punct.add(d)
          j++
          continue
        }
        return undefined
      }
      if (!closed) return undefined
      i = j + 1
      continue
    }
    if (c === '\\') {
      const e = body[i + 1]
      if (e === 'w' || e === 'd') i += 2
      else if (e !== undefined && /[.\-_:@+,/]/.test(e)) {
        punct.add(e)
        i += 2
      } else return undefined
      continue
    }
    if (/[A-Za-z0-9_]/.test(c)) {
      i++
      continue
    }
    if (c === '-' || c === ':' || c === '@' || c === ',') {
      punct.add(c)
      i++
      continue
    }
    if (c === '+' || c === '*' || c === '?') {
      // A quantifier, or a lazy/possessive marker: never a literal outside a class.
      if (i === 0) return undefined
      i++
      continue
    }
    if (c === '{') {
      const m = /^\{\d+(?:,\d*)?\}/.exec(body.slice(i))
      if (!m) return undefined
      i += m[0].length
      continue
    }
    if (c === '(') {
      i += body.startsWith('(?:', i) ? 3 : 1
      if (body[i] === '?') return undefined
      continue
    }
    if (c === ')') {
      i++
      continue
    }
    return undefined
  }
  const all = [...punct]
  return {
    shellSafe: all.every(p => SHELL_SAFE_PUNCT.has(p)),
    pathSafe: all.every(p => PATH_SAFE_PUNCT.has(p)),
    segmentSafe: all.every(p => SEGMENT_SAFE_PUNCT.has(p)),
  }
}

/** A JavaScript regex literal (`/^[\w.-]+$/i`) as an allow-list: anchored at both ends, no `m` flag. */
export function jsRegexCharset(literal: string): Charset | undefined {
  const m = /^\/(.*)\/([a-z]*)$/s.exec(literal)
  if (!m || m[2]!.includes('m')) return undefined
  const body = m[1]!
  if (!body.startsWith('^') || !body.endsWith('$') || body.endsWith('\\$')) return undefined
  return patternCharset(body.slice(1, -1))
}

/**
 * A Python pattern string as an allow-list for `fullmatch` (no anchors needed), `match` (anchored at the
 * start; needs `$` or `\Z` at the end) or `search` (needs both anchors).
 */
export function pyPatternCharset(pattern: string, method: string): Charset | undefined {
  let body = pattern
  if (body.startsWith('^')) body = body.slice(1)
  else if (method === 'search') return undefined
  const end = /(?:\$|\\Z)$/.exec(body)
  if (end) body = body.slice(0, -end[0].length)
  else if (method !== 'fullmatch') return undefined
  return patternCharset(body)
}

/** Whitespace-free text of tokens `[a, b)`, with optional chaining normalized. */
export function subjectText(model: FileModel, a: number, b: number): string {
  if (b <= a) return ''
  return model.source
    .slice(model.tokens[a]!.start, model.tokens[b - 1]!.end)
    .replace(/\s+/g, '')
    .replace(/\?\./g, '.')
}

/** Every guard of a file, found in one pass over its tokens. */
export function findGuards(model: FileModel): Guard[] {
  return model.lang === 'py' ? pyGuards(model) : jsGuards(model)
}

/** Whether a guard on `subject` holds at offset `at` (a later reassignment of the subject name ends it). */
export function guardAt(model: FileModel, guards: readonly Guard[], subject: string, at: number): Charset | undefined {
  const scope = new Set<FnFact | undefined>([undefined, ...fnChain(innermostFn(model.fns, at))])
  const root = /^[A-Za-z_$][\w$]*/.exec(subject)?.[0]
  let best: Charset | undefined
  for (const guard of guards) {
    if (guard.from > at || at >= guard.to || !scope.has(guard.fn)) continue
    if (guard.subject !== subject && !subject.startsWith(`${guard.subject}.`)) continue
    if (
      root !== undefined &&
      model.assigns.some(a => a.start >= guard.from && a.start < at && a.targets.some(t => t.name === root))
    )
      continue
    best = best ? anyOf(best, guard.charset) : guard.charset
  }
  return best
}

/** The value passed both checks: whatever either one keeps out stays out. */
export function anyOf(a: Charset, b: Charset): Charset {
  return {
    shellSafe: a.shellSafe || b.shellSafe,
    pathSafe: a.pathSafe || b.pathSafe,
    segmentSafe: a.segmentSafe || b.segmentSafe,
  }
}

/** Two values combined: only what both keep out stays out. */
export function allOf(a: Charset, b: Charset): Charset {
  return {
    shellSafe: a.shellSafe && b.shellSafe,
    pathSafe: a.pathSafe && b.pathSafe,
    segmentSafe: a.segmentSafe && b.segmentSafe,
  }
}

// ---------------------------------------------------------------------------
// JavaScript
// ---------------------------------------------------------------------------

function jsGuards(model: FileModel): Guard[] {
  const { tokens, match } = model
  const out: Guard[] = []
  for (let k = 0; k < tokens.length; k++) {
    const t = tokens[k]!
    if (t.type !== 'ident' || t.value !== 'if' || !isPunct(tokens[k + 1], '(')) continue
    if (isPunct(tokens[k - 1], '.') || tokens[k - 1]?.value === 'else') continue
    const open = k + 1
    const close = match[open]!
    if (close <= open) continue
    const test = jsTest(model, open + 1, close)
    if (!test) continue
    const body = statementRange(model, close + 1)
    if (!body) continue
    const fn = innermostFn(model.fns, t.start)
    if (test.negated) {
      if (!exits(tokens, match, body[0], body[1], ['return', 'throw'])) continue
      out.push({
        subject: test.subject,
        fn,
        from: tokens[body[1] - 1]!.end,
        to: fn ? fn.end : model.source.length,
        charset: test.charset,
      })
    } else {
      out.push({
        subject: test.subject,
        fn,
        from: tokens[body[0]]!.start,
        to: tokens[body[1] - 1]!.end,
        charset: test.charset,
      })
    }
  }
  return out
}

/** `!/re/.test(x)`, `/re/.test(x)`, `!SAFE.test(x)` (a module-level regex constant) inside an `if (…)`. */
function jsTest(
  model: FileModel,
  a: number,
  b: number,
): { negated: boolean; subject: string; charset: Charset } | undefined {
  const { tokens, match } = model
  let k = a
  let negated = false
  while (isPunct(tokens[k], '!')) {
    negated = !negated
    k++
  }
  const head = tokens[k]
  if (!head) return undefined
  let literal: string | undefined
  if (head.type === 'regex') literal = head.value
  else if (head.type === 'ident') {
    const v = model.vars.find(x => x.name === head.value)
    const value = v ? model.source.slice(v.value.start, v.value.end).trim() : ''
    if (/^\/.*\/[a-z]*$/s.test(value)) literal = value
  }
  if (literal === undefined) return undefined
  if (!isPunct(tokens[k + 1], '.') || tokens[k + 2]?.value !== 'test' || !isPunct(tokens[k + 3], '(')) return undefined
  const argOpen = k + 3
  const argClose = match[argOpen]!
  if (argClose !== b - 1 || argClose <= argOpen + 1) return undefined
  const charset = jsRegexCharset(literal)
  if (!charset) return undefined
  return { negated, subject: subjectText(model, argOpen + 1, argClose), charset }
}

/** The statement starting at token `k`: a `{…}` block, or tokens up to `;` or the end of the line. */
function statementRange(model: FileModel, k: number): [number, number] | undefined {
  const { tokens, match } = model
  if (k >= tokens.length) return undefined
  if (isPunct(tokens[k], '{')) {
    const end = match[k]!
    return end > k ? [k, end + 1] : undefined
  }
  let j = k
  while (j < tokens.length) {
    const t = tokens[j]!
    if (j > k && t.nl) break
    if (isPunct(t, ';')) {
      j++
      break
    }
    if (t.type === 'punct' && (t.value === '(' || t.value === '[' || t.value === '{' || t.sub === 'open')) {
      const m = match[j]!
      if (m < 0) return undefined
      j = m + 1
      continue
    }
    if (t.type === 'punct' && (t.value === ')' || t.value === ']' || t.value === '}')) break
    j++
  }
  return j > k ? [k, j] : undefined
}

/** A statement-level `return`/`throw` (or another exit word) inside tokens `[a, b)`, nested blocks excluded. */
function exits(tokens: readonly Token[], match: Int32Array, a: number, b: number, words: readonly string[]): boolean {
  let k = isPunct(tokens[a], '{') ? a + 1 : a
  const end = isPunct(tokens[a], '{') ? b - 1 : b
  let statementStart = true
  for (; k < end; k++) {
    const t = tokens[k]!
    if (t.type === 'punct' && (t.value === '(' || t.value === '[' || t.value === '{' || t.sub === 'open')) {
      const m = match[k]!
      if (m < 0) return false
      k = m
      statementStart = tokens[m + 1]?.nl ?? false
      continue
    }
    if (t.type === 'ident' && statementStart && words.includes(t.value)) return true
    statementStart = isPunct(t, ';') || (tokens[k + 1]?.nl ?? false)
  }
  return false
}

// ---------------------------------------------------------------------------
// Python
// ---------------------------------------------------------------------------

const PY_EXIT_CALLS = /^(?:abort|flask\.abort|sys\.exit|exit)$/

function pyGuards(model: FileModel): Guard[] {
  const { tokens, source } = model
  const out: Guard[] = []
  const compiled = pyCompiledPatterns(model)
  for (let k = 0; k < tokens.length; k++) {
    const t = tokens[k]!
    if (t.type !== 'ident' || t.value !== 'if' || !startsLine(source, t.start)) continue
    const colon = lineColon(model, k + 1)
    if (colon < 0) continue
    const test = pyTest(model, k + 1, colon, compiled)
    if (!test) continue
    const block = pyBlock(model, t.start, colon)
    if (!block) continue
    const fn = innermostFn(model.fns, t.start)
    if (test.negated) {
      if (!pyBlockExits(model, block)) continue
      out.push({ subject: test.subject, fn, from: block.end, to: fn ? fn.end : source.length, charset: test.charset })
    } else {
      out.push({ subject: test.subject, fn, from: block.start, to: block.end, charset: test.charset })
    }
  }
  return out
}

/** `SAFE = re.compile(r"…")` at module level: name → pattern text. */
function pyCompiledPatterns(model: FileModel): Map<string, string> {
  const out = new Map<string, string>()
  for (const v of model.assigns) {
    if (v.fn || v.op !== '=' || v.targets.length !== 1) continue
    const text = model.source.slice(v.value.start, v.value.end).trim()
    const m = /^re\.compile\(\s*([rRbBuU]{0,2}(['"])[\s\S]*\2)\s*(?:,[^)]*)?\)$/.exec(text)
    if (!m) continue
    const pattern = pyStringValue(m[1]!)
    if (pattern !== undefined) out.set(v.targets[0]!.name, pattern)
  }
  return out
}

/** Content of one Python string literal (raw strings as written, others with `\\` collapsed). */
function pyStringValue(literal: string): string | undefined {
  const m = /^([rRbBuU]{0,2})(['"])([\s\S]*)\2$/.exec(literal)
  if (!m) return undefined
  return /r/i.test(m[1]!) ? m[3]! : m[3]!.replace(/\\\\/g, '\\')
}

/**
 * `not re.fullmatch(P, x)`, `re.match(P, x)`, `not SAFE.fullmatch(x)`, `not x.isdigit()` between `a` and the
 * colon `b`.
 */
function pyTest(
  model: FileModel,
  a: number,
  b: number,
  compiled: ReadonlyMap<string, string>,
): { negated: boolean; subject: string; charset: Charset } | undefined {
  const { tokens, match } = model
  let k = a
  let negated = false
  while (tokens[k]?.type === 'ident' && tokens[k]!.value === 'not') {
    negated = !negated
    k++
  }
  const head = tokens[k]
  if (head?.type !== 'ident') return undefined
  // `x.isdigit()` / `x.isalnum()` …: letters and digits only.
  const callOpen = (() => {
    let j = k
    while (isPunct(tokens[j + 1], '.') && tokens[j + 2]?.type === 'ident') j += 2
    return j + 1
  })()
  if (!isPunct(tokens[callOpen], '(')) return undefined
  const close = match[callOpen]!
  if (close !== b - 1) return undefined
  const callee = subjectText(model, k, callOpen)
  const method = /\.(isdigit|isdecimal|isnumeric|isalnum|isalpha|isascii|isidentifier)$/.exec(callee)?.[1]
  if (method) {
    if (close !== callOpen + 1 || method === 'isascii') return undefined
    return {
      negated,
      subject: subjectText(model, k, callOpen - 2),
      charset: { shellSafe: true, pathSafe: true, segmentSafe: true },
    }
  }
  const m = /^(?:re\.|([A-Za-z_]\w*)\.)(fullmatch|match|search)$/.exec(callee)
  if (!m) return undefined
  const args = splitTop(tokens, match, callOpen + 1, close)
  let pattern: string | undefined
  let arg: [number, number] | undefined
  if (m[1] === undefined) {
    if (args.length < 2) return undefined
    const lit = args[0]!
    if (lit[1] - lit[0] !== 1 || tokens[lit[0]]!.type !== 'str' || tokens[lit[0]]!.interp) return undefined
    pattern = pyStringValue(tokens[lit[0]]!.value) ?? stringContent(tokens[lit[0]]!)
    arg = args[1]
  } else {
    pattern = compiled.get(m[1])
    arg = args[0]
  }
  if (pattern === undefined || !arg) return undefined
  const charset = pyPatternCharset(pattern, m[2]!)
  return charset ? { negated, subject: subjectText(model, arg[0], arg[1]), charset } : undefined
}

/** The block after the colon of an `if` line: the rest of that line, or the more-indented lines below. */
function pyBlock(model: FileModel, ifStart: number, colon: number): { start: number; end: number } | undefined {
  const { source, tokens } = model
  const colonTok = tokens[colon]!
  const lineEnd = source.indexOf('\n', colonTok.end)
  const rest = source.slice(colonTok.end, lineEnd < 0 ? source.length : lineEnd)
  if (rest.trim() !== '' && !rest.trim().startsWith('#')) {
    return { start: colonTok.end, end: lineEnd < 0 ? source.length : lineEnd }
  }
  const indent = indentOf(source, ifStart)
  let pos = lineEnd < 0 ? source.length : lineEnd + 1
  const start = pos
  let end = pos
  while (pos < source.length) {
    const next = source.indexOf('\n', pos)
    const line = source.slice(pos, next < 0 ? source.length : next)
    if (line.trim() !== '' && !line.trim().startsWith('#')) {
      if ((/^[ \t]*/.exec(line)?.[0].length ?? 0) <= indent) break
      end = next < 0 ? source.length : next
    }
    pos = next < 0 ? source.length : next + 1
  }
  return end > start ? { start, end } : undefined
}

/** Some statement of the block (at its own indentation) returns, raises or aborts. */
function pyBlockExits(model: FileModel, block: { start: number; end: number }): boolean {
  const text = model.source.slice(block.start, block.end)
  const lines = text.split('\n').filter(line => line.trim() !== '' && !line.trim().startsWith('#'))
  if (lines.length === 0) return false
  const own = Math.min(...lines.map(line => /^[ \t]*/.exec(line)?.[0].length ?? 0))
  return lines.some(line => {
    if ((/^[ \t]*/.exec(line)?.[0].length ?? 0) !== own) return false
    const s = line.trim()
    const call = /^([A-Za-z_][\w.]*)\s*\(/.exec(s)?.[1]
    return /^(?:return|raise)\b/.test(s) || (call !== undefined && PY_EXIT_CALLS.test(call))
  })
}

/** Index of the `:` that ends the header starting at token `k` (depth 0, same logical line), or -1. */
function lineColon(model: FileModel, k: number): number {
  const { tokens, match } = model
  for (let j = k; j < tokens.length; j++) {
    const t = tokens[j]!
    if (j > k && t.nl) return -1
    if (t.type === 'punct' && (t.value === '(' || t.value === '[' || t.value === '{')) {
      const m = match[j]!
      if (m < 0) return -1
      j = m
      continue
    }
    if (isPunct(t, ':')) return j
  }
  return -1
}

function startsLine(source: string, offset: number): boolean {
  const lineStart = source.lastIndexOf('\n', offset - 1) + 1
  return source.slice(lineStart, offset).trim() === ''
}

function indentOf(source: string, offset: number): number {
  const lineStart = source.lastIndexOf('\n', offset - 1) + 1
  return offset - lineStart
}

function splitTop(tokens: readonly Token[], match: Int32Array, a: number, b: number): [number, number][] {
  const out: [number, number][] = []
  let s = a
  for (let k = a; k < b; k++) {
    const t = tokens[k]!
    if (t.type === 'punct' && (t.value === '(' || t.value === '[' || t.value === '{' || t.sub === 'open')) {
      const m = match[k]!
      if (m < 0) break
      k = m
      continue
    }
    if (isPunct(t, ',')) {
      if (k > s) out.push([s, k])
      s = k + 1
    }
  }
  if (b > s) out.push([s, b])
  return out
}

function isPunct(t: Token | undefined, value: string): boolean {
  return t !== undefined && t.type === 'punct' && t.value === value && t.sub === undefined
}
