/**
 * Helpers shared by the JavaScript and Python rule sets: import-aware callee
 * qualification, argument access, object/dict property scanning, comparison
 * scanning, and reporting.
 */

import { stringContent, type Token } from './lexer.ts'
import { type CallFact, type FileModel, type FnFact, innermostFn, type Span } from './model.ts'
import { type Classification, classify, type FileContext, type Hit, type RuleMeta } from './rule.ts'
import { Expr, type Taint } from './taint.ts'

/** Module aliases normalized for matching (`node:fs` → `fs`). */
const JS_MODULE_ALIASES: Readonly<Record<string, string>> = {
  'fs/promises': 'fs.promises',
  'fs-extra': 'fs',
  'graceful-fs': 'fs',
  'node-fetch': 'fetch',
  'cross-fetch': 'fetch',
  'isomorphic-fetch': 'fetch',
  'lodash.merge': 'lodash.merge',
  'lodash.set': 'lodash.set',
  'lodash-es': 'lodash',
  underscore: 'lodash',
  'child-process-promise': 'child_process',
  'node-serialize': 'node-serialize',
  'js-yaml': 'js-yaml',
  'merge-deep': 'merge-deep',
}

/** Rule-set context for one file. */
export class Checker {
  readonly model: FileModel
  readonly ex: Expr
  readonly #ctx: FileContext
  readonly #aliases = new Map<string, string>()

  constructor(model: FileModel, ctx: FileContext) {
    this.model = model
    // Taint follows calls by their imported names too (`join` from `node:path` is `path.join`).
    this.ex = new Expr(model, {
      qualify: callee => this.qualify(callee),
      ...(ctx.scalarParams ? { scalarParams: ctx.scalarParams } : {}),
    })
    this.#ctx = ctx
    this.#buildAliases()
  }

  get path(): string {
    return this.#ctx.file.path
  }

  /** Canonical callee: the first segment is mapped through the file's imports. */
  qualify(callee: string): string {
    let c = callee
    if (this.model.lang === 'js') {
      c = c.replace(/^require\((['"`])([^'"`]+)\1\)/, (_m, _q, mod: string) => canonicalJsModule(mod))
      c = c.replace(/^await(?=[A-Za-z_$])/, '')
    }
    const first = /^[A-Za-z_$][\w$]*/.exec(c)?.[0]
    if (first) {
      const mapped = this.#aliases.get(first)
      if (mapped !== undefined) c = mapped + c.slice(first.length)
    }
    return c
  }

  /** Whether `local` is bound by an import of a module matching `module`. */
  importedFrom(local: string, module: RegExp): boolean {
    const mapped = this.#aliases.get(local)
    return mapped !== undefined && module.test(mapped)
  }

  /** Whether any import source matches. */
  imports(module: RegExp): boolean {
    return this.model.imports.some(imp => module.test(imp.source))
  }

  text(span: Span): string {
    return this.model.source.slice(span.start, span.end)
  }

  /** Positional argument `index` (keyword and splat arguments excluded). */
  positional(call: CallFact, index: number): Span | undefined {
    let i = 0
    for (const arg of call.args) {
      if (arg.keyword || arg.splat) continue
      if (i === index) return arg
      i++
    }
    return undefined
  }

  /** Python keyword argument value. */
  keyword(call: CallFact, name: string): Span | undefined {
    return call.args.find(arg => arg.keyword === name)
  }

  /** Values the span may hold: the span itself, or an identifier's visible assignments. */
  values(span: Span): Span[] {
    return this.ex.resolve(span, span.start)
  }

  /** Whether the expression builds a string, looking through one level of identifier assignment. */
  built(span: Span): boolean {
    return this.values(span).some(v => this.ex.isStringBuilt(v))
  }

  /** Not a compile-time constant (looking through identifiers). */
  dynamic(span: Span): boolean {
    return !this.ex.isConstant(span)
  }

  taint(span: Span): Taint | undefined {
    return this.ex.taint(span)
  }

  /** First taint among several spans. */
  taintAny(spans: readonly (Span | undefined)[]): Taint | undefined {
    for (const span of spans) {
      if (!span) continue
      const t = this.ex.taint(span)
      if (t) return t
    }
    return undefined
  }

  /** `high` when `span` spells out the request body itself, `medium` when it holds it through a local alias. */
  wholeBodyConfidence(span: Span, whole: string): 'high' | 'medium' {
    const text = this.text(span)
      .replace(/\s+/g, '')
      .replace(/^await/, '')
    return text === whole || text.replace(/\(\)$/, '') === whole.replace(/\(\)$/, '') ? 'high' : 'medium'
  }

  /** Innermost function containing the offset. */
  fnAt(offset: number): FnFact | undefined {
    return innermostFn(this.model.fns, offset)
  }

  /** Text of the innermost enclosing function, or ±`lines` lines around the offset at module level. */
  scopeText(offset: number, lines = 3): string {
    const fn = this.fnAt(offset)
    if (fn) return this.model.source.slice(fn.start, fn.end)
    const src = this.model.source
    let a = offset
    for (let i = 0; i <= lines && a > 0; i++) a = src.lastIndexOf('\n', a - 1)
    let b = offset
    for (let i = 0; i <= lines && b >= 0 && b < src.length; i++) b = src.indexOf('\n', b + 1)
    return src.slice(Math.max(0, a), b < 0 ? src.length : b)
  }

  /**
   * Source text of the statement around `span`: its own line(s) plus
   * following lines that continue a method chain (start with `.`).
   */
  statementText(span: Span): string {
    const src = this.model.source
    const a = src.lastIndexOf('\n', span.start - 1) + 1
    let b = src.indexOf('\n', span.end)
    while (b >= 0) {
      const next = src.indexOf('\n', b + 1)
      const line = src.slice(b + 1, next < 0 ? src.length : next)
      if (!/^\s*\??\./.test(line)) break
      b = next
    }
    return src.slice(a, b < 0 ? src.length : b)
  }

  /**
   * Source text saying what a digest computed at `span` is for: its statement, the later lines of the same
   * function that use a variable it is assigned to (`const h = createHash('md5')` … `h.update(pw)`;
   * `digest = sha1(…)` … `return digest == user.password_hash`), and the function's name when the function
   * returns the digest and its name says it hashes or checks something (`def hash_password(raw): return md5(…)`).
   */
  digestUsage(span: Span): string {
    const src = this.model.source
    const fn = this.fnAt(span.start)
    const parts = [this.statementText(span)]
    let returned = fn !== undefined && this.#resultStart(fn, span.start) === span.start
    const end = fn?.end ?? src.length
    for (const assign of this.model.assigns) {
      if (assign.fn !== fn || assign.value.start > span.start || span.end > assign.value.end) continue
      for (const { name } of assign.targets) {
        if (!/^[A-Za-z_$][\w$]*$/.test(name)) continue
        const word = new RegExp(`(?<![\\w$.])${name.replace(/\$/g, '\\$')}(?![\\w$])`)
        let lineStart = src.indexOf('\n', assign.end) + 1
        for (let n = 0; lineStart > 0 && lineStart < end && n < 40; n++) {
          const next = src.indexOf('\n', lineStart)
          const line = src.slice(lineStart, next < 0 ? end : Math.min(next, end))
          const use = word.exec(line)
          if (use) {
            parts.push(line)
            const at = lineStart + use.index
            if (fn && !returned) returned = this.#resultStart(fn, at) === at
          }
          lineStart = next + 1
        }
      }
    }
    if (returned && fn?.name && identifierWords(fn.name).some(w => HASHING_WORDS.has(w))) parts.push(fn.name)
    return parts.join('\n')
  }

  /**
   * Name of the function whose result a value at `span` is part of: the innermost enclosing function when it
   * has a name; through anonymous callbacks, the nearest named function when each callback returns the value
   * and the outermost one is in that function's `return`
   * (`function newApiKey() { return [...Array(32)].map(() => hex(Math.random())).join('') }`).
   */
  resultFnName(span: Span): string | undefined {
    let fn = this.fnAt(span.start)
    if (fn?.name) return fn.name
    let offset = span.start
    while (fn && !fn.name) {
      if (this.#resultStart(fn, offset) === undefined) return undefined
      offset = fn.start
      fn = fn.parent
    }
    return fn && this.#resultStart(fn, offset) !== undefined ? fn.name : undefined
  }

  /** The call at `span` is compared or offset (`Math.random() < 0.5`, `random() - 0.5`): a coin flip or a shuffle. */
  usedAsNumber(span: Span): boolean {
    const { tokens } = this.model
    const [a, b] = this.ex.range(span)
    const isOp = (t: Token | undefined, ops: readonly string[]) => t?.type === 'punct' && ops.includes(t.value)
    return isOp(tokens[b], ['<', '>', '<=', '>=', '-']) || isOp(tokens[a - 1], ['<', '>', '<=', '>='])
  }

  /**
   * Where the value `fn` returns starts, when `offset` lies in it: the body of an expression-bodied arrow, or
   * the expression of the `return` statement holding `offset` (`if (ok) return …` included).
   */
  #resultStart(fn: FnFact, offset: number): number | undefined {
    if (offset < fn.body.start || offset >= fn.body.end) return undefined
    const { tokens, match } = this.model
    const first = tokenIndexAt(tokens, fn.body.start)
    const open = tokens[first]
    if (!open) return undefined
    let ret: number
    if (this.model.lang === 'py') ret = this.#returnAt(first, tokenIndexAt(tokens, fn.body.end), offset)
    else if (open.type !== 'punct' || open.value !== '{') return open.start
    else ret = this.#returnAt(first + 1, match[first]! > first ? match[first]! : tokens.length, offset)
    if (ret < 0) return undefined
    let k = ret + 1
    while (tokens[k] && (tokens[k]!.value === 'await' || tokens[k]!.value === '(') && tokens[k]!.start < offset) k++
    return tokens[k]?.start
  }

  /** Token index of the `return` keyword of the statement holding `offset` among tokens `[from, to)`, else -1. */
  #returnAt(from: number, to: number, offset: number): number {
    const { tokens, match } = this.model
    const js = this.model.lang === 'js'
    let ret = -1
    let prev: Token | undefined
    for (let k = from; k < to; k++) {
      const t = tokens[k]!
      if (t.start > offset) break
      if (prev && ((prev.type === 'punct' && prev.value === ';') || (t.nl && (!js || jsStatementBreak(prev, t))))) {
        ret = -1
      }
      if (t.type === 'ident' && t.value === 'return' && !(prev?.type === 'punct' && prev.value === '.')) ret = k
      const close = t.type === 'punct' && (t.value === '(' || t.value === '[' || t.value === '{') ? match[k]! : -1
      if (close > k) {
        // Inside this bracket pair: a JS block holds statements of its own.
        if (offset < tokens[close]!.end)
          return js && t.value === '{' && opensBlock(prev) ? this.#returnAt(k + 1, close, offset) : ret
        prev = tokens[close]
        k = close
        continue
      }
      if (offset < t.end) break
      prev = t
    }
    return ret
  }

  /** Report a classified match. */
  report(rule: RuleMeta, span: Span, cls: Classification, extra: Partial<Omit<Hit, 'rule' | 'span'>> = {}): void {
    const note = [cls.note, extra.note].filter(Boolean).join(' ')
    this.#ctx.report({
      rule,
      span,
      kind: extra.kind ?? cls.kind,
      confidence: extra.confidence ?? cls.confidence,
      ...(cls.taint ? { taint: cls.taint } : {}),
      ...(extra.severity ? { severity: extra.severity } : {}),
      ...(note ? { note } : {}),
      ...(extra.mask ? { mask: extra.mask } : {}),
      ...(extra.metadata ? { metadata: extra.metadata } : {}),
    })
  }

  /** Classify by taint/dynamism and report when relevant. */
  check(
    rule: RuleMeta,
    span: Span,
    taint: Taint | undefined,
    dynamic: boolean,
    extra: Partial<Omit<Hit, 'rule' | 'span'>> = {},
  ): void {
    const cls = classify(rule, taint, dynamic)
    if (cls) this.report(rule, span, cls, extra)
  }

  /** Report a certain (non-taint) issue. */
  certain(
    rule: RuleMeta,
    span: Span,
    confidence: Hit['confidence'],
    extra: Partial<Omit<Hit, 'rule' | 'span'>> = {},
  ): void {
    this.report(rule, span, { kind: 'vulnerability', confidence }, extra)
  }

  /**
   * Object-literal (JS) or dict-literal (Python) properties whose key is in
   * `keys`, anywhere in the file. Values end at the next depth-0 `,` or the
   * closing brace.
   */
  *props(keys: ReadonlySet<string>): Generator<PropMatch> {
    const { tokens, match } = this.model
    for (let k = 1; k < tokens.length - 2; k++) {
      const t = tokens[k]!
      if (t.type !== 'ident' && t.type !== 'str') continue
      if (t.type === 'str' && t.interp) continue
      const key = t.type === 'str' ? stringContent(t) : t.value
      if (!keys.has(key)) continue
      const colon = tokens[k + 1]!
      if (colon.type !== 'punct' || colon.value !== ':' || colon.sub !== undefined) continue
      const prev = tokens[k - 1]!
      if (!(prev.type === 'punct' && (prev.value === '{' || prev.value === ',') && prev.sub === undefined)) continue
      const end = valueEnd(tokens, match, k + 2)
      if (end <= k + 2) continue
      yield {
        key,
        keySpan: { start: t.start, end: t.end },
        value: { start: tokens[k + 2]!.start, end: tokens[end - 1]!.end },
        span: { start: t.start, end: tokens[end - 1]!.end },
        objectStart: objectOpen(tokens, match, k - 1),
      }
    }
  }

  /** Equality comparisons `a == 'lit'` / `'lit' === a` with one side a plain string literal. */
  *literalComparisons(): Generator<Comparison> {
    const { tokens, match } = this.model
    const ops = this.model.lang === 'py' ? PY_EQ : JS_EQ
    for (let k = 1; k < tokens.length - 1; k++) {
      const t = tokens[k]!
      if (t.type !== 'punct' || !ops.has(t.value)) continue
      const right = tokens[k + 1]!
      const left = tokens[k - 1]!
      let lit: Token | undefined
      let other: Span | undefined
      let otherStart = -1
      if (right.type === 'str' && !right.interp && !continuesAfter(tokens, k + 2)) {
        const s = chainStartIndex(tokens, match, k - 1, this.model.lang)
        if (s < 0) continue
        lit = right
        otherStart = s
        other = { start: tokens[s]!.start, end: left.end }
      } else if (left.type === 'str' && !left.interp && !continuesBefore(tokens, k - 2)) {
        const e = chainEndIndex(tokens, match, k + 1, this.model.lang)
        if (e <= k + 1) continue
        lit = left
        other = { start: right.start, end: tokens[e - 1]!.end }
        otherStart = k + 1
      }
      if (!lit || !other) continue
      const before = tokens[otherStart - 1]
      if (before?.type === 'ident' && (before.value === 'typeof' || before.value === 'type')) continue
      yield {
        literal: stringContent(lit),
        literalSpan: { start: lit.start, end: lit.end },
        other,
        span: { start: Math.min(lit.start, other.start), end: Math.max(lit.end, other.end) },
      }
    }
  }

  /**
   * Names describing what a value at `span` is used for: assignment targets
   * containing it, the property/keyword it is assigned to, and the
   * enclosing function's name.
   */
  contextNames(span: Span): string[] {
    const names: string[] = []
    for (const assign of this.model.assigns) {
      if (assign.value.start <= span.start && span.end <= assign.value.end) {
        for (const target of assign.targets) names.push(target.name)
      }
    }
    for (const assign of this.model.memberAssigns) {
      if (assign.value.start <= span.start && span.end <= assign.value.end) names.push(assign.prop || assign.target)
    }
    const { tokens, match } = this.model
    let k = tokenIndexAt(tokens, span.start) - 1
    // Walk back over the enclosing expression to a `key:` or `kw=` label.
    for (let guard = 0; guard < 24 && k > 0; guard++, k--) {
      const t = tokens[k]!
      if (t.type === 'punct' && (t.value === ')' || t.value === ']' || t.value === '}')) {
        const m = match[k]!
        if (m < 0) break
        k = m
        continue
      }
      if (t.type === 'punct' && (t.value === ':' || t.value === '=') && t.sub === undefined) {
        const key = tokens[k - 1]
        if (key && (key.type === 'ident' || key.type === 'str'))
          names.push(key.type === 'str' ? stringContent(key) : key.value)
        break
      }
      if (t.type === 'punct' && (t.value === ',' || t.value === ';' || t.value === '{' || t.value === '(')) break
    }
    const fn = this.resultFnName(span)
    if (fn) names.push(fn)
    return names
  }

  #buildAliases(): void {
    for (const imp of this.model.imports) {
      if (this.model.lang === 'js') {
        const mod = canonicalJsModule(imp.source)
        for (const b of imp.bindings) {
          this.#aliases.set(b.local, b.imported === '*' || b.imported === 'default' ? mod : `${mod}.${b.imported}`)
        }
      } else {
        if (imp.source.startsWith('.')) continue
        for (const b of imp.bindings) {
          if (b.local === '*') continue
          if (imp.kind === 'import') {
            const top = imp.source.split('.')[0]!
            // `import os.path` binds `os`; `import os.path as p` binds `p` to `os.path`.
            this.#aliases.set(b.local, b.local === top && imp.source !== top ? top : imp.source)
          } else {
            this.#aliases.set(b.local, `${imp.source}.${b.imported}`)
          }
        }
      }
    }
    // `const exec = util.promisify(cp.exec)` / `promisify(require('child_process').exec)`
    if (this.model.lang === 'js') {
      for (const v of this.model.vars) {
        const text = this.model.source.slice(v.value.start, v.value.end).replace(/\s+/g, '')
        const m = /^(?:util\.)?promisify\(([^()]*(?:\([^()]*\))?[^()]*)\)$/.exec(text)
        if (m?.[1]) this.#aliases.set(v.name, this.qualify(m[1]))
      }
    }
  }
}

export interface PropMatch {
  readonly key: string
  readonly keySpan: Span
  readonly value: Span
  /** The whole `key: value` entry. */
  readonly span: Span
  /** Offset of the `{` opening the containing object, or -1. */
  readonly objectStart: number
}

export interface Comparison {
  readonly literal: string
  readonly literalSpan: Span
  readonly other: Span
  readonly span: Span
}

const JS_EQ: ReadonlySet<string> = new Set(['===', '==', '!==', '!='])
const PY_EQ: ReadonlySet<string> = new Set(['==', '!='])

/** Normalize a JS module specifier for matching. */
export function canonicalJsModule(source: string): string {
  const bare = source.replace(/^node:/, '')
  return JS_MODULE_ALIASES[bare] ?? bare
}

/** Last member name of a dotted chain (`headers` in `req.headers`), ignoring trailing calls/indexes. */
export function lastName(chain: string): string {
  const cleaned = chain.replace(/(?:\(\)|\[\])+$/, '')
  const m = /([A-Za-z_$][\w$]*)$/.exec(cleaned)
  return m?.[1] ?? ''
}

/** First identifier of a chain. */
export function rootName(chain: string): string {
  return /^[A-Za-z_$][\w$]*/.exec(chain)?.[0] ?? ''
}

/** Function-name words for computing or checking a digest (`hashPassword`, `verify_password`, `passwordDigest`). */
const HASHING_WORDS: ReadonlySet<string> = new Set([
  'hash',
  'hashed',
  'hashing',
  'digest',
  'crypt',
  'encrypt',
  'encode',
  'verify',
  'check',
  'compare',
  'match',
  'matches',
])

/** Words after which a JavaScript line break does not end the statement (`return\n  value`, `a\n  instanceof B`). */
const JS_JOINING_WORDS: ReadonlySet<string> = new Set([
  'return',
  'throw',
  'typeof',
  'new',
  'await',
  'yield',
  'void',
  'delete',
  'case',
  'do',
  'else',
  'in',
  'of',
  'instanceof',
  'as',
  'satisfies',
])

/** Whether the line break before `t` ends the JavaScript statement that `prev` belongs to (automatic semicolons, roughly). */
function jsStatementBreak(prev: Token, t: Token): boolean {
  const ends =
    prev.type === 'num' ||
    prev.type === 'regex' ||
    (prev.type === 'str' && (prev.part === undefined || prev.part === 'tail')) ||
    (prev.type === 'ident' && !JS_JOINING_WORDS.has(prev.value)) ||
    (prev.type === 'punct' && [')', ']', '}', '++', '--'].includes(prev.value))
  const starts =
    t.type === 'num' ||
    t.type === 'regex' ||
    t.type === 'str' ||
    (t.type === 'ident' &&
      !['in', 'of', 'instanceof', 'as', 'satisfies', 'else', 'catch', 'finally'].includes(t.value)) ||
    (t.type === 'punct' && ['!', '~', '++', '--'].includes(t.value))
  return ends && starts
}

/** Whether a `{` after `prev` opens a block statement rather than an object literal. */
function opensBlock(prev: Token | undefined): boolean {
  if (!prev) return true
  if (prev.type === 'punct') return [')', ';', '{', '}'].includes(prev.value)
  return prev.type === 'ident' && ['else', 'try', 'finally', 'do'].includes(prev.value)
}

function tokenIndexAt(tokens: readonly Token[], offset: number): number {
  let lo = 0
  let hi = tokens.length
  while (lo < hi) {
    const mid = (lo + hi) >>> 1
    if (tokens[mid]!.start < offset) lo = mid + 1
    else hi = mid
  }
  return lo
}

/** Exclusive end of a value starting at `from`: the next depth-0 `,`, `;` or unmatched closer. */
function valueEnd(tokens: readonly Token[], match: Int32Array, from: number): number {
  let k = from
  while (k < tokens.length) {
    const t = tokens[k]!
    if (t.type === 'punct') {
      if (t.sub === 'open' || t.value === '(' || t.value === '[' || t.value === '{') {
        const m = match[k]!
        if (m < 0) return k
        k = m + 1
        continue
      }
      if (
        t.sub === 'close' ||
        t.value === ')' ||
        t.value === ']' ||
        t.value === '}' ||
        t.value === ',' ||
        t.value === ';'
      ) {
        return k
      }
    }
    k++
  }
  return k
}

function objectOpen(tokens: readonly Token[], match: Int32Array, from: number): number {
  for (let k = from; k >= 0; k--) {
    const t = tokens[k]!
    if (t.type !== 'punct') continue
    if (t.value === ')' || t.value === ']' || (t.value === '}' && t.sub === undefined)) {
      const m = match[k]!
      if (m < 0) return -1
      k = m
      continue
    }
    if (t.value === '{' && t.sub === undefined) return t.start
    if (t.value === '(' || t.value === '[') return -1
  }
  return -1
}

/** Start index of the member/call chain ending at token `end`, or -1 when `end` does not end a chain. */
export function chainStartIndex(tokens: readonly Token[], match: Int32Array, end: number, lang: 'js' | 'py'): number {
  let cur = end
  const isP = (i: number, v: string): boolean => {
    const t = tokens[i]
    return t !== undefined && t.type === 'punct' && t.value === v && t.sub === undefined
  }
  const first = tokens[cur]
  if (!first || !(first.type === 'ident' || isP(cur, ')') || isP(cur, ']'))) return -1
  for (let guard = 0; guard < 64; guard++) {
    const t = tokens[cur]
    if (!t) return -1
    if (t.type === 'punct' && (t.value === ')' || t.value === ']')) {
      const m = match[cur]!
      if (m <= 0) return -1
      const before = tokens[m - 1]
      if (before && (before.type === 'ident' || isP(m - 1, ')') || isP(m - 1, ']'))) {
        cur = m - 1
        continue
      }
      if (lang === 'js' && isP(m - 1, '?.')) {
        cur = m - 2
        continue
      }
      return m
    }
    if (t.type === 'ident' && (isP(cur - 1, '.') || (lang === 'js' && isP(cur - 1, '?.')))) {
      cur -= 2
      continue
    }
    return t.type === 'ident' ? cur : -1
  }
  return cur
}

/** Exclusive end index of the member/call chain starting at identifier token `start`. */
function chainEndIndex(tokens: readonly Token[], match: Int32Array, start: number, lang: 'js' | 'py'): number {
  const t = tokens[start]
  if (t?.type !== 'ident') return start
  let k = start + 1
  const isP = (i: number, v: string): boolean => {
    const u = tokens[i]
    return u !== undefined && u.type === 'punct' && u.value === v && u.sub === undefined
  }
  for (let guard = 0; guard < 64 && k < tokens.length; guard++) {
    if ((isP(k, '.') || (lang === 'js' && isP(k, '?.'))) && tokens[k + 1]?.type === 'ident') {
      k += 2
      continue
    }
    if (isP(k, '(') || isP(k, '[')) {
      const m = match[k]!
      if (m < 0) return k
      k = m + 1
      continue
    }
    break
  }
  return k
}

/** The comparison's literal operand is followed by more expression (`'a' + b`). */
function continuesAfter(tokens: readonly Token[], k: number): boolean {
  const t = tokens[k]
  return (
    t !== undefined && t.type === 'punct' && ['+', '.', '[', '(', '%', '*'].includes(t.value) && t.sub === undefined
  )
}

function continuesBefore(tokens: readonly Token[], k: number): boolean {
  const t = tokens[k]
  return t !== undefined && t.type === 'punct' && ['+', '%', '*'].includes(t.value)
}

const CREDENTIAL_NAME =
  /^(?:pass(?:word|wd|phrase)?|pwd|secret|token|api_?key|apikey|auth_?token|access_?token|master_?(?:key|password|pass)|admin_?(?:pass(?:word)?|key|token|secret|code)|backdoor|magic_?(?:word|key))$|(?:password|passwd|passphrase|secret|apikey|api_key|authtoken|auth_token|accesstoken|access_token|adminkey|admin_key)$/i
const SECRET_HEADER = /admin|key|token|secret|auth|pass|debug|bypass|internal|backdoor|master/i
const NOT_A_SECRET =
  /^(?:|undefined|null|none|nil|true|false|string|object|number|bearer|basic|digest|jwt|refresh|access|id_token|access_token|refresh_token|password|passwd|token|secret|admin|guest|anonymous|test|production|development|dev|prod|local|staging|on|off|yes|no|0|1|\*+|x{3,}|changeme|change[_-]?me|replace[_-]?me|default|example|placeholder|dummy|sample|todo|empty|unset|n\/a|hidden|redacted|masked)$/i

/**
 * Whether a literal comparison looks like a hard-coded credential or
 * backdoor check (`password === 'hunter2'`, `req.headers['x-admin'] === 'k'`).
 */
export function isCredentialComparison(chk: Checker, cmp: Comparison): boolean {
  if (cmp.literal.trim() === '' || /^\$\{|^%|^<.*>$|^\{\{/.test(cmp.literal)) return false
  const text = chk.text(cmp.other).replace(/\s+/g, '')
  // Header access: req.headers['x-admin'], req.get('X-Api-Key'), request.headers.get('x-token')
  const header =
    /(?:headers|META)\s*\[\s*['"]([^'"]+)['"]\s*\]$/.exec(text) ??
    /(?:\.get|\.header|headers\.get|\.getHeader)\(\s*['"]([^'"]+)['"]\s*\)$/.exec(text) ??
    /headers\.([A-Za-z_$][\w$-]*)$/.exec(text)
  if (header?.[1] && /(?:headers|META|header|getHeader|\.get\(['"]x-)/i.test(text)) {
    const name = header[1]
    if (/^(?:content-type|accept|user-agent|origin|host|referer|x-requested-with|x-forwarded-proto)$/i.test(name)) {
      return false
    }
    // Any fixed value in a client-controlled header is a key anyone can send.
    return SECRET_HEADER.test(name) && !/^(?:bearer|basic|digest)$/i.test(cmp.literal.trim())
  }
  if (cmp.literal.length < 3 || NOT_A_SECRET.test(cmp.literal.trim())) return false
  // `form['password']`, `request.POST.get('password')`
  const key = /\[\s*['"]([^'"]+)['"]\s*\]$/.exec(text)?.[1] ?? /\.get\(\s*['"]([^'"]+)['"]\s*\)$/.exec(text)?.[1]
  if (key !== undefined) return CREDENTIAL_NAME.test(key)
  const name = lastName(text)
  return name !== '' && CREDENTIAL_NAME.test(name)
}

/** Single words that clearly mark a security-sensitive random value. */
const STRONG_SECRET_WORDS: ReadonlySet<string> = new Set([
  'token',
  'tokens',
  'secret',
  'secrets',
  'password',
  'passwords',
  'passwd',
  'pwd',
  'passphrase',
  'otp',
  'totp',
  'hotp',
  'nonce',
  'salt',
  'csrf',
  'xsrf',
  'apikey',
  'sessionid',
  'sessid',
  'sid',
  'jti',
])
/** Word pairs that mark one (`resetCode`, `api_key`, `session_id`). */
const STRONG_SECRET_PAIRS: readonly (readonly [RegExp, RegExp])[] = [
  [/^api$/, /^key$/],
  [/^session$/, /^id$/],
  [
    /^(?:auth|verification|verify|confirmation|invite|invitation|reset|recovery|activation|otp|mfa|sms|login)$/,
    /^(?:code|key|link|pin)$/,
  ],
  [/^magic$/, /^link$/],
  [/^one$/, /^time$/],
  [/^(?:access|private|signing|encryption|secret|master)$/, /^key$/],
]
/** Single words that may mark one; reported as a lower-confidence sink. */
const WEAK_SECRET_WORDS: ReadonlySet<string> = new Set(['key', 'session', 'code', 'pin', 'uuid', 'guid'])
/** Qualifiers that make a weak word clearly non-secret (`cacheKey`, `sortKey`, `colorCode`). */
const NON_SECRET_QUALIFIERS: ReadonlySet<string> = new Set([
  'cache',
  'sort',
  'shuffle',
  'dict',
  'map',
  'lookup',
  'hot',
  'primary',
  'foreign',
  'list',
  'row',
  'item',
  'partition',
  'group',
  'bucket',
  'shard',
  'storage',
  'local',
  'query',
  'react',
  'render',
  'index',
  'color',
  'colour',
  'country',
  'language',
  'lang',
  'locale',
  'zip',
  'postal',
  'area',
  'status',
  'error',
  'exit',
  'char',
  'key',
  'source',
  'qr',
  'bar',
])

/** Lower-case words of an identifier: `resetToken` → `reset token`, `API_KEY` → `api key`. */
export function identifierWords(name: string): string[] {
  return name
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .replace(/([A-Z]+)([A-Z][a-z])/g, '$1 $2')
    .split(/[^A-Za-z0-9]+/)
    .filter(Boolean)
    .map(word => word.toLowerCase())
}

/**
 * Classify identifier names around a random value by whole words, so
 * `resetToken` is strong, `sessionKey` weak, and `keyframes`/`monkey` nothing.
 */
export function secretContext(names: readonly string[]): 'strong' | 'weak' | undefined {
  let weak = false
  for (const name of names) {
    const words = identifierWords(name)
    if (words.some(w => STRONG_SECRET_WORDS.has(w))) return 'strong'
    for (let i = 0; i + 1 < words.length; i++) {
      if (STRONG_SECRET_PAIRS.some(([a, b]) => a.test(words[i]!) && b.test(words[i + 1]!))) return 'strong'
    }
    for (let i = 0; i < words.length; i++) {
      if (!WEAK_SECRET_WORDS.has(words[i]!)) continue
      const qualifier = i > 0 ? words[i - 1]! : undefined
      if (qualifier === undefined || !NON_SECRET_QUALIFIERS.has(qualifier)) weak = true
    }
  }
  return weak ? 'weak' : undefined
}

/** A call to something that looks like a sanitizer/escaper (`DOMPurify.sanitize`, `escape`, `bleach.clean`). */
export function isSanitizerCall(chk: Checker, span: Span): boolean {
  const text = chk.text(span).trim()
  return /^(?:[\w$.]+\.)?(?:sanitize\w*|purify|escape\w*|encode\w*|xss|filterXSS|clean|strip_?tags|bleach\.\w+|DOMPurify\.\w+)\s*\(/i.test(
    text,
  )
}
