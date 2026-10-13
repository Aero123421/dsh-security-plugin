/**
 * Builds the code model for JavaScript/TypeScript (JSX/TSX included), either
 * from the native AST (precise spans) or from the token stream (fallback).
 * Details that do not depend on the mode (parameter lists, destructuring
 * patterns, `require` bindings, CommonJS exports) are parsed from tokens in
 * both modes so the two paths stay consistent.
 */

import { findAllKinds, type SgNode } from '../astgrep.ts'
import { JS_KEYWORDS, lexJs, lineStarts, matchBrackets, stringContent, type Token, tokenAt } from './lexer.ts'
import {
  type ArgFact,
  type AssignTarget,
  type CallFact,
  type ClassFact,
  type DecoratorFact,
  type FileModel,
  type FnFact,
  finalizeFacts,
  type ImportBinding,
  normalizeCallee,
  type ParamFact,
  type RawFacts,
  type Span,
  splitCallee,
} from './model.ts'

const EOF: Token = { type: 'punct', value: '', start: 0, end: 0, nl: true }

const CALL_EXCLUDE: ReadonlySet<string> = new Set([
  'if',
  'for',
  'while',
  'switch',
  'catch',
  'with',
  'function',
  'return',
  'typeof',
  'void',
  'delete',
  'await',
  'yield',
  'in',
  'of',
  'instanceof',
  'case',
  'do',
  'else',
  'throw',
  'class',
  'new',
  'const',
  'let',
  'var',
  'export',
  'default',
  'extends',
  'satisfies',
  'as',
  'keyof',
  'is',
])

const METHOD_MODIFIERS: ReadonlySet<string> = new Set([
  'async',
  'static',
  'get',
  'set',
  'public',
  'private',
  'protected',
  'readonly',
  'override',
  'abstract',
  'declare',
  'accessor',
])

const PARAM_MODIFIERS: ReadonlySet<string> = new Set(['public', 'private', 'protected', 'readonly', 'override'])

/** Operators after which a line break never ends an expression. */
const CONTINUING_PUNCT: ReadonlySet<string> = new Set([
  '.',
  '?.',
  '?',
  ':',
  '=>',
  '=',
  '+',
  '-',
  '*',
  '/',
  '%',
  '**',
  '&&',
  '||',
  '??',
  '==',
  '===',
  '!=',
  '!==',
  '<',
  '>',
  '<=',
  '>=',
  '&',
  '|',
  '^',
  '<<',
  '>>',
  '>>>',
  ',',
  '(',
  '[',
  '{',
  '!',
  '~',
  '+=',
  '-=',
  '*=',
  '/=',
  '...',
])

/** Tokens that, at the start of a line, continue the previous expression. */
const LEADING_CONTINUATION: ReadonlySet<string> = new Set([
  '.',
  '?.',
  '?',
  ':',
  '=>',
  '&&',
  '||',
  '??',
  '==',
  '===',
  '!=',
  '!==',
  '*',
  '/',
  '%',
  '**',
  '|',
  '&',
  '^',
  '<=',
  '>=',
  ',',
  ')',
  ']',
  '}',
])

const ASSIGN_OPS: ReadonlySet<string> = new Set([
  '=',
  '+=',
  '-=',
  '*=',
  '/=',
  '%=',
  '**=',
  '<<=',
  '>>=',
  '>>>=',
  '&=',
  '|=',
  '^=',
  '&&=',
  '||=',
  '??=',
])

/** Build the model for a JS/TS file. `astRoot` selects AST mode. */
export function buildJsModel(path: string, source: string, astRoot?: SgNode, astLang?: string): FileModel {
  let lexSource = source
  if (astRoot && astLang) {
    // JSX text is prose, not code: blank it so apostrophes cannot open strings.
    const texts = findAllKinds(astRoot, astLang, ['jsx_text'])
    if (texts.length > 0) {
      const chars = source.split('')
      for (const node of texts) {
        const r = node.range()
        for (let i = r.start.index; i < r.end.index; i++) if (chars[i] !== '\n' && chars[i] !== '\r') chars[i] = ' '
      }
      lexSource = chars.join('')
    }
  }
  const tokens = lexJs(lexSource)
  const match = matchBrackets(tokens)
  const ctx = new JsCtx(source, tokens, match)
  const raw = astRoot && astLang ? astFacts(ctx, astRoot, astLang) : tokenFacts(ctx)
  postProcess(ctx, raw)
  const facts = finalizeFacts(raw)
  return {
    path,
    lang: 'js',
    source,
    mode: astRoot ? 'ast' : 'tokens',
    tokens,
    match,
    lines: lineStarts(source),
    fns: facts.fns,
    classes: facts.classes,
    calls: facts.calls,
    assigns: facts.assigns,
    memberAssigns: facts.memberAssigns,
    imports: facts.imports,
    exportedNames: facts.exportedNames,
    vars: facts.vars,
    exportAliases: facts.exportAliases,
    defaultExport: facts.defaultExport,
  }
}

// ---------------------------------------------------------------------------
// Token context
// ---------------------------------------------------------------------------

class JsCtx {
  readonly src: string
  readonly tokens: readonly Token[]
  readonly match: Int32Array

  constructor(src: string, tokens: readonly Token[], match: Int32Array) {
    this.src = src
    this.tokens = tokens
    this.match = match
  }

  at(i: number): Token {
    return this.tokens[i] ?? EOF
  }

  is(i: number, value: string): boolean {
    const t = this.tokens[i]
    return t !== undefined && t.type === 'punct' && t.value === value && t.sub === undefined
  }

  ident(i: number, value?: string): boolean {
    const t = this.tokens[i]
    return t !== undefined && t.type === 'ident' && (value === undefined || t.value === value)
  }

  /** The token at `i` is a member name (`a.b`, `a?.b`). */
  isMemberName(i: number): boolean {
    return this.is(i - 1, '.') || this.is(i - 1, '?.')
  }

  span(from: number, toExclusive: number): Span {
    const a = this.at(from)
    const b = this.at(toExclusive - 1)
    return { start: a.start, end: Math.max(a.start, b.end) }
  }

  text(from: number, toExclusive: number): string {
    const s = this.span(from, toExclusive)
    return this.src.slice(s.start, s.end)
  }

  /**
   * End (exclusive token index) of the expression starting at `from`: stops
   * at `;`, a depth-0 `,` (when `stopAtComma`), an unmatched closer, or a
   * line break that cannot continue the expression.
   */
  exprEnd(from: number, stopAtComma = true, limit = this.tokens.length): number {
    let k = from
    while (k < limit) {
      const t = this.tokens[k]!
      if (k > from && t.nl && !this.continues(k)) return k
      if (t.type === 'punct') {
        if (t.sub === 'open' || t.value === '(' || t.value === '[' || t.value === '{') {
          const m = this.match[k]!
          if (m < 0) return limit
          k = m + 1
          continue
        }
        if (t.sub === 'close' || t.value === ')' || t.value === ']' || t.value === '}') return k
        if (t.value === ';') return k
        if (t.value === ',' && stopAtComma) return k
      }
      k++
    }
    return limit
  }

  /** Whether the line break before token `k` continues the expression. */
  continues(k: number): boolean {
    const t = this.tokens[k]!
    const prev = this.tokens[k - 1]
    if (prev && prev.type === 'punct' && prev.sub === undefined && CONTINUING_PUNCT.has(prev.value)) return true
    if (prev && prev.type === 'ident' && (prev.value === 'await' || prev.value === 'new' || prev.value === 'typeof'))
      return true
    if (t.type === 'punct' && t.sub === undefined && LEADING_CONTINUATION.has(t.value)) return true
    if (t.type === 'ident' && (t.value === 'as' || t.value === 'satisfies' || t.value === 'instanceof')) return true
    return false
  }

  /** Index just past a template literal starting at chunk `i`. */
  templateEnd(i: number): number {
    let k = i
    while (k < this.tokens.length) {
      const next = this.tokens[k + 1]
      if (next && next.sub === 'open') {
        const m = this.match[k + 1]!
        if (m < 0) return this.tokens.length
        k = m + 1
        continue
      }
      return k + 1
    }
    return this.tokens.length
  }

  isTemplateStart(i: number): boolean {
    const t = this.tokens[i]
    return t !== undefined && t.type === 'str' && t.value.startsWith('`')
  }

  /** Walk back over a type-argument list ending at `>` (index `k`); returns the index of `<` or -1. */
  skipTypeArgsBack(k: number): number {
    let depth = 0
    for (let j = k; j >= 0 && j > k - 40; j--) {
      const t = this.tokens[j]!
      if (t.type === 'punct') {
        if (t.value === '>') depth++
        else if (t.value === '>>') depth += 2
        else if (t.value === '<') {
          depth--
          if (depth === 0) return j
        } else if (t.value === ')' || t.value === ']' || t.value === '}') {
          const m = this.match[j]!
          if (m < 0) return -1
          j = m
        } else if (!/^(?:[.,|&?:[\]{}]|=>)$/.test(t.value)) return -1
      }
    }
    return -1
  }

  /** Start index of the member chain ending at token `end` (ident, `)` or `]`). */
  chainStart(end: number): number {
    let cur = end
    for (let guard = 0; guard < 64; guard++) {
      const t = this.tokens[cur]
      if (!t) return end
      if (t.type === 'punct' && (t.value === ')' || t.value === ']')) {
        const m = this.match[cur]!
        if (m < 0) return cur
        cur = m
        const before = this.tokens[cur - 1]
        if (
          before &&
          (before.type === 'ident' || (before.type === 'punct' && (before.value === ')' || before.value === ']')))
        ) {
          if (before.type === 'ident' && CALL_EXCLUDE.has(before.value) && !this.isMemberName(cur - 1)) return cur
          cur = cur - 1
          continue
        }
        if (this.is(cur - 1, '.') || this.is(cur - 1, '?.')) {
          cur = cur - 1
        } else return cur
      }
      if (this.tokens[cur]?.type === 'ident' || this.tokens[cur]?.type === 'punct') {
        let p = cur - 1
        if (this.is(p, '!') && this.tokens[p - 1] && /^(?:ident|punct)$/.test(this.tokens[p - 1]!.type)) {
          // non-null assertion `a!.b`
          const pp = this.tokens[p - 1]!
          if (pp.type === 'ident' || pp.value === ')' || pp.value === ']') p = p - 1
        }
        if ((this.is(p, '.') || this.is(p, '?.')) && this.tokens[cur]?.type === 'ident') {
          const prevEnd = p - 1
          const pt = this.tokens[prevEnd]
          if (!pt) return cur
          if (
            pt.type === 'ident' ||
            (pt.type === 'punct' && (pt.value === ')' || pt.value === ']' || pt.value === '!'))
          ) {
            cur = pt.value === '!' ? prevEnd - 1 : prevEnd
            continue
          }
          return cur
        }
        if (
          this.tokens[cur]?.type === 'punct' &&
          (this.tokens[cur]!.value === '(' || this.tokens[cur]!.value === '[')
        ) {
          return cur
        }
        return cur
      }
      return cur
    }
    return cur
  }
}

// ---------------------------------------------------------------------------
// Token-mode facts
// ---------------------------------------------------------------------------

function emptyRaw(): RawFacts {
  return {
    fns: [],
    classes: [],
    calls: [],
    assigns: [],
    memberAssigns: [],
    imports: [],
    exportedNames: new Set(),
    vars: [],
    exportAliases: [],
  }
}

function tokenFacts(ctx: JsCtx): RawFacts {
  const raw = emptyRaw()
  const { tokens } = ctx
  const methodParens = new Set<number>()
  const fnParens = new Set<number>()

  // Pass 1: functions, methods, classes (so calls can skip declaration parens).
  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i]!
    if (t.type === 'ident' && !ctx.isMemberName(i)) {
      if (t.value === 'function') {
        const fn = tokenFunction(ctx, i)
        if (fn) {
          raw.fns.push(fn.fact)
          fnParens.add(fn.parenOpen)
        }
        continue
      }
      if (t.value === 'class' && !ctx.is(i + 1, '(') && !ctx.is(i - 1, '.')) {
        const cls = tokenClass(ctx, i)
        if (cls) raw.classes.push(cls)
        continue
      }
      if (ctx.is(i + 1, '(') && !CALL_EXCLUDE.has(t.value) && t.value !== 'async') {
        const method = tokenMethod(ctx, i)
        if (method) {
          raw.fns.push(method)
          methodParens.add(i + 1)
        }
      }
    } else if (t.type === 'punct' && t.value === '=>') {
      const fn = tokenArrow(ctx, i)
      if (fn) {
        raw.fns.push(fn.fact)
        if (fn.parenOpen >= 0) fnParens.add(fn.parenOpen)
      }
    }
  }

  // Parameter lists: their `=` are default values, not assignments.
  const paramRanges: [number, number][] = []
  for (const open of [...methodParens, ...fnParens]) {
    const close = ctx.match[open]!
    if (close > open) paramRanges.push([open, close])
  }
  paramRanges.sort((a, b) => a[0] - b[0])
  let pr = 0
  const active: [number, number][] = []

  // Pass 2: calls, assignments, imports, exports.
  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i]!
    while (pr < paramRanges.length && paramRanges[pr]![0] <= i) active.push(paramRanges[pr++]!)
    while (active.length > 0 && active[active.length - 1]![1] < i) active.pop()
    if (t.type === 'punct' && t.sub === undefined) {
      if (t.value === '(' && !methodParens.has(i) && !fnParens.has(i)) {
        const call = tokenCall(ctx, i)
        if (call) raw.calls.push(call)
      } else if (ASSIGN_OPS.has(t.value) && !active.some(([a, b]) => a < i && i < b)) {
        tokenAssign(ctx, i, raw)
      }
    } else if (t.type === 'str' && t.value.startsWith('`') && !t.value.startsWith('`}')) {
      const prevTok = tokens[i - 1]
      const isChunkContinuation = prevTok?.sub === 'close'
      if (!isChunkContinuation) {
        const tagged = tokenTaggedTemplate(ctx, i)
        if (tagged) raw.calls.push(tagged)
      }
    } else if (t.type === 'ident' && !ctx.isMemberName(i)) {
      if (t.value === 'const' || t.value === 'let' || t.value === 'var') tokenDeclaration(ctx, i, raw)
      else if (t.value === 'import' && !ctx.is(i + 1, '(') && !ctx.is(i + 1, '.')) tokenImport(ctx, i, raw)
      else if (t.value === 'export') tokenExport(ctx, i, raw)
    }
  }
  return raw
}

interface TokenFn {
  readonly fact: FnFact
  readonly parenOpen: number
}

/** `function` keyword at `i`. */
function tokenFunction(ctx: JsCtx, i: number): TokenFn | undefined {
  let j = i + 1
  if (ctx.is(j, '*')) j++
  let name: string | undefined
  if (ctx.ident(j) && !ctx.is(j, '(')) {
    name = ctx.at(j).value
    j++
  }
  if (ctx.is(j, '<')) {
    const close = skipTypeArgsForward(ctx, j)
    if (close < 0) return undefined
    j = close + 1
  }
  if (!ctx.is(j, '(')) return undefined
  const open = j
  const close = ctx.match[open]!
  if (close < 0) return undefined
  const bodyOpen = findBodyOpen(ctx, close + 1)
  if (bodyOpen < 0) return undefined
  const bodyClose = ctx.match[bodyOpen]!
  if (bodyClose < 0) return undefined
  let startTok = i
  if (ctx.ident(i - 1, 'async')) startTok = i - 1
  const decl = declPrefix(ctx, startTok)
  const fnName = name ?? inferName(ctx, startTok)
  return {
    parenOpen: open,
    fact: {
      name: fnName,
      kind: 'function',
      start: ctx.at(startTok).start,
      end: ctx.at(bodyClose).end,
      body: { start: ctx.at(bodyOpen).start, end: ctx.at(bodyClose).end },
      params: parseJsParams(ctx, open + 1, close),
      decorators: [],
      declStart: ctx.at(decl.start).start,
      exported: decl.exported,
      parent: undefined,
      className: undefined,
    },
  }
}

/** Arrow function whose `=>` is at `a`. */
function tokenArrow(ctx: JsCtx, a: number): TokenFn | undefined {
  let open = -1
  let close = -1
  let startTok: number
  const prev = a - 1
  if (ctx.is(prev, ')')) {
    close = prev
    open = ctx.match[close]!
    if (open < 0) return undefined
    startTok = open
  } else if (ctx.ident(prev)) {
    startTok = prev
  } else {
    // `(a): Type => ...`
    let k = prev
    let found = -1
    while (k >= 0 && k > a - 80) {
      const t = ctx.at(k)
      if (t.type === 'punct' && t.value === ':' && ctx.is(k - 1, ')')) {
        found = k - 1
        break
      }
      if (t.type === 'punct' && (t.value === ')' || t.value === ']' || t.value === '}')) {
        const m = ctx.match[k]!
        if (m < 0) return undefined
        k = m - 1
        continue
      }
      if (t.type === 'punct' && (t.value === '>' || t.value === '>>')) {
        const lt = ctx.skipTypeArgsBack(k)
        if (lt < 0) return undefined
        k = lt - 1
        continue
      }
      if (t.type === 'punct' && (t.value === ';' || t.value === '=>' || t.value === '=' || t.value === '{')) break
      k--
    }
    if (found < 0) return undefined
    close = found
    open = ctx.match[close]!
    if (open < 0) return undefined
    startTok = open
  }
  if (ctx.is(startTok - 1, '>')) {
    const lt = ctx.skipTypeArgsBack(startTok - 1)
    if (lt >= 0) startTok = lt
  }
  if (ctx.ident(startTok - 1, 'async') && !ctx.isMemberName(startTok - 1)) startTok--
  let bodySpan: Span
  let endTok: number
  if (ctx.is(a + 1, '{')) {
    const m = ctx.match[a + 1]!
    if (m < 0) return undefined
    bodySpan = { start: ctx.at(a + 1).start, end: ctx.at(m).end }
    endTok = m
  } else {
    const end = ctx.exprEnd(a + 1)
    if (end <= a + 1) return undefined
    bodySpan = ctx.span(a + 1, end)
    endTok = end - 1
  }
  const params = open >= 0 ? parseJsParams(ctx, open + 1, close) : [singleParam(ctx, startTok)]
  const decl = declPrefix(ctx, startTok)
  return {
    parenOpen: open,
    fact: {
      name: inferName(ctx, startTok),
      kind: 'arrow',
      start: ctx.at(startTok).start,
      end: ctx.at(endTok).end,
      body: bodySpan,
      params,
      decorators: [],
      declStart: ctx.at(decl.start).start,
      exported: decl.exported,
      parent: undefined,
      className: undefined,
    },
  }
}

function singleParam(ctx: JsCtx, i: number): ParamFact {
  const t = ctx.at(i)
  return { start: t.start, end: t.end, name: t.value, names: [t.value], decorators: [] }
}

/** `name(...) {` method definition (class or object literal) with the name at `i`. */
function tokenMethod(ctx: JsCtx, i: number): FnFact | undefined {
  const open = i + 1
  const close = ctx.match[open]!
  if (close < 0) return undefined
  const after = ctx.at(close + 1)
  if (!(after.type === 'punct' && (after.value === '{' || after.value === ':'))) return undefined
  if (after.value === '{' && after.nl) return undefined
  if (ctx.isMemberName(i)) return undefined
  const prev = ctx.at(i - 1)
  const okPrev =
    i === 0 ||
    ctx.at(i).nl ||
    (prev.type === 'punct' && ['{', '}', ';', ',', ')', '*'].includes(prev.value)) ||
    (prev.type === 'ident' && METHOD_MODIFIERS.has(prev.value))
  if (!okPrev) return undefined
  // A `)` before the name must close a decorator call.
  if (prev.type === 'punct' && prev.value === ')' && !isDecoratorEnd(ctx, i - 1)) return undefined
  const bodyOpen = after.value === '{' ? close + 1 : findBodyOpen(ctx, close + 1)
  if (bodyOpen < 0) return undefined
  const bodyClose = ctx.match[bodyOpen]!
  if (bodyClose < 0) return undefined
  let startTok = i
  while (ctx.at(startTok - 1).type === 'ident' && METHOD_MODIFIERS.has(ctx.at(startTok - 1).value)) startTok--
  if (ctx.is(startTok - 1, '*')) startTok--
  const decorators = decoratorsBefore(ctx, startTok)
  const declStart = decorators[0]?.start ?? ctx.at(startTok).start
  return {
    name: ctx.at(i).value,
    kind: 'method',
    start: ctx.at(startTok).start,
    end: ctx.at(bodyClose).end,
    body: { start: ctx.at(bodyOpen).start, end: ctx.at(bodyClose).end },
    params: parseJsParams(ctx, open + 1, close),
    decorators,
    declStart,
    exported: false,
    parent: undefined,
    className: undefined,
  }
}

/** `class` keyword at `i`. */
function tokenClass(ctx: JsCtx, i: number): ClassFact | undefined {
  let j = i + 1
  let name: string | undefined
  if (ctx.ident(j) && ctx.at(j).value !== 'extends' && ctx.at(j).value !== 'implements') {
    name = ctx.at(j).value
    j++
  }
  if (ctx.is(j, '<')) {
    const close = skipTypeArgsForward(ctx, j)
    if (close >= 0) j = close + 1
  }
  const bases: string[] = []
  let guard = 0
  while (j < ctx.tokens.length && !ctx.is(j, '{') && guard++ < 200) {
    if (ctx.ident(j, 'extends')) {
      let k = j + 1
      const startK = k
      let endK = -1
      while (k < ctx.tokens.length && !ctx.is(k, '{') && !ctx.ident(k, 'implements')) {
        if (ctx.is(k, '<') && endK < 0) endK = k
        if (ctx.is(k, '(') || ctx.is(k, '<')) {
          const m = ctx.is(k, '(') ? ctx.match[k]! : skipTypeArgsForward(ctx, k)
          if (m < 0) break
          k = m + 1
          continue
        }
        k++
      }
      const text = normalizeCallee(ctx.text(startK, endK < 0 ? k : endK))
      if (text) bases.push(text)
      j = k
      continue
    }
    j++
  }
  if (!ctx.is(j, '{')) return undefined
  const close = ctx.match[j]!
  if (close < 0) return undefined
  let startTok = i
  if (ctx.ident(i - 1, 'abstract')) startTok--
  const decl = declPrefix(ctx, startTok)
  const decorators = decoratorsBefore(ctx, decl.start)
  return {
    name: name ?? inferName(ctx, startTok),
    start: ctx.at(startTok).start,
    end: ctx.at(close).end,
    body: { start: ctx.at(j).start, end: ctx.at(close).end },
    bases,
    decorators,
    declStart: decorators[0]?.start ?? ctx.at(decl.start).start,
    exported: decl.exported,
  }
}

function tokenCall(ctx: JsCtx, open: number): CallFact | undefined {
  const close = ctx.match[open]!
  if (close < 0) return undefined
  let q = open - 1
  if (ctx.is(q, '?.')) q--
  const qt = ctx.tokens[q]
  if (!qt) return undefined
  if (qt.type === 'punct' && (qt.value === '>' || qt.value === '>>')) {
    const lt = ctx.skipTypeArgsBack(q)
    if (lt < 0) return undefined
    q = lt - 1
  }
  const ct = ctx.tokens[q]
  if (!ct) return undefined
  if (ct.type === 'ident') {
    if (!ctx.isMemberName(q) && (CALL_EXCLUDE.has(ct.value) || ct.value === 'async')) {
      if (ct.value !== 'async') return undefined
      if (ctx.is(close + 1, '=>')) return undefined
    }
    if (ctx.ident(q - 1, 'function')) return undefined
    if (ctx.ident(q - 1, 'class')) return undefined
  } else if (!(ct.type === 'punct' && (ct.value === ')' || ct.value === ']'))) {
    return undefined
  }
  if (ct.type === 'punct' && ct.value === ')' && ctx.is(close + 1, '=>')) return undefined
  const cs = ctx.chainStart(q)
  const calleeText = normalizeCallee(ctx.text(cs, q + 1))
  const [receiver, name] = splitCallee(calleeText)
  const isNew = ctx.ident(cs - 1, 'new')
  const decorator = ctx.is(cs - 1, '@')
  const startTok = isNew ? cs - 1 : cs
  return {
    callee: calleeText,
    name,
    receiver,
    calleeSpan: ctx.span(cs, q + 1),
    isNew,
    tagged: false,
    args: splitArgs(ctx, open + 1, close, 'js'),
    decorator,
    start: ctx.at(startTok).start,
    end: ctx.at(close).end,
    fn: undefined,
  }
}

function tokenTaggedTemplate(ctx: JsCtx, i: number): CallFact | undefined {
  let q = i - 1
  const qt = ctx.tokens[q]
  if (!qt) return undefined
  if (qt.type === 'punct' && (qt.value === '>' || qt.value === '>>')) {
    const lt = ctx.skipTypeArgsBack(q)
    if (lt < 0) return undefined
    q = lt - 1
  }
  const ct = ctx.tokens[q]
  if (!ct) return undefined
  if (ct.type === 'ident') {
    if (!ctx.isMemberName(q) && JS_KEYWORDS.has(ct.value)) return undefined
  } else if (!(ct.type === 'punct' && (ct.value === ')' || ct.value === ']'))) {
    return undefined
  }
  if (ct.nl === false && ctx.at(i).nl) return undefined
  const end = ctx.templateEnd(i)
  const cs = ctx.chainStart(q)
  const calleeText = normalizeCallee(ctx.text(cs, q + 1))
  const [receiver, name] = splitCallee(calleeText)
  return {
    callee: calleeText,
    name,
    receiver,
    calleeSpan: ctx.span(cs, q + 1),
    isNew: false,
    tagged: true,
    args: [ctx.span(i, end)],
    decorator: false,
    start: ctx.at(cs).start,
    end: ctx.at(end - 1).end,
    fn: undefined,
  }
}

/** Split `[from, to)` at depth-0 commas into argument spans. */
function splitArgs(ctx: JsCtx, from: number, to: number, lang: 'js' | 'py'): ArgFact[] {
  const args: ArgFact[] = []
  let a = from
  const flush = (b: number): void => {
    if (b <= a) return
    let s = a
    let splat: ArgFact['splat']
    let keyword: string | undefined
    const t = ctx.at(s)
    if (t.type === 'punct' && (t.value === '...' || (lang === 'py' && (t.value === '*' || t.value === '**')))) {
      splat = t.value as ArgFact['splat']
      s++
    } else if (lang === 'py' && t.type === 'ident' && ctx.is(s + 1, '=') && b > s + 2) {
      keyword = t.value
    }
    if (b <= s) return
    const span = ctx.span(s, b)
    args.push({ ...span, ...(splat ? { splat } : {}), ...(keyword ? { keyword } : {}) })
  }
  let k = from
  while (k < to) {
    const t = ctx.tokens[k]!
    if (t.type === 'punct' && (t.sub === 'open' || t.value === '(' || t.value === '[' || t.value === '{')) {
      const m = ctx.match[k]!
      if (m < 0 || m >= to) break
      k = m + 1
      continue
    }
    if (t.type === 'punct' && t.value === ',' && t.sub === undefined) {
      flush(k)
      a = k + 1
    }
    k++
  }
  flush(to)
  return args
}

/** Assignment operator at `i` (`=`, `+=`, ...): plain or member target. */
function tokenAssign(ctx: JsCtx, i: number, raw: RawFacts): void {
  const op = ctx.at(i).value
  const lhsEnd = i - 1
  const lt = ctx.tokens[lhsEnd]
  if (!lt) return
  const valueStart = i + 1
  const valueEnd = ctx.exprEnd(valueStart)
  if (valueEnd <= valueStart) return
  const value = ctx.span(valueStart, valueEnd)
  if (lt.type === 'ident') {
    if (ctx.isMemberName(lhsEnd)) {
      const cs = ctx.chainStart(lhsEnd)
      const target = normalizeCallee(ctx.text(cs, lhsEnd + 1))
      raw.memberAssigns.push({
        target,
        prop: lt.value,
        op,
        value,
        start: ctx.at(cs).start,
        end: value.end,
        fn: undefined,
      })
      return
    }
    // Declarations are handled by `tokenDeclaration`; skip their `=`.
    if (isDeclaratorName(ctx, lhsEnd)) return
    if (isJsxAttribute(ctx, lhsEnd)) return
    if (JS_KEYWORDS.has(lt.value) && lt.value !== 'of' && lt.value !== 'get' && lt.value !== 'set') return
    // Default values inside parameter lists and destructuring patterns are not assignments we track.
    raw.assigns.push({
      targets: [{ name: lt.value }],
      op,
      value,
      destructured: false,
      start: lt.start,
      end: value.end,
      fn: undefined,
    })
    return
  }
  if (lt.type === 'punct' && lt.value === ']') {
    const open = ctx.match[lhsEnd]!
    if (open < 0) return
    const before = ctx.at(open - 1)
    if (before.type === 'ident' || (before.type === 'punct' && (before.value === ')' || before.value === ']'))) {
      const cs = ctx.chainStart(lhsEnd)
      const target = normalizeCallee(ctx.text(cs, lhsEnd + 1))
      const inner = ctx.tokens[open + 1]
      const prop = inner && inner.type === 'str' && open + 2 === lhsEnd ? stringContent(inner) : ''
      raw.memberAssigns.push({
        target,
        prop,
        op,
        value,
        start: ctx.at(cs).start,
        end: value.end,
        fn: undefined,
      })
    }
  }
}

/**
 * `name={…}` / `name="…"` inside a JSX opening tag (`<li key={x}>`,
 * `<a data-id="1" {...p} onClick={f}>`). Walks back over attribute shapes
 * to `<Tag` where the `<` stands in expression position (not `a < b`).
 */
function isJsxAttribute(ctx: JsCtx, i: number): boolean {
  const value = ctx.at(i + 2)
  const jsxValue =
    (value.type === 'punct' && value.value === '{') || (value.type === 'str' && !value.value.startsWith('`'))
  if (!jsxValue) return false
  let k = i - 1
  for (let guard = 0; guard < 96 && k >= 0; guard++) {
    const t = ctx.at(k)
    if (t.type === 'punct' && t.value === '}' && t.sub === undefined) {
      const open = ctx.match[k]!
      if (open < 0 || !ctx.is(open, '{')) return false
      k = open - 1
      continue
    }
    if ((t.type === 'str' && !t.value.startsWith('`')) || ctx.is(k, '=') || ctx.is(k, '-') || ctx.is(k, ':')) {
      k--
      continue
    }
    if (t.type !== 'ident') return false
    // Tag name, possibly a member (`<Foo.Bar`).
    let tagStart = k
    while (ctx.is(tagStart - 1, '.') && ctx.ident(tagStart - 2)) tagStart -= 2
    if (ctx.is(tagStart - 1, '<') && jsxPosition(ctx, tagStart - 2)) return true
    k--
  }
  return false
}

/** Whether a `<` following token `k` starts JSX rather than a comparison or type arguments. */
function jsxPosition(ctx: JsCtx, k: number): boolean {
  const t = ctx.tokens[k]
  if (!t) return true
  if (t.type === 'ident') return JS_KEYWORDS.has(t.value) && t.value !== 'this'
  return t.type === 'punct' && t.sub === undefined && !/^(?:\)|\]|\+\+|--)$/.test(t.value)
}

function isDeclaratorName(ctx: JsCtx, i: number): boolean {
  // `const x =`, `let x: T =`, `const a = 1, b =` are parsed by tokenDeclaration.
  let k = i - 1
  const t = ctx.at(k)
  if (t.type === 'ident' && (t.value === 'const' || t.value === 'let' || t.value === 'var')) return true
  if (t.type === 'punct' && t.value === ',') {
    // walk back to see if we are inside a declaration list at the same depth
    for (k = i - 2; k >= 0 && k > i - 400; k--) {
      const u = ctx.at(k)
      if (u.type === 'punct' && (u.value === ')' || u.value === ']' || u.value === '}')) {
        const m = ctx.match[k]!
        if (m < 0) return false
        k = m
        continue
      }
      if (u.type === 'punct' && (u.value === ';' || u.value === '(' || u.value === '[' || u.value === '{')) return false
      if (u.type === 'ident' && (u.value === 'const' || u.value === 'let' || u.value === 'var')) return true
    }
  }
  return false
}

/** `const|let|var` at `i`: one AssignFact per declarator; `for (const x of y)` loop bindings. */
function tokenDeclaration(ctx: JsCtx, i: number, raw: RawFacts): void {
  const kw = ctx.at(i)
  const exported = ctx.ident(i - 1, 'export')
  const declStart = exported ? ctx.at(i - 1).start : kw.start
  const forOpen =
    ctx.is(i - 1, '(') && (ctx.ident(i - 2, 'for') || (ctx.ident(i - 2, 'await') && ctx.ident(i - 3, 'for')))
  let j = i + 1
  for (let guard = 0; guard < 64 && j < ctx.tokens.length; guard++) {
    const patStart = j
    let patEnd: number
    if (ctx.is(j, '{') || ctx.is(j, '[')) {
      const m = ctx.match[j]!
      if (m < 0) return
      patEnd = m + 1
    } else if (ctx.ident(j)) {
      patEnd = j + 1
    } else return
    const destructured = patEnd - patStart > 1
    const targets = patternTargets(ctx, patStart, patEnd)
    let k = patEnd
    if (ctx.is(k, '!')) k++
    if (ctx.is(k, ':')) {
      // type annotation: skip to `=` / `,` / `;` / `of` / `in` at depth 0
      k++
      while (k < ctx.tokens.length) {
        const t = ctx.at(k)
        if (t.type === 'punct' && (t.value === '=' || t.value === ',' || t.value === ';')) break
        if (t.type === 'ident' && (t.value === 'of' || t.value === 'in') && forOpen) break
        if (t.nl && k > patEnd + 1 && !ctx.continues(k)) break
        if (t.type === 'punct' && (t.value === '(' || t.value === '[' || t.value === '{')) {
          const m = ctx.match[k]!
          if (m < 0) return
          k = m + 1
          continue
        }
        if (t.type === 'punct' && (t.value === '<' || t.value === '>')) {
          k++
          continue
        }
        if (t.type === 'punct' && (t.value === ')' || t.value === ']' || t.value === '}')) break
        k++
      }
    }
    if (forOpen && (ctx.ident(k, 'of') || ctx.ident(k, 'in'))) {
      const close = ctx.match[i - 1]!
      if (close < 0) return
      const value = ctx.span(k + 1, close)
      raw.assigns.push({
        targets,
        op: 'for',
        value,
        destructured: true,
        start: ctx.at(patStart).start,
        end: value.end,
        fn: undefined,
      })
      return
    }
    if (!ctx.is(k, '=')) {
      if (ctx.is(k, ',')) {
        j = k + 1
        continue
      }
      return
    }
    const valueStart = k + 1
    const valueEnd = ctx.exprEnd(valueStart)
    if (valueEnd <= valueStart) return
    const value = ctx.span(valueStart, valueEnd)
    raw.assigns.push({
      targets,
      op: '=',
      value,
      destructured,
      start: ctx.at(patStart).start,
      end: value.end,
      fn: undefined,
    })
    if (!destructured && targets[0]) {
      const isFn =
        ctx.ident(valueStart, 'function') ||
        (ctx.ident(valueStart, 'async') && (ctx.ident(valueStart + 1, 'function') || isArrowAt(ctx, valueStart + 1))) ||
        isArrowAt(ctx, valueStart)
      raw.vars.push({
        name: targets[0].name,
        start: declStart,
        end: value.end,
        exported,
        isFn,
        value,
      })
    }
    if (ctx.is(valueEnd, ',')) {
      j = valueEnd + 1
      continue
    }
    return
  }
}

/** Whether an arrow function starts at token `k` (`(…) =>` or `x =>`). */
function isArrowAt(ctx: JsCtx, k: number): boolean {
  if (ctx.ident(k) && ctx.is(k + 1, '=>')) return true
  let j = k
  if (ctx.is(j, '<')) {
    const m = skipTypeArgsForward(ctx, j)
    if (m < 0) return false
    j = m + 1
  }
  if (!ctx.is(j, '(')) return false
  const m = ctx.match[j]!
  if (m < 0) return false
  if (ctx.is(m + 1, '=>')) return true
  if (ctx.is(m + 1, ':')) {
    for (let q = m + 2; q < ctx.tokens.length && q < m + 80; q++) {
      if (ctx.is(q, '=>')) return true
      if (ctx.is(q, ';') || ctx.is(q, '=')) return false
      const t = ctx.at(q)
      if (t.type === 'punct' && (t.value === '(' || t.value === '[' || t.value === '{')) {
        const mm = ctx.match[q]!
        if (mm < 0) return false
        q = mm
      }
    }
  }
  return false
}

function tokenImport(ctx: JsCtx, i: number, raw: RawFacts): void {
  let j = i + 1
  const bindings: ImportBinding[] = []
  if (ctx.ident(j, 'type') && !ctx.ident(j + 1, 'from') && !ctx.is(j + 1, ',')) j++
  for (let guard = 0; guard < 400 && j < ctx.tokens.length; guard++) {
    const t = ctx.at(j)
    if (t.type === 'str') {
      raw.imports.push({ source: stringContent(t), bindings, start: ctx.at(i).start, kind: 'import' })
      return
    }
    if (t.type === 'ident' && t.value === 'from') {
      j++
      continue
    }
    if (t.type === 'ident' && ctx.is(j + 1, '=') && ctx.ident(j + 2, 'require')) {
      // TS `import x = require('m')`
      const s = ctx.at(j + 4)
      if (s.type === 'str') {
        raw.imports.push({
          source: stringContent(s),
          bindings: [{ local: t.value, imported: '*' }],
          start: ctx.at(i).start,
          kind: 'require',
        })
      }
      return
    }
    if (t.type === 'ident') {
      bindings.push({ local: t.value, imported: 'default' })
      j++
      continue
    }
    if (t.type === 'punct' && t.value === '*') {
      if (ctx.ident(j + 1, 'as') && ctx.ident(j + 2)) {
        bindings.push({ local: ctx.at(j + 2).value, imported: '*' })
        j += 3
        continue
      }
      j++
      continue
    }
    if (t.type === 'punct' && t.value === '{') {
      const close = ctx.match[j]!
      if (close < 0) return
      bindings.push(...specifierList(ctx, j + 1, close))
      j = close + 1
      continue
    }
    if (t.type === 'punct' && t.value === ',') {
      j++
      continue
    }
    return
  }
}

/** Parse `a, b as c, type d` inside braces: `local` is the name bound here. */
function specifierList(ctx: JsCtx, from: number, to: number): ImportBinding[] {
  const out: ImportBinding[] = []
  let k = from
  while (k < to) {
    if (ctx.ident(k, 'type') && (ctx.ident(k + 1) || ctx.at(k + 1).type === 'str') && !ctx.ident(k + 1, 'as')) k++
    const t = ctx.at(k)
    if (t.type === 'ident' || t.type === 'str') {
      const imported = t.type === 'str' ? stringContent(t) : t.value
      if (ctx.ident(k + 1, 'as') && (ctx.ident(k + 2) || ctx.at(k + 2).type === 'str')) {
        const alias = ctx.at(k + 2)
        out.push({ local: alias.type === 'str' ? stringContent(alias) : alias.value, imported })
        k += 3
      } else {
        out.push({ local: imported, imported })
        k++
      }
      continue
    }
    k++
  }
  return out
}

function tokenExport(ctx: JsCtx, i: number, raw: RawFacts): void {
  const next = ctx.at(i + 1)
  if (next.type === 'punct' && next.value === '{') {
    const close = ctx.match[i + 1]!
    if (close < 0) return
    const specs = specifierList(ctx, i + 2, close)
    if (ctx.ident(close + 1, 'from') && ctx.at(close + 2).type === 'str') {
      raw.imports.push({
        source: stringContent(ctx.at(close + 2)),
        bindings: specs.map(s => ({ local: s.local, imported: s.imported })),
        start: ctx.at(i).start,
        kind: 'export-from',
      })
      for (const s of specs) raw.exportedNames.add(s.local)
      return
    }
    // `export { a as b }`: the local `a` is exported under the name `b`.
    for (const s of specs) {
      raw.exportedNames.add(s.imported)
      if (s.local !== s.imported) raw.exportAliases.push({ local: s.imported, exported: s.local })
    }
    return
  }
  if (next.type === 'punct' && next.value === '*') {
    let k = i + 2
    if (ctx.ident(k, 'as')) k += 2
    if (ctx.ident(k, 'from') && ctx.at(k + 1).type === 'str') {
      raw.imports.push({
        source: stringContent(ctx.at(k + 1)),
        bindings: [],
        start: ctx.at(i).start,
        kind: 'export-from',
      })
    }
    return
  }
  if (next.type === 'ident' && next.value === 'default') {
    const v = ctx.at(i + 2)
    if (v.type === 'ident' && !JS_KEYWORDS.has(v.value) && v.value !== 'class' && v.value !== 'function') {
      const after = ctx.at(i + 3)
      if (after.type !== 'punct' || after.value === ';' || after.nl) raw.exportedNames.add(v.value)
      raw.defaultExport = v.value
    }
    return
  }
  // `export const a = ...`, `export function f`, `export class C` set `exported` directly.
  if (next.type === 'ident' && (next.value === 'type' || next.value === 'interface' || next.value === 'enum')) {
    const name = ctx.at(i + 2)
    if (name.type === 'ident') raw.exportedNames.add(name.value)
  }
}

// ---------------------------------------------------------------------------
// Shared token helpers
// ---------------------------------------------------------------------------

/** Index of `>` matching a `<` at `j`, or -1. */
function skipTypeArgsForward(ctx: JsCtx, j: number): number {
  let depth = 0
  for (let k = j; k < ctx.tokens.length && k < j + 80; k++) {
    const t = ctx.at(k)
    if (t.type !== 'punct') continue
    if (t.value === '<') depth++
    else if (t.value === '>') {
      depth--
      if (depth === 0) return k
    } else if (t.value === '>>') {
      depth -= 2
      if (depth <= 0) return k
    } else if (t.value === '(' || t.value === '[' || t.value === '{') {
      const m = ctx.match[k]!
      if (m < 0) return -1
      k = m
    } else if (t.value === ';' || t.value === ')' || t.value === '}') return -1
  }
  return -1
}

/** After a parameter list: the `{` opening the body, skipping a return type annotation. */
function findBodyOpen(ctx: JsCtx, k: number): number {
  for (let guard = 0; guard < 200 && k < ctx.tokens.length; guard++) {
    const t = ctx.at(k)
    if (t.type === 'punct') {
      if (t.value === '{') {
        const prev = ctx.at(k - 1)
        const typeContext =
          prev.type === 'punct' && [':', '|', '&', '<', ',', '(', '=>', '=', '?'].includes(prev.value) && guard > 0
        if (!typeContext) return k
        const m = ctx.match[k]!
        if (m < 0) return -1
        k = m + 1
        continue
      }
      if (t.value === ';' || t.value === '}' || t.value === ')' || t.value === ',') return -1
      if (t.value === '=>' && guard > 0) return -1
      if (t.value === '(' || t.value === '[') {
        const m = ctx.match[k]!
        if (m < 0) return -1
        k = m + 1
        continue
      }
    }
    k++
  }
  return -1
}

/** Whether `)` at `k` closes a decorator call `@a.b(...)`. */
function isDecoratorEnd(ctx: JsCtx, k: number): boolean {
  const open = ctx.match[k]!
  if (open < 0) return false
  const cs = ctx.chainStart(open - 1)
  return ctx.is(cs - 1, '@')
}

/** Decorators immediately before token `start` (skipping `export`/`default`), in source order. */
function decoratorsBefore(ctx: JsCtx, start: number): DecoratorFact[] {
  const out: DecoratorFact[] = []
  let k = start - 1
  while (ctx.ident(k, 'export') || ctx.ident(k, 'default') || ctx.ident(k, 'abstract') || ctx.ident(k, 'declare')) k--
  for (let guard = 0; guard < 32 && k >= 0; guard++) {
    const t = ctx.at(k)
    let nameEnd = k
    let args: ArgFact[] | undefined
    if (t.type === 'punct' && t.value === ')') {
      const open = ctx.match[k]!
      if (open < 0) break
      args = splitArgs(ctx, open + 1, k, 'js')
      nameEnd = open - 1
    }
    if (!ctx.ident(nameEnd)) break
    const cs = ctx.chainStart(nameEnd)
    if (!ctx.is(cs - 1, '@')) break
    out.unshift({
      name: normalizeCallee(ctx.text(cs, nameEnd + 1)),
      start: ctx.at(cs - 1).start,
      end: ctx.at(k).end,
      ...(args ? { args } : {}),
    })
    k = cs - 2
  }
  return out
}

/** Start token (including `export`/`export default`/`async`) and whether the declaration is exported. */
function declPrefix(ctx: JsCtx, startTok: number): { start: number; exported: boolean } {
  let s = startTok
  if (ctx.ident(s - 1, 'default') && ctx.ident(s - 2, 'export')) return { start: s - 2, exported: true }
  if (ctx.ident(s - 1, 'export')) return { start: s - 1, exported: true }
  if (ctx.ident(s - 1, 'declare') && ctx.ident(s - 2, 'export')) return { start: s - 2, exported: true }
  // `export const name = (...) =>` / `export const name = function`
  if (ctx.is(s - 1, '=') && ctx.ident(s - 2)) {
    let k = s - 3
    if (ctx.ident(k, 'const') || ctx.ident(k, 'let') || ctx.ident(k, 'var')) {
      if (ctx.ident(k - 1, 'export')) return { start: k - 1, exported: true }
      return { start: k, exported: false }
    }
    // with a type annotation: `export const GET: Handler = async () =>`
    for (k = s - 2; k >= 0 && k > s - 40; k--) {
      const t = ctx.at(k)
      if (t.type === 'ident' && (t.value === 'const' || t.value === 'let' || t.value === 'var')) {
        if (ctx.ident(k - 1, 'export')) return { start: k - 1, exported: true }
        return { start: k, exported: false }
      }
      if (t.type === 'punct' && (t.value === ';' || t.value === '{' || t.value === '}')) break
      if (t.nl) break
    }
  }
  s = startTok
  return { start: s, exported: false }
}

/** Name for an anonymous function/class from its context (`const f = ...`, `f: ...`, `exports.f = ...`). */
function inferName(ctx: JsCtx, startTok: number): string | undefined {
  const prev = ctx.at(startTok - 1)
  if (prev.type === 'punct' && prev.value === '=') {
    let k = startTok - 2
    // skip a type annotation `name: Type =`
    const direct = ctx.at(k)
    if (direct.type === 'ident' && !ctx.isMemberName(k)) return direct.value
    if (direct.type === 'ident' && ctx.isMemberName(k)) return direct.value
    for (k = startTok - 2; k >= 0 && k > startTok - 40; k--) {
      const t = ctx.at(k)
      if (t.type === 'punct' && t.value === ':' && ctx.ident(k - 1)) return ctx.at(k - 1).value
      if (t.type === 'punct' && (t.value === ';' || t.value === '{' || t.value === '}' || t.value === '(')) break
      if (t.type === 'punct' && (t.value === ')' || t.value === ']')) {
        const m = ctx.match[k]!
        if (m < 0) break
        k = m
      }
    }
    return undefined
  }
  if (prev.type === 'punct' && prev.value === ':') {
    const key = ctx.at(startTok - 2)
    const before = ctx.at(startTok - 3)
    if (
      (key.type === 'ident' || key.type === 'str') &&
      before.type === 'punct' &&
      (before.value === '{' || before.value === ',')
    ) {
      return key.type === 'str' ? stringContent(key) : key.value
    }
  }
  if (prev.type === 'ident' && prev.value === 'default' && ctx.ident(startTok - 2, 'export')) return 'default'
  return undefined
}

/** Names bound by a binding pattern `[from, to)`: identifier, object or array pattern. */
function patternTargets(ctx: JsCtx, from: number, to: number, keyPrefix?: string): AssignTarget[] {
  const t = ctx.at(from)
  if (to - from === 1 && t.type === 'ident') return [{ name: t.value, ...(keyPrefix ? { key: keyPrefix } : {}) }]
  const out: AssignTarget[] = []
  if (t.type === 'punct' && (t.value === '{' || t.value === '[')) {
    const close = ctx.match[from]!
    if (close < 0) return out
    const isObject = t.value === '{'
    let a = from + 1
    let index = 0
    const entry = (b: number): void => {
      if (b <= a) {
        index++
        return
      }
      let s = a
      if (ctx.is(s, '...')) {
        const n = ctx.at(s + 1)
        if (n.type === 'ident') out.push({ name: n.value, key: keyPrefix ? `${keyPrefix}...` : '...' })
        index++
        return
      }
      if (isObject) {
        const key = ctx.at(s)
        let keyName = key.type === 'str' ? stringContent(key) : key.value
        if (key.type === 'punct' && key.value === '[') {
          const m = ctx.match[s]!
          keyName = ''
          s = m < 0 ? s : m
        }
        if (ctx.is(s + 1, ':')) {
          // `key: pattern [= default]`
          let pe = s + 2
          const pt = ctx.at(pe)
          if (pt.type === 'punct' && (pt.value === '{' || pt.value === '[')) {
            const m = ctx.match[pe]!
            pe = m < 0 ? pe + 1 : m + 1
          } else pe = pe + 1
          out.push(...patternTargets(ctx, s + 2, pe, keyPrefix ? `${keyPrefix}.${keyName}` : keyName))
        } else if (key.type === 'ident') {
          out.push({ name: key.value, key: keyPrefix ? `${keyPrefix}.${key.value}` : key.value })
        }
      } else {
        const pt = ctx.at(s)
        let pe = s + 1
        if (pt.type === 'punct' && (pt.value === '{' || pt.value === '[')) {
          const m = ctx.match[s]!
          pe = m < 0 ? s + 1 : m + 1
        }
        out.push(...patternTargets(ctx, s, pe, keyPrefix ? `${keyPrefix}.${index}` : String(index)))
      }
      index++
    }
    let k = from + 1
    while (k < close) {
      const u = ctx.at(k)
      if (u.type === 'punct' && (u.sub === 'open' || u.value === '(' || u.value === '[' || u.value === '{')) {
        const m = ctx.match[k]!
        if (m < 0 || m > close) break
        k = m + 1
        continue
      }
      if (u.type === 'punct' && u.value === ',') {
        entry(k)
        a = k + 1
      }
      k++
    }
    entry(close)
  }
  return out
}

/** Parameters between `from` and `to` (exclusive), i.e. inside the parentheses. */
function parseJsParams(ctx: JsCtx, from: number, to: number): ParamFact[] {
  const out: ParamFact[] = []
  const parts: [number, number][] = []
  let a = from
  let k = from
  while (k < to) {
    const t = ctx.at(k)
    if (t.type === 'punct' && (t.sub === 'open' || t.value === '(' || t.value === '[' || t.value === '{')) {
      const m = ctx.match[k]!
      if (m < 0 || m >= to) break
      k = m + 1
      continue
    }
    if (t.type === 'punct' && t.value === '<') {
      const m = skipTypeArgsForward(ctx, k)
      if (m > 0 && m < to) {
        k = m + 1
        continue
      }
    }
    if (t.type === 'punct' && t.value === ',') {
      parts.push([a, k])
      a = k + 1
    }
    k++
  }
  parts.push([a, to])
  for (const [ps, pe] of parts) {
    if (pe <= ps) continue
    let s = ps
    const decorators: string[] = []
    while (ctx.is(s, '@')) {
      let n = s + 1
      const nameStart = n
      while (ctx.ident(n) && (ctx.is(n + 1, '.') || ctx.is(n + 1, '?.'))) n += 2
      if (!ctx.ident(n)) break
      decorators.push(normalizeCallee(ctx.text(nameStart, n + 1)))
      n++
      if (ctx.is(n, '(')) {
        const m = ctx.match[n]!
        if (m < 0) break
        n = m + 1
      }
      s = n
    }
    while (ctx.ident(s) && PARAM_MODIFIERS.has(ctx.at(s).value) && (ctx.ident(s + 1) || ctx.is(s + 1, '{'))) s++
    let splat: ParamFact['splat']
    if (ctx.is(s, '...')) {
      splat = '...'
      s++
    }
    if (ctx.ident(s, 'this') && ctx.is(s + 1, ':')) continue
    let patEnd = s + 1
    const pt = ctx.at(s)
    if (pt.type === 'punct' && (pt.value === '{' || pt.value === '[')) {
      const m = ctx.match[s]!
      patEnd = m < 0 ? s + 1 : m + 1
    } else if (pt.type !== 'ident') continue
    const targets = patternTargets(ctx, s, patEnd)
    let q = patEnd
    if (ctx.is(q, '?')) q++
    let annotation: string | undefined
    let defaultValue: Span | undefined
    if (ctx.is(q, ':')) {
      let r = q + 1
      while (r < pe && !ctx.is(r, '=')) {
        const t = ctx.at(r)
        if (t.type === 'punct' && (t.value === '(' || t.value === '[' || t.value === '{')) {
          const m = ctx.match[r]!
          if (m < 0 || m >= pe) break
          r = m + 1
          continue
        }
        if (t.type === 'punct' && t.value === '<') {
          const m = skipTypeArgsForward(ctx, r)
          if (m > 0 && m < pe) {
            r = m + 1
            continue
          }
        }
        r++
      }
      annotation = ctx.text(q + 1, r).trim()
      q = r
    }
    if (ctx.is(q, '=') && q + 1 < pe) defaultValue = ctx.span(q + 1, pe)
    out.push({
      ...ctx.span(ps, pe),
      name: targets[0]?.name ?? '',
      names: targets.map(target => target.name),
      ...(annotation ? { annotation } : {}),
      ...(defaultValue ? { defaultValue } : {}),
      decorators,
      ...(splat ? { splat } : {}),
    })
  }
  return out
}

// ---------------------------------------------------------------------------
// AST-mode facts
// ---------------------------------------------------------------------------

const AST_KINDS = [
  'call_expression',
  'new_expression',
  'function_declaration',
  'generator_function_declaration',
  'function_expression',
  'function',
  'generator_function',
  'arrow_function',
  'method_definition',
  'class_declaration',
  'class',
  'abstract_class_declaration',
  'variable_declarator',
  'assignment_expression',
  'augmented_assignment_expression',
  'import_statement',
  'export_statement',
  'for_in_statement',
]

function astFacts(ctx: JsCtx, root: SgNode, lang: string): RawFacts {
  const raw = emptyRaw()
  const nodes = findAllKinds(root, lang, AST_KINDS)
  for (const node of nodes) {
    try {
      switch (node.kind()) {
        case 'call_expression':
        case 'new_expression': {
          const call = astCall(node)
          if (call) raw.calls.push(call)
          break
        }
        case 'function_declaration':
        case 'generator_function_declaration':
        case 'function_expression':
        case 'function':
        case 'generator_function':
        case 'arrow_function':
        case 'method_definition': {
          const fn = astFunction(ctx, node)
          if (fn) raw.fns.push(fn)
          break
        }
        case 'class_declaration':
        case 'class':
        case 'abstract_class_declaration': {
          const cls = astClass(node)
          if (cls) raw.classes.push(cls)
          break
        }
        case 'variable_declarator':
          astDeclarator(ctx, node, raw)
          break
        case 'assignment_expression':
        case 'augmented_assignment_expression':
          astAssignment(ctx, node, raw)
          break
        case 'import_statement':
          astImport(node, raw)
          break
        case 'export_statement':
          astExport(node, raw)
          break
        case 'for_in_statement':
          astForIn(ctx, node, raw)
          break
      }
    } catch {
      // A node the grammar shaped unexpectedly: skip it.
    }
  }
  return raw
}

function spanOf(node: SgNode): Span {
  const r = node.range()
  return { start: r.start.index, end: r.end.index }
}

/** Token index range `[from, to)` covering a node. */
function tokensOf(ctx: JsCtx, span: Span): [number, number] {
  const from = tokenAt(ctx.tokens, span.start)
  let to = tokenAt(ctx.tokens, span.end)
  while (to > from && ctx.at(to - 1).end > span.end) to--
  return [from, to]
}

function astCall(node: SgNode): CallFact | undefined {
  const isNew = node.kind() === 'new_expression'
  const fnNode = isNew ? node.field('constructor') : node.field('function')
  if (!fnNode) return undefined
  const argsNode = node.field('arguments')
  if (isNew && !argsNode) return undefined
  const tagged = argsNode?.kind() === 'template_string'
  const calleeText = normalizeCallee(fnNode.text())
  const [receiver, name] = splitCallee(calleeText)
  const args: ArgFact[] = []
  if (argsNode) {
    if (tagged) args.push(spanOf(argsNode))
    else {
      for (const child of argsNode.children()) {
        if (!child.isNamed() || child.kind() === 'comment') continue
        if (child.kind() === 'spread_element') {
          const inner = child.children().find(c => c.isNamed())
          args.push({ ...(inner ? spanOf(inner) : spanOf(child)), splat: '...' })
        } else args.push(spanOf(child))
      }
    }
  }
  const parent = node.parent()
  return {
    callee: calleeText,
    name: fnNode.kind() === 'import' ? 'import' : name,
    receiver,
    calleeSpan: spanOf(fnNode),
    isNew,
    tagged,
    args,
    decorator: parent?.kind() === 'decorator',
    ...spanOf(node),
    fn: undefined,
  }
}

function astFunction(ctx: JsCtx, node: SgNode): FnFact | undefined {
  const kind = node.kind()
  const body = node.field('body')
  if (!body) return undefined
  const span = spanOf(node)
  let name = node.field('name')?.text()
  const parent = node.parent()
  if (!name && parent) name = astInferName(parent)
  let params: ParamFact[] = []
  const paramsNode = node.field('parameters')
  if (paramsNode) {
    const [from, to] = tokensOf(ctx, spanOf(paramsNode))
    if (ctx.is(from, '(') && ctx.is(to - 1, ')')) params = parseJsParams(ctx, from + 1, to - 1)
  } else {
    const single = node.field('parameter')
    if (single) params = [{ ...spanOf(single), name: single.text(), names: [single.text()], decorators: [] }]
  }
  let declStart = span.start
  let exported = false
  let decorators: DecoratorFact[] = []
  if (kind === 'method_definition') {
    decorators = astSiblingDecorators(node)
    if (decorators[0]) declStart = decorators[0].start
  } else {
    let holder: SgNode | null = parent
    if (holder?.kind() === 'variable_declarator') holder = holder.parent()
    if (holder && (holder.kind() === 'lexical_declaration' || holder.kind() === 'variable_declaration')) {
      declStart = spanOf(holder).start
      holder = holder.parent()
    }
    if (holder?.kind() === 'export_statement') {
      exported = true
      declStart = spanOf(holder).start
    }
  }
  return {
    name,
    kind: kind === 'method_definition' ? 'method' : kind === 'arrow_function' ? 'arrow' : 'function',
    ...span,
    body: spanOf(body),
    params,
    decorators,
    declStart,
    exported,
    parent: undefined,
    className: undefined,
  }
}

function astInferName(parent: SgNode): string | undefined {
  switch (parent.kind()) {
    case 'variable_declarator': {
      const n = parent.field('name')
      return n?.kind() === 'identifier' ? n.text() : undefined
    }
    case 'assignment_expression': {
      const left = parent.field('left')
      if (!left) return undefined
      if (left.kind() === 'identifier') return left.text()
      if (left.kind() === 'member_expression') return left.field('property')?.text()
      return undefined
    }
    case 'pair': {
      const key = parent.field('key')
      if (!key) return undefined
      return key.kind() === 'string' ? key.text().slice(1, -1) : key.text()
    }
    case 'public_field_definition':
    case 'field_definition': {
      const n = parent.field('name') ?? parent.field('property')
      return n?.text()
    }
    case 'export_statement':
      return 'default'
    default:
      return undefined
  }
}

/** Decorators preceding a class member (tree-sitter puts them as siblings in the class body). */
function astSiblingDecorators(node: SgNode): DecoratorFact[] {
  const parent = node.parent()
  if (!parent) return []
  const siblings = parent.children()
  const index = siblings.findIndex(s => s.range().start.index === node.range().start.index && s.kind() === node.kind())
  const out: DecoratorFact[] = []
  for (let i = index - 1; i >= 0; i--) {
    const s = siblings[i]!
    if (s.kind() === 'comment') continue
    if (s.kind() !== 'decorator') break
    out.unshift(astDecorator(s))
  }
  // Decorators may also be direct children of the member (some grammar versions).
  for (const child of node.children()) if (child.kind() === 'decorator') out.push(astDecorator(child))
  return out
}

function astDecorator(node: SgNode): DecoratorFact {
  const expr = node.children().find(c => c.isNamed() && c.kind() !== 'comment')
  const span = spanOf(node)
  if (expr?.kind() === 'call_expression') {
    const fn = expr.field('function')
    const argsNode = expr.field('arguments')
    const args: ArgFact[] = []
    for (const child of argsNode?.children() ?? []) {
      if (child.isNamed() && child.kind() !== 'comment') args.push(spanOf(child))
    }
    return { name: normalizeCallee(fn?.text() ?? ''), args, ...span }
  }
  return { name: normalizeCallee(expr?.text() ?? ''), ...span }
}

function astClass(node: SgNode): ClassFact | undefined {
  const body = node.field('body')
  if (!body) return undefined
  const span = spanOf(node)
  const bases: string[] = []
  for (const child of node.children()) {
    if (child.kind() !== 'class_heritage') continue
    for (const clause of child.children()) {
      if (clause.kind() !== 'extends_clause') continue
      for (const v of clause.children()) {
        if (v.isNamed() && v.kind() !== 'type_arguments') bases.push(normalizeCallee(v.text()))
      }
    }
    if (bases.length === 0) {
      const text = child.text().replace(/^\s*extends\s+/, '')
      bases.push(normalizeCallee(text.split(/\s+implements\s+/)[0] ?? text))
    }
  }
  const decorators: DecoratorFact[] = []
  for (const child of node.children()) if (child.kind() === 'decorator') decorators.push(astDecorator(child))
  let declStart = span.start
  let exported = false
  const parent = node.parent()
  if (parent?.kind() === 'export_statement') {
    exported = true
    declStart = spanOf(parent).start
    for (const child of parent.children()) if (child.kind() === 'decorator') decorators.push(astDecorator(child))
  }
  decorators.sort((a, b) => a.start - b.start)
  if (decorators[0] && decorators[0].start < declStart) declStart = decorators[0].start
  let name = node.field('name')?.text()
  if (!name && parent) name = astInferName(parent)
  return { name, ...span, body: spanOf(body), bases, decorators, declStart, exported }
}

function astDeclarator(ctx: JsCtx, node: SgNode, raw: RawFacts): void {
  const nameNode = node.field('name')
  const valueNode = node.field('value')
  if (!nameNode || !valueNode) return
  const [pf, pt] = tokensOf(ctx, spanOf(nameNode))
  const targets = patternTargets(ctx, pf, pt)
  const destructured = nameNode.kind() !== 'identifier'
  const value = spanOf(valueNode)
  raw.assigns.push({
    targets,
    op: '=',
    value,
    destructured,
    start: spanOf(nameNode).start,
    end: value.end,
    fn: undefined,
  })
  const decl = node.parent()
  const holder = decl?.parent()
  if (!destructured && decl && holder && (holder.kind() === 'program' || holder.kind() === 'export_statement')) {
    const vk = valueNode.kind()
    raw.vars.push({
      name: nameNode.text(),
      start: spanOf(holder.kind() === 'export_statement' ? holder : decl).start,
      end: value.end,
      exported: holder.kind() === 'export_statement',
      isFn: vk === 'arrow_function' || vk === 'function_expression' || vk === 'function',
      value,
    })
  }
}

function astAssignment(ctx: JsCtx, node: SgNode, raw: RawFacts): void {
  const left = node.field('left')
  const right = node.field('right')
  if (!left || !right) return
  const op = node.kind() === 'assignment_expression' ? '=' : (node.field('operator')?.text() ?? '+=')
  const value = spanOf(right)
  const span = spanOf(node)
  const lk = left.kind()
  if (lk === 'identifier') {
    raw.assigns.push({ targets: [{ name: left.text() }], op, value, destructured: false, ...span, fn: undefined })
  } else if (lk === 'member_expression' || lk === 'subscript_expression') {
    let prop = ''
    if (lk === 'member_expression') prop = left.field('property')?.text() ?? ''
    else {
      const index = left.field('index')
      if (index?.kind() === 'string') prop = index.text().slice(1, -1)
    }
    raw.memberAssigns.push({ target: normalizeCallee(left.text()), prop, op, value, ...span, fn: undefined })
  } else if (lk === 'object_pattern' || lk === 'array_pattern' || lk === 'parenthesized_expression') {
    const [pf, pt] = tokensOf(ctx, spanOf(left))
    raw.assigns.push({ targets: patternTargets(ctx, pf, pt), op, value, destructured: true, ...span, fn: undefined })
  }
}

function astForIn(ctx: JsCtx, node: SgNode, raw: RawFacts): void {
  const left = node.field('left')
  const right = node.field('right')
  if (!left || !right) return
  const [pf, pt] = tokensOf(ctx, spanOf(left))
  const value = spanOf(right)
  raw.assigns.push({
    targets: patternTargets(ctx, pf, pt),
    op: 'for',
    value,
    destructured: true,
    start: spanOf(left).start,
    end: value.end,
    fn: undefined,
  })
}

function astImport(node: SgNode, raw: RawFacts): void {
  const sourceNode = node.field('source')
  if (!sourceNode) return
  const bindings: ImportBinding[] = []
  for (const child of node.children()) {
    if (child.kind() !== 'import_clause') continue
    for (const part of child.children()) {
      switch (part.kind()) {
        case 'identifier':
          bindings.push({ local: part.text(), imported: 'default' })
          break
        case 'namespace_import': {
          const id = part.children().find(c => c.kind() === 'identifier')
          if (id) bindings.push({ local: id.text(), imported: '*' })
          break
        }
        case 'named_imports':
          for (const spec of part.children()) {
            if (spec.kind() !== 'import_specifier') continue
            const name = spec.field('name')?.text()
            const alias = spec.field('alias')?.text()
            if (name) bindings.push({ local: alias ?? name, imported: name })
          }
          break
      }
    }
  }
  raw.imports.push({ source: unquote(sourceNode.text()), bindings, start: spanOf(node).start, kind: 'import' })
}

function astExport(node: SgNode, raw: RawFacts): void {
  const sourceNode = node.field('source')
  const specs: ImportBinding[] = []
  for (const child of node.children()) {
    if (child.kind() !== 'export_clause') continue
    for (const spec of child.children()) {
      if (spec.kind() !== 'export_specifier') continue
      const name = spec.field('name')?.text()
      const alias = spec.field('alias')?.text()
      if (name) specs.push({ local: alias ?? name, imported: name })
    }
  }
  if (sourceNode) {
    raw.imports.push({
      source: unquote(sourceNode.text()),
      bindings: specs,
      start: spanOf(node).start,
      kind: 'export-from',
    })
    for (const s of specs) raw.exportedNames.add(s.local)
    return
  }
  for (const s of specs) {
    raw.exportedNames.add(s.imported)
    if (s.local !== s.imported) raw.exportAliases.push({ local: s.imported, exported: s.local })
  }
  const value = node.field('value')
  if (value?.kind() === 'identifier') {
    raw.exportedNames.add(value.text())
    raw.defaultExport = value.text()
  } else if (!value) {
    for (const child of node.children()) {
      if (child.kind() === 'identifier' && node.text().includes('default')) {
        raw.exportedNames.add(child.text())
        raw.defaultExport = child.text()
      }
    }
  }
}

function unquote(text: string): string {
  return text.replace(/^['"`]|['"`]$/g, '')
}

// ---------------------------------------------------------------------------
// Mode-independent post-processing
// ---------------------------------------------------------------------------

const REQUIRE_RE =
  /^(?:await\s+)?(?:require|import)\s*\(\s*(['"`])([^'"`]+)\1\s*\)(?:\s*\.\s*([A-Za-z_$][\w$]*))?\s*;?$/

function postProcess(ctx: JsCtx, raw: RawFacts): void {
  // Bindings from declarations: `const x = require('m')`, `const { a } = require('m')`, `const { b } = await import('m')`.
  const requireStarts = new Set<number>()
  for (const assign of raw.assigns) {
    if (assign.op !== '=') continue
    const text = ctx.src.slice(assign.value.start, assign.value.end).trim()
    const m = REQUIRE_RE.exec(text)
    if (!m) continue
    const source = m[2]!
    const member = m[3]
    const bindings: ImportBinding[] = assign.targets.map(target => ({
      local: target.name,
      imported: assign.destructured ? (target.key?.split('.')[0] ?? target.name) : (member ?? '*'),
    }))
    const kind = /^(?:await\s+)?import\b/.test(text) ? 'dynamic' : 'require'
    raw.imports.push({ source, bindings, start: assign.start, kind })
    requireStarts.add(assign.value.start)
  }
  // Bare `require('m')` and dynamic `import('m')` calls.
  for (const call of raw.calls) {
    if ((call.callee !== 'require' && call.callee !== 'import') || call.args.length === 0) continue
    const arg = call.args[0]!
    const text = ctx.src.slice(arg.start, arg.end)
    const m = /^(['"`])([^'"`$]+)\1$/.exec(text.trim())
    if (!m) continue
    if ([...requireStarts].some(s => s <= call.start && call.start <= s + 8)) continue
    raw.imports.push({
      source: m[2]!,
      bindings: [],
      start: call.start,
      kind: call.callee === 'require' ? 'require' : 'dynamic',
    })
  }
  // CommonJS exports.
  for (const assign of raw.memberAssigns) {
    if (assign.op !== '=') continue
    const value = ctx.src.slice(assign.value.start, assign.value.end).trim()
    if (assign.target === 'module.exports') {
      if (/^[A-Za-z_$][\w$]*$/.test(value)) {
        raw.exportedNames.add(value)
        raw.defaultExport = value
      } else if (value.startsWith('{')) {
        const [from] = tokensOf(ctx, assign.value)
        if (ctx.is(from, '{')) {
          for (const pair of objectEntries(ctx, from)) {
            if (pair.valueIdent) raw.exportedNames.add(pair.valueIdent)
            else if (pair.key) raw.exportedNames.add(pair.key)
          }
        }
      }
    } else if (/^(?:module\.)?exports\.[A-Za-z_$][\w$]*$/.test(assign.target)) {
      raw.exportedNames.add(assign.prop)
      if (/^[A-Za-z_$][\w$]*$/.test(value)) raw.exportedNames.add(value)
    }
  }
}

interface ObjectEntry {
  readonly key: string | undefined
  readonly valueIdent: string | undefined
}

/** Top-level entries of the object literal opening at token `open`. */
function objectEntries(ctx: JsCtx, open: number): ObjectEntry[] {
  const close = ctx.match[open]!
  if (close < 0) return []
  const out: ObjectEntry[] = []
  let a = open + 1
  const entry = (b: number): void => {
    if (b <= a) return
    const k = ctx.at(a)
    if (ctx.is(a, '...')) return
    const key = k.type === 'str' ? stringContent(k) : k.type === 'ident' ? k.value : undefined
    if (b === a + 1 && k.type === 'ident') out.push({ key, valueIdent: k.value })
    else if (ctx.is(a + 1, ':') && b === a + 3 && ctx.ident(a + 2)) out.push({ key, valueIdent: ctx.at(a + 2).value })
    else out.push({ key, valueIdent: undefined })
  }
  let k = open + 1
  while (k < close) {
    const t = ctx.at(k)
    if (t.type === 'punct' && (t.sub === 'open' || t.value === '(' || t.value === '[' || t.value === '{')) {
      const m = ctx.match[k]!
      if (m < 0) break
      k = m + 1
      continue
    }
    if (t.type === 'punct' && t.value === ',') {
      entry(k)
      a = k + 1
    }
    k++
  }
  entry(close)
  return out
}
