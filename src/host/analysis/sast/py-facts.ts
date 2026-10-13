/**
 * Builds the code model for Python, from the native AST when
 * `@ast-grep/lang-python` is available, otherwise from tokens plus
 * indentation (block ends are found by dedent, like the interpreter does).
 */

import { findAllKinds, type SgNode } from '../astgrep.ts'
import { lexPython, lineStarts, matchBrackets, PY_KEYWORDS, stringContent, type Token, tokenAt } from './lexer.ts'
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

const AUG_OPS: ReadonlySet<string> = new Set([
  '+=',
  '-=',
  '*=',
  '/=',
  '//=',
  '%=',
  '**=',
  '>>=',
  '<<=',
  '&=',
  '|=',
  '^=',
  '@=',
])

/** Build the model for a Python file. `astRoot` selects AST mode. */
export function buildPyModel(path: string, source: string, astRoot?: SgNode, astLang?: string): FileModel {
  const tokens = lexPython(source)
  const match = matchBrackets(tokens)
  const ctx = new PyCtx(source, tokens, match)
  const raw = astRoot && astLang ? astFacts(ctx, astRoot, astLang) : tokenFacts(ctx)
  addModuleExports(ctx, raw)
  const facts = finalizeFacts(raw)
  for (const fn of facts.fns) {
    if (!fn.parent && fn.className === undefined && fn.name && isPublic(fn.name, raw)) fn.exported = true
  }
  for (const cls of facts.classes) if (cls.name && isPublic(cls.name, raw) && cls.declStart >= 0) cls.exported = true
  return {
    path,
    lang: 'py',
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
    defaultExport: undefined,
  }
}

function isPublic(name: string, raw: RawFacts): boolean {
  if (raw.exportedNames.size > 0 && raw.exportedNames.has('__all__')) return raw.exportedNames.has(name)
  return !name.startsWith('_')
}

class PyCtx {
  readonly src: string
  readonly tokens: readonly Token[]
  readonly match: Int32Array
  /** Index of the first token of the logical line containing each token. */
  readonly lineHead: Int32Array

  constructor(src: string, tokens: readonly Token[], match: Int32Array) {
    this.src = src
    this.tokens = tokens
    this.match = match
    this.lineHead = new Int32Array(tokens.length)
    let depth = 0
    let head = 0
    for (let i = 0; i < tokens.length; i++) {
      const t = tokens[i]!
      if (t.nl && depth === 0) head = i
      this.lineHead[i] = head
      if (t.type === 'punct') {
        if (t.value === '(' || t.value === '[' || t.value === '{' || t.sub === 'open') depth++
        else if (t.value === ')' || t.value === ']' || t.value === '}') depth = Math.max(0, depth - 1)
      }
    }
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

  isMemberName(i: number): boolean {
    return this.is(i - 1, '.')
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

  /** Whether token `i` starts a logical line. */
  isLineStart(i: number): boolean {
    return this.lineHead[i] === i
  }

  /** Exclusive end index of the logical line starting at `head`. */
  lineEnd(head: number): number {
    let k = head + 1
    while (k < this.tokens.length && this.lineHead[k] === head) k++
    return k
  }

  /** Column of a token (characters since the start of its physical line). */
  column(i: number): number {
    const t = this.at(i)
    const nl = this.src.lastIndexOf('\n', t.start - 1)
    return t.start - (nl + 1)
  }

  /** Exclusive end index of the block whose header line starts at `head` (indentation based). */
  blockEnd(head: number, colon: number): number {
    const lineEnd = this.lineEnd(head)
    if (colon + 1 < lineEnd) return lineEnd // one-line body: `def f(): return 1`
    const indent = this.column(head)
    let k = lineEnd
    while (k < this.tokens.length) {
      if (this.isLineStart(k) && this.column(k) <= indent) break
      k++
    }
    return k
  }

  /** Index of the depth-0 `:` that ends a compound statement header starting at `from`. */
  headerColon(from: number, lineEnd: number): number {
    let k = from
    while (k < lineEnd) {
      const t = this.at(k)
      if (t.type === 'punct' && (t.value === '(' || t.value === '[' || t.value === '{' || t.sub === 'open')) {
        const m = this.match[k]!
        if (m < 0) return -1
        k = m + 1
        continue
      }
      if (t.type === 'punct' && t.value === ':' && t.sub === undefined) return k
      if (t.type === 'ident' && t.value === 'lambda') {
        // skip the lambda's own `:`
        let q = k + 1
        while (q < lineEnd && !this.is(q, ':')) q++
        k = q + 1
        continue
      }
      k++
    }
    return -1
  }

  /** Start of the dotted/called chain ending at token `end`. */
  chainStart(end: number): number {
    let cur = end
    for (let guard = 0; guard < 64; guard++) {
      const t = this.tokens[cur]
      if (!t) return end
      if (t.type === 'punct' && (t.value === ')' || t.value === ']')) {
        const m = this.match[cur]!
        if (m < 0) return cur
        const before = this.tokens[m - 1]
        if (before && (before.type === 'ident' || before.value === ')' || before.value === ']')) {
          if (before.type === 'ident' && PY_KEYWORDS.has(before.value)) return m
          cur = m - 1
          continue
        }
        if (before && before.type === 'str' && this.is(m - 2, '.')) return m - 1
        return m
      }
      if (t.type === 'ident' && this.is(cur - 1, '.')) {
        const p = this.tokens[cur - 2]
        if (!p) return cur
        if (p.type === 'ident' || p.value === ')' || p.value === ']') {
          cur = cur - 2
          continue
        }
        if (p.type === 'str') return cur - 2
        return cur
      }
      return cur
    }
    return cur
  }
}

// ---------------------------------------------------------------------------
// Token mode
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

function tokenFacts(ctx: PyCtx): RawFacts {
  const raw = emptyRaw()
  const { tokens } = ctx
  const defParens = new Set<number>()
  let pendingDecorators: DecoratorFact[] = []
  for (let head = 0; head < tokens.length; ) {
    const end = ctx.lineEnd(head)
    const t = ctx.at(head)
    let k = head
    if (t.type === 'punct' && t.value === '@') {
      const dec = tokenDecorator(ctx, head, end)
      if (dec) pendingDecorators.push(dec)
      head = end
      continue
    }
    if (ctx.ident(k, 'async') && ctx.ident(k + 1, 'def')) k++
    if (ctx.ident(k, 'def') && ctx.ident(k + 1) && ctx.is(k + 2, '(')) {
      const fn = tokenDef(ctx, head, k, end, pendingDecorators)
      if (fn) {
        raw.fns.push(fn)
        defParens.add(k + 2)
      }
    } else if (ctx.ident(k, 'class') && ctx.ident(k + 1)) {
      const cls = tokenClass(ctx, head, end, pendingDecorators)
      if (cls) raw.classes.push(cls)
    } else if (ctx.ident(k, 'import') || ctx.ident(k, 'from')) {
      tokenImport(ctx, head, end, raw)
    } else if (ctx.ident(k, 'for') || (ctx.ident(k, 'async') && ctx.ident(k + 1, 'for'))) {
      tokenFor(ctx, ctx.ident(k, 'async') ? k + 1 : k, end, raw)
    } else if (ctx.ident(k, 'with') || (ctx.ident(k, 'async') && ctx.ident(k + 1, 'with'))) {
      tokenWith(ctx, ctx.ident(k, 'async') ? k + 1 : k, end, raw)
    } else {
      tokenAssignment(ctx, head, end, raw)
    }
    pendingDecorators = []
    head = end
  }
  for (let i = 0; i < tokens.length; i++) {
    if (!ctx.is(i, '(') || defParens.has(i)) continue
    const call = tokenCall(ctx, i)
    if (call) raw.calls.push(call)
  }
  return raw
}

function tokenDecorator(ctx: PyCtx, head: number, end: number): DecoratorFact | undefined {
  let k = head + 1
  const nameStart = k
  while (ctx.ident(k) && ctx.is(k + 1, '.')) k += 2
  if (!ctx.ident(k)) return undefined
  const name = normalizeCallee(ctx.text(nameStart, k + 1))
  let args: ArgFact[] | undefined
  if (ctx.is(k + 1, '(')) {
    const close = ctx.match[k + 1]!
    if (close > 0) args = splitPyArgs(ctx, k + 2, close)
  }
  return { name, start: ctx.at(head).start, end: ctx.at(end - 1).end, ...(args ? { args } : {}) }
}

function tokenDef(
  ctx: PyCtx,
  head: number,
  defTok: number,
  end: number,
  decorators: DecoratorFact[],
): FnFact | undefined {
  const open = defTok + 2
  const close = ctx.match[open]!
  if (close < 0) return undefined
  const colon = ctx.headerColon(close + 1, end)
  if (colon < 0) return undefined
  const blockEnd = ctx.blockEnd(head, colon)
  const lastTok = Math.max(colon, blockEnd - 1)
  return {
    name: ctx.at(defTok + 1).value,
    kind: 'function',
    start: ctx.at(head).start,
    end: ctx.at(lastTok).end,
    body: { start: ctx.at(Math.min(colon + 1, lastTok)).start, end: ctx.at(lastTok).end },
    params: parsePyParams(ctx, open + 1, close),
    decorators,
    declStart: decorators[0]?.start ?? ctx.at(head).start,
    exported: false,
    parent: undefined,
    className: undefined,
  }
}

function tokenClass(ctx: PyCtx, head: number, end: number, decorators: DecoratorFact[]): ClassFact | undefined {
  const colon = ctx.headerColon(head + 2, end)
  if (colon < 0) return undefined
  const bases: string[] = []
  if (ctx.is(head + 2, '(')) {
    const close = ctx.match[head + 2]!
    if (close > 0) {
      for (const arg of splitPyArgs(ctx, head + 3, close)) {
        if (!arg.keyword && !arg.splat) bases.push(normalizeCallee(ctx.src.slice(arg.start, arg.end)))
      }
    }
  }
  const blockEnd = ctx.blockEnd(head, colon)
  const lastTok = Math.max(colon, blockEnd - 1)
  return {
    name: ctx.at(head + 1).value,
    start: ctx.at(head).start,
    end: ctx.at(lastTok).end,
    body: { start: ctx.at(Math.min(colon + 1, lastTok)).start, end: ctx.at(lastTok).end },
    bases,
    decorators,
    declStart: decorators[0]?.start ?? ctx.at(head).start,
    exported: false,
  }
}

function tokenImport(ctx: PyCtx, head: number, end: number, raw: RawFacts): void {
  if (ctx.ident(head, 'import')) {
    for (const [a, b] of splitTop(ctx, head + 1, end)) {
      const asAt = findIdent(ctx, a, b, 'as')
      const modEnd = asAt < 0 ? b : asAt
      const source = ctx.text(a, modEnd).replace(/\s+/g, '')
      if (!source) continue
      const local = asAt >= 0 ? ctx.at(asAt + 1).value : (source.split('.')[0] ?? source)
      raw.imports.push({ source, bindings: [{ local, imported: '*' }], start: ctx.at(head).start, kind: 'import' })
    }
    return
  }
  const importAt = findIdent(ctx, head + 1, end, 'import')
  if (importAt < 0) return
  const source = ctx.text(head + 1, importAt).replace(/\s+/g, '')
  let a = importAt + 1
  let b = end
  if (ctx.is(a, '(')) {
    const close = ctx.match[a]!
    if (close > 0) b = close
    a++
  }
  const bindings: ImportBinding[] = []
  for (const [s, e] of splitTop(ctx, a, b)) {
    if (ctx.is(s, '*')) {
      bindings.push({ local: '*', imported: '*' })
      continue
    }
    if (!ctx.ident(s)) continue
    const imported = ctx.at(s).value
    const local = ctx.ident(s + 1, 'as') && ctx.ident(s + 2) && s + 2 < e ? ctx.at(s + 2).value : imported
    bindings.push({ local, imported })
  }
  raw.imports.push({ source, bindings, start: ctx.at(head).start, kind: 'from' })
}

function tokenFor(ctx: PyCtx, forTok: number, end: number, raw: RawFacts): void {
  const inAt = findIdent(ctx, forTok + 1, end, 'in')
  if (inAt < 0) return
  const colon = ctx.headerColon(inAt + 1, end)
  const valueEnd = colon < 0 ? end : colon
  if (valueEnd <= inAt + 1) return
  const value = ctx.span(inAt + 1, valueEnd)
  raw.assigns.push({
    targets: pyTargets(ctx, forTok + 1, inAt),
    op: 'for',
    value,
    destructured: true,
    start: ctx.at(forTok + 1).start,
    end: value.end,
    fn: undefined,
  })
}

function tokenWith(ctx: PyCtx, withTok: number, end: number, raw: RawFacts): void {
  const colon = ctx.headerColon(withTok + 1, end)
  let a = withTok + 1
  let b = colon < 0 ? end : colon
  if (ctx.is(a, '(') && ctx.match[a] === b - 1) {
    a++
    b--
  }
  for (const [s, e] of splitTop(ctx, a, b)) {
    const asAt = findIdent(ctx, s, e, 'as')
    if (asAt < 0 || asAt + 1 >= e) continue
    const value = ctx.span(s, asAt)
    raw.assigns.push({
      targets: pyTargets(ctx, asAt + 1, e),
      op: 'with',
      value,
      destructured: false,
      start: value.start,
      end: ctx.at(e - 1).end,
      fn: undefined,
    })
  }
}

function tokenAssignment(ctx: PyCtx, head: number, end: number, raw: RawFacts): void {
  // Depth-0 `=` / augmented operators split the line into targets and a value.
  const eqs: number[] = []
  let aug = -1
  let k = head
  while (k < end) {
    const t = ctx.at(k)
    if (t.type === 'punct' && (t.value === '(' || t.value === '[' || t.value === '{' || t.sub === 'open')) {
      const m = ctx.match[k]!
      if (m < 0) return
      k = m + 1
      continue
    }
    if (t.type === 'ident' && t.value === 'lambda') return
    if (t.type === 'punct' && t.value === '=') eqs.push(k)
    else if (t.type === 'punct' && AUG_OPS.has(t.value) && aug < 0 && eqs.length === 0) aug = k
    k++
  }
  if (aug >= 0) {
    const value = ctx.span(aug + 1, end)
    if (aug + 1 >= end) return
    addPyAssign(ctx, raw, head, aug, ctx.at(aug).value, value)
    return
  }
  if (eqs.length === 0) return
  const last = eqs[eqs.length - 1]!
  if (last + 1 >= end) return
  const value = ctx.span(last + 1, end)
  let from = head
  for (const eq of eqs) {
    addPyAssign(ctx, raw, from, eq, '=', value)
    from = eq + 1
  }
  if (
    eqs.length === 1 &&
    ctx.ident(head) &&
    (head + 1 === eqs[0] || ctx.is(head + 1, ':')) &&
    !ctx.isMemberName(head)
  ) {
    const isTop = ctx.column(head) === 0
    if (isTop) {
      raw.vars.push({
        name: ctx.at(head).value,
        start: ctx.at(head).start,
        end: value.end,
        exported: false,
        isFn: ctx.ident(last + 1, 'lambda'),
        value,
      })
    }
  }
}

/** One `targets <op> value` assignment; targets are `[from, opTok)`, possibly annotated. */
function addPyAssign(ctx: PyCtx, raw: RawFacts, from: number, opTok: number, op: string, value: Span): void {
  let to = opTok
  // `x: int = v` — drop the annotation.
  const colon = findTopPunct(ctx, from, to, ':')
  if (colon >= 0) to = colon
  if (to <= from) return
  const first = ctx.at(from)
  const lastTok = ctx.at(to - 1)
  const single = to - from === 1 && first.type === 'ident'
  if (single) {
    raw.assigns.push({
      targets: [{ name: first.value }],
      op,
      value,
      destructured: false,
      start: first.start,
      end: value.end,
      fn: undefined,
    })
    return
  }
  // Attribute or subscript target: `self.x = v`, `app.config['K'] = v`.
  if ((lastTok.type === 'ident' && ctx.is(to - 2, '.')) || (lastTok.type === 'punct' && lastTok.value === ']')) {
    if (findTopPunct(ctx, from, to, ',') < 0) {
      let prop = ''
      if (lastTok.type === 'ident') prop = lastTok.value
      else {
        const open = ctx.match[to - 1]!
        const inner = ctx.at(open + 1)
        if (open >= 0 && inner.type === 'str' && open + 2 === to - 1) prop = stringContent(inner)
      }
      raw.memberAssigns.push({
        target: normalizeCallee(ctx.text(from, to)),
        prop,
        op,
        value,
        start: first.start,
        end: value.end,
        fn: undefined,
      })
      return
    }
  }
  const targets = pyTargets(ctx, from, to)
  if (targets.length > 0) {
    raw.assigns.push({ targets, op, value, destructured: true, start: first.start, end: value.end, fn: undefined })
  }
}

/** Names bound by a target list such as `a, (b, c)` or `[x, *rest]`. */
function pyTargets(ctx: PyCtx, from: number, to: number): AssignTarget[] {
  const out: AssignTarget[] = []
  let index = 0
  for (const [s, e] of splitTop(ctx, from, to)) {
    let a = s
    if (ctx.is(a, '*')) a++
    if (e - a === 1 && ctx.ident(a)) out.push({ name: ctx.at(a).value, key: String(index) })
    else if ((ctx.is(a, '(') || ctx.is(a, '[')) && ctx.match[a] === e - 1) {
      for (const inner of pyTargets(ctx, a + 1, e - 1))
        out.push({ name: inner.name, key: `${index}.${inner.key ?? ''}` })
    }
    index++
  }
  return out
}

function tokenCall(ctx: PyCtx, open: number): CallFact | undefined {
  const close = ctx.match[open]!
  if (close < 0) return undefined
  const q = open - 1
  const ct = ctx.tokens[q]
  if (!ct) return undefined
  if (ct.type === 'ident') {
    if (!ctx.isMemberName(q) && PY_KEYWORDS.has(ct.value)) return undefined
    if (ctx.ident(q - 1, 'def') || ctx.ident(q - 1, 'class')) return undefined
  } else if (!(ct.type === 'punct' && (ct.value === ')' || ct.value === ']'))) {
    return undefined
  }
  const cs = ctx.chainStart(q)
  const calleeText = normalizeCallee(ctx.text(cs, q + 1))
  const [receiver, name] = splitCallee(calleeText)
  const head = ctx.lineHead[cs]!
  return {
    callee: calleeText,
    name,
    receiver,
    calleeSpan: ctx.span(cs, q + 1),
    isNew: false,
    tagged: false,
    args: splitPyArgs(ctx, open + 1, close),
    decorator: ctx.is(head, '@') && cs === head + 1,
    start: ctx.at(cs).start,
    end: ctx.at(close).end,
    fn: undefined,
  }
}

/** Arguments between `from` and `to`, with keyword names and `*`/`**` splats. */
export function splitPyArgs(
  ctx: {
    at(i: number): Token
    is(i: number, v: string): boolean
    ident(i: number): boolean
    span(a: number, b: number): Span
    match: Int32Array
  },
  from: number,
  to: number,
): ArgFact[] {
  const out: ArgFact[] = []
  for (const [s, e] of splitTopGeneric(ctx, from, to)) {
    let a = s
    const t = ctx.at(a)
    let splat: ArgFact['splat']
    let keyword: string | undefined
    if (t.type === 'punct' && (t.value === '*' || t.value === '**')) {
      splat = t.value as '*' | '**'
      a++
    } else if (t.type === 'ident' && ctx.is(a + 1, '=') && e > a + 2) {
      keyword = t.value
      a += 2
    }
    if (e <= a) continue
    out.push({ ...ctx.span(a, e), ...(splat ? { splat } : {}), ...(keyword ? { keyword } : {}) })
  }
  return out
}

/** Parameters between the parentheses `[from, to)`. */
function parsePyParams(ctx: PyCtx, from: number, to: number): ParamFact[] {
  const out: ParamFact[] = []
  for (const [s, e] of splitTop(ctx, from, to)) {
    let a = s
    let splat: ParamFact['splat']
    if (ctx.is(a, '*') || ctx.is(a, '**')) {
      splat = ctx.at(a).value as '*' | '**'
      a++
    }
    if (!ctx.ident(a)) continue
    const name = ctx.at(a).value
    let annotation: string | undefined
    let defaultValue: Span | undefined
    let q = a + 1
    if (ctx.is(q, ':')) {
      const eq = findTopPunct(ctx, q + 1, e, '=')
      const annEnd = eq < 0 ? e : eq
      annotation = ctx.text(q + 1, annEnd).trim()
      q = annEnd
    }
    if (ctx.is(q, '=') && q + 1 < e) defaultValue = ctx.span(q + 1, e)
    out.push({
      ...ctx.span(s, e),
      name,
      names: [name],
      ...(annotation ? { annotation } : {}),
      ...(defaultValue ? { defaultValue } : {}),
      decorators: [],
      ...(splat ? { splat } : {}),
    })
  }
  return out
}

function splitTop(ctx: PyCtx, from: number, to: number): [number, number][] {
  return splitTopGeneric(ctx, from, to)
}

function splitTopGeneric(
  ctx: { at(i: number): Token; match: Int32Array },
  from: number,
  to: number,
): [number, number][] {
  const out: [number, number][] = []
  let a = from
  let k = from
  while (k < to) {
    const t = ctx.at(k)
    if (t.type === 'punct' && (t.value === '(' || t.value === '[' || t.value === '{' || t.sub === 'open')) {
      const m = ctx.match[k]!
      if (m < 0 || m >= to) break
      k = m + 1
      continue
    }
    if (t.type === 'punct' && t.value === ',' && t.sub === undefined) {
      if (k > a) out.push([a, k])
      a = k + 1
    }
    k++
  }
  if (to > a) out.push([a, to])
  return out
}

function findIdent(ctx: PyCtx, from: number, to: number, value: string): number {
  let k = from
  while (k < to) {
    const t = ctx.at(k)
    if (t.type === 'punct' && (t.value === '(' || t.value === '[' || t.value === '{')) {
      const m = ctx.match[k]!
      if (m < 0) return -1
      k = m + 1
      continue
    }
    if (t.type === 'ident' && t.value === value) return k
    k++
  }
  return -1
}

function findTopPunct(ctx: PyCtx, from: number, to: number, value: string): number {
  let k = from
  while (k < to) {
    const t = ctx.at(k)
    if (t.type === 'punct' && (t.value === '(' || t.value === '[' || t.value === '{' || t.sub === 'open')) {
      const m = ctx.match[k]!
      if (m < 0) return -1
      k = m + 1
      continue
    }
    if (t.type === 'punct' && t.value === value && t.sub === undefined) return k
    k++
  }
  return -1
}

/** `__all__ = [...]` lists the public names explicitly. */
function addModuleExports(ctx: PyCtx, raw: RawFacts): void {
  for (const assign of raw.assigns) {
    if (assign.targets.length !== 1 || assign.targets[0]!.name !== '__all__') continue
    raw.exportedNames.add('__all__')
    const [from, to] = tokenSpan(ctx, assign.value)
    for (let k = from; k < to; k++) {
      const t = ctx.at(k)
      if (t.type === 'str') raw.exportedNames.add(stringContent(t))
    }
  }
}

function tokenSpan(ctx: PyCtx, span: Span): [number, number] {
  const from = tokenAt(ctx.tokens, span.start)
  let to = tokenAt(ctx.tokens, span.end)
  while (to > from && ctx.at(to - 1).end > span.end) to--
  return [from, to]
}

// ---------------------------------------------------------------------------
// AST mode (tree-sitter-python via @ast-grep/lang-python)
// ---------------------------------------------------------------------------

const AST_KINDS = [
  'call',
  'function_definition',
  'class_definition',
  'assignment',
  'augmented_assignment',
  'for_statement',
  'with_item',
  'import_statement',
  'import_from_statement',
]

function astFacts(ctx: PyCtx, root: SgNode, lang: string): RawFacts {
  const raw = emptyRaw()
  for (const node of findAllKinds(root, lang, AST_KINDS)) {
    try {
      switch (node.kind()) {
        case 'call': {
          const call = astCall(node)
          if (call) raw.calls.push(call)
          break
        }
        case 'function_definition': {
          const fn = astDef(ctx, node)
          if (fn) raw.fns.push(fn)
          break
        }
        case 'class_definition': {
          const cls = astClass(node)
          if (cls) raw.classes.push(cls)
          break
        }
        case 'assignment':
        case 'augmented_assignment':
          astAssign(ctx, node, raw)
          break
        case 'for_statement': {
          const left = node.field('left')
          const right = node.field('right')
          if (!left || !right) break
          const [a, b] = tokenSpan(ctx, spanOf(left))
          const value = spanOf(right)
          raw.assigns.push({
            targets: pyTargets(ctx, a, b),
            op: 'for',
            value,
            destructured: true,
            start: spanOf(left).start,
            end: value.end,
            fn: undefined,
          })
          break
        }
        case 'with_item': {
          const v = node.field('value')
          if (v?.kind() !== 'as_pattern') break
          const alias = v.field('alias')
          const valueNode = v.children().find(c => c.isNamed() && c.kind() !== 'as_pattern_target')
          if (!alias || !valueNode) break
          const [a, b] = tokenSpan(ctx, spanOf(alias))
          const value = spanOf(valueNode)
          raw.assigns.push({
            targets: pyTargets(ctx, a, b),
            op: 'with',
            value,
            destructured: false,
            start: value.start,
            end: spanOf(alias).end,
            fn: undefined,
          })
          break
        }
        case 'import_statement':
        case 'import_from_statement': {
          const [a, b] = tokenSpan(ctx, spanOf(node))
          tokenImport(ctx, a, b, raw)
          break
        }
      }
    } catch {
      // unexpected shape: skip
    }
  }
  return raw
}

function spanOf(node: SgNode): Span {
  const r = node.range()
  return { start: r.start.index, end: r.end.index }
}

function astCall(node: SgNode): CallFact | undefined {
  const fn = node.field('function')
  const argsNode = node.field('arguments')
  if (!fn || !argsNode) return undefined
  const calleeText = normalizeCallee(fn.text())
  const [receiver, name] = splitCallee(calleeText)
  const args: ArgFact[] = []
  if (argsNode.kind() === 'argument_list') {
    for (const child of argsNode.children()) {
      if (!child.isNamed() || child.kind() === 'comment') continue
      const kind = child.kind()
      if (kind === 'keyword_argument') {
        const value = child.field('value')
        const kw = child.field('name')?.text()
        if (value) args.push({ ...spanOf(value), ...(kw ? { keyword: kw } : {}) })
      } else if (kind === 'list_splat' || kind === 'dictionary_splat') {
        const inner = child.children().find(c => c.isNamed())
        args.push({ ...(inner ? spanOf(inner) : spanOf(child)), splat: kind === 'list_splat' ? '*' : '**' })
      } else args.push(spanOf(child))
    }
  } else {
    args.push(spanOf(argsNode)) // generator expression argument
  }
  return {
    callee: calleeText,
    name,
    receiver,
    calleeSpan: spanOf(fn),
    isNew: false,
    tagged: false,
    args,
    decorator: node.parent()?.kind() === 'decorator',
    ...spanOf(node),
    fn: undefined,
  }
}

function astDecorators(node: SgNode): DecoratorFact[] {
  const parent = node.parent()
  if (parent?.kind() !== 'decorated_definition') return []
  const out: DecoratorFact[] = []
  for (const child of parent.children()) {
    if (child.kind() !== 'decorator') continue
    const expr = child.children().find(c => c.isNamed() && c.kind() !== 'comment')
    if (!expr) continue
    if (expr.kind() === 'call') {
      const fn = expr.field('function')
      const args: ArgFact[] = []
      for (const a of expr.field('arguments')?.children() ?? []) {
        if (!a.isNamed() || a.kind() === 'comment') continue
        if (a.kind() === 'keyword_argument') {
          const value = a.field('value')
          const kw = a.field('name')?.text()
          if (value) args.push({ ...spanOf(value), ...(kw ? { keyword: kw } : {}) })
        } else args.push(spanOf(a))
      }
      out.push({ name: normalizeCallee(fn?.text() ?? ''), args, ...spanOf(child) })
    } else {
      out.push({ name: normalizeCallee(expr.text()), ...spanOf(child) })
    }
  }
  return out
}

function astDef(ctx: PyCtx, node: SgNode): FnFact | undefined {
  const name = node.field('name')?.text()
  const body = node.field('body')
  const paramsNode = node.field('parameters')
  if (!name || !body || !paramsNode) return undefined
  const decorators = astDecorators(node)
  const span = spanOf(node)
  const [a, b] = tokenSpan(ctx, spanOf(paramsNode))
  return {
    name,
    kind: 'function',
    ...span,
    body: spanOf(body),
    params: ctx.is(a, '(') && ctx.is(b - 1, ')') ? parsePyParams(ctx, a + 1, b - 1) : [],
    decorators,
    declStart: decorators[0]?.start ?? span.start,
    exported: false,
    parent: undefined,
    className: undefined,
  }
}

function astClass(node: SgNode): ClassFact | undefined {
  const body = node.field('body')
  if (!body) return undefined
  const bases: string[] = []
  for (const child of node.field('superclasses')?.children() ?? []) {
    if (child.isNamed() && child.kind() !== 'keyword_argument' && child.kind() !== 'comment') {
      bases.push(normalizeCallee(child.text()))
    }
  }
  const decorators = astDecorators(node)
  const span = spanOf(node)
  return {
    name: node.field('name')?.text(),
    ...span,
    body: spanOf(body),
    bases,
    decorators,
    declStart: decorators[0]?.start ?? span.start,
    exported: false,
  }
}

function astAssign(ctx: PyCtx, node: SgNode, raw: RawFacts): void {
  const left = node.field('left')
  let right = node.field('right')
  if (!left || !right) return
  // Chained `a = b = v`: the inner assignment node handles `b`; take its final value.
  while (right.kind() === 'assignment') {
    const next: SgNode | null = right.field('right')
    if (!next) return
    right = next
  }
  const op = node.kind() === 'assignment' ? '=' : (node.field('operator')?.text() ?? '+=')
  const value = spanOf(right)
  const [a, b] = tokenSpan(ctx, spanOf(left))
  addPyAssign(ctx, raw, a, b, op, value)
  const parent = node.parent()
  if (
    op === '=' &&
    left.kind() === 'identifier' &&
    parent?.kind() === 'expression_statement' &&
    parent.parent()?.kind() === 'module'
  ) {
    raw.vars.push({
      name: left.text(),
      start: spanOf(node).start,
      end: value.end,
      exported: false,
      isFn: right.kind() === 'lambda',
      value,
    })
  }
}
