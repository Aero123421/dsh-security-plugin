/**
 * Language-neutral code model shared by the SAST rules, route extraction and
 * the outline. It is built either from the native AST (precise ranges) or
 * from the token stream (fallback); consumers never need to know which.
 *
 * All positions are UTF-16 offsets into the file content; `end` is exclusive.
 */

import { lineOf, type Token } from './lexer.ts'

export interface Span {
  readonly start: number
  readonly end: number
}

export type ModelLang = 'js' | 'py'

export interface ArgFact extends Span {
  /** Python keyword argument name (`shell` in `shell=True`). */
  readonly keyword?: string
  readonly splat?: '...' | '*' | '**'
}

export interface CallFact extends Span {
  /** Callee text without whitespace, `?.` normalized to `.`, e.g. `db.query`, `require('fs').readFile`. */
  readonly callee: string
  /** Last member name (`query` for `db.query`), or the bare identifier. Empty for computed callees. */
  readonly name: string
  /** Callee without its last member (`db` for `db.query`); empty for bare calls. */
  readonly receiver: string
  readonly calleeSpan: Span
  readonly isNew: boolean
  /** A tagged template such as ``sql`...` ``; its only argument is the template. */
  readonly tagged: boolean
  readonly args: readonly ArgFact[]
  /** Part of a decorator (`@Get(':id')`, `@app.route('/')`). */
  readonly decorator: boolean
  fn: FnFact | undefined
}

export interface ParamFact extends Span {
  /** First bound identifier, or `''` for a pattern without names. */
  readonly name: string
  /** Every identifier the parameter binds (destructuring included). */
  readonly names: readonly string[]
  readonly annotation?: string
  readonly defaultValue?: Span
  /** Decorator names on the parameter (NestJS `@Body()` → `Body`). */
  readonly decorators: readonly string[]
  readonly splat?: '*' | '**' | '...'
}

export interface DecoratorFact extends Span {
  /** Decorator expression without arguments, e.g. `app.route`, `login_required`, `UseGuards`. */
  readonly name: string
  /** Argument spans when the decorator is called. */
  readonly args?: readonly ArgFact[]
}

export interface FnFact extends Span {
  readonly name: string | undefined
  readonly kind: 'function' | 'method' | 'arrow'
  readonly body: Span
  readonly params: readonly ParamFact[]
  readonly decorators: readonly DecoratorFact[]
  /** Start including decorators and `export`/`async` keywords, for line ranges. */
  readonly declStart: number
  exported: boolean
  parent: FnFact | undefined
  /** Name of the class whose body directly holds this function. */
  className: string | undefined
}

export interface ClassFact extends Span {
  readonly name: string | undefined
  readonly body: Span
  /** Base classes / mixins as written (`LoginRequiredMixin`, `Base`). */
  readonly bases: readonly string[]
  readonly decorators: readonly DecoratorFact[]
  readonly declStart: number
  exported: boolean
}

export interface AssignTarget {
  readonly name: string
  /** Destructuring key the name was bound from (`body` in `const { body: b } = req`). */
  readonly key?: string
}

export interface AssignFact extends Span {
  readonly targets: readonly AssignTarget[]
  /** `=`, an augmented operator (`+=`), `for` (loop variable) or `with` (Python `as`). */
  readonly op: string
  readonly value: Span
  /** The value is destructured (`const { a } = x`, `a, b = x`). */
  readonly destructured: boolean
  fn: FnFact | undefined
}

export interface MemberAssignFact extends Span {
  /** Whole target text, e.g. `el.innerHTML`, `self.config['X']`. */
  readonly target: string
  /** Last property (`innerHTML`) or string subscript (`X`). */
  readonly prop: string
  readonly op: string
  readonly value: Span
  fn: FnFact | undefined
}

export interface ImportBinding {
  /** Name bound in this file. */
  readonly local: string
  /** Name exported by the module (`default`, `*`, or the member name). */
  readonly imported: string
}

export interface ImportFact {
  readonly source: string
  readonly bindings: readonly ImportBinding[]
  readonly start: number
  readonly kind: 'import' | 'require' | 'dynamic' | 'export-from' | 'from'
}

/** A module-level variable declaration (`const handler = ...`, `GET = ...`). */
export interface VarFact extends Span {
  readonly name: string
  readonly exported: boolean
  /** The value is a function or arrow function expression. */
  readonly isFn: boolean
  readonly value: Span
}

/** `export { local as exported }`. */
export interface ExportAlias {
  readonly local: string
  readonly exported: string
}

export interface FileModel {
  readonly path: string
  readonly lang: ModelLang
  readonly source: string
  readonly mode: 'ast' | 'tokens'
  readonly tokens: readonly Token[]
  /** Bracket partner per token index (see `matchBrackets`). */
  readonly match: Int32Array
  readonly lines: readonly number[]
  /** Sorted by start. */
  readonly fns: readonly FnFact[]
  readonly classes: readonly ClassFact[]
  /** Sorted by start. */
  readonly calls: readonly CallFact[]
  /** Sorted by start. */
  readonly assigns: readonly AssignFact[]
  readonly memberAssigns: readonly MemberAssignFact[]
  readonly imports: readonly ImportFact[]
  /** Names exported through `export { a }` lists, `module.exports`, `__all__`, etc. */
  readonly exportedNames: ReadonlySet<string>
  /** Module-level variable declarations. */
  readonly vars: readonly VarFact[]
  readonly exportAliases: readonly ExportAlias[]
  /** Identifier exported as default (`export default router`, `module.exports = app`). */
  readonly defaultExport: string | undefined
}

/** Raw facts produced by a builder before scoping. */
export interface RawFacts {
  readonly fns: FnFact[]
  readonly classes: ClassFact[]
  readonly calls: CallFact[]
  readonly assigns: AssignFact[]
  readonly memberAssigns: MemberAssignFact[]
  readonly imports: ImportFact[]
  readonly exportedNames: Set<string>
  readonly vars: VarFact[]
  readonly exportAliases: ExportAlias[]
  defaultExport?: string
}

/** Sort facts, link parents, and attach the enclosing function to every fact. */
export function finalizeFacts(raw: RawFacts): RawFacts {
  const fns = dedupeSpans(raw.fns).sort((a, b) => a.start - b.start || b.end - a.end)
  const stack: FnFact[] = []
  for (const fn of fns) {
    while (stack.length > 0 && stack[stack.length - 1]!.end <= fn.start) stack.pop()
    const top = stack[stack.length - 1]
    fn.parent = top && top.end >= fn.end ? top : undefined
    stack.push(fn)
  }
  const classes = raw.classes.sort((a, b) => a.start - b.start)
  for (const fn of fns) {
    if (fn.className !== undefined) continue
    let owner: ClassFact | undefined
    for (const cls of classes) {
      if (cls.body.start <= fn.start && fn.end <= cls.body.end) {
        if (!owner || cls.start >= owner.start) owner = cls
      }
    }
    if (owner && (!fn.parent || fn.parent.start < owner.start)) fn.className = owner.name ?? ''
  }
  for (const fn of fns) {
    if (fn.name !== undefined && raw.exportedNames.has(fn.name) && !fn.parent && fn.className === undefined) {
      fn.exported = true
    }
  }
  for (const cls of classes) if (cls.name !== undefined && raw.exportedNames.has(cls.name)) cls.exported = true
  const calls = raw.calls.sort((a, b) => a.start - b.start || b.end - a.end)
  for (const call of calls) call.fn = innermostFn(fns, call.start)
  const assigns = raw.assigns.sort((a, b) => a.start - b.start)
  for (const assign of assigns) assign.fn = innermostFn(fns, assign.start)
  for (const assign of raw.memberAssigns) assign.fn = innermostFn(fns, assign.start)
  const seenVars = new Set<string>()
  const vars = raw.vars
    .filter(v => !innermostFn(fns, v.start) && !classes.some(c => c.body.start < v.start && v.start < c.body.end))
    .filter(v => {
      const key = `${v.name}@${v.value.start}`
      if (seenVars.has(key)) return false
      seenVars.add(key)
      return true
    })
    .map(v => (raw.exportedNames.has(v.name) && !v.exported ? { ...v, exported: true } : v))
    .sort((a, b) => a.start - b.start)
  return { ...raw, fns, classes, calls, assigns, vars }
}

/** Innermost function whose span contains `offset`. `fns` must be sorted by start. */
export function innermostFn(fns: readonly FnFact[], offset: number): FnFact | undefined {
  let lo = 0
  let hi = fns.length
  while (lo < hi) {
    const mid = (lo + hi) >>> 1
    if (fns[mid]!.start <= offset) lo = mid + 1
    else hi = mid
  }
  let fn: FnFact | undefined = fns[lo - 1]
  while (fn && !(fn.start <= offset && offset < fn.end)) fn = fn.parent
  return fn
}

/** Function chain from `fn` outwards. */
export function* fnChain(fn: FnFact | undefined): Generator<FnFact> {
  for (let cur = fn; cur; cur = cur.parent) yield cur
}

/** 1-based line of an offset. */
export function lineAt(model: Pick<FileModel, 'lines'>, offset: number): number {
  return lineOf(model.lines, offset)
}

/** Source text of a span. */
export function textOf(model: Pick<FileModel, 'source'>, span: Span): string {
  return model.source.slice(span.start, span.end)
}

/** Remove whitespace and normalize optional/non-null member access for callee matching. */
export function normalizeCallee(text: string): string {
  return text
    .replace(/^new\s+(?=[A-Za-z_$])/, '')
    .replace(/\s+/g, '')
    .replace(/\?\.(?=[([])/g, '')
    .replace(/\?\./g, '.')
    .replace(/!\./g, '.')
}

/** Split a normalized callee into `[receiver, name]`. */
export function splitCallee(callee: string): [string, string] {
  if (/^[A-Za-z_$][\w$]*$/.test(callee)) return ['', callee]
  const m = /^(.*)\.(#?[A-Za-z_$][\w$]*)$/.exec(callee)
  return m ? [m[1]!, m[2]!] : [callee, '']
}

function dedupeSpans<T extends Span>(items: T[]): T[] {
  const seen = new Set<string>()
  return items.filter(item => {
    const key = `${item.start}:${item.end}`
    if (seen.has(key)) return false
    seen.add(key)
    return true
  })
}
