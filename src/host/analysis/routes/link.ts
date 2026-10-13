/**
 * Cross-file resolution for route mounts. Extractors describe what a mount
 * argument holds symbolically (`Ref`): a local or imported binding, a module
 * export, a member, a call, a function or one of its parameters. Once every
 * file has been extracted, the linker follows those references through
 * imports (`resolveRelativeImport`), ES and CommonJS exports, barrels
 * (`export ... from`, `export *`), factories (`return router`) and plugin
 * wrappers (`fp(plugin)`) to the app/router they designate. No type checker:
 * only the bindings, exports and returns of the files involved are read,
 * each file at most once.
 */

import { resolveRelativeImport } from '../outline.ts'
import { type CallFact, type FileModel, type FnFact, fnChain, innermostFn, type Span } from '../sast/model.ts'
import { callAt, Expr } from '../sast/taint.ts'
import { type Snapshot, type SnapshotFile, yieldToEventLoop } from '../types.ts'
import { ANY_RECEIVER, type Mount, type MountTarget, type Ref, type RouteSink, targetKey } from './common.ts'

const MAX_RESOLVE_DEPTH = 24
const YIELD_EVERY = 200
/** Koa router accessors that stand for the router itself (`router.routes()`). */
const ACCESSORS = /^(?:routes|middleware)$/
const NOT_A_BINDING = /^(?:null|undefined|true|false|this|self|None|True|False|super|new|typeof|void|await|async)$/
/** Path aliases (`@/routes`, `~/routes`, `#routes`): local code the resolver cannot map without tsconfig. */
const ALIAS_IMPORT = /^(?:@\/|~\/|#)/

/** What a module binds and exports, as far as locating apps and routers goes. */
export interface LinkInfo {
  /** Module-level names (and JavaScript function locals as `name@<fn start>`) and what they hold. */
  readonly locals: ReadonlyMap<string, Ref>
  /** JavaScript exports (`default` for `export default`/`module.exports`); Python modules export their locals. */
  readonly exports: ReadonlyMap<string, Ref> | undefined
  /** Modules re-exported with `export * from`. */
  readonly stars: readonly string[]
  /** Parameter names per function start offset. */
  readonly params: ReadonlyMap<number, readonly string[]>
  /** What each function returns (`return router`, arrow expression bodies), per function start offset. */
  readonly returns: ReadonlyMap<number, readonly Ref[]>
}

/** What a reference designates once resolved. */
type Value =
  | { readonly kind: 'target'; readonly file: string; readonly receiver: string }
  | { readonly kind: 'fn'; readonly file: string; readonly start: number }
  | { readonly kind: 'module'; readonly file: string }
  | { readonly kind: 'external' }

/**
 * Names and symbolic values of one file: receiver ids for identifiers
 * (scoped to the declaring function in JavaScript), `Ref`s for expressions
 * and the file's `LinkInfo`.
 */
export class FileScope {
  readonly model: FileModel
  readonly ex: Expr
  readonly #snapshot: Snapshot
  #declared: Map<FnFact, Set<string>> | undefined

  constructor(model: FileModel, ex: Expr, snapshot: Snapshot) {
    this.model = model
    this.ex = ex
    this.#snapshot = snapshot
  }

  /**
   * Receiver id of identifier `name` used at offset `at`: `name` for a
   * module-level binding, `name@<fn start>` for a JavaScript parameter or
   * function-local declaration.
   */
  idOf(name: string, at: number): string {
    const ref = this.refOfName(name, at)
    return ref.kind === 'receiver' ? ref.receiver : ref.kind === 'local' ? ref.name : name
  }

  /** Reference for identifier `name` at `at`: a parameter (a receiver id) or a binding. */
  refOfName(name: string, at: number): Ref {
    const file = this.model.path
    if (this.model.lang === 'js') {
      for (const fn of fnChain(innermostFn(this.model.fns, at))) {
        if (fn.params.some(p => p.names.includes(name)))
          return { kind: 'receiver', file, receiver: `${name}@${fn.start}` }
        if (this.#declaredIn(fn).has(name)) return { kind: 'local', file, name: `${name}@${fn.start}` }
      }
    }
    return { kind: 'local', file, name }
  }

  /** Reference for the value of an expression, or `undefined` when it cannot hold an app, router or plugin. */
  refOfExpr(span: Span, depth = 0): Ref | undefined {
    const { model } = this
    const [a, b] = this.ex.range(span)
    if (b <= a || depth > 8) return undefined
    const first = model.tokens[a]!
    if (first.type === 'punct' && first.value === '(' && model.match[a] === b - 1 && b - a > 2) {
      return this.refOfExpr({ start: model.tokens[a + 1]!.start, end: model.tokens[b - 2]!.end }, depth + 1)
    }
    if (first.type === 'ident' && first.value === 'await' && b - a > 1) {
      return this.refOfExpr({ start: model.tokens[a + 1]!.start, end: span.end }, depth + 1)
    }
    const whole = { start: first.start, end: model.tokens[b - 1]!.end }
    const fn = fnStartingAt(model, whole)
    if (fn) return { kind: 'fn', file: model.path, start: fn.start }
    const call = callAt(model, whole)
    if (call) return this.#refOfCall(call)
    return this.refOfText(this.ex.text(span).trim().replace(/\s+/g, ''), span.start)
  }

  /** Reference for a callee or receiver chain given as text (`items.router`, `require('./x').admin`). */
  refOfText(text: string, at: number): Ref | undefined {
    const plain = text.replace(/!+$/, '')
    if (/^[A-Za-z_$][\w$]*$/.test(plain)) return NOT_A_BINDING.test(plain) ? undefined : this.refOfName(plain, at)
    const req = /^(?:require|import)\((['"`])([^'"`]+)\1\)$/.exec(plain)
    if (req) return this.model.lang === 'js' ? this.importRef(req[2]!, '*') : undefined
    const member = /^(.+)\.([A-Za-z_$][\w$]*)$/.exec(plain)
    if (member) {
      const object = this.refOfText(member[1]!, at)
      return object ? { kind: 'member', object, name: member[2]! } : undefined
    }
    const accessor = /^(.+)\.([A-Za-z_$][\w$]*)\(\)$/.exec(plain)
    if (accessor && ACCESSORS.test(accessor[2]!)) return this.refOfText(accessor[1]!, at)
    return undefined
  }

  /** Reference for `imported` (`*` for the module object) of module `source` as imported by this file. */
  importRef(source: string, imported: string): Ref {
    const { model } = this
    const snapshot = this.#snapshot
    if (model.lang === 'py') {
      // `from .routers import items` may name a submodule or an attribute of the package.
      if (imported !== '*') {
        const asModule = resolveRelativeImport(model.path, joinModule(source, imported), snapshot)
        if (asModule) return { kind: 'export', file: asModule, name: '*' }
      }
      const file = resolveRelativeImport(model.path, source, snapshot)
      if (file) return { kind: 'export', file, name: imported }
      return source.startsWith('.') ? { kind: 'missing', spec: source } : { kind: 'external' }
    }
    if (source.startsWith('.') || source.startsWith('/')) {
      const file = resolveRelativeImport(model.path, source, snapshot)
      return file ? { kind: 'export', file, name: imported } : { kind: 'missing', spec: source }
    }
    return ALIAS_IMPORT.test(source) ? { kind: 'missing', spec: source } : { kind: 'external' }
  }

  /** Bindings, exports, parameters and returns of this file. */
  link(): LinkInfo {
    const { model, ex } = this
    const file = model.path
    const js = model.lang === 'js'
    const locals = new Map<string, Ref>()
    const setLocal = (name: string, ref: Ref | undefined): void => {
      if (ref && !locals.has(name)) locals.set(name, ref)
    }
    for (const imp of model.imports) {
      if (imp.kind === 'export-from') continue
      for (const b of imp.bindings) setLocal(b.local, this.importRef(imp.source, b.imported))
    }
    // Module-level bindings first, so a Python function-local name never shadows a module one.
    for (const inFn of [false, true]) {
      for (const assign of model.assigns) {
        if (!!assign.fn !== inFn || assign.op !== '=' || assign.destructured || assign.targets.length !== 1) continue
        const name = assign.targets[0]!.name
        setLocal(js ? this.idOf(name, assign.start) : name, this.refOfExpr(assign.value))
      }
    }
    for (const fn of model.fns) {
      if (!fn.name || !isFnDeclaration(model, fn)) continue
      setLocal(js && fn.parent ? `${fn.name}@${fn.parent.start}` : fn.name, { kind: 'fn', file, start: fn.start })
    }
    const params = new Map<number, readonly string[]>()
    for (const fn of model.fns)
      params.set(
        fn.start,
        fn.params.map(p => p.name),
      )
    const returns = this.#returns()
    if (!js) return { locals, exports: undefined, stars: [], params, returns }

    const exports = new Map<string, Ref>()
    const stars: string[] = []
    const local = (name: string): Ref => ({ kind: 'local', file, name })
    for (const v of model.vars) if (v.exported) exports.set(v.name, local(v.name))
    for (const fn of model.fns) {
      if (fn.exported && fn.name && !fn.parent && isFnDeclaration(model, fn)) exports.set(fn.name, local(fn.name))
    }
    for (const name of model.exportedNames) if (!exports.has(name) && locals.has(name)) exports.set(name, local(name))
    for (const alias of model.exportAliases) exports.set(alias.exported, local(alias.local))
    for (const imp of model.imports) {
      if (imp.kind !== 'export-from') continue
      if (imp.bindings.length === 0) {
        // `export * from './x'` or `export * as ns from './x'`
        const ns = /^export\s*\*\s*as\s+([A-Za-z_$][\w$]*)/.exec(model.source.slice(imp.start, imp.start + 200))
        const target = this.importRef(imp.source, '*')
        if (ns) exports.set(ns[1]!, target)
        else if (target.kind === 'export') stars.push(target.file)
        continue
      }
      for (const b of imp.bindings) exports.set(b.local, this.importRef(imp.source, b.imported))
    }
    for (const m of model.source.matchAll(/(?:^|[;}\n])[ \t]*export\s+default\s+/g)) {
      const ref = this.#defaultExport(m.index, m.index + m[0].length)
      if (ref) exports.set('default', ref)
    }
    // CommonJS: `module.exports = x`, `module.exports = { a, b: c }`, `exports.a = x`
    for (const assign of model.memberAssigns) {
      if (assign.fn || assign.op !== '=') continue
      if (assign.target === 'module.exports') {
        if (ex.isObjectLiteral(assign.value)) {
          for (const entry of ex.objectEntries(assign.value)) {
            const ref = entry.key && entry.value && !entry.spread ? this.refOfExpr(entry.value) : undefined
            if (ref) exports.set(entry.key!, ref)
          }
        } else {
          const ref = this.refOfExpr(assign.value)
          if (ref) exports.set('default', ref)
        }
        continue
      }
      const named = /^(?:module\.)?exports\.([A-Za-z_$][\w$]*)$/.exec(assign.target)
      const ref = named ? this.refOfExpr(assign.value) : undefined
      if (named && ref) exports.set(named[1]!, ref)
    }
    if (!exports.has('default') && model.defaultExport && locals.has(model.defaultExport)) {
      exports.set('default', local(model.defaultExport))
    }
    return { locals, exports, stars, params, returns }
  }

  /** `export default <function | call | identifier>` whose keyword ends at `at`. */
  #defaultExport(from: number, at: number): Ref | undefined {
    const { model } = this
    const declared = model.fns.find(f => !f.parent && f.declStart >= from && f.declStart <= at && at <= f.start + 1)
    if (declared) return { kind: 'fn', file: model.path, start: declared.start }
    const call = outermostCallAt(model, at)
    if (call) return this.#refOfCall(call)
    const name = /^([A-Za-z_$][\w$]*)[ \t]*(?:;|\r?\n|$)/.exec(model.source.slice(at, at + 200))?.[1]
    return name && !/^(?:class|function|async)$/.test(name) ? { kind: 'local', file: model.path, name } : undefined
  }

  #refOfCall(call: CallFact): Ref | undefined {
    if ((call.callee === 'require' || call.callee === 'import') && call.args[0]) {
      const spec = this.ex.literal(call.args[0])
      return spec !== undefined && this.model.lang === 'js' ? this.importRef(spec, '*') : undefined
    }
    if (ACCESSORS.test(call.name) && call.args.length === 0 && call.receiver) {
      return this.refOfText(call.receiver, call.start)
    }
    const args = call.args.filter(arg => !arg.keyword && !arg.splat).map(arg => this.refOfExpr(arg))
    return { kind: 'call', callee: this.refOfText(call.callee, call.start), args }
  }

  #returns(): Map<number, Ref[]> {
    const { model } = this
    const out = new Map<number, Ref[]>()
    const add = (fn: FnFact | undefined, ref: Ref | undefined): void => {
      if (!fn || !ref) return
      const list = out.get(fn.start)
      if (list) list.push(ref)
      else out.set(fn.start, [ref])
    }
    if (model.lang === 'js') {
      for (const fn of model.fns) {
        if (fn.kind === 'arrow' && model.source[fn.body.start] !== '{') add(fn, this.refOfExpr(fn.body))
      }
    }
    for (const m of model.source.matchAll(/\breturn[ \t]+([A-Za-z_$][\w$]*)[ \t]*;?[ \t]*(?=\r?\n|\}|$)/g)) {
      const name = m[1]!
      if (NOT_A_BINDING.test(name)) continue
      const at = m.index + m[0].indexOf(name, 6)
      add(innermostFn(model.fns, at), this.refOfName(name, at))
    }
    return out
  }

  /** Names a JavaScript function declares (`const`/`let`/`var`, nested function declarations). */
  #declaredIn(fn: FnFact): ReadonlySet<string> {
    if (!this.#declared) {
      const { model } = this
      const moduleNames = new Set<string>()
      for (const imp of model.imports) for (const b of imp.bindings) moduleNames.add(b.local)
      for (const assign of model.assigns) if (!assign.fn) for (const t of assign.targets) moduleNames.add(t.name)
      for (const f of model.fns) if (!f.parent && f.name) moduleNames.add(f.name)
      const declared = new Map<FnFact, Set<string>>()
      const add = (owner: FnFact, name: string): void => {
        const set = declared.get(owner)
        if (set) set.add(name)
        else declared.set(owner, new Set([name]))
      }
      for (const assign of model.assigns) {
        if (!assign.fn) continue
        const head = model.source.slice(Math.max(0, assign.start - 40), assign.start)
        const decl = /\b(?:const|let|var)\s*[[{]?[\s\w$,:]*$/.test(head)
        for (const t of assign.targets) if (decl || !moduleNames.has(t.name)) add(assign.fn, t.name)
      }
      for (const f of model.fns) if (f.parent && f.name && isFnDeclaration(model, f)) add(f.parent, f.name)
      this.#declared = declared
    }
    return this.#declared.get(fn) ?? EMPTY
  }
}

const EMPTY: ReadonlySet<string> = new Set()

/** `base` + `.name` as a Python module path (`.` + `views` → `.views`). */
export function joinModule(base: string, name: string): string {
  if (/^\.+$/.test(base)) return base + name
  return `${base}.${name}`
}

/**
 * Resolves the symbolic mounts of a `RouteSink`. Link info is computed at
 * most once per file (`links` holds what extraction already computed) and
 * only for files a reference reaches; every resolution is memoized, so
 * linking is linear in the number of mounts and files involved.
 */
export class Linker {
  readonly #sink: RouteSink
  readonly #snapshot: Snapshot
  readonly #modelOf: (file: SnapshotFile) => FileModel | undefined
  readonly #infos = new Map<string, LinkInfo | null>()
  readonly #memo = new Map<string, Value | null>()
  readonly #active = new Set<string>()
  readonly #canonical = new Map<string, MountTarget>()
  /** Receivers known to be apps/routers: constructed by a framework, or with routes, mounts or middleware. */
  readonly #routers = new Set<string>()

  constructor(
    sink: RouteSink,
    snapshot: Snapshot,
    modelOf: (file: SnapshotFile) => FileModel | undefined,
    links: ReadonlyMap<string, LinkInfo> = new Map(),
  ) {
    this.#sink = sink
    this.#snapshot = snapshot
    this.#modelOf = modelOf
    for (const [path, info] of links) this.#infos.set(path, info)
    const add = (t: MountTarget): void => {
      this.#routers.add(targetKey(t.file, t.receiver))
    }
    for (const r of sink.receivers) add(r)
    for (const r of sink.routes) if (r.receiver !== undefined) add({ file: r.file, receiver: r.receiver })
    for (const m of sink.mounts) add(m.parent)
    for (const u of sink.uses) add(u.parent)
    for (const s of sink.scoped) add(s)
    for (const p of sink.prefixes) add(p)
  }

  /**
   * The app/router a receiver id stands for: itself, or the binding it was
   * imported from (`import { router } from './base'` then `router.get(...)`).
   */
  canonical(target: MountTarget): MountTarget {
    if (target.receiver === ANY_RECEIVER || target.receiver.includes('.')) return target
    const key = targetKey(target.file, target.receiver)
    const hit = this.#canonical.get(key)
    if (hit) return hit
    const value = this.resolve({ kind: 'local', file: target.file, name: target.receiver })
    const out = value?.kind === 'target' ? { file: value.file, receiver: value.receiver } : target
    this.#canonical.set(key, out)
    return out
  }

  /**
   * Resolve pending mounts and `use(...)` calls to concrete mounts (children
   * canonical, parents as written). Middleware passed to `use(...)` becomes
   * receiver-scoped middleware in `sink.scoped`; unresolved router-like
   * mounts add their warning to `sink.warnings`.
   */
  async mounts(signal?: AbortSignal): Promise<Mount[]> {
    const sink = this.#sink
    const out: Mount[] = []
    let n = 0
    const tick = async (): Promise<void> => {
      if (++n % YIELD_EVERY !== 0) return
      await yieldToEventLoop()
      signal?.throwIfAborted()
    }
    for (const pending of sink.mounts) {
      await tick()
      const value = this.resolve(pending.child)
      const child = this.#targetOf(value, pending.moduleReceiver)
      if (!child) {
        // A package plugin (`register(cors)`) is not a mount to follow.
        if (pending.unresolved && value?.kind !== 'external') sink.warnings.push(pending.unresolved)
        continue
      }
      out.push({
        parent: pending.parent,
        child: this.canonical(child),
        prefix: pending.prefix,
        middleware: pending.middleware,
        file: pending.parent.file,
        offset: pending.offset,
        ...(pending.replacesPrefix ? { replacesPrefix: true } : {}),
      })
    }
    for (const use of sink.uses) {
      await tick()
      const names: string[] = []
      const parent = this.canonical(use.parent)
      for (const arg of use.args) {
        const value = arg.ref ? this.resolve(arg.ref) : undefined
        const child = value?.kind === 'target' ? this.canonical(value) : undefined
        const isRouter =
          child !== undefined &&
          (arg.unresolved !== undefined || this.#routers.has(targetKey(child.file, child.receiver))) &&
          targetKey(child.file, child.receiver) !== targetKey(parent.file, parent.receiver)
        if (child && isRouter) {
          out.push({
            parent: use.parent,
            child,
            prefix: use.prefix,
            middleware: [...names],
            file: use.parent.file,
            offset: use.offset,
          })
          continue
        }
        if (arg.unresolved !== undefined && (value === undefined || value.kind === 'module')) {
          sink.warnings.push(arg.unresolved)
          continue
        }
        names.push(...arg.names)
      }
      if (names.length > 0) {
        sink.scoped.push({
          file: use.parent.file,
          receiver: use.parent.receiver,
          names,
          // Only what is registered after this call sees its middleware; its own routers carry it as mount middleware.
          offset: use.end,
          ordered: use.ordered,
          ...(use.prefix && use.prefix !== '/' ? { pathPrefix: use.prefix } : {}),
        })
      }
    }
    return out
  }

  /** What `ref` designates, or `undefined` when it leaves the snapshot or cannot be followed. */
  resolve(ref: Ref, depth = 0, wantModule = false): Value | undefined {
    if (depth > MAX_RESOLVE_DEPTH) return undefined
    switch (ref.kind) {
      case 'receiver':
        return { kind: 'target', file: ref.file, receiver: ref.receiver }
      case 'fn':
        return { kind: 'fn', file: ref.file, start: ref.start }
      case 'external':
        return { kind: 'external' }
      case 'missing':
        return undefined
      case 'local':
      case 'export': {
        const key = `${ref.kind}\0${ref.file}\0${ref.name}\0${wantModule ? 1 : 0}`
        const hit = this.#memo.get(key)
        if (hit !== undefined) return hit ?? undefined
        if (this.#active.has(key)) return undefined
        this.#active.add(key)
        const value =
          ref.kind === 'local'
            ? this.#local(ref.file, ref.name, depth, wantModule)
            : this.#export(ref.file, ref.name, depth, wantModule)
        this.#active.delete(key)
        this.#memo.set(key, value ?? null)
        return value
      }
      case 'member': {
        const object = this.resolve(ref.object, depth + 1, true)
        if (object?.kind === 'module')
          return this.resolve({ kind: 'export', file: object.file, name: ref.name }, depth + 1)
        if (object?.kind === 'target' && ACCESSORS.test(ref.name)) return object
        return object?.kind === 'external' ? object : undefined
      }
      case 'call': {
        const callee = ref.callee ? this.resolve(ref.callee, depth + 1) : undefined
        if (callee?.kind === 'fn') {
          // A factory: what it returns (`return router`).
          for (const ret of this.#info(callee.file)?.returns.get(callee.start) ?? []) {
            const value = this.resolve(ret, depth + 1)
            if (value && value.kind !== 'external') return value
          }
          return undefined
        }
        if (callee?.kind === 'target' || callee?.kind === 'module') return undefined
        // A package wrapper (`fp(plugin)`, `asyncify(router)`): the first app, router or function passed.
        for (const arg of ref.args) {
          const value = arg ? this.resolve(arg, depth + 1) : undefined
          if (value?.kind === 'target' || value?.kind === 'fn') return value
        }
        // Anything else a package returns (`cors()`, `express.json()`) is not ours.
        return callee?.kind === 'external' ? callee : undefined
      }
      case 'param': {
        const fn = this.resolve(ref.fn, depth + 1)
        if (fn?.kind !== 'fn') return undefined
        const name = this.#info(fn.file)?.params.get(fn.start)?.[ref.index]
        return name ? { kind: 'target', file: fn.file, receiver: `${name}@${fn.start}` } : undefined
      }
    }
  }

  /** A mount child: an app/router, a plugin function (its first parameter), or a module when allowed. */
  #targetOf(value: Value | undefined, moduleReceiver: string | undefined): MountTarget | undefined {
    if (value?.kind === 'target') return value
    if (value?.kind === 'module' && moduleReceiver) return { file: value.file, receiver: moduleReceiver }
    if (value?.kind === 'fn') {
      const first = this.#info(value.file)?.params.get(value.start)?.[0]
      return first ? { file: value.file, receiver: `${first}@${value.start}` } : undefined
    }
    return undefined
  }

  #local(file: string, name: string, depth: number, wantModule: boolean): Value | undefined {
    const bound = this.#info(file)?.locals.get(name)
    const value = bound ? this.resolve(bound, depth + 1, wantModule) : undefined
    if (value && value.kind !== 'external') return value
    if (this.#routers.has(targetKey(file, name))) return { kind: 'target', file, receiver: name }
    return value
  }

  #export(file: string, name: string, depth: number, wantModule: boolean): Value | undefined {
    const info = this.#info(file)
    if (!info) return undefined
    if (!info.exports) {
      // Python: a module exports its module-level names; a package also exposes its submodules.
      if (name === '*') return { kind: 'module', file }
      const value = this.#local(file, name, depth, wantModule)
      if (value || !file.endsWith('__init__.py')) return value
      const dir = file.slice(0, -'__init__.py'.length)
      const sub = [`${dir}${name}.py`, `${dir}${name}/__init__.py`].find(p => this.#snapshot.files.has(p))
      return sub ? { kind: 'module', file: sub } : undefined
    }
    if (name === '*') {
      // `require('./x')` is `module.exports` (the default export); `x.member` reads the namespace.
      const def = info.exports.get('default')
      if (!wantModule && def) return this.resolve(def, depth + 1)
      return { kind: 'module', file }
    }
    const direct = info.exports.get(name)
    if (direct) return this.resolve(direct, depth + 1, wantModule)
    for (const star of info.stars) {
      const value = this.resolve({ kind: 'export', file: star, name }, depth + 1, wantModule)
      if (value) return value
    }
    // CommonJS `module.exports = router` read as `require('./x').router`: not an export.
    return undefined
  }

  #info(path: string): LinkInfo | undefined {
    const cached = this.#infos.get(path)
    if (cached !== undefined) return cached ?? undefined
    const file = this.#snapshot.files.get(path)
    let info: LinkInfo | undefined
    try {
      const model = file && !file.isGenerated ? this.#modelOf(file) : undefined
      info = model ? new FileScope(model, new Expr(model), this.#snapshot).link() : undefined
    } catch {
      info = undefined
    }
    this.#infos.set(path, info ?? null)
    return info
  }
}

/** A function (expression or declaration) spanning `span`. */
function fnStartingAt(model: FileModel, span: Span): FnFact | undefined {
  const fns = model.fns
  let lo = 0
  let hi = fns.length
  while (lo < hi) {
    const mid = (lo + hi) >>> 1
    if (fns[mid]!.start < span.start) lo = mid + 1
    else hi = mid
  }
  for (let i = lo; i < fns.length && fns[i]!.start <= span.start + 8; i++) {
    const fn = fns[i]!
    if (Math.abs(fn.end - span.end) <= 1) return fn
  }
  return undefined
}

/** The widest call starting at `at` (`fp(async () => {})` rather than a call nested in it). */
function outermostCallAt(model: FileModel, at: number): CallFact | undefined {
  let lo = 0
  let hi = model.calls.length
  while (lo < hi) {
    const mid = (lo + hi) >>> 1
    if (model.calls[mid]!.start < at) lo = mid + 1
    else hi = mid
  }
  let best: CallFact | undefined
  for (let i = lo; i < model.calls.length && model.calls[i]!.start === at; i++) {
    const call = model.calls[i]!
    if (!best || call.end > best.end) best = call
  }
  return best
}

/** `function name() {}` / Python `def name():`, not a function expression or arrow. */
function isFnDeclaration(model: FileModel, fn: FnFact): boolean {
  if (fn.kind !== 'function' || !fn.name || fn.className !== undefined) return false
  if (model.lang === 'py') return true
  const head = model.source.slice(fn.start, fn.start + fn.name.length + 30)
  return new RegExp(`^(?:async\\s+)?function\\s*\\*?\\s*${fn.name.replace(/\$/g, '\\$')}\\b`).test(head)
}
