/**
 * Code navigation for AI tools: per-file outlines (imports and symbols with
 * line ranges), symbol lookup across a snapshot, and relative import
 * resolution. Built on the shared code model, so it works with the native
 * AST when available and with the token/indentation fallback otherwise.
 */

import type { AstGrepHandle } from './astgrep.ts'
import type { FileModel, FnFact } from './sast/model.ts'
import { lineAt } from './sast/model.ts'
import { modelFor, modelKind } from './sast/models.ts'
import type { FileOutline, OutlineImport, OutlineSymbol, Snapshot, SnapshotFile } from './types.ts'

const JS_EXTENSIONS = ['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs', '.mts', '.cts']
const DEFAULT_FIND_LIMIT = 20

/**
 * Outline one file: imports (ES `import`, `require(...)`, dynamic `import()`,
 * `export ... from`, Python `import`/`from ... import`) and symbols
 * (functions, classes, methods, top-level variables) with 1-based line
 * ranges. Files that are not JS/TS/Python return an empty outline.
 */
export function outlineFile(file: SnapshotFile, astGrep?: AstGrepHandle): FileOutline {
  const model = modelKind(file) ? modelFor(file, astGrep) : undefined
  if (!model) return { path: file.path, language: file.language, imports: [], symbols: [] }
  return { path: file.path, language: file.language, imports: outlineImports(model), symbols: outlineSymbols(model) }
}

/**
 * Definitions named `name` across the snapshot (functions, classes, methods
 * and top-level variables; never call sites). `Class.method` narrows to a
 * method of that class. Results are sorted by path then line.
 */
export function findSymbol(
  snapshot: Snapshot,
  name: string,
  options: { readonly astGrep?: AstGrepHandle; readonly limit?: number } = {},
): { path: string; startLine: number; endLine: number; kind: OutlineSymbol['kind'] }[] {
  const limit = Math.max(1, options.limit ?? DEFAULT_FIND_LIMIT)
  const dot = name.lastIndexOf('.')
  const owner = dot > 0 ? name.slice(0, dot) : undefined
  const bare = dot > 0 ? name.slice(dot + 1) : name
  if (!/^[\p{L}_$][\p{L}\p{N}_$]*$/u.test(bare)) return []
  const needle = new RegExp(`(?<![\\p{L}\\p{N}_$])${bare.replace(/\$/g, '\\$')}(?![\\p{L}\\p{N}_$])`, 'u')
  const out: { path: string; startLine: number; endLine: number; kind: OutlineSymbol['kind'] }[] = []
  const paths = [...snapshot.files.keys()].sort()
  for (const path of paths) {
    const file = snapshot.files.get(path)!
    if (!modelKind(file) || file.isGenerated || !needle.test(file.content)) continue
    const model = modelFor(file, options.astGrep)
    if (!model) continue
    for (const symbol of outlineSymbols(model, true)) {
      if (symbol.name !== bare) continue
      if (owner !== undefined && symbol.owner !== owner) continue
      out.push({ path, startLine: symbol.startLine, endLine: symbol.endLine, kind: symbol.kind })
      if (out.length >= limit) return out
    }
  }
  return out
}

/**
 * Resolve an import specifier to a snapshot path. JavaScript/TypeScript:
 * `./x` → `x.ts|.tsx|.js|.jsx|.mjs|.cjs` or `x/index.*` (also `./x.js` →
 * `x.ts`). Python: relative (`.mod`, `..pkg.mod`) or absolute (`pkg.mod`)
 * modules → `pkg/mod.py` or `pkg/mod/__init__.py`, searched from the
 * snapshot root, the importing file's directory and `src/`.
 */
export function resolveRelativeImport(fromPath: string, specifier: string, snapshot: Snapshot): string | undefined {
  const has = (p: string): boolean => snapshot.files.has(p)
  if (/\.pyi?$/.test(fromPath)) return resolvePython(fromPath, specifier, has)
  if (!specifier.startsWith('.') && !specifier.startsWith('/')) return undefined
  const dir = dirOf(fromPath)
  const target = normalizePath(specifier.startsWith('/') ? specifier.slice(1) : joinPath(dir, specifier))
  if (target === undefined) return undefined
  const candidates: string[] = []
  if (target !== '') {
    candidates.push(target)
    const ext = /\.(?:[cm]?js|jsx)$/.exec(target)?.[0]
    if (ext) {
      const stem = target.slice(0, -ext.length)
      const mapped = ext === '.mjs' ? ['.mts'] : ext === '.cjs' ? ['.cts'] : ext === '.jsx' ? ['.tsx'] : ['.ts', '.tsx']
      for (const m of mapped) candidates.push(stem + m)
    }
    for (const e of JS_EXTENSIONS) candidates.push(target + e)
  }
  for (const e of JS_EXTENSIONS) candidates.push(`${target === '' ? '' : `${target}/`}index${e}`)
  return candidates.find(has)
}

/** The innermost symbol whose line range contains `line` (methods win over their class). */
export function enclosingSymbol(outline: FileOutline, line: number): OutlineSymbol | undefined {
  let best: OutlineSymbol | undefined
  for (const symbol of outline.symbols) {
    if (symbol.startLine > line || symbol.endLine < line) continue
    if (!best || symbol.endLine - symbol.startLine <= best.endLine - best.startLine) best = symbol
  }
  return best
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

interface InternalSymbol extends OutlineSymbol {
  /** Owning class name for methods. */
  readonly owner?: string
}

function outlineImports(model: FileModel): OutlineImport[] {
  const seen = new Set<string>()
  const out: OutlineImport[] = []
  for (const imp of [...model.imports].sort((a, b) => a.start - b.start)) {
    const line = lineAt(model, imp.start)
    const key = `${imp.source}@${line}`
    if (seen.has(key)) continue
    seen.add(key)
    out.push({ source: imp.source, names: imp.bindings.map(b => b.local), line })
  }
  return out
}

function outlineSymbols(model: FileModel, withOwner = false): InternalSymbol[] {
  const out: InternalSymbol[] = []
  const covered = new Set<number>()
  for (const cls of model.classes) {
    if (!cls.name) continue
    out.push({
      name: cls.name,
      kind: 'class',
      startLine: lineAt(model, cls.declStart),
      endLine: lineAt(model, Math.max(cls.declStart, cls.end - 1)),
      exported: cls.exported || model.exportedNames.has(cls.name),
    })
  }
  for (const fn of model.fns) {
    const name = fn.name
    if (!name || (name === 'default' && !fn.exported)) continue
    const kind = symbolKind(fn)
    if (!kind) continue
    // Only named declarations, methods, and functions bound to a module-level name.
    let symbolName = name
    if (fn.kind === 'arrow' || (fn.kind === 'function' && model.lang === 'js' && !isDeclaration(model, fn))) {
      const binding = moduleBinding(model, fn)
      if (!binding) continue
      symbolName = binding
    }
    covered.add(fn.start)
    out.push({
      name: symbolName,
      kind,
      startLine: lineAt(model, fn.declStart),
      endLine: lineAt(model, Math.max(fn.declStart, fn.end - 1)),
      exported:
        kind === 'method'
          ? false
          : fn.exported || model.exportedNames.has(symbolName) || exportedByAlias(model, symbolName),
      ...(withOwner && fn.className !== undefined ? { owner: fn.className } : {}),
    })
  }
  for (const v of model.vars) {
    if (
      v.isFn &&
      model.fns.some(fn => fn.start >= v.value.start && fn.start <= v.value.start + 16 && covered.has(fn.start))
    ) {
      continue
    }
    const exported =
      model.lang === 'py'
        ? isPublicPython(model, v.name)
        : v.exported || model.exportedNames.has(v.name) || exportedByAlias(model, v.name)
    // JS: exported bindings and module-level functions. Python: public module-level names.
    if (model.lang === 'js' ? !(exported || v.isFn) : !exported && v.name.startsWith('_')) continue
    out.push({
      name: v.name,
      kind: v.isFn ? 'function' : 'variable',
      startLine: lineAt(model, v.start),
      endLine: lineAt(model, Math.max(v.start, v.end - 1)),
      exported,
    })
  }
  out.sort((a, b) => a.startLine - b.startLine || b.endLine - a.endLine || (a.name < b.name ? -1 : 1))
  return out
}

function symbolKind(fn: FnFact): OutlineSymbol['kind'] | undefined {
  if (fn.className !== undefined) return 'method'
  if (fn.kind === 'method') return fn.parent ? undefined : 'method'
  return 'function'
}

/** A JS `function` that is a declaration (`function f() {}`), not an expression argument. */
function isDeclaration(model: FileModel, fn: FnFact): boolean {
  const before = model.source.slice(Math.max(0, fn.declStart - 1), fn.start)
  const head = model.source.slice(fn.declStart, fn.start + 20)
  if (/^(?:export\s+(?:default\s+)?)?(?:async\s+)?function\b/.test(head)) {
    const prev = model.source.slice(Math.max(0, fn.declStart - 40), fn.declStart).trimEnd()
    return (
      prev === '' || /[;{}]$/.test(prev) || /\n$/.test(model.source.slice(0, fn.declStart)) || before.endsWith('\n')
    )
  }
  return false
}

/**
 * Name under which an arrow/function expression is bound at module level
 * (`const f = () => {}`, `exports.f = function () {}`) or as a class field;
 * `undefined` for anonymous callbacks.
 */
function moduleBinding(model: FileModel, fn: FnFact): string | undefined {
  if (fn.className !== undefined && !fn.parent) return fn.name
  if (fn.parent) return undefined
  const v = model.vars.find(x => x.isFn && x.value.start <= fn.start && fn.start <= x.value.start + 16)
  if (v) return v.name
  const m = model.memberAssigns.find(
    a => a.value.start <= fn.start && fn.start <= a.value.start + 16 && /^(?:module\.)?exports\./.test(a.target),
  )
  return m?.prop
}

/** Python visibility: listed in `__all__` when the module defines one, otherwise not `_`-prefixed. */
function isPublicPython(model: FileModel, name: string): boolean {
  // `__all__` is recorded in `exportedNames` as a marker that the list exists.
  if (model.exportedNames.has('__all__')) return name !== '__all__' && model.exportedNames.has(name)
  return !name.startsWith('_')
}

function exportedByAlias(model: FileModel, name: string): boolean {
  return model.exportAliases.some(alias => alias.local === name) || model.defaultExport === name
}

function resolvePython(fromPath: string, specifier: string, has: (p: string) => boolean): string | undefined {
  const lead = /^\.*/.exec(specifier)?.[0].length ?? 0
  const rest = specifier.slice(lead)
  if (rest !== '' && !/^[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*$/.test(rest)) return undefined
  const parts = rest === '' ? [] : rest.split('.')
  const bases: string[] = []
  if (lead > 0) {
    let dir = dirOf(fromPath)
    for (let i = 1; i < lead; i++) {
      if (dir === '') return undefined
      dir = dirOf(dir)
    }
    bases.push(dir)
  } else {
    bases.push('')
    const own = dirOf(fromPath)
    // Walk up from the importing file: package roots are often subdirectories.
    for (let dir = own; dir !== ''; dir = dirOf(dir)) bases.push(dir)
    bases.push('src')
  }
  for (const base of bases) {
    const stem = [base, ...parts].filter(Boolean).join('/')
    // A bare package (`from . import x`) is its `__init__.py`; a module may be a file or a package.
    const pkg = stem === '' ? '__init__.py' : `${stem}/__init__.py`
    const candidates = parts.length === 0 ? [pkg] : [`${stem}.py`, `${stem}.pyi`, pkg]
    const found = candidates.find(has)
    if (found) return found
  }
  return undefined
}

function dirOf(path: string): string {
  const slash = path.lastIndexOf('/')
  return slash < 0 ? '' : path.slice(0, slash)
}

function joinPath(dir: string, rel: string): string {
  return dir === '' ? rel : `${dir}/${rel}`
}

/** Normalize `a/./b/../c`; `undefined` when it escapes the root. */
function normalizePath(path: string): string | undefined {
  const out: string[] = []
  for (const seg of path.split('/')) {
    if (seg === '' || seg === '.') continue
    if (seg === '..') {
      if (out.length === 0) return undefined
      out.pop()
      continue
    }
    out.push(seg)
  }
  return out.join('/')
}
