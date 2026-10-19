/**
 * Project facts the per-file taint engine cannot see on its own: which Django view parameters every URLconf
 * route fills through an `int` or `uuid` converter (`path('products/<int:product_id>/', views.detail)`). Such
 * a parameter is a number or a UUID, never attacker-chosen text.
 */

import type { AstGrepHandle } from '../astgrep.ts'
import { resolveRelativeImport } from '../outline.ts'
import type { Snapshot } from '../types.ts'
import type { FileModel } from './model.ts'
import { modelFor } from './models.ts'
import { Expr } from './taint.ts'

/** View file → view function name → parameters filled only by numeric or UUID converters. */
export type ScalarParams = ReadonlyMap<string, ReadonlyMap<string, ReadonlySet<string>>>

const SCALAR_CONVERTERS: ReadonlySet<string> = new Set(['int', 'uuid'])
/** `re_path` groups whose pattern admits only digits (`(?P<id>\d+)`, `(?P<id>[0-9]{1,8})`). */
const DIGIT_GROUP = /^(?:\\d|\[0-9\])(?:[+*]|\{\d+(?:,\d*)?\})?$/

/**
 * Scan the snapshot's Django URLconfs (files defining `urlpatterns`) once. A parameter is listed when at least
 * one route fills it and every route that fills it uses `<int:…>`/`<uuid:…>` (or a digits-only `re_path`
 * group). Views reached through `include()` of another URLconf are covered by that URLconf's own patterns.
 */
export function djangoScalarParams(snapshot: Snapshot, astGrep: AstGrepHandle | undefined): ScalarParams {
  // view key → param → whether every binding so far was scalar
  const bindings = new Map<string, Map<string, boolean>>()
  for (const file of snapshot.files.values()) {
    if (!file.path.endsWith('.py') || file.isGenerated || !file.content.includes('urlpatterns')) continue
    const model = modelFor(file, astGrep)
    if (model?.lang !== 'py') continue
    const ex = new Expr(model)
    for (const call of model.calls) {
      const fn = call.callee.replace(/^.*\./, '')
      if ((fn !== 'path' && fn !== 're_path' && fn !== 'url') || call.decorator) continue
      const positional = call.args.filter(a => !a.keyword)
      const routeArg = positional[0]
      const viewArg = positional[1]
      if (!routeArg || !viewArg) continue
      const route = ex.literal(routeArg)
      if (route === undefined) continue
      const viewText = ex.text(viewArg).replace(/\s+/g, '')
      if (!/^(?:[A-Za-z_]\w*\.)*[A-Za-z_]\w*$/.test(viewText)) continue // include(...), as_view(), wrappers
      const view = resolveView(model, snapshot, viewText)
      if (!view) continue
      const key = `${view.file}\u0000${view.name}`
      const params = bindings.get(key) ?? new Map<string, boolean>()
      bindings.set(key, params)
      for (const [name, scalar] of routeConverters(route, fn === 'path')) {
        params.set(name, (params.get(name) ?? true) && scalar)
      }
    }
  }
  const out = new Map<string, Map<string, Set<string>>>()
  for (const [key, params] of bindings) {
    const [file, name] = key.split('\u0000') as [string, string]
    const scalar = [...params].filter(([, ok]) => ok).map(([param]) => param)
    if (scalar.length === 0) continue
    const byFn = out.get(file) ?? new Map<string, Set<string>>()
    byFn.set(name, new Set(scalar))
    out.set(file, byFn)
  }
  return out
}

/** Parameters a route pattern fills, and whether each is numeric or a UUID. */
function routeConverters(route: string, typed: boolean): [string, boolean][] {
  const out: [string, boolean][] = []
  if (typed) {
    for (const m of route.matchAll(/<(?:([A-Za-z_]\w*):)?([A-Za-z_]\w*)>/g)) {
      out.push([m[2]!, SCALAR_CONVERTERS.has(m[1] ?? 'str')])
    }
    return out
  }
  for (const m of route.matchAll(/\(\?P<([A-Za-z_]\w*)>([^()]*)\)/g)) out.push([m[1]!, DIGIT_GROUP.test(m[2]!)])
  return out
}

/** The module file and function a URLconf view reference names (`views.detail`, `detail`, `shop.views.detail`). */
function resolveView(
  model: FileModel,
  snapshot: Snapshot,
  viewText: string,
): { file: string; name: string } | undefined {
  const parts = viewText.split('.')
  const name = parts.pop()!
  const qualifier = parts.join('.')
  for (const imp of model.imports) {
    if (qualifier === '') {
      const binding = imp.bindings.find(b => b.local === name)
      if (!binding || imp.kind !== 'from') continue
      const file = resolveRelativeImport(model.path, imp.source, snapshot)
      return file ? { file, name: binding.imported } : undefined
    }
    const head = parts[0]!
    const binding = imp.bindings.find(b => b.local === head)
    if (!binding) continue
    const module = imp.kind === 'from' ? joinModule(imp.source, binding.imported) : imp.source
    const dotted = parts.length > 1 ? `${module}.${parts.slice(1).join('.')}` : module
    const file = resolveRelativeImport(model.path, dotted, snapshot)
    return file ? { file, name } : undefined
  }
  // A view defined in the URLconf itself.
  return qualifier === '' && model.fns.some(f => f.name === name && !f.parent) ? { file: model.path, name } : undefined
}

function joinModule(base: string, name: string): string {
  return /^\.+$/.test(base) ? base + name : `${base}.${name}`
}
