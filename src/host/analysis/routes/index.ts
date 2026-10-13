/**
 * Attack-surface extraction: HTTP endpoints declared in the snapshot, with
 * their handlers, attached middleware/guards/dependencies, auth hints and
 * path parameters.
 *
 * Each file contributes raw routes registered on a receiver (an app or
 * router variable), mounts (`app.use('/api', router)`, `include_router`,
 * Django `include`) and receiver-scoped middleware. The driver then walks
 * mount chains so a route declared on an imported router gets its full
 * path and the middleware of every mount above it.
 */

import type { AstGrepHandle } from '../astgrep.ts'
import type { FileModel } from '../sast/model.ts'
import { modelFor, modelKind } from '../sast/models.ts'
import { Expr } from '../sast/taint.ts'
import { type Endpoint, type Snapshot, type SnapshotFile, yieldToEventLoop } from '../types.ts'
import {
  ANY_RECEIVER,
  authHintsOf,
  joinRoute,
  type Mount,
  type RouteSink,
  routeParams,
  staticPrefix,
  underPrefix,
} from './common.ts'
import { extractJsRoutes } from './js.ts'
import { extractPyRoutes } from './python.ts'

const YIELD_EVERY = 25
const MAX_MOUNT_DEPTH = 8
const MAX_PATHS_PER_ROUTE = 16
const ROUTE_HINT =
  /@nestjs\/|\b(?:express|Router|fastify|koa|hono|app\.(?:get|post|put|patch|delete|all|use|route)|router\.|Flask|Blueprint|FastAPI|APIRouter|urlpatterns|add_url_rule|export\s+(?:async\s+)?(?:function|const)\s+(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b|export\s*\{[^}]*\bas\s+(?:GET|POST)\b|export\s+default)/

/**
 * Extract HTTP endpoints from a snapshot. Endpoints are sorted by route then
 * declaration line. `warnings` lists mounts and includes that could not be
 * resolved within the snapshot. Throws the abort reason when `signal` aborts.
 */
export async function extractRoutes(
  snapshot: Snapshot,
  options: { readonly astGrep?: AstGrepHandle; readonly signal?: AbortSignal } = {},
): Promise<{ endpoints: Endpoint[]; warnings: string[] }> {
  const { astGrep, signal } = options
  signal?.throwIfAborted()
  const sink: RouteSink = { routes: [], mounts: [], scoped: [], prefixes: [], warnings: [] }
  const modelOf = (file: SnapshotFile): FileModel | undefined => (modelKind(file) ? modelFor(file, astGrep) : undefined)
  let index = 0
  for (const file of snapshot.files.values()) {
    if (++index % YIELD_EVERY === 0) {
      await yieldToEventLoop()
      signal?.throwIfAborted()
    }
    const kind = modelKind(file)
    if (!kind || kind === 'embedded-js' || file.isGenerated) continue
    if (!ROUTE_HINT.test(file.content) && !/(?:^|\/)(?:app|pages)\//.test(file.path)) continue
    const model = modelOf(file)
    if (!model) continue
    try {
      const ctx = { file, model, ex: new Expr(model), snapshot, astGrep, sink, modelOf }
      if (model.lang === 'js') extractJsRoutes(ctx)
      else extractPyRoutes(ctx)
    } catch (error) {
      sink.warnings.push(
        `routes: ${file.path}: ${error instanceof Error ? error.message.slice(0, 200) : 'extraction failed'}`,
      )
    }
  }
  signal?.throwIfAborted()
  const endpoints = resolveEndpoints(sink)
  return { endpoints, warnings: [...new Set(sink.warnings)].sort() }
}

interface Context {
  readonly prefix: string
  readonly middleware: readonly string[]
}

function resolveEndpoints(sink: RouteSink): Endpoint[] {
  const key = (file: string, receiver: string): string => `${file}\0${receiver}`
  const mountsByChild = new Map<string, Mount[]>()
  for (const mount of sink.mounts) {
    const k = key(mount.child.file, mount.child.receiver)
    const list = mountsByChild.get(k)
    if (list) list.push(mount)
    else mountsByChild.set(k, [mount])
  }
  const prefixOf = new Map<string, string>()
  for (const p of sink.prefixes) prefixOf.set(key(p.file, p.receiver), p.prefix)

  /** Mounts targeting a receiver; an `export default`-style child also matches `default`/`*`. */
  const mountsOf = (file: string, receiver: string): Mount[] => {
    const out = [...(mountsByChild.get(key(file, receiver)) ?? [])]
    for (const alt of ['default', ANY_RECEIVER]) {
      if (alt === receiver) continue
      for (const m of mountsByChild.get(key(file, alt)) ?? []) if (!out.includes(m)) out.push(m)
    }
    if (receiver !== ANY_RECEIVER && out.length === 0)
      out.push(...(mountsByChild.get(key(file, 'router')) ?? []).filter(m => m.child.receiver === receiver))
    return out
  }

  /** Every (prefix, inherited middleware) chain from the top-level apps down to `receiver`. */
  const contexts = (file: string, receiver: string, depth: number, seen: Set<string>): Context[] => {
    const own = prefixOf.get(key(file, receiver)) ?? ''
    const mounts = depth >= MAX_MOUNT_DEPTH ? [] : mountsOf(file, receiver)
    if (mounts.length === 0) return [{ prefix: own, middleware: [] }]
    const out: Context[] = []
    for (const mount of mounts) {
      const k = key(mount.parent.file, mount.parent.receiver)
      if (seen.has(k)) continue
      const next = new Set(seen).add(k)
      const parentMw = scopedFor(sink, mount.parent.file, mount.parent.receiver, mount.offset, mount.prefix)
      for (const parent of contexts(mount.parent.file, mount.parent.receiver, depth + 1, next)) {
        const local = mount.replacesPrefix ? mount.prefix : joinRoute(mount.prefix, own)
        out.push({
          prefix: joinRoute(parent.prefix, local),
          middleware: [...parent.middleware, ...parentMw, ...mount.middleware],
        })
        if (out.length >= MAX_PATHS_PER_ROUTE) return out
      }
    }
    return out.length > 0 ? out : [{ prefix: own, middleware: [] }]
  }

  const endpoints = new Map<string, Endpoint>()
  for (const route of sink.routes) {
    const ctxs =
      route.receiver === undefined
        ? [{ prefix: '', middleware: [] }]
        : contexts(route.file, route.receiver, 0, new Set([key(route.file, route.receiver)]))
    for (const ctx of ctxs) {
      const joined = route.receiver === undefined ? route.path : joinRoute(ctx.prefix, route.path)
      const path = joined === '' ? '/' : joined
      const scoped =
        route.receiver === undefined ? [] : scopedFor(sink, route.file, route.receiver, route.offset, route.path)
      const middleware = dedupe([...ctx.middleware, ...scoped, ...route.middleware])
      const authHints = dedupe([...authHintsOf(middleware), ...(route.extraAuthHints ?? [])])
      const params = dedupe([...routeParams(path), ...(route.params ?? [])])
      const id = `${route.method} ${path} @ ${route.declaredAt.path}:${route.declaredAt.startLine}`
      if (endpoints.has(id)) continue
      endpoints.set(id, {
        id,
        framework: route.framework,
        method: route.method,
        route: path,
        declaredAt: route.declaredAt,
        ...(route.handler ? { handler: route.handler } : {}),
        middleware,
        authHints,
        params,
      })
    }
  }
  return [...endpoints.values()].sort(
    (a, b) =>
      compare(a.route, b.route) ||
      compare(a.declaredAt.path, b.declaredAt.path) ||
      a.declaredAt.startLine - b.declaredAt.startLine ||
      compare(a.method, b.method),
  )
}

/** Receiver-scoped middleware that applies to a route (or mount) at `offset` with local path `path`. */
function scopedFor(sink: RouteSink, file: string, receiver: string, offset: number, path: string): string[] {
  const out: string[] = []
  for (const s of sink.scoped) {
    if (s.file !== file || (s.receiver !== receiver && s.receiver !== ANY_RECEIVER)) continue
    if (s.ordered && s.offset > offset) continue
    if (s.pathPrefix && !underPrefix(path, staticPrefix(s.pathPrefix))) continue
    out.push(...s.names)
  }
  return out
}

function dedupe(values: readonly string[]): string[] {
  return [...new Set(values)]
}

function compare(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0
}
