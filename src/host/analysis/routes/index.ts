/**
 * Attack-surface extraction: HTTP endpoints declared in the snapshot, with
 * their handlers, attached middleware/guards/dependencies, auth hints and
 * path parameters.
 *
 * Each file contributes raw routes registered on a receiver (an app or
 * router variable), mounts (`app.use('/api', router)`, `include_router`,
 * Django `include`) and receiver-scoped middleware. Mounted children are
 * described symbolically and resolved across files by the linker
 * (`link.ts`). The driver then walks mount chains so a route declared on an
 * imported router gets its full path and the middleware of every mount
 * above it, outermost first.
 *
 * Cross-file mounts followed: Express `use` (nested routers, order-sensitive
 * and path-scoped middleware, registration functions `register(app)`),
 * Koa `use(router.routes())` with `prefix`, Hono `route()`, Fastify
 * `register(plugin, { prefix })` with `addHook`, FastAPI `include_router`,
 * Flask `register_blueprint` (nested too) with `before_request`, Django
 * `include`. Known gaps: a hook added inside a `fastify-plugin` (`fp`)
 * wrapped plugin is not propagated to the parent, and `fp` plugins still
 * get the `prefix` option; dynamically built mounts (`require(variable)`,
 * `routers[0]`) and path aliases (`@/routes`) are not followed (a warning
 * is recorded and their routes keep local paths); a route reachable only
 * through chains deeper than `MAX_MOUNT_DEPTH` mounts is listed with its
 * local path.
 */

import type { AstGrepHandle } from '../astgrep.ts'
import type { FileModel } from '../sast/model.ts'
import { modelFor, modelKind } from '../sast/models.ts'
import { Expr } from '../sast/taint.ts'
import { type Endpoint, type Snapshot, type SnapshotFile, yieldToEventLoop } from '../types.ts'
import {
  ANY_RECEIVER,
  AUTH_HINT,
  joinRoute,
  type Mount,
  type MountTarget,
  newSink,
  type RawRoute,
  type ReceiverPrefix,
  type RouteSink,
  routeParams,
  type ScopedMiddleware,
  staticPrefix,
  targetKey,
  underPrefix,
} from './common.ts'
import { extractJsRoutes } from './js.ts'
import { FileScope, type LinkInfo, Linker } from './link.ts'
import { extractPyRoutes } from './python.ts'

const YIELD_EVERY = 25
const MAX_MOUNT_DEPTH = 8
/** Mount chains (hence endpoints) listed per declared route at most. */
export const MAX_PATHS_PER_ROUTE = 16
/** Chain steps explored per route, so many mounts of many routers cannot blow up. */
const MAX_STEPS_PER_ROUTE = 256
const ROUTE_HINT =
  /@nestjs\/|\b(?:express|Router|fastify|koa|hono|app\.(?:get|post|put|patch|delete|all|use|route)|router\.|Flask|Blueprint|FastAPI|APIRouter|urlpatterns|add_url_rule|export\s+(?:async\s+)?(?:function|const)\s+(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b|export\s*\{[^}]*\bas\s+(?:GET|POST)\b|export\s+default)/

/**
 * Extract HTTP endpoints from a snapshot. Endpoints are sorted by route then
 * declaration line. A route on a router mounted elsewhere (in any file) gets
 * the full mount prefix, and the middleware of every enclosing mount (outer
 * to inner) before its own; `authHints` is computed from that combined list.
 * `warnings` lists mounts and includes that could not be resolved within the
 * snapshot (their routes are still listed, with local paths). Throws the
 * abort reason when `signal` aborts.
 */
export async function extractRoutes(
  snapshot: Snapshot,
  options: { readonly astGrep?: AstGrepHandle; readonly signal?: AbortSignal } = {},
): Promise<{ endpoints: Endpoint[]; warnings: string[] }> {
  const { astGrep, signal } = options
  signal?.throwIfAborted()
  const sink = newSink()
  const links = new Map<string, LinkInfo>()
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
      const ex = new Expr(model)
      const scope = new FileScope(model, ex, snapshot)
      const ctx = { file, model, ex, scope, snapshot, astGrep, sink, modelOf }
      if (model.lang === 'js') extractJsRoutes(ctx)
      else extractPyRoutes(ctx)
      // Bindings and exports, kept so linking never re-parses a route file evicted from the model cache.
      links.set(file.path, scope.link())
    } catch (error) {
      sink.warnings.push(
        `routes: ${file.path}: ${error instanceof Error ? error.message.slice(0, 200) : 'extraction failed'}`,
      )
    }
  }
  signal?.throwIfAborted()
  const linker = new Linker(sink, snapshot, modelOf, links)
  const mounts = await linker.mounts(signal)
  const endpoints = await resolveEndpoints(sink, mounts, linker, signal)
  return { endpoints, warnings: [...new Set(sink.warnings)].sort() }
}

/** Where a receiver sits in a top-level app: the prefix above its routes and the middleware they inherit. */
interface Context {
  readonly prefix: string
  readonly middleware: readonly string[]
}

/** Per-receiver indexes over the sink, keyed by canonical receiver. */
class Graph {
  readonly #linker: Linker
  readonly #mountsByChild = new Map<string, Mount[]>()
  readonly #scopedBy = new Map<string, ScopedMiddleware[]>()
  readonly #prefixOf = new Map<string, string>()
  /** Fewest mounts between a receiver and a top-level app (see `heightOf`). */
  readonly #height = new Map<string, number>()
  readonly #sorted = new Map<string, readonly { readonly mount: Mount; readonly height: number }[]>()
  /** Names that count as auth hints because of what they do (a hook whose body checks auth). */
  readonly hinted = new Set<string>()

  constructor(sink: RouteSink, mounts: readonly Mount[], linker: Linker) {
    this.#linker = linker
    const mountsByParent = new Map<string, Mount[]>()
    for (const mount of mounts) {
      const parent = linker.canonical(mount.parent)
      const canonical = { ...mount, parent }
      push(this.#mountsByChild, targetKey(mount.child.file, mount.child.receiver), canonical)
      push(mountsByParent, targetKey(parent.file, parent.receiver), canonical)
    }
    // Breadth-first from the top-level apps (parents that are mounted nowhere), so chains can be walked shortest first.
    const queue: string[] = []
    for (const [key, list] of mountsByParent) {
      if (this.mountsOf(list[0]!.parent).length === 0) {
        this.#height.set(key, 0)
        queue.push(key)
      }
    }
    for (let i = 0; i < queue.length; i++) {
      const key = queue[i]!
      const next = this.#height.get(key)! + 1
      for (const mount of mountsByParent.get(key) ?? []) {
        const child = targetKey(mount.child.file, mount.child.receiver)
        if (this.#height.has(child)) continue
        this.#height.set(child, next)
        queue.push(child)
      }
    }
    for (const s of sink.scoped) {
      const c = linker.canonical(s)
      push(
        this.#scopedBy,
        targetKey(c.file, c.receiver),
        s.pathPrefix ? { ...s, pathPrefix: staticPrefix(s.pathPrefix) } : s,
      )
      for (const name of s.hints ?? []) this.hinted.add(name)
    }
    for (const p of sink.prefixes) this.#setPrefix(p)
  }

  canonical(target: MountTarget): MountTarget {
    return this.#linker.canonical(target)
  }

  ownPrefix(t: MountTarget): string {
    return this.#prefixOf.get(targetKey(t.file, t.receiver)) ?? ''
  }

  /** Mounts of `t`; every receiver of a file also matches an `ANY_RECEIVER` child (Django URLconfs). */
  mountsOf(t: MountTarget): readonly Mount[] {
    const own = this.#mountsByChild.get(targetKey(t.file, t.receiver)) ?? []
    if (t.receiver === ANY_RECEIVER) return own
    const any = this.#mountsByChild.get(targetKey(t.file, ANY_RECEIVER))
    return any ? [...own, ...any.filter(m => !own.includes(m))] : own
  }

  /** Fewest mounts between `t` and a top-level app (`Infinity` when only cycles lead to `t`). */
  heightOf(t: MountTarget): number {
    return Math.min(
      this.#height.get(targetKey(t.file, t.receiver)) ?? Infinity,
      this.#height.get(targetKey(t.file, ANY_RECEIVER)) ?? Infinity,
    )
  }

  /** Mounts of `t` with the height of their parent, closest to a top-level app first (stable otherwise). */
  mountsByHeight(t: MountTarget): readonly { readonly mount: Mount; readonly height: number }[] {
    const key = targetKey(t.file, t.receiver)
    const hit = this.#sorted.get(key)
    if (hit) return hit
    const sorted = this.mountsOf(t)
      .map(mount => ({ mount, height: this.heightOf(mount.parent) }))
      .sort((a, b) => (a.height === b.height ? 0 : a.height < b.height ? -1 : 1))
    this.#sorted.set(key, sorted)
    return sorted
  }

  /**
   * Middleware registered on `t` that applies to a registration at `offset`
   * in `file` whose path relative to `t` is `path`. Order only counts within
   * one file: middleware registered on an imported app runs before routes
   * other modules add to it.
   */
  scopedFor(t: MountTarget, file: string, offset: number, path: string): string[] {
    const out: string[] = []
    const own = this.#scopedBy.get(targetKey(t.file, t.receiver))
    const any = t.receiver === ANY_RECEIVER ? undefined : this.#scopedBy.get(targetKey(t.file, ANY_RECEIVER))
    for (const list of [own, any]) {
      for (const s of list ?? []) {
        if (s.ordered && s.file === file && s.offset > offset) continue
        if (s.pathPrefix && !underPrefix(path, s.pathPrefix)) continue
        out.push(...s.names)
      }
    }
    return out
  }

  #setPrefix(p: ReceiverPrefix): void {
    const c = this.#linker.canonical(p)
    const key = targetKey(c.file, c.receiver)
    // A prefix set where the router is created wins over one set elsewhere.
    if (!this.#prefixOf.has(key) || (p.file === c.file && p.receiver === c.receiver)) this.#prefixOf.set(key, p.prefix)
  }
}

async function resolveEndpoints(
  sink: RouteSink,
  mounts: readonly Mount[],
  linker: Linker,
  signal: AbortSignal | undefined,
): Promise<Endpoint[]> {
  const graph = new Graph(sink, mounts, linker)

  /**
   * Every (prefix, inherited middleware) chain from the top-level apps down
   * to `t`, for a route whose path relative to `t` (below its own prefix) is
   * `path`. Middleware registered on a parent is filtered by the route's
   * path as the parent sees it. Mounts closest to a top-level app are
   * followed first and those that cannot reach one within `MAX_MOUNT_DEPTH`
   * are skipped; a chain cut by a limit or a cycle yields nothing rather
   * than a partial prefix (`[]` when every chain was cut).
   */
  const contexts = (
    t: MountTarget,
    path: string,
    depth: number,
    seen: Set<string>,
    budget: { steps: number },
  ): Context[] => {
    const own = graph.ownPrefix(t)
    const mountsOfT = graph.mountsByHeight(t)
    if (mountsOfT.length === 0) return [{ prefix: own, middleware: [] }]
    if (depth >= MAX_MOUNT_DEPTH) return []
    const out: Context[] = []
    for (const { mount, height } of mountsOfT) {
      // Sorted by height: once a parent's shortest chain is too deep, so are the others'.
      if (height > 0 && depth + height >= MAX_MOUNT_DEPTH) break
      const parent = mount.parent
      const k = targetKey(parent.file, parent.receiver)
      if (seen.has(k)) continue
      if (--budget.steps < 0) break
      const base = mount.replacesPrefix ? mount.prefix : joinRoute(mount.prefix, own)
      const pathInParent = joinRoute(base, path)
      const parentMw = graph.scopedFor(parent, mount.file, mount.offset, pathInParent)
      seen.add(k)
      for (const above of contexts(parent, pathInParent, depth + 1, seen, budget)) {
        out.push({
          prefix: joinRoute(above.prefix, base),
          middleware: [...above.middleware, ...parentMw, ...mount.middleware],
        })
        if (out.length >= MAX_PATHS_PER_ROUTE) break
      }
      seen.delete(k)
      if (out.length >= MAX_PATHS_PER_ROUTE) break
    }
    return out
  }

  const endpoints = new Map<string, Endpoint>()
  let n = 0
  for (const route of sink.routes) {
    if (++n % (YIELD_EVERY * 8) === 0) {
      await yieldToEventLoop()
      signal?.throwIfAborted()
    }
    const target =
      route.receiver === undefined ? undefined : graph.canonical({ file: route.file, receiver: route.receiver })
    const found = target
      ? contexts(target, route.path, 0, new Set([targetKey(target.file, target.receiver)]), {
          steps: MAX_STEPS_PER_ROUTE,
        })
      : []
    // Every chain cut by a limit or a cycle: list the route with its local path, as for an unresolved mount.
    const ctxs = found.length > 0 ? found : [{ prefix: target ? graph.ownPrefix(target) : '', middleware: [] }]
    for (const ctx of ctxs) addEndpoint(endpoints, graph, route, target, ctx)
  }
  return [...endpoints.values()].sort(
    (a, b) =>
      compare(a.route, b.route) ||
      compare(a.declaredAt.path, b.declaredAt.path) ||
      a.declaredAt.startLine - b.declaredAt.startLine ||
      compare(a.method, b.method),
  )
}

function addEndpoint(
  endpoints: Map<string, Endpoint>,
  graph: Graph,
  route: RawRoute,
  target: MountTarget | undefined,
  ctx: Context,
): void {
  const joined = target === undefined ? route.path : joinRoute(ctx.prefix, route.path)
  const path = joined === '' ? '/' : joined
  const scoped = target === undefined ? [] : graph.scopedFor(target, route.file, route.offset, route.path)
  const middleware = dedupe([...ctx.middleware, ...scoped, ...route.middleware])
  const authHints = dedupe([
    ...middleware.filter(name => AUTH_HINT.test(name) || graph.hinted.has(name)),
    ...(route.extraAuthHints ?? []),
  ])
  const params = dedupe([...routeParams(path), ...(route.params ?? [])])
  const id = `${route.method} ${path} @ ${route.declaredAt.path}:${route.declaredAt.startLine}`
  if (endpoints.has(id)) return
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

function push<T>(map: Map<string, T[]>, key: string, value: T): void {
  const list = map.get(key)
  if (list) list.push(value)
  else map.set(key, [value])
}

function dedupe(values: readonly string[]): string[] {
  return [...new Set(values)]
}

function compare(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0
}
