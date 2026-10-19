/**
 * Shared vocabulary for route extraction: raw routes registered on a
 * receiver (an app/router variable), mounts that attach one receiver under
 * another with a prefix, and receiver-scoped middleware.
 *
 * Extractors describe mounted children symbolically (`Ref`), because whether
 * `requireAuth` in `app.use('/api', requireAuth, ordersRouter)` is a router
 * or middleware depends on another file. The linker (`link.ts`) resolves the
 * references once every file has been extracted.
 */

import type { CodeRef } from '../../../shared/domain.ts'
import type { AstGrepHandle } from '../astgrep.ts'
import { type FileModel, lineAt, type Span } from '../sast/model.ts'
import type { Expr } from '../sast/taint.ts'
import type { Snapshot, SnapshotFile } from '../types.ts'
import type { FileScope } from './link.ts'

/** Receiver id meaning "every receiver in the file" (Django URLconfs). */
export const ANY_RECEIVER = '*'

export interface RawRoute {
  readonly framework: string
  readonly method: string
  /** Path as declared on its receiver, before mount prefixes. */
  readonly path: string
  readonly file: string
  /**
   * Receiver id the route is registered on (see `MountTarget.receiver`);
   * `undefined` when it cannot be mounted.
   */
  readonly receiver: string | undefined
  readonly declaredAt: CodeRef
  readonly handler?: CodeRef
  readonly middleware: readonly string[]
  /** Extra auth hints from nearby code (e.g. Next.js middleware). */
  readonly extraAuthHints?: readonly string[]
  /** Source offset, for order-sensitive middleware. */
  readonly offset: number
  /** Path params that cannot be read from `path` (e.g. Next.js catch-alls). */
  readonly params?: readonly string[]
}

/**
 * An app/router within a file. `receiver` is the variable name for a
 * module-level binding, `name@<offset>` for a parameter or local of the
 * function starting at `offset` (JavaScript), or `ANY_RECEIVER`.
 */
export interface MountTarget {
  readonly file: string
  readonly receiver: string
}

/**
 * Symbolic reference to a value that may be an app, router or plugin.
 * `export` with name `*` is the module object itself (`require('./x')`).
 */
export type Ref =
  | { readonly kind: 'receiver'; readonly file: string; readonly receiver: string }
  | { readonly kind: 'local'; readonly file: string; readonly name: string }
  | { readonly kind: 'export'; readonly file: string; readonly name: string }
  | { readonly kind: 'member'; readonly object: Ref; readonly name: string }
  | { readonly kind: 'fn'; readonly file: string; readonly start: number }
  | { readonly kind: 'call'; readonly callee: Ref | undefined; readonly args: readonly (Ref | undefined)[] }
  | { readonly kind: 'param'; readonly fn: Ref; readonly index: number }
  /** A package import: known, but never an app/router of this snapshot. */
  | { readonly kind: 'external' }
  /** A local import that is not in the snapshot. */
  | { readonly kind: 'missing'; readonly spec: string }

/** A mount whose child is known to be an app/router/plugin, pending resolution. */
export interface PendingMount {
  readonly parent: MountTarget
  readonly child: Ref
  readonly prefix: string
  readonly middleware: readonly string[]
  readonly offset: number
  /** The mount prefix replaces the child's own prefix (Flask `register_blueprint(url_prefix=...)`). */
  readonly replacesPrefix?: boolean
  /** Receiver to use when `child` resolves to a whole module (Django `include(urls_module)` → `*`). */
  readonly moduleReceiver?: string
  /** Warning recorded when `child` does not resolve; without one the mount is dropped silently. */
  readonly unresolved?: string
}

/** One argument of an Express/Koa `use(...)` call after the optional path. */
export interface UseArg {
  /** Middleware names the argument contributes when it is not a router. */
  readonly names: readonly string[]
  readonly ref?: Ref
  /**
   * Set when the argument looks like a router (`ordersRouter`,
   * `require('./x')`): the warning recorded when `ref` does not resolve, in
   * which case it is neither a mount nor middleware. Other unresolved
   * arguments count as middleware.
   */
  readonly unresolved?: string
}

/** `app.use('/api', auth, router)`: routers among `args` become mounts, the rest middleware. */
export interface UseCall {
  readonly parent: MountTarget
  readonly prefix: string
  readonly args: readonly UseArg[]
  readonly offset: number
  readonly end: number
  /** Middleware it registers applies only to later registrations (Express/Koa/Hono). */
  readonly ordered: boolean
}

/** A resolved mount of `child` under `parent`. */
export interface Mount {
  readonly parent: MountTarget
  readonly child: MountTarget
  readonly prefix: string
  readonly middleware: readonly string[]
  /** File holding the mount call; `offset` is an offset into it. */
  readonly file: string
  readonly offset: number
  readonly replacesPrefix?: boolean
}

/** A prefix declared on the receiver itself (`Blueprint(url_prefix=)`, `APIRouter(prefix=)`, `new Router({ prefix })`). */
export interface ReceiverPrefix {
  readonly file: string
  readonly receiver: string
  readonly prefix: string
}

/** Middleware attached to a receiver (`router.use(auth)`, Fastify hooks, FastAPI router dependencies). */
export interface ScopedMiddleware {
  readonly file: string
  readonly receiver: string
  readonly names: readonly string[]
  readonly offset: number
  /** Applies only to routes declared after it (Express/Koa/Hono order semantics). */
  readonly ordered: boolean
  /** Applies only to paths under this prefix. */
  readonly pathPrefix?: string
  /** Names that count as auth hints whatever they are called (a hook whose body checks auth). */
  readonly hints?: readonly string[]
}

export interface RouteSink {
  readonly routes: RawRoute[]
  readonly mounts: PendingMount[]
  readonly uses: UseCall[]
  readonly scoped: ScopedMiddleware[]
  readonly prefixes: ReceiverPrefix[]
  /** Apps and routers created by a known constructor (`express.Router()`, `APIRouter()`). */
  readonly receivers: MountTarget[]
  readonly warnings: string[]
}

export interface RouteFileContext {
  readonly file: SnapshotFile
  readonly model: FileModel
  readonly ex: Expr
  readonly snapshot: Snapshot
  readonly astGrep: AstGrepHandle | undefined
  readonly sink: RouteSink
  /** Receiver ids and symbolic values for this file. */
  readonly scope: FileScope
  /** Code model of another snapshot file (cached). */
  readonly modelOf: (file: SnapshotFile) => FileModel | undefined
}

/** An empty sink. */
export function newSink(): RouteSink {
  return { routes: [], mounts: [], uses: [], scoped: [], prefixes: [], receivers: [], warnings: [] }
}

/** Map key for a receiver. */
export function targetKey(file: string, receiver: string): string {
  return `${file}\0${receiver}`
}

/**
 * Names suggesting authentication or authorization: the documented core
 * (`auth|login|session|jwt|token|passport|guard|protect|require(User|Admin|Role)|isAuthenticated|verify|acl|permission|rbac|admin`)
 * plus framework idioms it misses (`@Roles`, `roles_required`, `get_current_user`,
 * `staff_member_required`, `user_passes_test`, `api_key`).
 *
 * Names that are clearly rate limiting, throttling, or logging never count,
 * even when they mention auth (`loginLimiter`, `authRateLimit`,
 * `loginThrottle`, `authLogger`): telling a reviewer such a route is guarded
 * would hide a missing check.
 */
export const AUTH_HINT =
  /^(?![\s\S]*(?:limit|throttl|slow_?down|logg(?:er|ing)))[\s\S]*?(?:auth|login|session|jwt|token|passport|guard|protect|require(?:User|Admin|Role)|isAuthenticated|verify|acl|permission|rbac|admin|role|current_?(?:active_?)?user|signed_?in|logged_?in|api_?key|passes_?test|staff|superuser)/i

/**
 * Middleware that loads request state but never rejects a request: session stores (`session({...})`,
 * `cookieSession()`, `require('express-session')(...)`), Passport's `initialize()` and `session()`, and
 * database-session dependencies (`Depends(get_session)`). Their names match `AUTH_HINT`, yet a route behind
 * them alone is still public, so they are not auth hints. Enforcing names (`requireSession`,
 * `passport.authenticate`, `verifySession`) still are.
 */
const NON_ENFORCING_MIDDLEWARE =
  /^(?:(?:express|cookie|koa|fastify|secure|client|iron|redis)?[Ss]ession|(?:express|cookie|koa|fastify|secure)[_-]session|passport\.(?:initialize|session)|require\((['"`])(?:express-session|cookie-session|koa-session|koa-generic-session|@fastify\/(?:secure-)?session|passport)\1\)(?:\.\w+)?|(?:get|create|open|new|load)_?(?:db_?|async_?|sql_?)?[Ss]ession|(?:get|create|open|new|load)(?:Db|DB|Async|Sql)?Session|SessionLocal)$/

/** Whether a middleware, guard, decorator or dependency name suggests that it enforces authentication or authorization. */
export function isAuthHint(name: string): boolean {
  if (!AUTH_HINT.test(name)) return false
  const bare = name.replace(/^Depends\(\s*([^()]*?)\s*\)$/, '$1')
  return !NON_ENFORCING_MIDDLEWARE.test(bare)
}

/** Middleware names whose text suggests auth. */
export function authHintsOf(middleware: readonly string[]): string[] {
  return [...new Set(middleware.filter(isAuthHint))]
}

/** CodeRef for a span of a model. */
export function refOf(model: FileModel, span: Span): CodeRef {
  const startLine = lineAt(model, span.start)
  return {
    path: model.path,
    startLine,
    endLine: Math.max(startLine, lineAt(model, Math.max(span.start, span.end - 1))),
  }
}

/** `path:line` of a span, for warnings. */
export function refString(model: FileModel, span: Span): string {
  return `${model.path}:${lineAt(model, span.start)}`
}

/** Join a mount prefix and a route path (`/api` + `/users` → `/api/users`). */
export function joinRoute(prefix: string, path: string): string {
  if (prefix === '' || prefix === '/') return path === '' ? prefix || '' : path
  // An empty child path keeps the prefix exactly as written (Django `include('shop/')` + `path('')`).
  if (path === '') return prefix
  const head = prefix.endsWith('/') ? prefix.slice(0, -1) : prefix
  if (path === '/') return head || '/'
  return path.startsWith('/') ? head + path : `${head}/${path}`
}

/** Path parameter names in a route pattern (`:id`, `{id}`, `<int:id>`, `[id]`, `(?P<id>...)`, `*name`). */
export function routeParams(route: string): string[] {
  const out: string[] = []
  const add = (name: string | undefined): void => {
    if (name && !out.includes(name)) out.push(name)
  }
  for (const m of route.matchAll(/\(\?P<(\w+)>/g)) add(m[1])
  const plain = route.replace(/\(\?P<\w+>[^)]*\)/g, '')
  for (const m of plain.matchAll(/(?:^|[/.;-]):([A-Za-z_$][\w$]*)/g)) add(m[1])
  for (const m of plain.matchAll(/\{([A-Za-z_]\w*)(?::[^}]*)?\}/g)) add(m[1])
  for (const m of plain.matchAll(/<(?:[A-Za-z_]\w*:)?([A-Za-z_]\w*)>/g)) add(m[1])
  for (const m of plain.matchAll(/\[\[?(?:\.\.\.)?([A-Za-z_$][\w$]*)\]\]?/g)) add(m[1])
  for (const m of plain.matchAll(/(?:^|\/)\*([A-Za-z_$][\w$]*)/g)) add(m[1])
  return out
}

/** Strip a trailing wildcard so a scoped middleware path can be compared as a prefix. */
export function staticPrefix(path: string): string {
  let p = path.replace(/\/?\*+$/, '').replace(/\(\.\*\)$/, '')
  if (p === '') p = '/'
  return p
}

/** Whether `path` lies under `prefix` (segment-aware). */
export function underPrefix(path: string, prefix: string): boolean {
  if (prefix === '/' || prefix === '') return true
  const p = prefix.endsWith('/') ? prefix.slice(0, -1) : prefix
  return path === p || path.startsWith(`${p}/`)
}
