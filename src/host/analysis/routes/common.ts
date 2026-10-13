/**
 * Shared vocabulary for route extraction: raw routes registered on a
 * receiver (an app/router variable), mounts that attach one receiver under
 * another with a prefix, and receiver-scoped middleware.
 */

import type { CodeRef } from '../../../shared/domain.ts'
import type { AstGrepHandle } from '../astgrep.ts'
import { type FileModel, lineAt, type Span } from '../sast/model.ts'
import type { Expr } from '../sast/taint.ts'
import type { Snapshot, SnapshotFile } from '../types.ts'

/** Receiver id meaning "every receiver in the file" (Fastify plugins, Django URLconfs). */
export const ANY_RECEIVER = '*'

export interface RawRoute {
  readonly framework: string
  readonly method: string
  /** Path as declared on its receiver, before mount prefixes. */
  readonly path: string
  readonly file: string
  /** App/router variable the route is registered on; `undefined` when it cannot be mounted. */
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

export interface MountTarget {
  readonly file: string
  readonly receiver: string
}

export interface Mount {
  readonly parent: MountTarget
  readonly child: MountTarget
  readonly prefix: string
  readonly middleware: readonly string[]
  readonly offset: number
  readonly at: CodeRef
  /** The mount prefix replaces the child's own prefix (Flask `register_blueprint(url_prefix=...)`). */
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
}

export interface RouteSink {
  readonly routes: RawRoute[]
  readonly mounts: Mount[]
  readonly scoped: ScopedMiddleware[]
  readonly prefixes: ReceiverPrefix[]
  readonly warnings: string[]
}

export interface RouteFileContext {
  readonly file: SnapshotFile
  readonly model: FileModel
  readonly ex: Expr
  readonly snapshot: Snapshot
  readonly astGrep: AstGrepHandle | undefined
  readonly sink: RouteSink
  /** Code model of another snapshot file (cached). */
  readonly modelOf: (file: SnapshotFile) => FileModel | undefined
}

/**
 * Names suggesting authentication or authorization: the documented core
 * (`auth|login|session|jwt|token|passport|guard|protect|require(User|Admin|Role)|isAuthenticated|verify|acl|permission|rbac|admin`)
 * plus framework idioms it misses (`@Roles`, `roles_required`, `get_current_user`,
 * `staff_member_required`, `user_passes_test`, `api_key`).
 */
export const AUTH_HINT =
  /auth|login|session|jwt|token|passport|guard|protect|require(?:User|Admin|Role)|isAuthenticated|verify|acl|permission|rbac|admin|role|current_?(?:active_?)?user|signed_?in|logged_?in|api_?key|passes_?test|staff|superuser/i

/** Middleware names whose text suggests auth. */
export function authHintsOf(middleware: readonly string[]): string[] {
  return [...new Set(middleware.filter(name => AUTH_HINT.test(name)))]
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
