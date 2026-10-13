/**
 * Route extraction for JavaScript/TypeScript frameworks: Express (including
 * `Router` mounts and `router.route()` chains), Fastify, Koa router, Hono,
 * NestJS and Next.js (app router and pages API).
 *
 * Receivers are identified by `FileScope.idOf`, so a plugin parameter
 * (`fastify@120`) never collides with a module-level `fastify`. Mounted
 * children (`app.use('/api', auth, ordersRouter)`, `register(plugin)`,
 * `app.route('/x', sub)`, `registerRoutes(app)`) are recorded symbolically
 * and resolved across files by the linker.
 */

import { resolveRelativeImport } from '../outline.ts'
import type { CallFact, FileModel, FnFact, Span } from '../sast/model.ts'
import { callAt } from '../sast/taint.ts'
import { type RawRoute, type RouteFileContext, refOf, refString, type UseArg } from './common.ts'

const HTTP_METHODS: ReadonlySet<string> = new Set([
  'get',
  'post',
  'put',
  'patch',
  'delete',
  'del',
  'head',
  'options',
  'all',
  'any',
  'on',
])
const NEXT_METHODS: ReadonlySet<string> = new Set(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'])
const NEST_METHODS: Readonly<Record<string, string>> = {
  Get: 'GET',
  Post: 'POST',
  Put: 'PUT',
  Patch: 'PATCH',
  Delete: 'DELETE',
  Head: 'HEAD',
  Options: 'OPTIONS',
  All: 'ANY',
  Search: 'SEARCH',
}

const FRAMEWORK_MODULES: readonly [RegExp, string][] = [
  [/^(?:express|express-serve-static-core|router|express-promise-router)$/, 'express'],
  [/^fastify$/, 'fastify'],
  [/^(?:koa|@koa\/router|koa-router|koa-tree-router)$/, 'koa'],
  [/^hono(?:\/.*)?$/, 'hono'],
  [/^(?:restify)$/, 'restify'],
  [/^(?:@hapi\/hapi|hapi)$/, 'hapi'],
  [/^polka$/, 'polka'],
]

/** What kind of app/router a local variable holds. */
interface ReceiverInfo {
  readonly framework: string
  /** Created in this file (`express()`, `Router()`, `new Hono()`), or a handler parameter (Fastify plugin). */
  readonly local: boolean
  /** Koa/@koa/router `prefix` option. */
  readonly prefix?: string
}

/** Extract routes from one JS/TS file. */
export function extractJsRoutes(ctx: RouteFileContext): void {
  const { model, file } = ctx
  if (isNextRouteFile(file.path, ctx.snapshot)) nextRoutes(ctx)
  if (/\b(?:Controller)\s*\(/.test(model.source) && /@nestjs\/common/.test(model.source)) nestRoutes(ctx)
  const receivers = findReceivers(ctx)
  if (receivers.size === 0 && !looksLikeServerCode(model) && !importsFramework(model)) return
  for (const call of model.calls) {
    if (call.decorator || call.tagged) continue
    if (call.receiver !== '') callRoute(ctx, call, receivers)
    registrationCall(ctx, call, receivers)
  }
}

// ---------------------------------------------------------------------------
// Receivers
// ---------------------------------------------------------------------------

function findReceivers(ctx: RouteFileContext): Map<string, ReceiverInfo> {
  const { model } = ctx
  const out = new Map<string, ReceiverInfo>()
  const frameworkOf = new Map<string, string>()
  for (const imp of model.imports) {
    const fw = FRAMEWORK_MODULES.find(([re]) => re.test(imp.source))?.[1]
    if (!fw) continue
    for (const b of imp.bindings) frameworkOf.set(b.local, fw)
  }
  const ctorFramework = (callee: string): string | undefined => {
    const root = callee.split('.')[0]!
    const fw = frameworkOf.get(root)
    if (fw) return fw
    if (/^(?:express|Router|express\.Router)$/.test(callee)) return 'express'
    if (/^(?:fastify|Fastify)$/.test(callee)) return 'fastify'
    if (/^(?:Hono|OpenAPIHono)$/.test(callee)) return 'hono'
    if (/^(?:Koa|KoaRouter|Router)$/.test(callee)) return 'koa'
    return undefined
  }
  for (const assign of model.assigns) {
    if (assign.op !== '=' || assign.destructured || assign.targets.length !== 1) continue
    const name = assign.targets[0]!.name
    // The constructor may be the whole value or the head of a chain
    // (`new Hono().basePath('/api')`, `express().use(...)`, `await Fastify()`).
    const candidates = model.calls.filter(
      c =>
        c.start >= assign.value.start &&
        c.end <= assign.value.end &&
        /^\s*(?:await\s+)?$/.test(model.source.slice(assign.value.start, c.start)),
    )
    let call: CallFact | undefined
    let fw: string | undefined
    for (const candidate of candidates) {
      const callee = candidate.callee.replace(/^require\((['"`])([^'"`]+)\1\)/, (_m, _q, mod: string) => mod)
      let found = ctorFramework(callee)
      if (!found && /^(?:express|fastify|hono|koa-router|@koa\/router)(?:\.Router)?$/.test(callee))
        found = callee.startsWith('express') ? 'express' : callee
      if (!found) {
        // `express.Router()` where `express` is a known import
        const m = /^([A-Za-z_$][\w$]*)\.Router$/.exec(callee)
        if (m && frameworkOf.get(m[1]!) === 'express') found = 'express'
      }
      if (found) {
        call = candidate
        fw = found
        break
      }
    }
    if (!call || !fw) continue
    let prefix: string | undefined
    const opts = call.args[0]
    if (opts && ctx.ex.isObjectLiteral(opts)) {
      const p = ctx.ex.prop(opts, 'prefix') ?? ctx.ex.prop(opts, 'basePath')
      prefix = p ? ctx.ex.literal(p) : undefined
    }
    // `new Hono().basePath('/api')`
    const base = /\.basePath\(\s*(['"`])([^'"`]+)\1\s*\)/.exec(ctx.ex.text(assign.value))
    if (base) prefix = base[2]!
    const id = ctx.scope.idOf(name, assign.start)
    out.set(id, {
      framework: fw === 'koa-router' || fw === '@koa/router' ? 'koa' : fw,
      local: true,
      ...(prefix ? { prefix } : {}),
    })
    ctx.sink.receivers.push({ file: model.path, receiver: id })
    if (prefix) ctx.sink.prefixes.push({ file: model.path, receiver: id, prefix })
  }
  // Fastify plugins: `async function routes(fastify, opts) { fastify.get(...) }`
  for (const fn of model.fns) {
    const first = fn.params[0]?.name
    if (first && /^(?:fastify|instance|server|app)$/.test(first) && /fastify/i.test(model.source)) {
      out.set(`${first}@${fn.start}`, { framework: 'fastify', local: false })
    }
  }
  return out
}

/**
 * The receiver name as written: an identifier (`app`), or the root of a
 * chain of calls that return the receiver (`app.use(a).use(b)`,
 * `app.get('/a', h).post('/b', h)`); other text as is (`this.app`).
 */
function receiverName(text: string): string {
  if (/^[A-Za-z_$][\w$]*$/.test(text)) return text
  const root = /^([A-Za-z_$][\w$]*)\.(?:use|get|post|put|patch|delete|del|all|options|head)\(/.exec(text)?.[1]
  return root && text.endsWith(')') ? root : text
}

/** Receiver id (see `FileScope.idOf`) for a receiver as written. */
function receiverId(ctx: RouteFileContext, text: string, at: number): string {
  const name = receiverName(text)
  return /^[A-Za-z_$][\w$]*$/.test(name) ? ctx.scope.idOf(name, at) : name
}

function looksLikeServerCode(model: FileModel): boolean {
  return /\b(?:express|fastify|koa|hono|Router)\b/.test(model.source)
}

const RECEIVER_NAME =
  /^(?:app|router|api|server|routes|r|v1|v2|admin|adminRouter|apiRouter|[a-z]\w*Router|[a-z]\w*Routes|fastify)$/

/**
 * A receiver not created in this file is accepted only when the file uses a
 * server framework, or the receiver is a parameter (`module.exports = app =>
 * { app.get(...) }`) or imported from a relative module. This keeps HTTP
 * client calls such as `api.get('/users', config)` in front-end code out.
 */
function plausibleReceiver(ctx: RouteFileContext, receiver: string): boolean {
  if (!RECEIVER_NAME.test(receiver)) return false
  const { model, snapshot } = ctx
  if (importsFramework(model)) return true
  if (looksLikeClientCode(model)) return false
  if (model.fns.some(fn => fn.params.some(p => p.name === receiver))) return true
  for (const imp of model.imports) {
    if (!imp.source.startsWith('.') || !imp.bindings.some(b => b.local === receiver)) continue
    // An imported receiver counts only when its module creates a server app/router.
    const target = resolveRelativeImport(model.path, imp.source, snapshot)
    const content = target ? snapshot.files.get(target)?.content : undefined
    return content !== undefined && SERVER_MODULE_IMPORT.test(content)
  }
  return false
}

const SERVER_MODULE_IMPORT =
  /(?:from\s*|require\s*\(\s*)['"`](?:express|fastify|koa|@koa\/router|koa-router|hono(?:\/[\w-]+)?|restify|polka|express-promise-router)['"`]/

/** Front-end code: a `'use client'` module, or one that imports UI or HTTP-client libraries but no server framework. */
function looksLikeClientCode(model: FileModel): boolean {
  if (/^\s*(?:\/\/[^\n]*\n\s*|\/\*[\s\S]*?\*\/\s*)*['"]use client['"]/.test(model.source)) return true
  return model.imports.some(imp =>
    /^(?:react|react-dom|vue|svelte|@angular\/[\w-]+|preact|solid-js|axios|ky|swr|@tanstack\/[\w-]+|next\/(?:router|navigation|link))$/.test(
      imp.source,
    ),
  )
}

function importsFramework(model: FileModel): boolean {
  return model.imports.some(imp => FRAMEWORK_MODULES.some(([re]) => re.test(imp.source)))
}

// ---------------------------------------------------------------------------
// Call-based frameworks
// ---------------------------------------------------------------------------

function callRoute(ctx: RouteFileContext, call: CallFact, receivers: Map<string, ReceiverInfo>): void {
  const method = call.name.toLowerCase()
  const isRouteChain = /\.route\((['"`][^'"`]*['"`])\)$/.test(call.receiver) || /\.route\(['"`]/.test(call.receiver)
  if (isRouteChain && HTTP_METHODS.has(method)) {
    routeChain(ctx, call, receivers)
    return
  }
  const receiver = receiverId(ctx, call.receiver, call.start)
  const info = receivers.get(receiver)
  if (!info && !plausibleReceiver(ctx, receiverName(call.receiver))) return
  const framework = info?.framework ?? guessFramework(ctx.model)
  if (
    call.name === 'use' ||
    (call.name === 'route' && call.args.length === 2) ||
    call.name === 'register' ||
    call.name === 'addHook'
  ) {
    mountOrMiddleware(ctx, call, receiver, framework)
    return
  }
  if (call.name === 'prefix' && framework === 'koa' && call.args.length === 1) {
    // @koa/router `router.prefix('/v2')`
    const prefix = ctx.ex.literal(call.args[0]!)
    if (prefix) ctx.sink.prefixes.push({ file: ctx.model.path, receiver, prefix })
    return
  }
  if (call.name === 'route' && framework === 'fastify') {
    fastifyRouteObject(ctx, call, receiver)
    return
  }
  if (!HTTP_METHODS.has(method)) return
  const pathArg = call.args[0]
  if (!pathArg || pathArg.splat) return
  const path = routePath(ctx, pathArg)
  if (path === undefined) return
  if (method === 'get' && call.args.length === 1) return // `app.get('setting')`
  let verb = method === 'del' ? 'DELETE' : method === 'all' || method === 'any' ? 'ANY' : method.toUpperCase()
  if (method === 'on') {
    // Hono `app.on('GET', '/x', handler)` / `app.on(['GET','POST'], ...)`
    const verbs = ctx.ex.isArrayLiteral(pathArg)
      ? ctx.ex.elements(pathArg).map(e => ctx.ex.literal(e))
      : [ctx.ex.literal(pathArg)]
    const second = call.args[1]
    const p = second ? routePath(ctx, second) : undefined
    if (p === undefined || verbs.some(v => v === undefined)) return
    for (const v of verbs) addCallRoute(ctx, call, receiver, framework, v!.toUpperCase(), p, call.args.slice(2))
    return
  }
  const rest = call.args.slice(1)
  const lastArg = rest[rest.length - 1]
  if (!lastArg || ctx.ex.literal(lastArg) !== undefined || (ctx.ex.isObjectLiteral(lastArg) && framework !== 'fastify'))
    return
  if (framework === 'fastify' && rest.length >= 2 && ctx.ex.isObjectLiteral(rest[0]!)) {
    const options = rest[0]!
    const mw = fastifyHooks(ctx, options)
    addCallRoute(ctx, call, receiver, framework, verb, path, rest.slice(1), mw)
    return
  }
  if (verb === 'ANY' && framework === 'hono' && method === 'all') verb = 'ANY'
  addCallRoute(ctx, call, receiver, framework, verb, path, rest)
}

/** `router.route('/x').get(h).post(h)` */
function routeChain(ctx: RouteFileContext, call: CallFact, receivers: Map<string, ReceiverInfo>): void {
  const m = /^(.*?)\.route\((['"`])([^'"`]*)\2\)/.exec(call.receiver)
  if (!m) return
  const receiver = receiverId(ctx, m[1]!, call.start)
  const path = m[3]!
  const framework = receivers.get(receiver)?.framework ?? guessFramework(ctx.model)
  const method = call.name.toLowerCase()
  addCallRoute(ctx, call, receiver, framework, method === 'all' ? 'ANY' : method.toUpperCase(), path, [...call.args])
}

function addCallRoute(
  ctx: RouteFileContext,
  call: CallFact,
  receiver: string,
  framework: string,
  method: string,
  path: string,
  handlers: readonly Span[],
  extraMiddleware: readonly string[] = [],
): void {
  const { model } = ctx
  const last = handlers[handlers.length - 1]
  const middleware = [...extraMiddleware]
  for (const h of handlers.slice(0, -1)) middleware.push(...middlewareNames(ctx, h))
  const handler = last ? handlerRef(ctx, last) : undefined
  const route: RawRoute = {
    framework,
    method,
    path,
    file: model.path,
    receiver,
    declaredAt: refOf(model, { start: call.start, end: call.start + 1 }),
    ...(handler ? { handler } : {}),
    middleware,
    offset: call.start,
  }
  ctx.sink.routes.push(route)
}

/**
 * `app.use('/api', auth, router)`, `app.use(auth)`, `router.use('/x', r.routes())`,
 * Hono `app.route('/x', sub)`, `fastify.register(plugin, { prefix })` and
 * Fastify `addHook('preHandler', fn)`.
 */
function mountOrMiddleware(ctx: RouteFileContext, call: CallFact, receiver: string, framework: string): void {
  const { model } = ctx
  const parent = { file: model.path, receiver }
  if (call.name === 'addHook') {
    const hook = ctx.ex.literal(call.args[0] ?? { start: 0, end: 0 })
    if (!hook || !/^(?:onRequest|preHandler|preValidation|preParsing)$/.test(hook)) return
    const names = call.args[1] ? middlewareNames(ctx, call.args[1]) : []
    if (names.length > 0) ctx.sink.scoped.push({ ...parent, names, offset: call.start, ordered: false })
    return
  }
  if (call.name === 'register') {
    const plugin = call.args[0]
    if (!plugin) return
    const opts = call.args[1]
    const prefixSpan = opts && ctx.ex.isObjectLiteral(opts) ? ctx.ex.prop(opts, 'prefix') : undefined
    const prefix = prefixSpan ? (ctx.ex.literal(prefixSpan) ?? '') : ''
    const child = ctx.scope.refOfExpr(plugin)
    const knownPlugin =
      /^(?:require\(|import\()?['"`]?@?fastify[/-]|cors|helmet|cookie|formbody|multipart|static|swagger|rateLimit|rate-limit|jwt|auth/i.test(
        ctx.ex.text(plugin),
      )
    ctx.sink.mounts.push({
      parent,
      child: child ?? { kind: 'missing', spec: ctx.ex.text(plugin).trim() },
      prefix,
      middleware: [],
      offset: call.start,
      ...(prefix && !knownPlugin
        ? {
            unresolved: `${refString(model, call)}: could not resolve the plugin registered under '${prefix}'; its routes keep their local paths.`,
          }
        : {}),
    })
    return
  }
  const args = [...call.args]
  let prefix = ''
  let rest = args
  const first = args[0]
  if (first && !first.splat) {
    const p = routePath(ctx, first)
    if (p !== undefined) {
      prefix = p
      rest = args.slice(1)
    }
  }
  if (rest.length === 0) return
  // Hono `app.route('/x', sub)` always mounts; `use` arguments are routers or middleware.
  const mountsOnly = call.name === 'route'
  const useArgs: UseArg[] = []
  for (const arg of rest) {
    const text = ctx.ex.text(arg).trim()
    // Koa `router.allowedMethods()` answers OPTIONS/405 for the router mounted next to it.
    if (/\.allowedMethods\(\s*\)$/.test(text)) continue
    const ref = ctx.scope.refOfExpr(arg)
    const routerLike = mountsOnly || looksLikeRouter(text)
    useArgs.push({
      names: middlewareNames(ctx, arg),
      ...(ref ? { ref } : {}),
      ...(routerLike
        ? {
            unresolved: `${refString(model, call)}: router '${text}' mounted at '${prefix || '/'}' could not be resolved in the snapshot; its routes keep their local paths.`,
          }
        : {}),
    })
  }
  ctx.sink.uses.push({
    parent,
    prefix,
    args: useArgs,
    offset: call.start,
    end: call.end,
    ordered: framework !== 'fastify',
  })
}

/** An argument that names a router (`ordersRouter`, `api.routes()`, `require('./routes/x')`) rather than middleware. */
function looksLikeRouter(text: string): boolean {
  if (/^(?:require|import)\(\s*['"`]\./.test(text)) return true
  const name = /^([A-Za-z_$][\w$]*)(?:\.(?:routes|middleware)\(\))?$/.exec(text)?.[1]
  return name !== undefined && /(?:router|routes|api|controller)$/i.test(name)
}

/**
 * `registerRoutes(app)`, `require('./routes')(app)`: a function in the
 * snapshot that receives an app/router registers routes on it through its
 * parameter. Recorded as a mount of that parameter under the app, with no
 * prefix; the linker drops it when the callee is not such a function.
 */
function registrationCall(ctx: RouteFileContext, call: CallFact, receivers: Map<string, ReceiverInfo>): void {
  if (call.args.length === 0 || /^(?:require|import)$/.test(call.callee)) return
  if (call.receiver !== '' && (HTTP_METHODS.has(call.name.toLowerCase()) || REGISTRATION_METHODS.test(call.name)))
    return
  for (let index = 0; index < call.args.length; index++) {
    const arg = call.args[index]!
    if (arg.splat) break
    const text = ctx.ex.text(arg).trim()
    if (!/^[A-Za-z_$][\w$]*$/.test(text)) continue
    const receiver = ctx.scope.idOf(text, call.start)
    if (!receivers.has(receiver) && !plausibleReceiver(ctx, text)) continue
    const fn = ctx.scope.refOfText(call.callee, call.start)
    if (!fn) return
    ctx.sink.mounts.push({
      parent: { file: ctx.model.path, receiver },
      child: { kind: 'param', fn, index },
      prefix: '',
      middleware: [],
      offset: call.start,
    })
  }
}

const REGISTRATION_METHODS = /^(?:use|route|register|addHook|listen|set|enable|disable|engine|param|decorate)$/

/** `fastify.route({ method, url, preHandler, handler })` */
function fastifyRouteObject(ctx: RouteFileContext, call: CallFact, receiver: string): void {
  const opts = call.args[0]
  if (!opts || !ctx.ex.isObjectLiteral(opts)) return
  const urlSpan = ctx.ex.prop(opts, 'url') ?? ctx.ex.prop(opts, 'path')
  const methodSpan = ctx.ex.prop(opts, 'method')
  const handlerSpan = ctx.ex.prop(opts, 'handler')
  const path = urlSpan ? ctx.ex.literal(urlSpan) : undefined
  if (path === undefined || !methodSpan) return
  const methods = ctx.ex.isArrayLiteral(methodSpan)
    ? ctx.ex.elements(methodSpan).map(e => ctx.ex.literal(e))
    : [ctx.ex.literal(methodSpan)]
  const mw = fastifyHooks(ctx, opts)
  for (const m of methods) {
    if (!m) continue
    addCallRoute(ctx, call, receiver, 'fastify', m.toUpperCase(), path, handlerSpan ? [handlerSpan] : [], mw)
  }
}

function fastifyHooks(ctx: RouteFileContext, opts: Span): string[] {
  const out: string[] = []
  for (const key of ['onRequest', 'preHandler', 'preValidation', 'preParsing']) {
    const v = ctx.ex.prop(opts, key)
    if (v) out.push(...middlewareNames(ctx, v))
  }
  return out
}

// ---------------------------------------------------------------------------
// NestJS
// ---------------------------------------------------------------------------

function nestRoutes(ctx: RouteFileContext): void {
  const { model } = ctx
  for (const cls of model.classes) {
    const controller = cls.decorators.find(d => /(?:^|\.)Controller$/.test(d.name))
    if (!controller) continue
    let prefix = ''
    const arg = controller.args?.[0]
    if (arg) {
      const lit = ctx.ex.literal(arg)
      if (lit !== undefined) prefix = lit
      else if (ctx.ex.isObjectLiteral(arg)) {
        const p = ctx.ex.prop(arg, 'path')
        prefix = (p && ctx.ex.literal(p)) ?? ''
      }
    }
    const classGuards = cls.decorators.flatMap(d => nestGuards(ctx, d))
    for (const fn of model.fns) {
      if (fn.className !== cls.name || fn.kind !== 'method' || fn.start < cls.body.start || fn.end > cls.body.end)
        continue
      for (const dec of fn.decorators) {
        const verb = NEST_METHODS[dec.name.replace(/^.*\./, '')]
        if (!verb) continue
        let sub = ''
        const a = dec.args?.[0]
        if (a) {
          const lit = ctx.ex.literal(a)
          if (lit === undefined) continue
          sub = lit
        }
        const path = joinNest(prefix, sub)
        const guards = [...classGuards, ...fn.decorators.flatMap(d => nestGuards(ctx, d))]
        ctx.sink.routes.push({
          framework: 'nestjs',
          method: verb,
          path,
          file: model.path,
          receiver: undefined,
          declaredAt: refOf(model, dec),
          handler: refOf(model, fn),
          middleware: guards,
          offset: dec.start,
        })
      }
    }
  }
}

function nestGuards(ctx: RouteFileContext, dec: { name: string; args?: readonly Span[] }): string[] {
  const name = dec.name.replace(/^.*\./, '')
  if (/^(?:UseGuards|UseInterceptors|UseFilters|UsePipes)$/.test(name)) {
    return (dec.args ?? []).flatMap(a => middlewareNames(ctx, a))
  }
  if (
    /^(?:Roles|Public|Auth|Permissions|RequirePermissions|Scopes|SetMetadata|ApiBearerAuth|ApiSecurity)$/.test(name) ||
    /Auth|Role|Guard|Permission|Public/.test(name)
  ) {
    return [`@${name}`]
  }
  return []
}

function joinNest(prefix: string, sub: string): string {
  const parts = [prefix, sub].map(p => p.replace(/^\/+|\/+$/g, '')).filter(Boolean)
  return `/${parts.join('/')}`
}

// ---------------------------------------------------------------------------
// Next.js
// ---------------------------------------------------------------------------

/** Next.js app-router `route.ts` or pages-router `pages/api/**`. */
export function isNextRouteFile(path: string, snapshot?: ProjectFiles): boolean {
  return nextRouteOf(path, snapshot) !== undefined
}

/** The part of a snapshot needed to locate a Next.js project root: which paths exist. */
export interface ProjectFiles {
  readonly files: { has(path: string): boolean }
}

/** A Next.js route file's URL pattern, path parameters, router kind and project root (`''` or `dir/`). */
export interface NextRouteInfo {
  readonly route: string
  readonly params: string[]
  readonly kind: 'app' | 'pages'
  readonly root: string
}

/**
 * URL pattern for a Next.js route file, or `undefined`. When several `app/`
 * or `pages/` segments could be the router directory, the leftmost one whose
 * project root (the directory holding it, or holding its `src/`) has a
 * `next.config.*` or `package.json` wins; without a snapshot, the leftmost.
 */
export function nextRouteOf(path: string, snapshot?: ProjectFiles): NextRouteInfo | undefined {
  const segs = path.split('/')
  const file = segs[segs.length - 1] ?? ''
  const candidates: NextRouteInfo[] = []
  for (let i = 0; i < segs.length - 1; i++) {
    const seg = segs[i]
    if (seg !== 'app' && seg !== 'pages') continue
    const before = segs.slice(0, i)
    if (before.includes('node_modules')) continue
    const projectSegs = before[before.length - 1] === 'src' ? before.slice(0, -1) : before
    const root = projectSegs.length > 0 ? `${projectSegs.join('/')}/` : ''
    if (seg === 'app') {
      if (!/^route\.(?:[cm]?[jt]sx?)$/.test(file)) continue
      candidates.push({ ...nextPattern(segs.slice(i + 1, -1).join('/'), 'app'), root })
    } else {
      if (segs[i + 1] !== 'api' || !/\.(?:[cm]?[jt]sx?)$/.test(file)) continue
      const rel = segs
        .slice(i + 1)
        .join('/')
        .replace(/\.(?:[cm]?[jt]sx?)$/, '')
        .replace(/(?:^|\/)index$/, '')
      candidates.push({ ...nextPattern(rel, 'pages'), root })
    }
  }
  if (candidates.length === 0) return undefined
  if (snapshot) {
    const marked = candidates.find(c =>
      ['next.config.js', 'next.config.mjs', 'next.config.ts', 'next.config.cjs', 'package.json'].some(name =>
        snapshot.files.has(`${c.root}${name}`),
      ),
    )
    if (marked) return marked
  }
  return candidates[0]
}

function nextPattern(dir: string, kind: 'app' | 'pages'): { route: string; params: string[]; kind: 'app' | 'pages' } {
  const params: string[] = []
  const segments: string[] = []
  for (const seg of dir.split('/')) {
    if (seg === '' || /^\(.*\)$/.test(seg) || seg.startsWith('@')) continue // route groups and parallel slots
    if (seg.startsWith('_')) continue
    const catchAll = /^\[\[?\.\.\.([^\]]+)\]\]?$/.exec(seg)
    if (catchAll) {
      params.push(catchAll[1]!)
      segments.push(`:${catchAll[1]!}*`)
      continue
    }
    const dyn = /^\[([^\]]+)\]$/.exec(seg)
    if (dyn) {
      params.push(dyn[1]!)
      segments.push(`:${dyn[1]!}`)
      continue
    }
    segments.push(seg)
  }
  return { route: `/${segments.join('/')}`, params, kind }
}

function nextRoutes(ctx: RouteFileContext): void {
  const { model, file, snapshot } = ctx
  const info = nextRouteOf(file.path, snapshot)
  if (!info) return
  const guard = nextMiddlewarePath(info.root, snapshot)
  const extra = guard ? ['next-middleware'] : []
  const base = {
    framework: 'next',
    path: info.route,
    file: model.path,
    receiver: undefined,
    middleware: [] as string[],
    params: info.params,
    ...(extra.length > 0 ? { extraAuthHints: extra } : {}),
  }
  if (info.kind === 'pages') {
    if (!/\bexport\s+default\b|module\.exports\s*=/.test(model.source)) return
    const handler = defaultExportFn(model)
    const at = handler ?? { start: 0, end: 1 }
    ctx.sink.routes.push({
      ...base,
      method: 'ANY',
      declaredAt: refOf(model, { start: handler?.declStart ?? at.start, end: (handler?.declStart ?? at.start) + 1 }),
      ...(handler ? { handler: refOf(model, handler) } : {}),
      offset: at.start,
    })
    return
  }
  const seen = new Set<string>()
  for (const fn of model.fns) {
    if (!fn.name || !NEXT_METHODS.has(fn.name) || fn.parent || !fn.exported) continue
    if (seen.has(fn.name)) continue
    seen.add(fn.name)
    ctx.sink.routes.push({
      ...base,
      method: fn.name,
      declaredAt: refOf(model, { start: fn.declStart, end: fn.declStart + 1 }),
      handler: refOf(model, fn),
      offset: fn.declStart,
    })
  }
  for (const v of model.vars) {
    if (!NEXT_METHODS.has(v.name) || seen.has(v.name) || !(v.exported || model.exportedNames.has(v.name))) continue
    seen.add(v.name)
    ctx.sink.routes.push({
      ...base,
      method: v.name,
      declaredAt: refOf(model, { start: v.start, end: v.start + 1 }),
      handler: refOf(model, v.value),
      offset: v.start,
    })
  }
  // `export { handler as GET, handler as POST }`
  for (const alias of model.exportAliases) {
    if (!NEXT_METHODS.has(alias.exported) || seen.has(alias.exported)) continue
    seen.add(alias.exported)
    const fn = model.fns.find(f => f.name === alias.local && !f.parent)
    const v = model.vars.find(x => x.name === alias.local)
    const target: Span | undefined = fn ?? v?.value
    const at = fn ? fn.declStart : (v?.start ?? 0)
    ctx.sink.routes.push({
      ...base,
      method: alias.exported,
      declaredAt: refOf(model, { start: at, end: at + 1 }),
      ...(target ? { handler: refOf(model, target) } : {}),
      offset: at,
    })
  }
  for (const imp of model.imports) {
    if (imp.kind !== 'export-from') continue
    for (const b of imp.bindings) {
      if (!NEXT_METHODS.has(b.local) || seen.has(b.local)) continue
      seen.add(b.local)
      ctx.sink.routes.push({
        ...base,
        method: b.local,
        declaredAt: refOf(model, { start: imp.start, end: imp.start + 1 }),
        offset: imp.start,
      })
    }
  }
}

/** `middleware.(ts|js)` (or Next 16 `proxy.*`) at the project root or in its `src/`. */
function nextMiddlewarePath(root: string, snapshot: RouteFileContext['snapshot']): string | undefined {
  for (const dir of [root, `${root}src/`]) {
    for (const ext of ['ts', 'js', 'mjs', 'tsx', 'jsx']) {
      for (const name of ['middleware', 'proxy']) {
        const candidate = `${dir}${name}.${ext}`
        if (snapshot.files.has(candidate)) return candidate
      }
    }
  }
  return undefined
}

function defaultExportFn(model: FileModel): FnFact | undefined {
  const direct = model.fns.find(
    fn => !fn.parent && fn.exported && /^export\s+default\b/.test(model.source.slice(fn.declStart, fn.declStart + 20)),
  )
  if (direct) return direct
  const name = model.defaultExport
  if (name) {
    const fn = model.fns.find(f => f.name === name && !f.parent)
    if (fn) return fn
  }
  // `export default withAuth(handler)` → handler
  const m = /export\s+default\s+([A-Za-z_$][\w$]*)\s*\(\s*([A-Za-z_$][\w$]*)\s*\)/.exec(model.source)
  if (m) return model.fns.find(f => f.name === m[2] && !f.parent)
  return undefined
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function routePath(ctx: RouteFileContext, span: Span): string | undefined {
  const lit = ctx.ex.literal(span)
  if (lit !== undefined)
    return lit.startsWith('/') || lit === '' || lit === '*' || lit.startsWith(':')
      ? lit
      : lit.includes('/')
        ? lit
        : /^[\w-]+$/.test(lit)
          ? lit
          : undefined
  // Regex routes: `app.get(/^\/files\/(.*)$/, ...)`
  const [a, b] = ctx.ex.range(span)
  if (b - a === 1 && ctx.model.tokens[a]!.type === 'regex') return ctx.model.tokens[a]!.value
  // Arrays of paths: keep the first.
  if (ctx.ex.isArrayLiteral(span)) {
    const first = ctx.ex.elements(span)[0]
    return first ? ctx.ex.literal(first) : undefined
  }
  return undefined
}

/**
 * Names of middleware in an argument: identifiers (`auth`), calls
 * (`passport.authenticate('jwt')` → `passport.authenticate`), arrays of
 * those, and inline functions (`<inline>`).
 */
export function middlewareNames(ctx: RouteFileContext, span: Span): string[] {
  const { ex } = ctx
  if (ex.isArrayLiteral(span)) return ex.elements(span).flatMap(e => middlewareNames(ctx, e))
  const text = ex.text(span).trim()
  if (/^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*$/.test(text)) return [text]
  const call = callAt(ctx.model, span)
  if (call) return [call.callee]
  if (ex.isFunctionLike(span)) return [AUTH_INLINE.test(text.slice(0, 600)) ? '<inline auth check>' : '<inline>']
  return []
}

const AUTH_INLINE =
  /\b(?:isAuthenticated|req\.user|req\.session\.user|authorization|verifyToken|jwt\.verify|401|403|Unauthorized|Forbidden)\b/

function handlerRef(ctx: RouteFileContext, span: Span): RawRoute['handler'] {
  const { model } = ctx
  const fn = model.fns.find(
    f => f.start === span.start || (f.start >= span.start && f.start <= span.start + 8 && f.end <= span.end + 1),
  )
  if (fn) return refOf(model, fn)
  const text = ctx.ex.text(span).trim()
  // Named handler in the same file: `getUser`, `controller.getUser`, `wrap(getUser)`.
  const name =
    /^(?:[A-Za-z_$][\w$]*\.)*([A-Za-z_$][\w$]*)$/.exec(text)?.[1] ?? /\(\s*([A-Za-z_$][\w$]*)\s*\)$/.exec(text)?.[1]
  if (name) {
    const target = model.fns.find(f => f.name === name && !f.parent)
    if (target) return refOf(model, target)
    const v = model.vars.find(x => x.name === name && x.isFn)
    if (v) return refOf(model, v)
  }
  return undefined
}

function guessFramework(model: FileModel): string {
  for (const imp of model.imports) {
    const fw = FRAMEWORK_MODULES.find(([re]) => re.test(imp.source))?.[1]
    if (fw) return fw
  }
  return 'express'
}
