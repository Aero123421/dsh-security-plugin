/**
 * Route extraction for Python frameworks: Flask (app and blueprints),
 * FastAPI (apps and `APIRouter`s) and Django URLconfs.
 *
 * `register_blueprint`, `include_router` and Django `include(...)` children
 * are recorded symbolically (`items.router`, `from .views import bp`,
 * `include('shop.urls')`) and resolved across files by the linker.
 */

import { resolveRelativeImport } from '../outline.ts'
import type { CallFact, ClassFact, DecoratorFact, FileModel, FnFact, Span } from '../sast/model.ts'
import { callAt } from '../sast/taint.ts'
import { ANY_RECEIVER, AUTH_HINT, joinRoute, type RouteFileContext, refOf, refString } from './common.ts'
import { joinModule } from './link.ts'

const FLASK_VERBS: Readonly<Record<string, string>> = {
  get: 'GET',
  post: 'POST',
  put: 'PUT',
  patch: 'PATCH',
  delete: 'DELETE',
  head: 'HEAD',
  options: 'OPTIONS',
  websocket: 'WS',
  api_route: 'GET',
  route: 'GET',
}

/** Decorators that only wrap a view and are never auth related. */
const NEUTRAL_DECORATORS =
  /^(?:staticmethod|classmethod|property|wraps|functools\.wraps|lru_cache|cache|cached|csrf_exempt|require_(?:GET|POST|http_methods|safe)|never_cache|cache_page|vary_on_\w+|gzip_page|transaction\.atomic|atomic|cross_origin|limiter\.limit|swag_from|doc|marshal_with|api\.\w+)$/

interface Receiver {
  readonly framework: 'flask' | 'fastapi'
  readonly prefix: string
  /** Router-level dependencies (FastAPI) or blueprint-level decorators. */
  readonly middleware: readonly string[]
}

/** Extract routes from one Python file. */
export function extractPyRoutes(ctx: RouteFileContext): void {
  const { model } = ctx
  const receivers = findReceivers(ctx)
  decoratedRoutes(ctx, receivers)
  beforeRequestHooks(ctx)
  mounts(ctx, receivers)
  if (/(?:^|\/)urls\.py$/.test(model.path) || /\burlpatterns\s*=/.test(model.source)) djangoRoutes(ctx)
  // Flask `app.add_url_rule('/x', view_func=f)` and Starlette `Route('/x', endpoint)`
  for (const call of model.calls) {
    if (call.name === 'add_url_rule' && call.receiver !== '') addUrlRule(ctx, call, receivers)
  }
}

/** Flask/FastAPI apps and routers, module-level or created in an app factory (`def create_app(): app = Flask(...)`). */
function findReceivers(ctx: RouteFileContext): Map<string, Receiver> {
  const { model, ex } = ctx
  const out = new Map<string, Receiver>()
  const bindings = [
    ...model.vars.map(v => ({ name: v.name, value: v.value })),
    ...model.assigns
      .filter(a => a.fn && a.op === '=' && !a.destructured && a.targets.length === 1)
      .map(a => ({ name: a.targets[0]!.name, value: a.value })),
  ]
  for (const v of bindings) {
    if (out.has(v.name)) continue
    const call = callAt(model, v.value)
    if (!call) continue
    const name = call.callee.replace(/^.*\./, '')
    let framework: Receiver['framework'] | undefined
    if (name === 'Flask' || name === 'Blueprint' || name === 'APIBlueprint') framework = 'flask'
    else if (name === 'FastAPI' || name === 'APIRouter') framework = 'fastapi'
    if (!framework) continue
    const prefixArg = keyword(call, 'url_prefix') ?? keyword(call, 'prefix')
    const prefix = prefixArg ? (ex.literal(prefixArg) ?? '') : ''
    const deps = keyword(call, 'dependencies')
    const middleware = deps ? dependencyNames(ctx, deps) : []
    out.set(v.name, { framework, prefix, middleware })
    ctx.sink.receivers.push({ file: model.path, receiver: v.name })
  }
  return out
}

/** A receiver imported from a module of the snapshot (`from .views import admin`). */
function importedReceiver(ctx: RouteFileContext, name: string): boolean {
  return ctx.model.imports.some(
    imp => imp.kind === 'from' && imp.source.startsWith('.') && imp.bindings.some(b => b.local === name),
  )
}

/**
 * Flask `@bp.before_request` / `bp.before_request(fn)` hooks, as middleware
 * scoped to the receiver (they run before every route of the blueprint or
 * app, whatever the declaration order). A hook counts as an auth hint when
 * its name or body suggests an authentication check.
 */
function beforeRequestHooks(ctx: RouteFileContext): void {
  const { model, ex } = ctx
  const add = (receiver: string, name: string, body: string, offset: number): void => {
    const label = `before_request:${name}`
    const hint = AUTH_HINT.test(name) || BEFORE_REQUEST_AUTH.test(body)
    ctx.sink.scoped.push({
      file: model.path,
      receiver,
      names: [label],
      offset,
      ordered: false,
      ...(hint ? { hints: [label] } : {}),
    })
  }
  for (const fn of model.fns) {
    for (const dec of fn.decorators) {
      const m = /^([A-Za-z_]\w*)\.before_(?:app_)?request$/.exec(dec.name)
      if (m && fn.name) add(m[1]!, fn.name, ex.text(fn.body), dec.start)
    }
  }
  for (const call of model.calls) {
    if (!/^before_(?:app_)?request$/.test(call.name) || call.receiver === '' || call.decorator) continue
    const arg = call.args[0]
    const name = arg ? ex.text(arg).trim() : ''
    if (!/^[A-Za-z_][\w.]*$/.test(name)) continue
    const fn = model.fns.find(f => f.name === name && !f.parent)
    add(call.receiver, name, fn ? ex.text(fn.body) : '', call.start)
  }
}

const BEFORE_REQUEST_AUTH =
  /\b(?:abort\(\s*40[13]|is_authenticated|is_anonymous|current_user|login_required|verify_jwt_in_request|g\.user\b|session\[|session\.get\(|Unauthorized|Forbidden|redirect\(\s*url_for\(\s*['"][\w.]*login)/

function decoratedRoutes(ctx: RouteFileContext, receivers: Map<string, Receiver>): void {
  const { model, ex } = ctx
  for (const fn of model.fns) {
    if (fn.decorators.length === 0) continue
    const routeDecs = fn.decorators.filter(d => {
      const m = /^([A-Za-z_][\w.]*)\.(\w+)$/.exec(d.name)
      return (
        m !== null &&
        m[2]! in FLASK_VERBS &&
        (receivers.has(m[1]!) ||
          /^(?:app|api|bp|blueprint|router|\w+_bp|\w+_router|\w+_blueprint)$/.test(m[1]!) ||
          importedReceiver(ctx, m[1]!))
      )
    })
    if (routeDecs.length === 0) continue
    const others = fn.decorators.filter(d => !routeDecs.includes(d))
    const decoratorMw = others.filter(d => !NEUTRAL_DECORATORS.test(d.name)).map(d => d.name)
    const paramDeps = fn.params.flatMap(p => {
      const def = p.defaultValue ? ex.text(p.defaultValue) : ''
      const ann = p.annotation ?? ''
      const m = /\b(?:Depends|Security)\(\s*([A-Za-z_][\w.]*)/.exec(`${def} ${ann}`)
      return m ? [`Depends(${m[1]})`] : []
    })
    for (const dec of routeDecs) {
      const [, recv, verb] = /^([A-Za-z_][\w.]*)\.(\w+)$/.exec(dec.name)!
      const receiver = receivers.get(recv!)
      const framework = receiver?.framework ?? (/fastapi/i.test(model.source) ? 'fastapi' : 'flask')
      const pathArg =
        dec.args?.find(a => !a.keyword) ?? dec.args?.find(a => a.keyword === 'rule' || a.keyword === 'path')
      const path = pathArg ? ex.literal(pathArg) : undefined
      if (path === undefined) continue
      let methods: string[] = [FLASK_VERBS[verb!]!]
      if (verb === 'route' || verb === 'api_route') {
        const m = dec.args?.find(a => a.keyword === 'methods')
        const listed = m
          ? ex
              .elements(m)
              .map(e => ex.literal(e)?.toUpperCase())
              .filter((v): v is string => !!v)
          : []
        // Flask, FastAPI and Starlette all default a function view to GET.
        methods = listed.length > 0 ? listed : ['GET']
      }
      const decDeps = dec.args?.find(a => a.keyword === 'dependencies')
      const middleware = [...decoratorMw, ...(decDeps ? dependencyNames(ctx, decDeps) : []), ...paramDeps]
      for (const method of methods) {
        ctx.sink.routes.push({
          framework,
          method,
          path,
          file: model.path,
          receiver: recv!,
          declaredAt: refOf(model, dec),
          handler: refOf(model, fn),
          middleware,
          offset: dec.start,
        })
      }
    }
  }
  // Receiver-level middleware and prefixes are applied by the driver.
  for (const [name, r] of receivers) {
    if (r.middleware.length > 0) {
      ctx.sink.scoped.push({ file: model.path, receiver: name, names: r.middleware, offset: 0, ordered: false })
    }
  }
}

/** `app.register_blueprint(bp, url_prefix=...)`, `app.include_router(router, prefix=..., dependencies=[...])`. */
function mounts(ctx: RouteFileContext, receivers: Map<string, Receiver>): void {
  const { model, ex } = ctx
  for (const [name, r] of receivers) {
    if (r.prefix) ctx.sink.prefixes.push({ file: model.path, receiver: name, prefix: r.prefix })
  }
  for (const call of model.calls) {
    if (call.name !== 'register_blueprint' && call.name !== 'include_router') continue
    if (call.receiver === '') continue
    const childArg = call.args.find(a => !a.keyword) ?? keyword(call, 'blueprint') ?? keyword(call, 'router')
    if (!childArg) continue
    const prefixArg = keyword(call, 'url_prefix') ?? keyword(call, 'prefix')
    const prefix = prefixArg ? (ex.literal(prefixArg) ?? '') : ''
    const deps = keyword(call, 'dependencies')
    const middleware = deps ? dependencyNames(ctx, deps) : []
    const text = ex.text(childArg).trim().replace(/\s+/g, '')
    const child = ctx.scope.refOfText(text, call.start)
    ctx.sink.mounts.push({
      parent: { file: model.path, receiver: call.receiver },
      child: child ?? { kind: 'missing', spec: text },
      prefix,
      middleware,
      offset: call.start,
      ...(call.name === 'register_blueprint' && prefixArg ? { replacesPrefix: true } : {}),
      unresolved: `${refString(model, call)}: could not resolve '${text}' mounted at '${prefix || '/'}'; its routes keep their local paths.`,
    })
  }
}

function addUrlRule(ctx: RouteFileContext, call: CallFact, receivers: Map<string, Receiver>): void {
  const { model, ex } = ctx
  const pathArg = call.args.find(a => !a.keyword) ?? keyword(call, 'rule')
  const path = pathArg ? ex.literal(pathArg) : undefined
  if (path === undefined) return
  const view = keyword(call, 'view_func') ?? call.args.filter(a => !a.keyword)[2]
  const methodsArg = keyword(call, 'methods')
  const methods = methodsArg
    ? ex
        .elements(methodsArg)
        .map(e => ex.literal(e)?.toUpperCase())
        .filter((v): v is string => !!v)
    : ['GET']
  const viewText = view ? ex.text(view).trim() : ''
  const viewName = /^([A-Za-z_]\w*)(?:\.as_view\(.*\))?$/s.exec(viewText)?.[1]
  const target = viewName ? findView(model, viewName) : undefined
  const middleware = target ? viewMiddleware(model, target) : []
  for (const method of methods) {
    ctx.sink.routes.push({
      framework: receivers.get(call.receiver)?.framework ?? 'flask',
      method,
      path,
      file: model.path,
      receiver: call.receiver,
      declaredAt: refOf(model, call),
      ...(target ? { handler: refOf(model, target) } : {}),
      middleware,
      offset: call.start,
    })
  }
}

// ---------------------------------------------------------------------------
// Django
// ---------------------------------------------------------------------------

interface DjangoPattern {
  readonly call: CallFact
  readonly pattern: string
  readonly view: Span
}

/** A `path()`/`re_path()`/`url()` call of a URLconf: its normalized pattern (`/orders/<int:id>/`) and view. */
function djangoPattern(ctx: RouteFileContext, call: CallFact): DjangoPattern | undefined {
  const fn = call.callee.replace(/^.*\./, '')
  if (fn !== 'path' && fn !== 're_path' && fn !== 'url') return undefined
  if (call.receiver !== '' && !/^(?:django\.urls|urls|django\.conf\.urls)$/.test(call.receiver)) return undefined
  const routeArg = call.args.find(a => !a.keyword) ?? keyword(call, 'route')
  const view = call.args.filter(a => !a.keyword)[1] ?? keyword(call, 'view')
  if (!routeArg || !view) return undefined
  let route = ctx.ex.literal(routeArg)
  if (route === undefined) return undefined
  if (fn !== 'path') route = route.replace(/^\^/, '').replace(/\$$/, '')
  return { call, pattern: route === '' ? '' : `/${route}`.replace(/\/{2,}/g, '/'), view }
}

function djangoRoutes(ctx: RouteFileContext): void {
  const { model, ex } = ctx
  const patterns = model.calls.map(call => djangoPattern(ctx, call)).filter((p): p is DjangoPattern => !!p)
  // DRF also commonly exposes `urlpatterns = router.urls` without include().
  for (const assign of model.assigns) {
    if (!assign.targets.some(t => t.name === 'urlpatterns')) continue
    const router = /^([A-Za-z_]\w*)\.urls$/.exec(ex.text(assign.value).trim())?.[1]
    if (router && !drfRouterRoutes(ctx, router, '', assign)) {
      ctx.sink.warnings.push(
        `${refString(model, assign)}: include(${router}.urls) at '/' was not followed; routes it defines are listed without this prefix.`,
      )
    }
  }
  // `path('api/', include([path('users/', ...), ...]))`: inline lists prefix the patterns inside them.
  const inline: { span: Span; prefix: string }[] = []
  for (const p of patterns) {
    const viewCall = callAt(model, p.view)
    const list = viewCall && /(?:^|\.)include$/.test(viewCall.callee) ? viewCall.args[0] : undefined
    if (list && ex.isArrayLiteral(list)) inline.push({ span: list, prefix: p.pattern })
  }
  const prefixOf = (at: number): string => {
    let prefix = ''
    for (const i of inline) if (i.span.start < at && at < i.span.end) prefix = joinRoute(prefix, i.prefix)
    return prefix
  }
  for (const { call, pattern: own, view: viewArg } of patterns) {
    const outer = prefixOf(call.start)
    const pattern = outer ? joinRoute(outer, own) : own
    const viewCall = callAt(model, viewArg)
    if (viewCall && /(?:^|\.)include$/.test(viewCall.callee)) {
      djangoInclude(ctx, call, viewCall, pattern)
      continue
    }
    const viewText = ex.text(viewArg).trim().replace(/\s+/g, '')
    const nameMatch = /^(?:[A-Za-z_]\w*\.)*([A-Za-z_]\w*)(?:\.as_view\(.*\))?$/s.exec(viewText)
    const viewName = nameMatch?.[1]
    const resolved = viewName ? resolveDjangoView(ctx, viewText, viewName) : undefined
    const wrapped = /^(?:login_required|permission_required|staff_member_required|user_passes_test)\(/.test(viewText)
      ? [viewText.replace(/\(.*$/s, '')]
      : []
    ctx.sink.routes.push({
      framework: 'django',
      method: 'ANY',
      path: pattern,
      file: model.path,
      receiver: ANY_RECEIVER,
      declaredAt: refOf(model, call),
      ...(resolved ? { handler: resolved.ref } : {}),
      middleware: [...wrapped, ...(resolved?.middleware ?? [])],
      offset: call.start,
    })
  }
}

/**
 * `include('shop.urls')`, `include(('shop.urls', 'shop'))`, `include(shop_urls)`
 * (an imported module) or `include('shop.urls', namespace='shop')`: mount
 * every pattern of the included URLconf under `pattern`. Inline lists are
 * handled by `djangoRoutes`.
 */
function djangoInclude(ctx: RouteFileContext, call: CallFact, include: CallFact, pattern: string): void {
  const { model, ex, snapshot } = ctx
  let arg = include.args.find(a => !a.keyword) ?? keyword(include, 'arg')
  if (arg && ex.isArrayLiteral(arg)) return
  const tuple = arg ? ex.elements(arg) : []
  if (arg && tuple.length > 0) arg = tuple[0]
  const parent = { file: model.path, receiver: ANY_RECEIVER }
  const prefix = pattern === '/' ? '' : pattern
  const target = arg ? ex.literal(arg) : undefined
  const text = target !== undefined ? `'${target}'` : ex.text(arg ?? include).trim()
  const unresolved = `${refString(model, call)}: include(${text}) at '${pattern}' was not followed; routes it defines are listed without this prefix.`
  const router = target === undefined ? /^([A-Za-z_][\w.]*)\.urls$/.exec(text)?.[1] : undefined
  const routerUsage =
    router &&
    (/router$/i.test(router) ||
      model.calls.some(c => c.receiver === router && c.name === 'register') ||
      (/rest_framework/.test(model.source) && model.vars.some(v => v.name === router)))
  if (router && routerUsage) {
    if (!drfRouterRoutes(ctx, router, prefix, call)) ctx.sink.warnings.push(unresolved)
    return
  }
  if (target !== undefined) {
    const resolved = resolveRelativeImport(model.path, target, snapshot)
    if (!resolved) {
      ctx.sink.warnings.push(unresolved)
      return
    }
    ctx.sink.mounts.push({
      parent,
      child: { kind: 'receiver', file: resolved, receiver: ANY_RECEIVER },
      prefix,
      middleware: [],
      offset: call.start,
    })
    return
  }
  const child = arg ? ctx.scope.refOfText(ex.text(arg).trim().replace(/\s+/g, ''), call.start) : undefined
  ctx.sink.mounts.push({
    parent,
    child: child ?? { kind: 'missing', spec: text },
    prefix,
    middleware: [],
    offset: call.start,
    moduleReceiver: ANY_RECEIVER,
    unresolved,
  })
}

/** Resolve the common URLconf-local DRF router registration shape without executing Python. */
function drfRouterRoutes(ctx: RouteFileContext, router: string, prefix: string, mount: Span): boolean {
  const { model, ex } = ctx
  const value =
    model.vars.find(v => v.name === router)?.value ??
    model.assigns.find(a => a.op === '=' && a.targets.some(t => t.name === router))?.value
  const ctor = value ? callAt(model, value) : undefined
  if (!ctor || !/(?:^|\.)(?:DefaultRouter|SimpleRouter)$/.test(ctor.callee)) return false
  const registrations = model.calls.filter(c => c.receiver === router && c.name === 'register')
  let complete = registrations.length > 0
  for (const register of registrations) {
    const args = register.args.filter(a => !a.keyword)
    const pathArg = args[0] ?? keyword(register, 'prefix')
    const viewArg = args[1] ?? keyword(register, 'viewset')
    const path = pathArg ? ex.literal(pathArg) : undefined
    const view = viewArg ? ex.text(viewArg).trim() : ''
    const name = /(?:^|\.)([A-Za-z_]\w*)$/.exec(view)?.[1]
    if (path === undefined || !name) {
      complete = false
      continue
    }
    const resolved = resolveDjangoView(ctx, view, name)
    const base = joinRoute(prefix, path.startsWith('/') ? path : `/${path}`)
    const actions = resolved ? drfActions(resolved.model, resolved.view) : undefined
    for (const [method, detail, action] of [
      ['GET', false, 'list'],
      ['POST', false, 'create'],
      ['GET', true, 'retrieve'],
      ['PUT', true, 'update'],
      ['PATCH', true, 'partial_update'],
      ['DELETE', true, 'destroy'],
    ] as const) {
      if (actions && !actions.has(action)) continue
      ctx.sink.routes.push({
        framework: 'django',
        method,
        path: detail ? joinRoute(base, ':pk') : base,
        file: model.path,
        receiver: ANY_RECEIVER,
        declaredAt: refOf(model, register),
        ...(resolved ? { handler: resolved.ref } : {}),
        middleware: resolved?.middleware ?? [],
        offset: mount.start,
      })
    }
  }
  return complete
}

/** Known DRF base classes/mixins and methods constrain the standard router mappings. */
function drfActions(model: FileModel, view: FnFact | ClassFact): Set<string> | undefined {
  if ('kind' in view) return undefined
  const bases = view.bases.map(b => b.replace(/^.*\./, ''))
  if (bases.includes('ModelViewSet')) return undefined // all six standard actions
  const actions = new Set(
    model.fns
      .filter(f => f.className === view.name && view.body.start <= f.start && f.end <= view.body.end)
      .map(f => f.name ?? ''),
  )
  if (bases.includes('ReadOnlyModelViewSet')) {
    actions.add('list')
    actions.add('retrieve')
  }
  for (const [base, methods] of [
    ['ListModelMixin', ['list']],
    ['CreateModelMixin', ['create']],
    ['RetrieveModelMixin', ['retrieve']],
    ['UpdateModelMixin', ['update', 'partial_update']],
    ['DestroyModelMixin', ['destroy']],
  ] as const)
    if (bases.includes(base)) for (const method of methods) actions.add(method)
  return actions.size > 0 || bases.some(b => /^(?:ViewSet|GenericViewSet|ReadOnlyModelViewSet)$/.test(b))
    ? actions
    : undefined
}

/** Find a view by simple name in this file, an imported module, or the sibling `views.py`. */
function resolveDjangoView(
  ctx: RouteFileContext,
  viewText: string,
  name: string,
): { ref: ReturnType<typeof refOf>; middleware: string[]; model: FileModel; view: FnFact | ClassFact } | undefined {
  const { model, snapshot } = ctx
  const local = findView(model, name)
  if (local) return { ref: refOf(model, local), middleware: viewMiddleware(model, local), model, view: local }
  const qualifier = /^([A-Za-z_]\w*)\./.exec(viewText)?.[1]
  const candidates: string[] = []
  for (const imp of model.imports) {
    if (qualifier && imp.bindings.some(b => b.local === qualifier)) {
      const b = imp.bindings.find(x => x.local === qualifier)!
      const asModule =
        imp.kind === 'from'
          ? resolveRelativeImport(model.path, joinModule(imp.source, b.imported), snapshot)
          : undefined
      const file = asModule ?? resolveRelativeImport(model.path, imp.source, snapshot)
      if (file) candidates.push(file)
    } else if (!qualifier && imp.bindings.some(b => b.local === name)) {
      const file = resolveRelativeImport(model.path, imp.source, snapshot)
      if (file) candidates.push(file)
    }
  }
  const dir = model.path.includes('/') ? model.path.slice(0, model.path.lastIndexOf('/') + 1) : ''
  candidates.push(`${dir}views.py`, `${dir}views/__init__.py`)
  for (const path of candidates) {
    const file = snapshot.files.get(path)
    if (!file || path === model.path) continue
    const other = ctx.modelOf(file)
    if (!other) continue
    const target = findView(other, name)
    if (target)
      return { ref: refOf(other, target), middleware: viewMiddleware(other, target), model: other, view: target }
  }
  return undefined
}

function findView(model: FileModel, name: string): FnFact | ClassFact | undefined {
  return (
    model.classes.find(c => c.name === name) ??
    model.fns.find(f => f.name === name && !f.parent && f.className === undefined)
  )
}

/** Decorators of a function view, or auth mixins/decorators of a class-based view. */
function viewMiddleware(model: FileModel, view: FnFact | ClassFact): string[] {
  if ('kind' in view) return view.decorators.map((d: DecoratorFact) => d.name).filter(n => !NEUTRAL_DECORATORS.test(n))
  const out = view.bases.filter(b => /Mixin$|Required|Permission/.test(b))
  for (const d of view.decorators) if (!NEUTRAL_DECORATORS.test(d.name)) out.push(d.name)
  // `@method_decorator(login_required, name='dispatch')` and `permission_classes = [IsAuthenticated]`
  const body = model.source.slice(view.body.start, view.body.end)
  const pc = /permission_classes\s*=\s*[[(]([^\])]*)[\])]/.exec(body)
  if (pc) for (const p of pc[1]!.split(',')) if (p.trim()) out.push(p.trim())
  const ac = /authentication_classes\s*=\s*[[(]([^\])]*)[\])]/.exec(body)
  if (ac) for (const p of ac[1]!.split(',')) if (p.trim()) out.push(p.trim())
  for (const m of body.matchAll(/@method_decorator\(\s*([A-Za-z_][\w.]*)/g)) out.push(m[1]!)
  return out
}

function dependencyNames(ctx: RouteFileContext, span: Span): string[] {
  const out: string[] = []
  for (const el of ctx.ex.elements(span)) {
    const m = /^(?:Depends|Security)\(\s*([A-Za-z_][\w.]*)/.exec(ctx.ex.text(el).trim())
    if (m) out.push(`Depends(${m[1]})`)
  }
  return out
}

function keyword(call: CallFact, name: string): Span | undefined {
  return call.args.find(a => a.keyword === name)
}
