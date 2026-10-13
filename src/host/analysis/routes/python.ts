/**
 * Route extraction for Python frameworks: Flask (app and blueprints),
 * FastAPI (apps and `APIRouter`s) and Django URLconfs.
 */

import { resolveRelativeImport } from '../outline.ts'
import type { CallFact, ClassFact, DecoratorFact, FileModel, FnFact, Span } from '../sast/model.ts'
import { callAt } from '../sast/taint.ts'
import { ANY_RECEIVER, type RouteFileContext, refOf } from './common.ts'

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
  mounts(ctx, receivers)
  if (/(?:^|\/)urls\.py$/.test(model.path) || /\burlpatterns\s*=/.test(model.source)) djangoRoutes(ctx)
  // Flask `app.add_url_rule('/x', view_func=f)` and Starlette `Route('/x', endpoint)`
  for (const call of model.calls) {
    if (call.name === 'add_url_rule' && call.receiver !== '') addUrlRule(ctx, call, receivers)
  }
}

function findReceivers(ctx: RouteFileContext): Map<string, Receiver> {
  const { model, ex } = ctx
  const out = new Map<string, Receiver>()
  for (const v of model.vars) {
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
  }
  return out
}

function decoratedRoutes(ctx: RouteFileContext, receivers: Map<string, Receiver>): void {
  const { model, ex } = ctx
  // Blueprint-wide `@bp.before_request` hooks named like auth.
  const beforeRequest = new Map<string, string[]>()
  for (const fn of model.fns) {
    for (const dec of fn.decorators) {
      const m = /^([A-Za-z_]\w*)\.before_(?:app_)?request$/.exec(dec.name)
      if (m && fn.name) beforeRequest.set(m[1]!, [...(beforeRequest.get(m[1]!) ?? []), `before_request:${fn.name}`])
    }
  }
  for (const fn of model.fns) {
    if (fn.decorators.length === 0) continue
    const routeDecs = fn.decorators.filter(d => {
      const m = /^([A-Za-z_][\w.]*)\.(\w+)$/.exec(d.name)
      return (
        m !== null &&
        m[2]! in FLASK_VERBS &&
        (receivers.has(m[1]!) || /^(?:app|api|bp|blueprint|router|\w+_bp|\w+_router|\w+_blueprint)$/.test(m[1]!))
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
      const middleware = [
        ...decoratorMw,
        ...(decDeps ? dependencyNames(ctx, decDeps) : []),
        ...paramDeps,
        ...(beforeRequest.get(recv!) ?? []),
      ]
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
    const childArg = call.args.find(a => !a.keyword)
    if (!childArg) continue
    const prefixArg = keyword(call, 'url_prefix') ?? keyword(call, 'prefix')
    const prefix = prefixArg ? (ex.literal(prefixArg) ?? '') : ''
    const deps = keyword(call, 'dependencies')
    const middleware = deps ? dependencyNames(ctx, deps) : []
    const target = pyMountTarget(ctx, childArg)
    const parent = { file: model.path, receiver: call.receiver }
    if (target) {
      ctx.sink.mounts.push({
        parent,
        child: target,
        prefix,
        middleware,
        offset: call.start,
        at: refOf(model, call),
        ...(call.name === 'register_blueprint' && prefixArg ? { replacesPrefix: true } : {}),
      })
    } else {
      ctx.sink.warnings.push(
        `${model.path}:${refOf(model, call).startLine}: could not resolve '${ex.text(childArg).trim()}' mounted at '${prefix || '/'}'; its routes keep their local paths.`,
      )
    }
  }
}

function pyMountTarget(ctx: RouteFileContext, arg: Span): { file: string; receiver: string } | undefined {
  const { model, snapshot, ex } = ctx
  const text = ex.text(arg).trim().replace(/\s+/g, '')
  const dotted = /^([A-Za-z_]\w*)\.([A-Za-z_]\w*)$/.exec(text)
  const name = dotted ? dotted[1]! : text
  if (!/^[A-Za-z_]\w*$/.test(name)) return undefined
  if (!dotted && model.vars.some(v => v.name === name)) return { file: model.path, receiver: name }
  for (const imp of model.imports) {
    const binding = imp.bindings.find(b => b.local === name)
    if (!binding) continue
    if (imp.kind === 'from') {
      // `from .routes import users` (module) or `from .routes.users import router` (object)
      const asModule = resolveRelativeImport(model.path, joinModule(imp.source, binding.imported), snapshot)
      if (asModule && dotted) return { file: asModule, receiver: dotted[2]! }
      const file = resolveRelativeImport(model.path, imp.source, snapshot)
      if (file) return { file, receiver: binding.imported }
      if (asModule) return { file: asModule, receiver: 'router' }
    } else if (dotted) {
      const file = resolveRelativeImport(model.path, imp.source, snapshot)
      if (file) return { file, receiver: dotted[2]! }
    }
    return undefined
  }
  return undefined
}

function joinModule(base: string, name: string): string {
  if (/^\.+$/.test(base)) return base + name
  return `${base}.${name}`
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

function djangoRoutes(ctx: RouteFileContext): void {
  const { model, ex, snapshot } = ctx
  for (const call of model.calls) {
    const fn = call.callee.replace(/^.*\./, '')
    if (fn !== 'path' && fn !== 're_path' && fn !== 'url') continue
    if (call.receiver !== '' && !/^(?:django\.urls|urls|django\.conf\.urls)$/.test(call.receiver)) continue
    const routeArg = call.args.find(a => !a.keyword) ?? keyword(call, 'route')
    const viewArg = call.args.filter(a => !a.keyword)[1] ?? keyword(call, 'view')
    if (!routeArg || !viewArg) continue
    let route = ex.literal(routeArg)
    if (route === undefined) continue
    if (fn !== 'path') route = route.replace(/^\^/, '').replace(/\$$/, '')
    const pattern = route === '' ? '' : `/${route}`.replace(/\/{2,}/g, '/')
    const viewCall = callAt(model, viewArg)
    if (viewCall && /(?:^|\.)include$/.test(viewCall.callee)) {
      const target = viewCall.args[0] ? ex.literal(viewCall.args[0]) : undefined
      const resolved = target ? resolveRelativeImport(model.path, target, snapshot) : undefined
      if (resolved) {
        ctx.sink.mounts.push({
          parent: { file: model.path, receiver: ANY_RECEIVER },
          child: { file: resolved, receiver: ANY_RECEIVER },
          prefix: pattern === '/' ? '' : pattern,
          middleware: [],
          offset: call.start,
          at: refOf(model, call),
        })
      } else {
        ctx.sink.warnings.push(
          `${model.path}:${refOf(model, call).startLine}: include(${target ? `'${target}'` : ex.text(viewCall.args[0] ?? viewArg).trim()}) at '${pattern}' was not followed; routes it defines are listed without this prefix.`,
        )
      }
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

/** Find a view by simple name in this file, an imported module, or the sibling `views.py`. */
function resolveDjangoView(
  ctx: RouteFileContext,
  viewText: string,
  name: string,
): { ref: ReturnType<typeof refOf>; middleware: string[] } | undefined {
  const { model, snapshot } = ctx
  const local = findView(model, name)
  if (local) return { ref: refOf(model, local), middleware: viewMiddleware(model, local) }
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
    if (target) return { ref: refOf(other, target), middleware: viewMiddleware(other, target) }
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
