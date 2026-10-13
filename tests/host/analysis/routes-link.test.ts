import { describe, expect, it } from 'vitest'
import type { AstGrepHandle } from '../../../src/host/analysis/astgrep.ts'
import { extractRoutes, MAX_PATHS_PER_ROUTE } from '../../../src/host/analysis/routes/index.ts'
import type { Endpoint } from '../../../src/host/analysis/types.ts'
import { snapshotOf } from './helpers.ts'
import { appFixture, endpoint } from './routes-helpers.ts'
import { MODES, PY_MODES } from './sast-helpers.ts'

/** Extract routes from in-memory files. */
function routesIn(
  files: Record<string, string>,
  handle: AstGrepHandle | undefined,
): Promise<{ endpoints: Endpoint[]; warnings: string[] }> {
  return extractRoutes(snapshotOf(files), { astGrep: handle })
}

/** `METHOD route [middleware] {authHints}` per endpoint, in output order. */
function summary(endpoints: readonly Endpoint[]): string[] {
  return endpoints.map(e => `${e.method} ${e.route} [${e.middleware.join(',')}] {${e.authHints.join(',')}}`)
}

const lines = (...rows: string[]): string => `${rows.join('\n')}\n`

describe.each(MODES)('cross-file route linking: JavaScript (%s mode)', (_mode, handle) => {
  it('express-shop: requireAuth from another file reaches /api/orders/:id; /api/admin/users stays unguarded', async () => {
    const { endpoints, warnings } = await extractRoutes(await appFixture('express-shop'), { astGrep: handle })
    expect(warnings).toEqual([])
    // Mounted in src/app.ts with `app.use('/api/orders', requireAuth, ordersRouter)`, declared in the router file.
    expect(endpoint(endpoints, 'GET', '/api/orders/:id')).toMatchObject({
      id: 'GET /api/orders/:id @ src/routes/orders.ts:25',
      framework: 'express',
      declaredAt: { path: 'src/routes/orders.ts', startLine: 25 },
      handler: { path: 'src/routes/orders.ts', startLine: 25, endLine: 36 },
      middleware: ['helmet', 'express.json', 'requireAuth'],
      authHints: ['requireAuth'],
      params: ['id'],
    })
    // The planted vulnerability: `app.use('/api/admin', adminRouter)` without a guard.
    expect(endpoint(endpoints, 'GET', '/api/admin/users')).toMatchObject({
      declaredAt: { path: 'src/routes/admin.ts', startLine: 12 },
      middleware: ['helmet', 'express.json'],
      authHints: [],
    })
    // Its siblings carry route-level guards after the inherited middleware.
    expect(endpoint(endpoints, 'PATCH', '/api/admin/users/:id/role').middleware).toEqual([
      'helmet',
      'express.json',
      'requireAuth',
      'requireAdmin',
    ])
    expect(endpoint(endpoints, 'GET', '/api/products/search').authHints).toEqual([])
    expect(endpoints.some(e => e.route === '/:id' || e.route === '/users')).toBe(false)
  })

  it('Express: routers nested two levels deep across files', async () => {
    const files = {
      'src/app.ts': lines(
        "import express from 'express'",
        "import api from './routes/api.ts'",
        'const app = express()',
        'app.use(cors())',
        "app.use('/api', api)",
        'export default app',
      ),
      'src/routes/api.ts': lines(
        "import { Router } from 'express'",
        "import { usersRouter } from './users.ts'",
        "import { requireAuth } from '../auth.ts'",
        'const api = Router()',
        "api.use('/users', requireAuth, usersRouter)",
        'export default api',
      ),
      'src/routes/users.ts': lines(
        "import { Router } from 'express'",
        'export const usersRouter = Router()',
        "usersRouter.get('/:id', isOwner, (req, res) => {",
        '  res.json({})',
        '})',
      ),
      'src/auth.ts': 'export const requireAuth = (req, res, next) => next()\n',
    }
    const first = await routesIn(files, handle)
    expect(first.warnings).toEqual([])
    expect(first.endpoints).toEqual([
      {
        id: 'GET /api/users/:id @ src/routes/users.ts:3',
        framework: 'express',
        method: 'GET',
        route: '/api/users/:id',
        declaredAt: { path: 'src/routes/users.ts', startLine: 3, endLine: 3 },
        handler: { path: 'src/routes/users.ts', startLine: 3, endLine: 5 },
        // Outer to inner: app, the /api mount, the /users mount, then the route's own.
        middleware: ['cors', 'requireAuth', 'isOwner'],
        authHints: ['requireAuth'],
        params: ['id'],
      },
    ])
    // Stable across runs.
    expect((await routesIn(files, handle)).endpoints).toEqual(first.endpoints)
  })

  it('Express: a global app.use(auth) guards only routers mounted after it', async () => {
    const { endpoints, warnings } = await routesIn(
      {
        'server.js': lines(
          "const express = require('express')",
          "const { auth } = require('./auth')",
          "const early = require('./early')",
          "const late = require('./late')",
          'const app = express()',
          "app.use('/early', early)",
          'app.use(auth)',
          "app.use('/late', late)",
          "app.get('/after', (req, res) => res.end())",
        ),
        'early.js': lines(
          "const router = require('express').Router()",
          "router.get('/x', (req, res) => res.end())",
          'module.exports = router',
        ),
        'late.js': lines(
          "const express = require('express')",
          'const router = express.Router()',
          "router.get('/y', (req, res) => res.end())",
          'module.exports = router',
        ),
        'auth.js': 'exports.auth = (req, res, next) => next()\n',
      },
      handle,
    )
    expect(warnings).toEqual([])
    expect(summary(endpoints)).toEqual(['GET /after [auth] {auth}', 'GET /early/x [] {}', 'GET /late/y [auth] {auth}'])
  })

  it('Express: middleware mounted on a sibling prefix does not leak to other routers', async () => {
    const { endpoints } = await routesIn(
      {
        'app.js': lines(
          "const express = require('express')",
          "const { adminRouter } = require('./admin')",
          "const { publicRouter } = require('./public')",
          'const app = express()',
          "app.use('/admin', requireAdmin)",
          "app.use('/admin', adminRouter)",
          "app.use('/administrators', publicRouter)",
          "app.use('/pub', publicRouter)",
        ),
        'admin.js': lines(
          "const express = require('express')",
          'const adminRouter = express.Router()',
          "adminRouter.get('/stats', (req, res) => res.end())",
          'module.exports = { adminRouter }',
        ),
        'public.js': lines(
          "const express = require('express')",
          'const r = express.Router()',
          "r.get('/info', (req, res) => res.end())",
          'module.exports = { publicRouter: r }',
        ),
      },
      handle,
    )
    expect(summary(endpoints)).toEqual([
      'GET /admin/stats [requireAdmin] {requireAdmin}',
      'GET /administrators/info [] {}',
      'GET /pub/info [] {}',
    ])
  })

  it('Express: CommonJS destructured require, module.exports = router and one router mounted twice', async () => {
    const { endpoints, warnings } = await routesIn(
      {
        'app.js': lines(
          "const express = require('express')",
          "const { r } = require('./x')",
          "const shared = require('./shared')",
          'const app = express()',
          "app.use('/x', authenticate, r)",
          "app.use('/a', [requireAuth, rateLimit], shared)",
          "app.use('/b', shared)",
        ),
        'x.js': lines(
          "const { Router } = require('express')",
          'const r = Router()',
          "r.get('/a', (req, res) => res.end())",
          'module.exports = { r }',
        ),
        'shared.js': lines(
          "const router = require('express').Router()",
          "router.get('/s', (req, res) => res.end())",
          'module.exports = router',
        ),
      },
      handle,
    )
    expect(warnings).toEqual([])
    expect(summary(endpoints)).toEqual([
      'GET /a/s [requireAuth,rateLimit] {requireAuth}',
      'GET /b/s [] {}',
      'GET /x/a [authenticate] {authenticate}',
    ])
    expect(endpoints.map(e => e.id)).toEqual(['GET /a/s @ shared.js:2', 'GET /b/s @ shared.js:2', 'GET /x/a @ x.js:3'])
  })

  it('Express: export default, a one-level barrel re-export and export *', async () => {
    const { endpoints, warnings } = await routesIn(
      {
        'src/app.ts': lines(
          "import express from 'express'",
          "import { ordersRouter, usersRouter } from './routes/index.ts'",
          "import health from './health.ts'",
          "import { requireAuth } from './auth.ts'",
          'const app = express()',
          "app.use('/orders', requireAuth, ordersRouter)",
          "app.use('/users', usersRouter)",
          "app.use('/health', health)",
        ),
        'src/routes/index.ts': lines("export { ordersRouter } from './orders.ts'", "export * from './users.ts'"),
        'src/routes/orders.ts': lines(
          "import { Router } from 'express'",
          'export const ordersRouter = Router()',
          "ordersRouter.get('/:id', (req, res) => res.end())",
        ),
        'src/routes/users.ts': lines(
          "import { Router } from 'express'",
          'const router = Router()',
          "router.get('/', (req, res) => res.end())",
          'export { router as usersRouter }',
        ),
        'src/health.ts': lines(
          "import { Router } from 'express'",
          'const router = Router()',
          "router.get('/live', (req, res) => res.end())",
          'export default router',
        ),
      },
      handle,
    )
    expect(warnings).toEqual([])
    expect(summary(endpoints)).toEqual([
      'GET /health/live [] {}',
      'GET /orders/:id [requireAuth] {requireAuth}',
      'GET /users [] {}',
    ])
    expect(endpoint(endpoints, 'GET', '/orders/:id').declaredAt.path).toBe('src/routes/orders.ts')
  })

  it('Express: routes added to an imported router and through a registration function', async () => {
    const { endpoints } = await routesIn(
      {
        'src/base.ts': lines("import { Router } from 'express'", 'export const router = Router()'),
        // No framework import: the router comes from `./base.ts`, the app from the caller.
        'src/extra.ts': lines("import { router } from './base.ts'", "router.get('/extra', (req, res) => res.end())"),
        'src/register.ts': lines(
          'export default function registerRoutes(app) {',
          "  app.get('/registered', (req, res) => res.end())",
          '}',
        ),
        'src/server.ts': lines(
          "import express from 'express'",
          "import { router } from './base.ts'",
          "import registerRoutes from './register.ts'",
          'const app = express()',
          "app.get('/open', (req, res) => res.end())",
          'app.use(authenticate)',
          "app.use('/base', router)",
          'registerRoutes(app)',
        ),
      },
      handle,
    )
    expect(summary(endpoints)).toEqual([
      'GET /base/extra [authenticate] {authenticate}',
      'GET /open [] {}',
      'GET /registered [authenticate] {authenticate}',
    ])
    expect(endpoint(endpoints, 'GET', '/registered').declaredAt).toEqual({
      path: 'src/register.ts',
      startLine: 2,
      endLine: 2,
    })
  })

  it('Koa: router.use(mw), prefix and app.use(router.routes()) across files', async () => {
    const { endpoints, warnings } = await routesIn(
      {
        'server.ts': lines(
          "import Koa from 'koa'",
          "import { api } from './api.ts'",
          "import legacy from './legacy.ts'",
          'const app = new Koa()',
          'app.use(api.routes())',
          'app.use(api.allowedMethods())',
          'app.use(koaJwt({ secret: process.env.SECRET }))',
          'app.use(legacy.routes()).use(legacy.allowedMethods())',
        ),
        'api.ts': lines(
          "import Router from '@koa/router'",
          "import { users } from './users.ts'",
          "export const api = new Router({ prefix: '/api' })",
          "api.get('/ping', ctx => { ctx.body = 'ok' })",
          'api.use(requireRole())',
          "api.use('/users', users.routes())",
        ),
        'users.ts': lines(
          "import Router from '@koa/router'",
          'export const users = new Router()',
          "users.prefix('/v1')",
          "users.get('/:id', ctx => { ctx.body = 1 })",
        ),
        'legacy.ts': lines(
          "const Router = require('koa-router')",
          'const router = new Router()',
          "router.get('/old', ctx => {})",
          'module.exports = router',
        ),
      },
      handle,
    )
    expect(warnings).toEqual([])
    expect(summary(endpoints)).toEqual([
      'GET /api/ping [] {}',
      'GET /api/users/v1/:id [requireRole] {requireRole}',
      'GET /old [koaJwt] {koaJwt}',
    ])
    expect(new Set(endpoints.map(e => e.framework))).toEqual(new Set(['koa']))
  })

  it('Hono: app.route() with sub.use(mw), path-scoped app.use and basePath', async () => {
    const { endpoints, warnings } = await routesIn(
      {
        'index.ts': lines(
          "import { Hono } from 'hono'",
          "import { admin } from './admin.ts'",
          "import books from './books.ts'",
          'const app = new Hono()',
          "app.use('/books/*', jwt({ secret: 's' }))",
          "app.route('/admin', admin)",
          "app.route('/books', books)",
          "app.route('/bookshelf', books)",
          "const api = new Hono().basePath('/api')",
          "api.route('/v1/books', books)",
          "app.route('/', api)",
          'export default app',
        ),
        'admin.ts': lines(
          "import { Hono } from 'hono'",
          'export const admin = new Hono()',
          "admin.get('/health', c => c.text('ok'))",
          "admin.use(bearerAuth({ token: 'x' }))",
          "admin.get('/stats', c => c.text('s'))",
        ),
        'books.ts': lines(
          "import { Hono } from 'hono'",
          'const books = new Hono()',
          "books.get('/:id', c => c.text('b'))",
          'export default books',
        ),
      },
      handle,
    )
    expect(warnings).toEqual([])
    expect(summary(endpoints)).toEqual([
      'GET /admin/health [] {}',
      'GET /admin/stats [bearerAuth] {bearerAuth}',
      'GET /api/v1/books/:id [] {}',
      'GET /books/:id [jwt] {jwt}',
      'GET /bookshelf/:id [] {}',
    ])
  })

  it('Fastify: register(plugin, { prefix }) across files with addHook at both levels', async () => {
    const { endpoints, warnings } = await routesIn(
      {
        'server.ts': lines(
          "import Fastify from 'fastify'",
          "import billing from './billing.ts'",
          'const app = Fastify()',
          "app.get('/status', async () => 'ok')",
          "app.register(billing, { prefix: '/billing' })",
          "app.register(require('./users.js'), { prefix: '/users' })",
          'app.register(async (instance) => {',
          "  instance.addHook('preHandler', instance.verifyJwt)",
          "  instance.get('/secret', async () => 's')",
          "}, { prefix: '/inline' })",
          "app.addHook('onRequest', app.rateLimit)",
        ),
        'billing.ts': lines(
          "import type { FastifyInstance } from 'fastify'",
          'export default async function billing(fastify: FastifyInstance) {',
          "  fastify.addHook('preHandler', requireUser)",
          "  fastify.get('/invoices/:id', async () => ({}))",
          '}',
        ),
        'users.js': lines(
          'module.exports = async function (fastify, opts) {',
          "  fastify.get('/:id', async () => ({}))",
          '}',
        ),
      },
      handle,
    )
    expect(warnings).toEqual([])
    // Fastify hooks are not order-sensitive and apply to every plugin below the instance.
    expect(summary(endpoints)).toEqual([
      'GET /billing/invoices/:id [app.rateLimit,requireUser] {requireUser}',
      'GET /inline/secret [app.rateLimit,instance.verifyJwt] {instance.verifyJwt}',
      'GET /status [app.rateLimit] {}',
      'GET /users/:id [app.rateLimit] {}',
    ])
    expect(endpoint(endpoints, 'GET', '/billing/invoices/:id').declaredAt.path).toBe('billing.ts')
  })

  it('mount cycles terminate and never invent a top-level app', async () => {
    const router = (name: string, child: string): string =>
      lines(
        "const express = require('express')",
        `const ${child} = require('./${child}')`,
        `const ${name} = express.Router()`,
        `${name}.get('/${name}-route', (req, res) => res.end())`,
        `${name}.use('/${child}', ${child})`,
        `module.exports = ${name}`,
      )
    const { endpoints } = await routesIn(
      {
        'app.js': lines(
          "const express = require('express')",
          "const aRouter = require('./aRouter')",
          'const app = express()',
          "app.use('/a', guard, aRouter)",
        ),
        'aRouter.js': router('aRouter', 'bRouter'),
        'bRouter.js': router('bRouter', 'aRouter'),
        // A cycle no app mounts: listed with local paths.
        'cRouter.js': router('cRouter', 'dRouter'),
        'dRouter.js': router('dRouter', 'cRouter'),
      },
      handle,
    )
    expect(summary(endpoints)).toEqual([
      'GET /a/aRouter-route [guard] {guard}',
      'GET /a/bRouter/bRouter-route [guard] {guard}',
      'GET /cRouter-route [] {}',
      'GET /dRouter-route [] {}',
    ])
  })

  it('an unresolvable mount records a warning and its routes keep local paths', async () => {
    const { endpoints, warnings } = await routesIn(
      {
        'app.js': lines(
          "const express = require('express')",
          "const path = require('path')",
          "const ordersRouter = require(path.join(__dirname, 'routes', 'orders'))",
          "const ghostRouter = require('./ghost')",
          'const app = express()',
          "app.use('/orders', requireAuth, ordersRouter)",
          "app.use('/ghost', ghostRouter)",
          "app.use('/aliased', require('@/routes/aliased'))",
        ),
        'routes/orders.js': lines(
          "const router = require('express').Router()",
          "router.get('/:id', (req, res) => res.end())",
          'module.exports = router',
        ),
      },
      handle,
    )
    expect(warnings).toEqual([
      "app.js:6: router 'ordersRouter' mounted at '/orders' could not be resolved in the snapshot; its routes keep their local paths.",
      "app.js:7: router 'ghostRouter' mounted at '/ghost' could not be resolved in the snapshot; its routes keep their local paths.",
      "app.js:8: router 'require('@/routes/aliased')' mounted at '/aliased' could not be resolved in the snapshot; its routes keep their local paths.",
    ])
    // Neither treated as middleware nor given a guessed prefix.
    expect(summary(endpoints)).toEqual(['GET /:id [] {}'])
    expect(endpoints[0]!.declaredAt).toEqual({ path: 'routes/orders.js', startLine: 2, endLine: 2 })
  })

  it('performance: ~300 router files with dense cross-file mounts stay fast and bounded', async () => {
    const N = 300
    const files: Record<string, string> = {}
    const app = ["const express = require('express')", 'const app = express()']
    for (let i = 0; i < N; i++) {
      app.push(`const r${i} = require('./routes/r${i}')`)
      if (i % 10 === 0) app.push(`app.use('/m${i}', requireAuth, r${i})`)
      // Each router also mounts the next three: exponentially many chains reach the last ones.
      const kids = [i + 1, i + 2, i + 3].filter(k => k < N)
      files[`routes/r${i}.js`] = lines(
        "const express = require('express')",
        ...kids.map(k => `const c${k} = require('./r${k}')`),
        'const router = express.Router()',
        `router.get('/a${i}', (req, res) => res.end())`,
        `router.post('/b${i}', check${i}, (req, res) => res.end())`,
        ...kids.map(k => `router.use('/k${k}', mw${k}, c${k})`),
        'module.exports = router',
      )
    }
    files['app.js'] = lines(...app)
    const started = performance.now()
    const { endpoints, warnings } = await routesIn(files, handle)
    expect(performance.now() - started).toBeLessThan(2000)
    expect(warnings).toEqual([])

    const perDeclaration = new Map<string, number>()
    for (const e of endpoints) {
      const key = `${e.method} ${e.declaredAt.path}:${e.declaredAt.startLine}`
      perDeclaration.set(key, (perDeclaration.get(key) ?? 0) + 1)
    }
    expect(perDeclaration.size).toBe(2 * N)
    expect(Math.max(...perDeclaration.values())).toBeLessThanOrEqual(MAX_PATHS_PER_ROUTE)
    // Chains cut by the limits are dropped rather than listed with a partial prefix:
    // every endpoint is reached from the app, through a guarded `/m<n>` mount.
    expect(endpoints.every(e => /^\/m\d+\//.test(e.route) && e.authHints[0] === 'requireAuth')).toBe(true)
    // The shortest chain is among those kept for a deep router.
    expect(endpoint(endpoints, 'GET', '/m10/k11/k14/a14').middleware).toEqual(['requireAuth', 'mw11', 'mw14'])
    // Sorted by route, then declaration.
    const routes = endpoints.map(e => e.route)
    expect(routes).toEqual([...routes].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0)))
  })
})

describe.each(PY_MODES)('cross-file route linking: Python (%s mode)', (_mode, handle) => {
  it('FastAPI: include_router(items.router, prefix, dependencies) from another module', async () => {
    const { endpoints, warnings } = await routesIn(
      {
        'app/__init__.py': '',
        'app/main.py': lines(
          'from fastapi import Depends, FastAPI',
          'from .auth import get_current_user',
          'from .routers import items, users',
          'from .routers.admin import router as admin_router',
          '',
          'app = FastAPI()',
          "app.include_router(items.router, prefix='/items', dependencies=[Depends(get_current_user)])",
          "app.include_router(users.router, prefix='/users')",
          "app.include_router(admin_router, prefix='/admin')",
        ),
        'app/auth.py': lines('def get_current_user():', '    pass'),
        'app/routers/__init__.py': '',
        'app/routers/items.py': lines(
          'from fastapi import APIRouter, Depends',
          '',
          'router = APIRouter(dependencies=[Depends(audit_log)])',
          '',
          "@router.get('/{item_id}')",
          'def read_item(item_id: int):',
          '    return {}',
        ),
        'app/routers/users.py': lines(
          'from fastapi import APIRouter',
          '',
          "router = APIRouter(prefix='/v1')",
          '',
          "@router.get('/me')",
          'def me():',
          '    return {}',
        ),
        'app/routers/admin.py': lines(
          'from fastapi import APIRouter',
          '',
          'router = APIRouter()',
          '',
          "@router.delete('/users/{user_id}')",
          'def delete_user(user_id: int):',
          '    return {}',
        ),
      },
      handle,
    )
    expect(warnings).toEqual([])
    expect(summary(endpoints)).toEqual([
      'DELETE /admin/users/{user_id} [] {}',
      'GET /items/{item_id} [Depends(get_current_user),Depends(audit_log)] {Depends(get_current_user)}',
      'GET /users/v1/me [] {}',
    ])
    expect(endpoint(endpoints, 'GET', '/items/{item_id}')).toMatchObject({
      framework: 'fastapi',
      declaredAt: { path: 'app/routers/items.py', startLine: 5 },
      handler: { path: 'app/routers/items.py', startLine: 6 },
      params: ['item_id'],
    })
  })

  it('Flask: register_blueprint(url_prefix=...) across files, nested blueprints and @bp.before_request', async () => {
    const { endpoints, warnings } = await routesIn(
      {
        'shop/__init__.py': lines(
          'from flask import Flask',
          'from .admin import admin_bp',
          'from . import public',
          'from .api import api',
          '',
          'def create_app():',
          '    app = Flask(__name__)',
          "    app.register_blueprint(admin_bp, url_prefix='/admin')",
          "    app.register_blueprint(public.bp, url_prefix='/pub')",
          "    app.register_blueprint(api, url_prefix='/api')",
          '    return app',
        ),
        'shop/admin.py': lines(
          'from flask import Blueprint, abort, session',
          '',
          "admin_bp = Blueprint('admin', __name__, url_prefix='/ignored')",
          '',
          '@admin_bp.before_request',
          'def check_admin():',
          "    if not session.get('is_admin'):",
          '        abort(403)',
          '',
          "@admin_bp.route('/users', methods=['GET', 'DELETE'])",
          'def users():',
          "    return 'x'",
        ),
        'shop/public.py': lines(
          'from flask import Blueprint',
          '',
          "bp = Blueprint('public', __name__)",
          '',
          "@bp.get('/catalog')",
          'def catalog():',
          "    return 'c'",
        ),
        'shop/api.py': lines(
          'from flask import Blueprint',
          'from .v1 import v1',
          '',
          "api = Blueprint('api', __name__)",
          "api.register_blueprint(v1, url_prefix='/v1')",
        ),
        'shop/v1.py': lines(
          'from flask import Blueprint',
          '',
          "v1 = Blueprint('v1', __name__)",
          '',
          "@v1.route('/things')",
          'def things():',
          "    return 't'",
        ),
      },
      handle,
    )
    expect(warnings).toEqual([])
    expect(summary(endpoints)).toEqual([
      'DELETE /admin/users [before_request:check_admin] {before_request:check_admin}',
      'GET /admin/users [before_request:check_admin] {before_request:check_admin}',
      'GET /api/v1/things [] {}',
      'GET /pub/catalog [] {}',
    ])
    expect(endpoint(endpoints, 'GET', '/admin/users').handler).toEqual({
      path: 'shop/admin.py',
      startLine: 11,
      endLine: 12,
    })
  })

  it("Django: include('app.urls') prefixes nested URLconfs and imported urls modules", async () => {
    const { endpoints, warnings } = await routesIn(
      {
        'project/__init__.py': '',
        'project/urls.py': lines(
          'from django.urls import include, path',
          'from shop import urls as shop_urls',
          '',
          'urlpatterns = [',
          "    path('api/', include('api.urls')),",
          "    path('shop/', include(shop_urls)),",
          ']',
        ),
        'api/__init__.py': '',
        'api/urls.py': lines(
          'from django.urls import include, path',
          'from . import views',
          '',
          'urlpatterns = [',
          "    path('orders/<int:pk>/', views.order_detail),",
          "    path('v2/', include('api.v2.urls')),",
          ']',
        ),
        'api/views.py': lines(
          'from django.contrib.auth.decorators import login_required',
          '',
          '@login_required',
          'def order_detail(request, pk):',
          '    pass',
        ),
        'api/v2/__init__.py': '',
        'api/v2/urls.py': lines(
          'from django.urls import path',
          'from . import views',
          '',
          "urlpatterns = [path('ping/', views.ping)]",
        ),
        'api/v2/views.py': lines('def ping(request):', '    pass'),
        'shop/__init__.py': '',
        'shop/urls.py': lines(
          'from django.urls import path',
          'from . import views',
          '',
          "urlpatterns = [path('cart/', views.cart)]",
        ),
        'shop/views.py': lines('def cart(request):', '    pass'),
      },
      handle,
    )
    expect(warnings).toEqual([])
    expect(summary(endpoints)).toEqual([
      'ANY /api/orders/<int:pk>/ [login_required] {login_required}',
      'ANY /api/v2/ping/ [] {}',
      'ANY /shop/cart/ [] {}',
    ])
    expect(endpoint(endpoints, 'ANY', '/api/orders/<int:pk>/')).toMatchObject({
      declaredAt: { path: 'api/urls.py', startLine: 5 },
      handler: { path: 'api/views.py', startLine: 4 },
      params: ['pk'],
    })
  })

  it('an unresolvable include_router records a warning and its routes keep local paths', async () => {
    const { endpoints, warnings } = await routesIn(
      {
        'app/__init__.py': '',
        'app/main.py': lines(
          'from fastapi import FastAPI',
          'from .registry import ROUTERS',
          '',
          'app = FastAPI()',
          "app.include_router(ROUTERS[0], prefix='/dyn')",
        ),
        'app/registry.py': lines('from .orphan import router', 'ROUTERS = [router]'),
        'app/orphan.py': lines(
          'from fastapi import APIRouter',
          'router = APIRouter()',
          '',
          "@router.get('/orphan')",
          'def orphan():',
          '    return {}',
        ),
      },
      handle,
    )
    expect(warnings).toEqual([
      "app/main.py:5: could not resolve 'ROUTERS[0]' mounted at '/dyn'; its routes keep their local paths.",
    ])
    expect(summary(endpoints)).toEqual(['GET /orphan [] {}'])
  })
})
