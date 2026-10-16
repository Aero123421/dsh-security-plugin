import { describe, expect, it } from 'vitest'
import { extractRoutes } from '../../../src/host/analysis/routes/index.ts'
import { nextRouteOf } from '../../../src/host/analysis/routes/js.ts'
import { AUTH_HINT, authHintsOf, routeParams } from '../../../src/host/analysis/routes/common.ts'
import { snapshotOf } from './helpers.ts'
import { endpoint, routeFixture, routeList, routesOf } from './routes-helpers.ts'
import { MODES } from './sast-helpers.ts'

describe.each(MODES)('route extraction (%s mode)', (_mode, handle) => {
  it('Express: routes, route() chains, mounted routers with prefixes and ordered middleware', async () => {
    const { endpoints, warnings } = await routesOf('express', handle)
    expect(routeList(endpoints)).toEqual([
      'GET /admin/stats',
      'DELETE /admin/users/:userId',
      'GET /api/users',
      'GET /api/users/:id',
      'PUT /api/users/:id/profile',
      'GET /health',
      'DELETE /items/:itemId',
      'GET /items/:itemId',
      'POST /login',
    ])
    expect(new Set(endpoints.map(e => e.framework))).toEqual(new Set(['express']))

    // Mounted router: prefix from `app.use('/api/users', requireAuth, usersRouter)`, declared in the router file.
    const getUser = endpoint(endpoints, 'GET', '/api/users/:id')
    expect(getUser).toMatchObject({
      id: 'GET /api/users/:id @ routes/users.js:5',
      declaredAt: { path: 'routes/users.js', startLine: 5, endLine: 5 },
      handler: { path: 'routes/users.js', startLine: 8, endLine: 10 },
      middleware: ['express.json', 'requireAuth', 'isAdmin'],
      authHints: ['requireAuth', 'isAdmin'],
      params: ['id'],
    })

    // `router.use(requireAdmin)` only guards routes registered after it.
    expect(endpoint(endpoints, 'GET', '/admin/stats').authHints).toEqual([])
    expect(endpoint(endpoints, 'DELETE', '/admin/users/:userId').authHints).toEqual(['requireAdmin'])

    // `app.route('/items/:itemId').get(listItem).delete(requireAuth, deleteItem)`
    expect(endpoint(endpoints, 'GET', '/items/:itemId')).toMatchObject({
      authHints: [],
      handler: { path: 'server.js', startLine: 23, endLine: 25 },
    })
    expect(endpoint(endpoints, 'DELETE', '/items/:itemId')).toMatchObject({
      authHints: ['requireAuth'],
      handler: { path: 'server.js', startLine: 27, endLine: 29 },
    })

    // Rate limiting is middleware, not an auth hint.
    expect(endpoint(endpoints, 'POST', '/login')).toMatchObject({
      middleware: ['express.json', 'rateLimit'],
      authHints: [],
    })

    expect(warnings).toEqual([
      "server.js:16: router 'require('./missing-router')' mounted at '/legacy' could not be resolved in the snapshot; its routes keep their local paths.",
    ])
  })

  it('Fastify: shorthand routes, route({...}), preHandler/onRequest hooks and prefixed plugins', async () => {
    const { endpoints, warnings } = await routesOf('fastify', handle)
    expect(warnings).toEqual([])
    expect(routeList(endpoints)).toEqual([
      'GET /billing/invoices/:invoiceId',
      'POST /orders/:orderId',
      'GET /reports/:reportId',
      'HEAD /reports/:reportId',
      'GET /status',
    ])
    expect(endpoint(endpoints, 'POST', '/orders/:orderId')).toMatchObject({
      framework: 'fastify',
      middleware: ['fastify.authenticate'],
      authHints: ['fastify.authenticate'],
      handler: { path: 'server.ts', startLine: 8, endLine: 10 },
    })
    expect(endpoint(endpoints, 'GET', '/reports/:reportId')).toMatchObject({
      id: 'GET /reports/:reportId @ server.ts:11',
      authHints: ['verifyJwt'],
      params: ['reportId'],
    })
    // `fastify.register(billing, { prefix: '/billing' })` + `addHook('preHandler', ...)` inside the plugin.
    expect(endpoint(endpoints, 'GET', '/billing/invoices/:invoiceId')).toMatchObject({
      declaredAt: { path: 'routes/billing.ts', startLine: 4 },
      authHints: ['fastify.requireUser'],
    })
    expect(endpoint(endpoints, 'GET', '/status').authHints).toEqual([])
  })

  it('Koa router: constructor prefix, per-route middleware and del()', async () => {
    const { endpoints } = await routesOf('koa', handle)
    expect(routeList(endpoints)).toEqual(['POST /v1/things', 'GET /v1/things/:id', 'DELETE /v1/things/:id'])
    expect(endpoint(endpoints, 'GET', '/v1/things/:id')).toMatchObject({
      framework: 'koa',
      authHints: ['jwtAuth'],
      params: ['id'],
      handler: { path: 'router.ts', startLine: 6, endLine: 8 },
    })
    expect(endpoint(endpoints, 'DELETE', '/v1/things/:id').authHints).toEqual(['requireRole'])
    expect(endpoint(endpoints, 'POST', '/v1/things').authHints).toEqual([])
  })

  it('Hono: basePath, per-route middleware and on([...methods])', async () => {
    const { endpoints } = await routesOf('hono', handle)
    expect(routeList(endpoints)).toEqual([
      'POST /api/admin/posts',
      'GET /api/hello/:name',
      'PATCH /api/posts/:postId',
      'PUT /api/posts/:postId',
    ])
    expect(endpoint(endpoints, 'POST', '/api/admin/posts')).toMatchObject({
      framework: 'hono',
      middleware: ['bearerAuth'],
      authHints: ['bearerAuth'],
    })
    expect(endpoint(endpoints, 'GET', '/api/hello/:name').params).toEqual(['name'])
  })

  it('NestJS: @Controller prefix, method decorators and @UseGuards at class and method level', async () => {
    const { endpoints } = await routesOf('nest', handle)
    expect(endpoints.map(e => e.id)).toEqual([
      'GET /health/live @ health.controller.ts:6',
      'GET /users @ users.controller.ts:11',
      'POST /users @ users.controller.ts:27',
      'GET /users/:id @ users.controller.ts:16',
      'DELETE /users/:id @ users.controller.ts:21',
    ])
    expect(endpoint(endpoints, 'GET', '/users')).toMatchObject({
      framework: 'nestjs',
      middleware: ['AuthGuard'],
      authHints: ['AuthGuard'],
      handler: { path: 'users.controller.ts', startLine: 12, endLine: 14 },
    })
    expect(endpoint(endpoints, 'DELETE', '/users/:id')).toMatchObject({
      middleware: ['AuthGuard', 'RolesGuard'],
      authHints: ['AuthGuard', 'RolesGuard'],
      params: ['id'],
    })
    // `@Controller({ path: 'health' })` without guards; `@Header` is not middleware.
    expect(endpoint(endpoints, 'GET', '/health/live')).toMatchObject({ middleware: [], authHints: [] })
  })

  it('Next.js: app router route files, pages/api, path mapping and the middleware hint', async () => {
    const { endpoints, warnings } = await routesOf('next', handle)
    expect(warnings).toEqual([])
    expect(endpoints.map(e => e.id)).toEqual([
      'GET /api/files @ src/app/api/files/route.ts:2',
      'POST /api/files @ src/app/api/files/route.ts:2',
      'ANY /api/legacy @ src/pages/api/legacy/index.ts:2',
      'ANY /api/posts/:postId @ src/pages/api/posts/[postId].ts:4',
      'GET /api/users/:id @ src/app/api/users/[id]/route.ts:4',
      'DELETE /api/users/:id @ src/app/api/users/[id]/route.ts:8',
      'POST /dashboard/:slug* @ src/app/(admin)/dashboard/[...slug]/route.ts:2',
    ])
    // This fixture's middleware only calls NextResponse.next(); presence is not an auth check.
    expect(endpoints.every(e => e.framework === 'next' && e.authHints.length === 0)).toBe(true)
    // `[...slug]` → `:slug*`, `(admin)` dropped; `export const DELETE = async () => {}` has a handler.
    expect(endpoint(endpoints, 'POST', '/dashboard/:slug*').params).toEqual(['slug'])
    expect(endpoint(endpoints, 'DELETE', '/api/users/:id')).toMatchObject({
      params: ['id'],
      handler: { path: 'src/app/api/users/[id]/route.ts', startLine: 8, endLine: 10 },
    })
    // `export { handler as GET, handler as POST }`
    expect(endpoint(endpoints, 'GET', '/api/files').handler).toEqual({
      path: 'src/app/api/files/route.ts',
      startLine: 2,
      endLine: 4,
    })
    // Pages (page.tsx) are not API endpoints.
    expect(endpoints.some(e => e.route.includes('about'))).toBe(false)
  })

  it('Next.js: no middleware hint without middleware.(ts|js) at the root or in src/', async () => {
    const snapshot = await routeFixture('next')
    const files = new Map(snapshot.files)
    files.delete('src/middleware.ts')
    const { endpoints } = await extractRoutes({ ...snapshot, files }, { astGrep: handle })
    expect(endpoints.length).toBeGreaterThan(0)
    expect(endpoints.every(e => e.authHints.length === 0)).toBe(true)
    const root = await extractRoutes(
      snapshotOf({
        'middleware.js': 'export function middleware() {}\n',
        'app/api/ping/route.js': 'export function GET() { return new Response("ok") }\n',
      }),
      { astGrep: handle },
    )
    expect(root.endpoints.map(e => [e.id, e.authHints])).toEqual([['GET /api/ping @ app/api/ping/route.js:1', []]])
  })

  it('Flask: @app.route methods, @bp.get, url_prefix and auth decorators', async () => {
    const { endpoints, warnings } = await routesOf('flask', handle)
    expect(warnings).toEqual([])
    expect(endpoints.map(e => e.id)).toEqual([
      'GET / @ app/__init__.py:10',
      'POST /admin/reports @ app/admin.py:13',
      'GET /admin/users/<int:user_id> @ app/admin.py:7',
      'DELETE /api/v1/items/<item_id> @ app/api.py:6',
      'GET /login @ app/__init__.py:15',
      'POST /login @ app/__init__.py:15',
    ])
    // `register_blueprint(..., url_prefix='/admin')` replaces the blueprint's own prefix.
    expect(endpoint(endpoints, 'GET', '/admin/users/<int:user_id>')).toMatchObject({
      framework: 'flask',
      middleware: ['login_required'],
      authHints: ['login_required'],
      params: ['user_id'],
      handler: { path: 'app/admin.py', startLine: 9, endLine: 10 },
    })
    expect(endpoint(endpoints, 'POST', '/admin/reports').authHints).toEqual(['jwt_required', 'roles_required'])
    // `Blueprint(url_prefix='/api/v1')` kept when registered without one.
    expect(endpoint(endpoints, 'DELETE', '/api/v1/items/<item_id>').params).toEqual(['item_id'])
    expect(endpoint(endpoints, 'GET', '/').authHints).toEqual([])
  })

  it('FastAPI: decorators, APIRouter(prefix=), include_router dependencies and Depends() parameters', async () => {
    const { endpoints, warnings } = await routesOf('fastapi', handle)
    expect(warnings).toEqual([])
    expect(routeList(endpoints)).toEqual([
      'POST /api/items',
      'GET /api/items/{item_id}',
      'GET /me',
      'GET /ping',
      'DELETE /sessions/{session_id}',
    ])
    expect(endpoint(endpoints, 'GET', '/api/items/{item_id}')).toMatchObject({
      framework: 'fastapi',
      declaredAt: { path: 'app/routers/items.py', startLine: 6 },
      authHints: ['Depends(get_current_user)'],
      params: ['item_id'],
    })
    expect(endpoint(endpoints, 'GET', '/me').authHints).toEqual(['Depends(get_current_user)'])
    expect(endpoint(endpoints, 'DELETE', '/sessions/{session_id}').authHints).toEqual(['Depends(verify_token)'])
    expect(endpoint(endpoints, 'GET', '/ping')).toMatchObject({ middleware: [], authHints: [] })
  })

  it('Django: path/re_path, followed includes, unresolved include warning and view auth', async () => {
    const { endpoints, warnings } = await routesOf('django', handle)
    expect(endpoints.map(e => `${e.id} [${e.authHints.join(',')}]`)).toEqual([
      'ANY /invoices/<uuid:invoice_id>/ @ project/urls.py:8 [permission_required]',
      'ANY /shop/ @ shop/urls.py:6 []',
      'ANY /shop/account/ @ shop/urls.py:8 [LoginRequiredMixin]',
      'ANY /shop/archive/(?P<year>[0-9]{4})/ @ shop/urls.py:9 []',
      'ANY /shop/orders/<int:order_id>/ @ shop/urls.py:7 [login_required]',
    ])
    expect(endpoint(endpoints, 'ANY', '/shop/orders/<int:order_id>/')).toMatchObject({
      framework: 'django',
      params: ['order_id'],
      handler: { path: 'shop/views.py', startLine: 11, endLine: 12 },
    })
    expect(endpoint(endpoints, 'ANY', '/shop/archive/(?P<year>[0-9]{4})/').params).toEqual(['year'])
    expect(warnings).toEqual([
      "project/urls.py:7: include('blog.urls') at '/blog/' was not followed; routes it defines are listed without this prefix.",
    ])
  })

  it('sorts by route then line and builds ids from method, route and declaration', async () => {
    const { endpoints } = await extractRoutes(
      snapshotOf({
        'b.js': "const app = require('express')()\napp.get('/b', h)\n\n\napp.post('/a', h)\napp.get('/a', h)\n",
        'a.js': "const app = require('express')()\n\napp.put('/b', h)\n",
      }),
      { astGrep: handle },
    )
    expect(endpoints.map(e => e.id)).toEqual([
      'POST /a @ b.js:5',
      'GET /a @ b.js:6',
      'PUT /b @ a.js:3',
      'GET /b @ b.js:2',
    ])
    for (const e of endpoints) {
      expect(e.id).toBe(`${e.method} ${e.route} @ ${e.declaredAt.path}:${e.declaredAt.startLine}`)
    }
  })

  it('ignores HTTP client calls in front-end code', async () => {
    const { endpoints } = await extractRoutes(
      snapshotOf({
        'web/api.ts': "import axios from 'axios'\nexport const api = axios.create({ baseURL: '/api' })\n",
        'web/users.ts': [
          "import { api } from './api'",
          "export const save = (u) => api.post('/users', u)",
          "export const load = () => api.get('/users', { params: { q: 1 } })",
        ].join('\n'),
        'web/App.tsx': "'use client'\nexport function App({ router }) { router.get('/x', () => 1) }\n",
      }),
      { astGrep: handle },
    )
    expect(endpoints).toEqual([])
  })

  it('honors an aborted signal', async () => {
    const files: Record<string, string> = {}
    for (let i = 0; i < 60; i++) files[`src/r${i}.js`] = `const app = require('express')()\napp.get('/r${i}', h)\n`
    const aborted = new AbortController()
    aborted.abort(new Error('stop'))
    await expect(extractRoutes(snapshotOf(files), { astGrep: handle, signal: aborted.signal })).rejects.toThrow('stop')
    const late = new AbortController()
    const pending = extractRoutes(snapshotOf(files), { astGrep: handle, signal: late.signal })
    late.abort(new Error('late stop'))
    await expect(pending).rejects.toThrow('late stop')
  })
})

describe('route helpers', () => {
  it('maps Next.js file paths to URL patterns', () => {
    expect(nextRouteOf('app/api/users/[id]/route.ts')).toMatchObject({
      route: '/api/users/:id',
      params: ['id'],
      kind: 'app',
    })
    expect(nextRouteOf('src/app/(shop)/cart/[...items]/route.js')).toMatchObject({
      route: '/cart/:items*',
      params: ['items'],
    })
    expect(nextRouteOf('app/docs/[[...slug]]/route.ts')).toMatchObject({ route: '/docs/:slug*', params: ['slug'] })
    expect(nextRouteOf('app/route.ts')).toMatchObject({ route: '/' })
    expect(nextRouteOf('pages/api/index.ts')).toMatchObject({ route: '/api', kind: 'pages' })
    expect(nextRouteOf('pages/api/users/[uid].ts')).toMatchObject({ route: '/api/users/:uid', params: ['uid'] })
    expect(nextRouteOf('app/dashboard/page.tsx')).toBeUndefined()
    expect(nextRouteOf('pages/about.tsx')).toBeUndefined()
    expect(nextRouteOf('node_modules/x/app/route.js')).toBeUndefined()
    // A monorepo package: the router directory belongs to the project that has a package.json.
    const files = new Map([['apps/web/package.json', '{}']])
    expect(nextRouteOf('apps/web/app/api/route.ts', { files })).toMatchObject({ route: '/api', root: 'apps/web/' })
  })

  it('treats guard names as auth hints but not rate limiters, throttles, or loggers', () => {
    const guards = [
      'requireLogin',
      'loginRequired',
      'login_required',
      'ensureLoggedIn',
      'isAuthenticated',
      'requireAuth',
      'authenticate',
      'passport.authenticate',
      'Depends(get_current_user)',
      'fastify.verifyJwt',
      'AuthGuard',
    ]
    const notGuards = [
      'loginLimiter',
      'authRateLimit',
      'loginThrottle',
      'authLimiter',
      'login_rate_limit',
      'ThrottlerGuard',
      'authSlowDown',
      'auth_slowdown',
      'authLogger',
      'sessionLogging',
      'rateLimit',
      'express.json',
    ]
    for (const name of guards) expect(AUTH_HINT.test(name), name).toBe(true)
    for (const name of notGuards) expect(AUTH_HINT.test(name), name).toBe(false)
    expect(authHintsOf(['loginLimiter', 'requireLogin', 'requireLogin', 'helmet'])).toEqual(['requireLogin'])
  })

  it('reads parameter names from every supported pattern syntax', () => {
    expect(routeParams('/a/:id/b/:slug*')).toEqual(['id', 'slug'])
    expect(routeParams('/items/{item_id}/{path:path}')).toEqual(['item_id', 'path'])
    expect(routeParams('/u/<int:uid>/<name>')).toEqual(['uid', 'name'])
    expect(routeParams('/docs/[id]/[...rest]')).toEqual(['id', 'rest'])
    expect(routeParams('^archive/(?P<year>[0-9]{4})/$')).toEqual(['year'])
    expect(routeParams('/static/*')).toEqual([])
  })
})
