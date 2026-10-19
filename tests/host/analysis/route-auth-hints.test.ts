import { describe, expect, it } from 'vitest'
import { authHintsOf, isAuthHint } from '../../../src/host/analysis/routes/common.ts'
import { extractRoutes } from '../../../src/host/analysis/routes/index.ts'
import { routeSignals } from '../../../src/host/analysis/routes/signals.ts'
import { snapshotOf } from './helpers.ts'
import { endpoint } from './routes-helpers.ts'
import { MODES, PY_MODES } from './sast-helpers.ts'

/** A layered Express API: session and Passport set up globally, auth per route, one route without it. */
const LAYERED_API: Record<string, string> = {
  'src/index.ts': `import express from 'express'
import session from 'express-session'
import cookieSession from 'cookie-session'
import passport from 'passport'
import { router } from './routes/index.js'
const app = express()
app.use(express.json())
app.use(session({ secret: process.env.SESSION_SECRET, resave: false, saveUninitialized: false }))
app.use(cookieSession({ keys: [process.env.COOKIE_KEY] }))
app.use(require('express-session')({ secret: process.env.SESSION_SECRET }))
app.use(passport.initialize())
app.use(passport.session())
app.use('/api', router)
app.listen(3000)
`,
  'src/routes/index.ts': `import { Router } from 'express'
import { tenantRoutes } from './tenant.routes.js'
export const router = Router()
router.use('/tenants', tenantRoutes)
`,
  'src/routes/tenant.routes.ts': `import { Router } from 'express'
import passport from 'passport'
import { requireAuth } from '../middleware/requireAuth.js'
import * as controller from '../controllers/tenant.controller.js'
export const tenantRoutes = Router()
tenantRoutes.get('/', requireAuth, controller.listTenants)
tenantRoutes.delete('/:id', passport.authenticate('jwt', { session: false }), controller.deleteTenant)
tenantRoutes.post('/:id/impersonate', controller.impersonate)
`,
  'src/controllers/tenant.controller.ts': `export async function listTenants(req, res) { res.json([]) }
export async function deleteTenant(req, res) { res.status(204).end() }
export async function impersonate(req, res) { res.json({ token: await issue(req.params.id) }) }
`,
  'src/middleware/requireAuth.ts': 'export function requireAuth(req, res, next) { next() }\n',
}

describe('auth hints: middleware that never rejects a request', () => {
  it.each([
    'session',
    'expressSession',
    'cookieSession',
    'koaSession',
    'passport.initialize',
    'passport.session',
    "require('express-session')",
    "require('cookie-session')",
    'Depends(get_session)',
    'Depends(get_db_session)',
    'Depends(get_async_session)',
    'getDbSession',
  ])('%s is not an auth hint', name => {
    expect(isAuthHint(name)).toBe(false)
  })

  it.each([
    'requireAuth',
    'requireSession',
    'verifySession',
    'ensureSession',
    'sessionAuth',
    'passport.authenticate',
    'Depends(get_current_user)',
    'Depends(verify_token)',
    'login_required',
  ])('%s is still an auth hint', name => {
    expect(isAuthHint(name)).toBe(true)
  })

  it('filters middleware lists the same way', () => {
    expect(authHintsOf(['session', 'passport.initialize', 'requireAuth', 'requireAuth'])).toEqual(['requireAuth'])
  })
})

describe.each(MODES)('auth hints in a layered Express app (%s mode)', (_mode, handle) => {
  it('does not mark routes guarded by session(), cookieSession() or Passport setup alone', async () => {
    const { endpoints } = await extractRoutes(snapshotOf(LAYERED_API), { astGrep: handle })
    const impersonate = endpoint(endpoints, 'POST', '/api/tenants/:id/impersonate')
    expect(impersonate.middleware).toEqual(
      expect.arrayContaining(['session', 'passport.initialize', 'passport.session']),
    )
    expect(impersonate.authHints).toEqual([])
    expect(endpoint(endpoints, 'GET', '/api/tenants').authHints).toEqual(['requireAuth'])
    expect(endpoint(endpoints, 'DELETE', '/api/tenants/:id').authHints).toEqual(['passport.authenticate'])
  })

  it('steers review to the unauthenticated mutating route', async () => {
    const snapshot = snapshotOf(LAYERED_API)
    const { endpoints } = await extractRoutes(snapshot, { astGrep: handle })
    const signals = routeSignals(endpoints, snapshot)
    expect(signals.map(s => s.fingerprintParts.slice(1, 3).join(' '))).toEqual(['POST /api/tenants/:id/impersonate'])
  })
})

describe.each(PY_MODES)('auth hints for FastAPI dependencies (%s mode)', (_mode, handle) => {
  it('does not count a database-session dependency as auth', async () => {
    const { endpoints } = await extractRoutes(
      snapshotOf({
        'app/main.py': `from fastapi import FastAPI, Depends
app = FastAPI()
@app.post('/items')
def create(item: dict, db = Depends(get_session)):
    return item
@app.delete('/items/{item_id}')
def delete(item_id: int, db = Depends(get_session), user = Depends(get_current_user)):
    return None
`,
      }),
      { astGrep: handle },
    )
    expect(endpoint(endpoints, 'POST', '/items').authHints).toEqual([])
    expect(endpoint(endpoints, 'DELETE', '/items/{item_id}').authHints).toEqual(['Depends(get_current_user)'])
  })
})

describe.each(MODES)('Next.js middleware scoped by request path (%s mode)', (_mode, handle) => {
  const routes = {
    'app/api/items/route.ts': 'export function GET() { return Response.json({}) }',
    'app/dashboard/stats/route.ts': 'export function GET() { return Response.json({}) }',
    'package.json': '{}',
  }
  const hintsFor = async (middleware: string) => {
    const { endpoints } = await extractRoutes(snapshotOf({ ...routes, 'middleware.ts': middleware }), {
      astGrep: handle,
    })
    return Object.fromEntries(endpoints.map(e => [e.route, e.authHints]))
  }

  it('treats pathname.startsWith(literal) around the check as the matcher', async () => {
    for (const middleware of [
      `export function middleware(req) {
  if (req.nextUrl.pathname.startsWith('/dashboard')) {
    const token = req.cookies.get('token')
    if (!token) return NextResponse.redirect(new URL('/login', req.url))
  }
  return NextResponse.next()
}`,
      `export function middleware(req) {
  const { pathname } = req.nextUrl
  if (pathname.startsWith('/dashboard') && !req.auth) return NextResponse.redirect(new URL('/login', req.url))
  return NextResponse.next()
}`,
      `export function middleware(req) {
  const pathname = req.nextUrl.pathname
  if (pathname.startsWith('/dashboard') && !req.auth) return NextResponse.redirect(new URL('/login', req.url))
}`,
    ]) {
      expect(await hintsFor(middleware)).toEqual({ '/api/items': [], '/dashboard/stats': ['next-middleware'] })
    }
  })

  it('grants nothing when the path is read in a way it cannot follow', async () => {
    for (const middleware of [
      `export function middleware(req) {
  if (!req.nextUrl.pathname.startsWith('/public') && !req.auth) return NextResponse.redirect(new URL('/login', req.url))
}`,
      `export function middleware(req) {
  const { pathname } = req.nextUrl
  if (PROTECTED.some(p => pathname.startsWith(p)) && !req.auth) return NextResponse.redirect(new URL('/login', req.url))
}`,
      `export function middleware(req) {
  if (req.nextUrl.pathname === '/login') return NextResponse.next()
  if (!req.auth) return NextResponse.redirect(new URL('/login', req.url))
}`,
    ]) {
      expect(await hintsFor(middleware)).toEqual({ '/api/items': [], '/dashboard/stats': [] })
    }
  })

  it('keeps the blanket hint when the check does not depend on the path', async () => {
    expect(
      await hintsFor(
        `export function middleware(req) { if (!req.auth) return NextResponse.redirect(new URL('/login', req.url)) }`,
      ),
    ).toEqual({ '/api/items': ['next-middleware'], '/dashboard/stats': ['next-middleware'] })
  })
})
