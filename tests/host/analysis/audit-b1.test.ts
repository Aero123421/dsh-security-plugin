import { spawnSync } from 'node:child_process'
import { describe, expect, it } from 'vitest'
import { parseDependencies } from '../../../src/host/analysis/dependencies.ts'
import { extractRoutes } from '../../../src/host/analysis/routes/index.ts'
import { snapshotOf } from './helpers.ts'
import { MODES, PY_MODES, ofRule, sast } from './sast-helpers.ts'

// Run pathological inputs in a killable child: reintroducing a synchronous
// ReDoS must fail the test rather than wedge the Vitest worker indefinitely.
function boundedAnalysis(mode: string, script: string): unknown {
  const imports = [
    `import { snapshotOf } from ${JSON.stringify(new URL('./helpers.ts', import.meta.url).href)}`,
    `import { extractRoutes } from ${JSON.stringify(new URL('../../../src/host/analysis/routes/index.ts', import.meta.url).href)}`,
    `import { runSast } from ${JSON.stringify(new URL('../../../src/host/analysis/sast/engine.ts', import.meta.url).href)}`,
    `import { loadAstGrep } from ${JSON.stringify(new URL('../../../src/host/analysis/astgrep.ts', import.meta.url).href)}`,
    `const handle = ${mode === 'ast' ? 'await loadAstGrep()' : 'undefined'}`,
  ].join('\n')
  const start = performance.now()
  const result = spawnSync(
    process.execPath,
    ['--experimental-strip-types', '--no-warnings', '--input-type=module', '-e', imports + '\n' + script],
    {
      encoding: 'utf8',
      timeout: 5000,
      killSignal: 'SIGKILL',
      maxBuffer: 1024 * 1024,
    },
  )
  expect(result.error, result.stderr).toBeUndefined()
  expect(result.status, result.stderr).toBe(0)
  expect(performance.now() - start).toBeLessThan(10000)
  return JSON.parse(result.stdout)
}
describe.each(MODES)('B1 JavaScript (%s)', (_mode, handle) => {
  it('handles 48 leading block comments without regex backtracking', () => {
    const header = '/* header comment */ \n'.repeat(48)
    const server = `export function registerRoutes(app) { app.get('/x', handler) }`
    const result = boundedAnalysis(
      _mode,
      `
      const server = await extractRoutes(snapshotOf(${JSON.stringify({ 'server.js': header + server })}), { astGrep: handle })
      const client = await extractRoutes(snapshotOf(${JSON.stringify({ 'client.js': header + "'use client';\n" + server })}), { astGrep: handle })
      console.log(JSON.stringify([server.endpoints.map(e => e.route), client.endpoints]))
    `,
    )
    expect(result).toEqual([['/x'], []])
  })

  it('parses long response chains structurally including a failing suffix', () => {
    const chain = 'res' + '.status(200)'.repeat(48)
    const code = `function handler(req, res) {\n${chain}.foo.send(req.query.name)\nres.status((200)).set('X-Test', String(1)).send(req.query.name)\nres?.status?.(200)?.send(req.query.name)\n}`
    const result = boundedAnalysis(
      _mode,
      `
      const run = await runSast(snapshotOf(${JSON.stringify({ 'server.js': code })}), { astGrep: handle })
      console.log(JSON.stringify(run.signals.filter(s => s.ruleId === 'js.xss').map(s => s.location.startLine)))
    `,
    )
    // Optional-call chains are not emitted by the existing fallback fact builder.
    expect(result).toEqual(_mode === 'ast' ? [3, 4] : [3])
  })

  it('propagates route().all middleware without a phantom ANY endpoint', async () => {
    const result = await extractRoutes(
      snapshotOf({
        'server.js': `import express from 'express'
const app = express()
app.route('/x').all(requireAuth).post((req, res) => res.send('ok')).get(read)
app.route('/terminal').all((req, res) => res.send('ok'))
app.route('/only-auth').all(requireAuth)
app.route('/ends').all(requireAuth, (req, res) => res.send('done')).post(read)
`,
      }),
      { astGrep: handle },
    )
    expect(result.endpoints.map(e => [e.method, e.route, e.authHints])).toEqual([
      ['ANY', '/ends', ['requireAuth']],
      ['POST', '/ends', ['requireAuth']],
      ['ANY', '/terminal', []],
      ['GET', '/x', ['requireAuth']],
      ['POST', '/x', ['requireAuth']],
    ])
  })

  it('detects TypeORM string predicates and Sequelize literal, not parameter bindings or Mongo objects', async () => {
    const code = `import { literal } from 'sequelize'
function handler(req, res) {
  qb.where('name = ' + req.query.name)
  qb.andWhere(\`id = \${req.query.id}\`)
  qb.orWhere('email = ' + req.body.email)
  literal('name = ' + req.query.name)
  sequelize.literal(\`id = \${req.query.id}\`)
  qb.where('id = :id', { id: req.query.id })
  qb.where({ id: req.query.id })
  collection.find({ id: String(req.query.id) })
  literal('name = :name')
}`
    const signals = await sast({ 'server.js': code }, handle)
    expect(ofRule(signals, 'js.sql-injection').map(s => s.location.startLine)).toEqual([3, 4, 5, 6, 7])
    expect(ofRule(signals, 'js.nosql-injection')).toEqual([])
  })

  it('handles aliased literals and direct SQL-builder strings without weakening Mongo guards', async () => {
    const signals = await sast(
      {
        'server.js': `import { literal as rawSql } from 'sequelize'
function handler(req) {
  const qb = dataSource.createQueryBuilder('User')
  qb.where(req.query.sql)
  qb.andWhere(req.body.sql)
  rawSql('id = ' + req.query.id)
  collection.where({ id: req.query.id })
}`,
      },
      handle,
    )
    expect(ofRule(signals, 'js.sql-injection').map(s => s.location.startLine)).toEqual([4, 5, 6])
    expect(ofRule(signals, 'js.nosql-injection').map(s => s.location.startLine)).toEqual([7])
  })

  it('does not grant Next auth hints for presence-only or dynamic/uncovered matchers', async () => {
    const routes = { 'app/api/items/route.ts': 'export function GET() { return Response.json({}) }' }
    for (const middleware of [
      'export function middleware(req) { return NextResponse.next() }',
      `export function middleware(req) { if (req.locale) return NextResponse.redirect('/auth') }`,
      `export function middleware(req) { console.log(req.auth); if (req.locale) return NextResponse.redirect('/login') }`,
      `export function middleware(req) { /* if (!req.auth) redirect('/login') */ return NextResponse.next() }`,
      `export function middleware(req) { if (!req.auth) return NextResponse.redirect('/login') }\nexport const config = dynamicConfig`,
      `export function middleware(req) { if (!req.auth) return NextResponse.redirect('/login') }\nexport const config = { matcher: '/api/:path*', ...dynamicConfig }`,
      `export function middleware(req) { if (!req.auth) return NextResponse.redirect('/login') }
export const config = { matcher: '/admin/:path*' }`,
      `export function middleware(req) { if (!req.auth) return NextResponse.redirect('/login') }
export const config = { matcher: dynamicMatcher }`,
    ]) {
      const result = await extractRoutes(snapshotOf({ ...routes, 'middleware.ts': middleware }), { astGrep: handle })
      expect(result.endpoints[0]?.authHints).toEqual([])
    }
  })

  it('grants Next auth hints only where literal matchers cover the route', async () => {
    for (const matcher of [
      '',
      `export const config = { matcher: '/api/:path*' }`,
      `export const config = { matcher: ['/admin/:path*', '/api/:path*'] }`,
    ]) {
      const result = await extractRoutes(
        snapshotOf({
          'app/api/items/route.ts': 'export function GET() { return Response.json({}) }',
          'middleware.ts': `export function middleware(req) { if (!req.auth) return NextResponse.redirect('/login'); return NextResponse.next() }\n${matcher}`,
        }),
        { astGrep: handle },
      )
      expect(result.endpoints[0]?.authHints).toEqual(['next-middleware'])
    }
  })
})

describe.each(PY_MODES)('B1 Python (%s)', (_mode, handle) => {
  it('extracts mounted DRF DefaultRouter/SimpleRouter CRUD endpoints and permissions', async () => {
    for (const router of ['DefaultRouter', 'SimpleRouter']) {
      const result = await extractRoutes(
        snapshotOf({
          'project/urls.py': `from django.urls import path, include\nurlpatterns = [path('api/', include('shop.urls'))]`,
          'shop/urls.py': `from django.urls import path, include
from rest_framework.routers import ${router}
from .views import UserViewSet
router = ${router}()
router.register('users', UserViewSet, basename='users')
router.register('people', UserViewSet)
urlpatterns = [path('v1/', include(router.urls))]`,
          'shop/views.py': `from rest_framework.viewsets import ModelViewSet
from rest_framework.permissions import IsAuthenticated
class UserViewSet(ModelViewSet):
    permission_classes = [IsAuthenticated]
`,
        }),
        { astGrep: handle },
      )
      expect(result.warnings).toEqual([])
      expect(result.endpoints).toHaveLength(12)
      expect(
        result.endpoints.every(e => e.route.startsWith('/api/v1/') && e.authHints.includes('IsAuthenticated')),
      ).toBe(true)
      expect(result.endpoints.map(e => `${e.method} ${e.route}`)).toContain('PATCH /api/v1/users/:pk')
    }
  })

  it('handles direct router urlpatterns and constrains read-only ViewSets', async () => {
    const result = await extractRoutes(
      snapshotOf({
        'urls.py': `from rest_framework import routers
from rest_framework.viewsets import ReadOnlyModelViewSet
class Books(ReadOnlyModelViewSet):
    permission_classes = []
router = routers.SimpleRouter()
router.register('books', Books)
urlpatterns = router.urls
`,
      }),
      { astGrep: handle },
    )
    expect(result.warnings).toEqual([])
    expect(result.endpoints.map(e => [e.method, e.route, e.authHints])).toEqual([
      ['GET', '/books', []],
      ['GET', '/books/:pk', []],
    ])
  })

  it('preserves existing unresolved dotted Django include warnings', async () => {
    const result = await extractRoutes(
      snapshotOf({
        'urls.py': `from django.urls import path, include\nimport shop.urls\nurlpatterns = [path('web/', include(shop.urls))]`,
        'shop/urls.py': `from django.urls import path\nurlpatterns = [path('items/', items)]\ndef items(request):\n    pass`,
      }),
      { astGrep: handle },
    )
    expect(result.warnings.join(' ')).toMatch(/include\(shop.urls\).*was not followed/)
    expect(result.endpoints.map(e => e.route)).toEqual(['/items/'])
  })

  it('warns for unresolvable DRF routers instead of returning silent zero', async () => {
    const result = await extractRoutes(
      snapshotOf({
        'urls.py': `from django.urls import path, include
from rest_framework import routers
router = routers.DefaultRouter()
router.register(dynamicPrefix, UnknownViewSet)
urlpatterns = [path('api/', include(router.urls))]`,
      }),
      { astGrep: handle },
    )
    expect(result.endpoints).toEqual([])
    expect(result.warnings.join(' ')).toMatch(/include\(router.urls\).*was not followed/)
  })

  it('detects SQLAlchemy text in query builders while preserving bound queries', async () => {
    const signals = await sast(
      {
        'app.py': `from sqlalchemy import text
from flask import request
def handler():
    query.filter(text(f"name = '{request.args.get('name')}'"))
    query.where(text('id = ' + request.args.get('id')))
    query.having(text(f"count(*) > {request.args.get('count')}"))
    query.filter(text('id = :id')).params(id=request.args.get('id'))
    query.filter(User.id == request.args.get('id'))
    text(f"unused {request.args.get('name')}")
`,
      },
      handle,
    )
    expect(ofRule(signals, 'py.sql-injection').map(s => s.location.startLine)).toEqual([4, 5, 6])
  })
})

it('follows snapshot-only split requirements and warns for cycles and missing targets', async () => {
  const result = await parseDependencies(
    snapshotOf({
      'requirements/local.txt':
        '-r base.txt\n--requirement=../pins/runtime.in\n-r missing.txt\n-r /etc/passwd\n-r https://example.com/deps.txt\npytest==8.0.0',
      'requirements/base.txt': '-r local.txt\nDjango==4.2.0',
      'pins/runtime.in': 'requests==2.31.0',
    }),
  )
  expect(result.dependencies.map(d => d.name).sort()).toEqual(['django', 'pytest', 'requests'])
  expect(result.warnings.join(' ')).toMatch(/cycle/)
  expect(result.warnings.join(' ')).toMatch(/missing.txt/)
  expect(result.warnings.join(' ')).toMatch(/outside|confined|snapshot/)
  expect(result.dependencies.find(d => d.name === 'requests')).toMatchObject({ manifest: 'pins/runtime.in', line: 1 })
})

it('bounds requirement include depth and follows short/long include syntax in cookiecutter layouts', async () => {
  const files: Record<string, string> = {
    'requirements/production.txt': '--requirement base.txt\n-r../pins/runtime.in',
  }
  files['requirements/base.txt'] = 'Django==4.2.0'
  files['pins/runtime.in'] = '-r chain1.in\nrequests==2.31.0'
  for (let i = 1; i <= 20; i++) files[`pins/chain${i}.in`] = i === 20 ? 'deep==1.0.0' : `-r chain${i + 1}.in`
  const result = await parseDependencies(snapshotOf(files))
  expect(result.dependencies.map(d => d.name).sort()).toEqual(['django', 'requests'])
  expect(result.warnings.join(' ')).toMatch(/depth limit/)
})
