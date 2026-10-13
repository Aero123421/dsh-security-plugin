import { describe, expect, it } from 'vitest'
import { expectedHits, hits, MODES, ofRule, sast } from './sast-helpers.ts'

/**
 * Each case is a file whose lines are tagged in comments:
 * `// VULN` → a `vulnerability` on that line, `// SINK` → a `sink`, anything
 * else must not be reported for the rule. Cases run in fallback and AST mode.
 */
interface Case {
  readonly rule: string
  readonly name: string
  readonly path?: string
  readonly code: string
}

const CASES: readonly Case[] = [
  {
    rule: 'js.sql-injection',
    name: 'concatenation and templates with request data; parameterized and tagged queries are safe',
    code: `
app.get('/u/:id', async (req, res) => {
  await db.query('SELECT * FROM users WHERE id = ' + req.params.id) // VULN
  await pool.query(\`SELECT * FROM t WHERE name = '\${req.query.name}'\`) // VULN
  await knex.raw('select * from t where a = ' + req.body.a) // VULN
  await sequelize.query(\`DELETE FROM t WHERE id = \${req.body.id}\`) // VULN
  await prisma.$queryRawUnsafe(\`SELECT * FROM t WHERE id = \${req.query.id}\`) // VULN
  await db.query(\`SELECT * FROM t WHERE x = \${computeX()}\`) // SINK
  await db.query('SELECT * FROM users WHERE id = $1', [req.params.id])
  await db.query('SELECT * FROM users WHERE id = ?', [req.params.id])
  await prisma.$queryRaw\`SELECT * FROM users WHERE id = \${req.params.id}\`
  await sql\`SELECT * FROM users WHERE id = \${req.params.id}\`
  await db.query('SELECT * FROM ' + TABLE_NAME)
  cache.query('key' + req.params.id)
})`,
  },
  {
    rule: 'js.sql-injection',
    name: 'one-level aliases: destructuring and plain copies',
    code: `
app.get('/u/:id', async (req, res) => {
  const { id } = req.params
  const name = req.query.name
  const q = 'SELECT * FROM users WHERE id = ' + id
  await db.query(q) // VULN
  await db.query("SELECT * FROM users WHERE name = '" + name + "'") // VULN
  const safe = parseInt(id, 10)
  await db.query('SELECT * FROM users WHERE id = ' + safe) // SINK
})`,
  },
  {
    rule: 'js.nosql-injection',
    name: 'request objects as filters and $where',
    code: `
app.post('/login', async (req, res) => {
  await User.findOne(req.body) // VULN
  await User.find({ username: req.body.username, password: req.body.password }) // VULN
  await db.collection('u').find({ $where: 'this.name == "' + something + '"' }) // SINK
  await User.findOne({ username: String(req.body.username) })
  await User.find({ $where: function () { return this.a > 1 } })
  await User.findById(req.params.id)
})`,
  },
  {
    rule: 'js.command-injection',
    name: 'exec with input; execFile without shell is safe',
    code: `
const { exec, execFile, spawn } = require('child_process')
const cp = require('child_process')
app.get('/run', (req, res) => {
  exec('ls ' + req.query.dir) // VULN
  cp.execSync(\`git log \${req.body.branch}\`) // VULN
  spawn('sh', ['-c', req.query.cmd]) // VULN
  spawn(req.query.prog, [], { shell: true }) // VULN
  exec(\`convert \${inputFile} out.png\`) // SINK
  execFile('git', [req.query.ref])
  spawn('ls', [req.query.dir])
  exec('ls -la')
})`,
  },
  {
    rule: 'js.code-injection',
    name: 'eval, Function, vm and string timers',
    code: `
const vm = require('vm')
app.post('/calc', (req, res) => {
  eval(req.body.expr) // VULN
  new Function('a', req.query.body) // VULN
  vm.runInNewContext(req.body.code, {}) // VULN
  eval(templateSource) // SINK
  setTimeout('tick(' + n + ')', 100) // SINK
  setTimeout(() => tick(n), 100)
  eval('1 + 1')
  JSON.parse(req.body.json)
})`,
  },
  {
    rule: 'js.path-traversal',
    name: 'file operations with request paths; basename is sanitizing',
    code: `
const fs = require('fs')
const path = require('path')
app.get('/f', (req, res) => {
  fs.readFile(path.join(__dirname, 'uploads', req.query.name), cb) // VULN
  fs.createReadStream('/srv/' + req.params.file) // VULN
  res.download(req.query.path) // VULN
  res.sendFile(req.query.name, { root: '/srv/public' }) // SINK
  fs.readFile(path.join(__dirname, 'uploads', path.basename(req.query.name)), cb)
  fs.readFile(path.join(__dirname, 'static', 'index.html'), cb)
  fs.unlink(tmpFile, cb)
})`,
  },
  {
    rule: 'js.ssrf',
    name: 'outgoing requests to request-controlled URLs',
    code: `
import axios from 'axios'
import got from 'got'
app.post('/hook', async (req, res) => {
  await fetch(req.body.url) // VULN
  await axios.get(req.query.target) // VULN
  await got(\`\${req.body.base}/status\`) // VULN
  await axios.get(\`https://api.example.com/users/\${req.params.id}\`) // SINK
  await fetch('https://api.example.com/health')
  await fetch(config.serviceUrl + '/ping')
})`,
  },
  {
    rule: 'js.open-redirect',
    name: 'redirects to request URLs',
    code: `
import { NextResponse } from 'next/server'
app.get('/go', (req, res) => {
  res.redirect(req.query.next) // VULN
  res.redirect(302, req.query.returnTo) // VULN
  res.redirect('/dashboard')
  res.redirect('/users/' + req.params.id)
})
router.get('/k', ctx => {
  ctx.redirect(ctx.query.url) // VULN
})
export function GET(request) {
  const target = request.nextUrl.searchParams.get('to')
  return NextResponse.redirect(new URL(target)) // VULN
}`,
  },
  {
    rule: 'js.xss',
    name: 'reflected HTML responses and DOM sinks',
    path: 'src/app.jsx',
    code: `
app.get('/hi', (req, res) => {
  res.send('<h1>Hello ' + req.query.name + '</h1>') // VULN
  res.write(\`<p>\${req.body.comment}</p>\`) // VULN
  res.json({ name: req.query.name })
  res.send(req.body)
  res.send('ok')
})
function render(html) {
  document.getElementById('out').innerHTML = location.hash.slice(1) // VULN
  el.innerHTML = html // SINK
  el.insertAdjacentHTML('beforeend', userHtml) // SINK
  document.write(location.search) // VULN
  el.innerHTML = DOMPurify.sanitize(html)
  el.innerHTML = '<b>static</b>'
  el.textContent = location.hash
  return <div dangerouslySetInnerHTML={{ __html: html }} /> // SINK
}
const Safe = () => <div dangerouslySetInnerHTML={{ __html: '<br/>' }} />`,
  },
  {
    rule: 'js.insecure-deserialization',
    name: 'node-serialize',
    code: `
const serialize = require('node-serialize')
app.post('/s', (req, res) => {
  serialize.unserialize(req.cookies.profile) // VULN
  serialize.unserialize(cachedBlob) // SINK
  JSON.parse(req.cookies.profile)
})`,
  },
  {
    rule: 'js.unsafe-yaml-load',
    name: 'js-yaml load is only a sink',
    code: `
const yaml = require('js-yaml')
app.post('/y', (req, res) => {
  yaml.load(req.body.doc) // SINK
  yaml.load(text, { schema: yaml.JSON_SCHEMA })
  yaml.load('a: 1')
})`,
  },
  {
    rule: 'js.weak-password-hash',
    name: 'md5/sha1 near passwords only',
    code: `
const crypto = require('crypto')
function hashPassword(password) {
  return crypto.createHash('md5').update(password).digest('hex') // VULN
}
function etag(body) {
  return crypto.createHash('sha1').update(body).digest('hex')
}
const pw = crypto.createHash('sha256').update(password).digest('hex')`,
  },
  {
    rule: 'js.weak-cipher',
    name: 'createCipher and weak algorithms',
    code: `
const crypto = require('crypto')
const a = crypto.createCipher('aes-256-cbc', key) // VULN
const b = crypto.createCipheriv('des-ede3-cbc', key, iv) // VULN
const c = crypto.createCipheriv('aes-256-gcm', key, iv)`,
  },
  {
    rule: 'js.insecure-random',
    name: 'Math.random for secrets',
    code: `
const resetToken = Math.random().toString(36).slice(2) // VULN
function generatePassword() { return Math.random().toString(36) } // VULN
const sessionKey = Math.random() // SINK
const jitter = Math.random() * 100
const color = colors[Math.floor(Math.random() * colors.length)]`,
  },
  {
    rule: 'js.jwt-none-algorithm',
    name: 'none algorithm',
    code: `
jwt.verify(token, key, { algorithms: ['HS256', 'none'] }) // VULN
jwt.verify(token, key, { algorithms: ['HS256'] })`,
  },
  {
    rule: 'js.jwt-decode-without-verify',
    name: 'decode trusted for auth without verify',
    code: `
const jwt = require('jsonwebtoken')
function auth(req, res, next) {
  const token = req.headers.authorization.split(' ')[1]
  req.user = jwt.decode(token) // VULN
  next()
}
function authOk(req, res, next) {
  const token = req.headers.authorization.split(' ')[1]
  const claims = jwt.decode(token)
  req.user = jwt.verify(token, key)
  next()
}
function logToken(t) { console.log(jwt.decode(t)) }`,
  },
  {
    rule: 'js.jwt-ignore-expiration',
    name: 'ignoreExpiration',
    code: `
jwt.verify(token, key, { ignoreExpiration: true }) // VULN
jwt.verify(token, key, { ignoreExpiration: false })`,
  },
  {
    rule: 'js.tls-verification-disabled',
    name: 'rejectUnauthorized false and env override',
    code: `
const agent = new https.Agent({ rejectUnauthorized: false }) // VULN
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0' // VULN
const ok = new https.Agent({ rejectUnauthorized: true })
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '1'`,
  },
  {
    rule: 'js.cors-misconfiguration',
    name: 'reflected origin with credentials',
    code: `
app.use(cors({ origin: true, credentials: true })) // VULN
app.use(cors({ origin: ['https://app.example.com'], credentials: true }))
app.use(cors({ origin: true }))
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', req.headers.origin) // VULN
  res.setHeader('Access-Control-Allow-Credentials', 'true')
  next()
})
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', req.headers.origin)
  next()
})`,
  },
  {
    rule: 'js.cookie-insecure',
    name: 'secure false in cookie options',
    code: `
app.use(session({ secret: process.env.S, cookie: { secure: false } })) // VULN
res.cookie('sid', id, { secure: false }) // VULN
app.use(session({ secret: process.env.S, cookie: { secure: true } }))
const tls = { secure: false, host: 'smtp.example.com' }`,
  },
  {
    rule: 'js.cookie-without-httponly',
    name: 'httpOnly false',
    code: `
res.cookie('sid', id, { httpOnly: false }) // VULN
res.cookie('sid', id, { httpOnly: true })`,
  },
  {
    rule: 'js.hardcoded-session-secret',
    name: 'literal session secrets',
    code: `
app.use(session({ secret: 'keyboard cat' })) // VULN
app.use(cookieSession({ keys: ['k1-abc', 'k2-def'] })) // VULN
app.use(session({ secret: process.env.SESSION_SECRET }))`,
  },
  {
    rule: 'js.mass-assignment',
    name: 'whole request bodies into models',
    code: `
app.post('/u', async (req, res) => {
  await User.create(req.body) // VULN
  await user.update(req.body) // VULN
  Object.assign(user, req.body) // VULN
  const u = new User(req.body) // VULN
  await prisma.user.update({ where: { id }, data: req.body }) // VULN
  await User.create({ name: req.body.name, email: req.body.email })
  const opts = Object.assign({}, req.body)
  map.set('k', req.body)
})`,
  },
  {
    rule: 'js.prototype-pollution',
    name: 'deep merge of request data',
    code: `
const _ = require('lodash')
app.post('/cfg', (req, res) => {
  _.merge(settings, req.body) // SINK
  $.extend(true, defaults, req.query) // SINK
  _.merge(settings, defaults)
  $.extend(defaults, req.query)
})`,
  },
  {
    rule: 'js.regex-injection',
    name: 'user-controlled patterns',
    code: `
app.get('/search', (req, res) => {
  const re = new RegExp(req.query.q) // VULN
  const ok = new RegExp(escapeRegExp(req.query.q))
  const fixed = new RegExp('^[a-z]+$')
})`,
  },
  {
    rule: 'js.hardcoded-credential-check',
    name: 'literal password and admin-header comparisons',
    code: `
app.post('/admin', (req, res) => {
  if (req.body.password === 'Sup3rS3cret!') grant() // VULN
  if (req.headers['x-admin-key'] === 'letmein-2024') grant() // VULN
  if (req.body.password === '') deny()
  if (req.body.role === 'admin') grant()
  if (typeof password === 'string') check()
  if (req.headers['content-type'] === 'application/json') parse()
})`,
  },
]

describe.each(MODES)('JS/TS rules (%s mode)', (_mode, handle) => {
  it.each(CASES.map(c => [`${c.rule}: ${c.name}`, c] as const))('%s', async (_label, c) => {
    const path = c.path ?? 'src/server.ts'
    const signals = await sast({ [path]: c.code }, handle)
    expect(hits(signals, c.rule)).toEqual(expectedHits(c.code))
  })
})

describe.each(MODES)('JS signal details (%s mode)', (_mode, handle) => {
  it('reports the source, CWE, references and beginner-friendly text', async () => {
    const signals = await sast(
      {
        'src/a.ts':
          "app.get('/x', (req, res) => {\n  exec('ping ' + req.query.host)\n})\nconst { exec } = require('child_process')\n",
      },
      handle,
    )
    const [s] = ofRule(signals, 'js.command-injection')
    expect(s).toMatchObject({
      analyzer: 'sast',
      kind: 'vulnerability',
      severity: 'critical',
      confidence: 'high',
      cwe: 'CWE-78',
      category: 'command-execution',
      location: { path: 'src/a.ts', startLine: 2, endLine: 2 },
    })
    expect(s?.message).toContain('`req.query.host`')
    expect(s?.recommendation).toMatch(/execFile/)
    expect(s?.references?.some(r => r.includes('cwe.mitre.org/data/definitions/78'))).toBe(true)
    expect(s?.snippet).toBe("  exec('ping ' + req.query.host)")
  })

  it('marks aliased taint as medium confidence and direct taint as high', async () => {
    const signals = await sast(
      {
        'src/a.ts': [
          "app.get('/u/:id', async (req, res) => {",
          '  const { id } = req.params',
          "  await db.query('SELECT * FROM t WHERE id = ' + id)",
          "  await db.query('SELECT * FROM t WHERE id = ' + req.params.id)",
          '})',
        ].join('\n'),
      },
      handle,
    )
    expect(ofRule(signals, 'js.sql-injection').map(s => [s.location.startLine, s.confidence])).toEqual([
      [3, 'medium'],
      [4, 'high'],
    ])
  })

  it('does not let taint leak across functions or survive reassignment', async () => {
    const signals = await sast(
      {
        'src/a.ts': [
          "app.get('/a', (req, res) => { const id = req.query.id })",
          "function other(id) { return db.query('SELECT * FROM t WHERE id = ' + id) }",
          "app.get('/b', async (req, res) => {",
          '  let name = req.query.name',
          "  name = 'fixed'",
          "  await db.query('SELECT * FROM t WHERE name = ' + name)",
          '})',
        ].join('\n'),
      },
      handle,
    )
    // Line 2: unknown parameter → sink only. Line 6: `name` was reassigned to a constant → nothing.
    expect(hits(signals, 'js.sql-injection')).toEqual(['2 sink'])
  })

  it('treats process.argv as local input (sink, not vulnerability)', async () => {
    const signals = await sast(
      { 'bin/cli.js': "const { exec } = require('child_process')\nexec('ls ' + process.argv[2])\n" },
      handle,
    )
    expect(hits(signals, 'js.command-injection')).toEqual(['2 sink'])
    expect(ofRule(signals, 'js.command-injection')[0]?.message).toMatch(/command-line/)
  })

  it('recognizes Koa, Hono, Lambda and Next.js sources', async () => {
    const signals = await sast(
      {
        'src/koa.ts': "router.get('/k', async ctx => { await db.query('SELECT ' + ctx.query.col) })\n",
        'src/hono.ts': "app.get('/h', async c => { await db.query('SELECT ' + c.req.query('col')) })\n",
        'src/lambda.ts':
          "export const handler = async event => { await db.query('SELECT ' + event.queryStringParameters.col) }\n",
        'app/api/items/[id]/route.ts':
          "export async function GET(req, { params }) { return db.query('SELECT * FROM t WHERE id = ' + params.id) }\n",
      },
      handle,
    )
    expect(ofRule(signals, 'js.sql-injection').map(s => `${s.location.path} ${s.kind}`)).toEqual([
      'app/api/items/[id]/route.ts vulnerability',
      'src/hono.ts vulnerability',
      'src/koa.ts vulnerability',
      'src/lambda.ts vulnerability',
    ])
  })

  it('treats NestJS @Body()/@Query() parameters as user input', async () => {
    const signals = await sast(
      {
        'src/users.controller.ts': [
          "import { Body, Controller, Post, Query } from '@nestjs/common'",
          "@Controller('users')",
          'export class UsersController {',
          '  @Post()',
          '  create(@Body() dto: any, @Query() q: any, internal: string) {',
          "    this.db.query('SELECT * FROM t WHERE a = ' + dto.name)",
          "    this.db.query('SELECT * FROM t WHERE a = ' + internal)",
          '  }',
          '}',
        ].join('\n'),
      },
      handle,
    )
    expect(hits(signals, 'js.sql-injection')).toEqual(['6 vulnerability', '7 sink'])
  })
})

describe.each(MODES)('JS precision (%s mode)', (_mode, handle) => {
  it('does not mistake hashes, Sequelize updates or fs-extra calls for MongoDB queries', async () => {
    const code = `
import fs from 'fs-extra'
const crypto = require('crypto')
app.post('/a', async (req, res) => {
  crypto.createHash('sha256').update(req.body.password).digest('hex')
  crypto.createHmac('sha256', key).update(req.body.payload)
  await User.update(req.body, { where: { id: req.params.id } })
  await fs.remove(tmpDir)
  await users.updateOne(req.body.filter, { $set: { seen: true } }) // VULN
  await users.deleteMany(req.query) // VULN
})`
    expect(hits(await sast({ 'src/a.ts': code }, handle), 'js.nosql-injection')).toEqual(expectedHits(code))
  })

  it('matches secret names by whole words, not substrings, and ignores JSX keys', async () => {
    const code = `
const keyframes = Math.random()
const monkey = Math.random()
const cacheKey = Math.random()
const spinnerDelay = Math.random() * 300
const items = list.map(i => <Item key={Math.random()} {...i} data-id={i.id} />)
const sessionKey = Math.random() // SINK
const resetCode = Math.random() // VULN
const csrf_token = Math.random() // VULN`
    expect(hits(await sast({ 'src/a.tsx': code }, handle), 'js.insecure-random')).toEqual(expectedHits(code))
  })

  it('treats escaped template parts and constant ternaries as safe', async () => {
    const code = `
function render(el, user, order) {
  el.innerHTML = \`<b>\${escapeHtml(user.name)}</b> <i>\${LABEL}</i>\`
  el.innerHTML = '<b>' + DOMPurify.sanitize(user.bio) + '</b>'
  el.innerHTML = \`<b>\${user.name}</b>\` // SINK
  return db.query(\`SELECT * FROM t ORDER BY \${order === 'asc' ? 'ASC' : 'DESC'}\`)
}`
    const signals = await sast({ 'src/a.js': code }, handle)
    expect(hits(signals, 'js.xss')).toEqual(expectedHits(code))
    expect(hits(signals, 'js.sql-injection')).toEqual([])
  })

  it('reads sources out of destructured request objects', async () => {
    const code = `
app.post('/a', async (req, res) => {
  const { body, query: { q }, method, user } = req
  await User.create(body) // VULN
  await db.query('SELECT * FROM t WHERE q = ' + q) // VULN
  await db.query('SELECT * FROM t WHERE m = ' + method) // SINK
  await db.query('SELECT * FROM t WHERE u = ' + user.id) // SINK
})`
    const signals = await sast({ 'src/a.js': code }, handle)
    expect([...hits(signals, 'js.mass-assignment'), ...hits(signals, 'js.sql-injection')].sort()).toEqual(
      expectedHits(code).sort(),
    )
    expect(ofRule(signals, 'js.mass-assignment')[0]?.confidence).toBe('medium')
  })

  it('downgrades SSRF to a review hint when an allow-list check is visible', async () => {
    const code = `
app.get('/proxy', async (req, res) => {
  if (!ALLOWED_HOSTS.includes(new URL(req.query.url).hostname)) return res.sendStatus(400)
  await fetch(req.query.url) // SINK
})
app.get('/open', async (req, res) => {
  await fetch(req.query.url) // VULN
})`
    expect(hits(await sast({ 'src/a.js': code }, handle), 'js.ssrf')).toEqual(expectedHits(code))
  })

  it('flags CORS callbacks that accept every origin with credentials', async () => {
    const code = `
app.use(cors({ origin: (origin, cb) => cb(null, true), credentials: true })) // VULN
app.use(cors({ origin: (origin, callback) => callback(null, origin), credentials: true })) // VULN
app.use(cors({ origin: (o, cb) => cb(null, ALLOWED.includes(o)), credentials: true }))
app.use(cors({ origin: '*', credentials: true })) // VULN`
    const signals = await sast({ 'src/a.js': code }, handle)
    expect(hits(signals, 'js.cors-misconfiguration')).toEqual(expectedHits(code))
    expect(ofRule(signals, 'js.cors-misconfiguration').map(s => s.severity)).toEqual(['medium', 'medium', 'low'])
  })

  it('follows bindings from await import() and string algorithms', async () => {
    const code = `
const { execSync } = await import('node:child_process')
app.get('/x', (req, res) => execSync(\`ls \${req.query.d}\`)) // VULN`
    expect(hits(await sast({ 'src/a.mjs': code }, handle), 'js.command-injection')).toEqual(expectedHits(code))
    const jwt = "jwt.verify(t, k, { algorithms: 'none' })\n"
    expect(hits(await sast({ 'src/b.js': jwt }, handle), 'js.jwt-none-algorithm')).toEqual(['1 vulnerability'])
  })
})

describe.each(MODES)('template files (%s mode)', (_mode, handle) => {
  it('flags unescaped output in EJS, Handlebars, Pug, Vue and Svelte only', async () => {
    const signals = await sast(
      {
        'views/a.ejs': '<p><%= user.name %></p>\n<div><%- user.bio %></div>\n<%- include("footer") %>\n',
        'views/b.hbs': '<p>{{name}}</p>\n<div>{{{bio}}}</div>\n',
        'views/c.pug': 'p= name\ndiv!= bio\np #{safe}\n',
        'src/C.vue': '<template>\n  <p>{{ name }}</p>\n  <div v-html="bio"></div>\n</template>\n',
        'src/D.svelte': '<p>{name}</p>\n{@html bio}\n',
      },
      handle,
    )
    expect(
      ofRule(signals, 'js.template-unescaped-output').map(s => `${s.location.path}:${s.location.startLine}`),
    ).toEqual(['src/C.vue:3', 'src/D.svelte:2', 'views/a.ejs:2', 'views/b.hbs:2', 'views/c.pug:2'])
  })
})
