import { describe, expect, it } from 'vitest'
import { expectedHits, hits, MODES, PY_MODES, sast } from './sast-helpers.ts'

/**
 * How request data flows through ordinary expression shapes. Each case runs in both engines; lines marked
 * `VULN`/`SINK` must be reported for the rule, unmarked lines must not.
 */
interface Case {
  readonly rule: string
  readonly name: string
  readonly path?: string
  readonly code: string
}

const JS_CASES: readonly Case[] = [
  {
    rule: 'js.path-traversal',
    name: 'path helpers imported by name keep the taint of their arguments',
    path: 'src/server.ts',
    code: `import express from 'express'
import { join, resolve } from 'node:path'
import * as p from 'path'
import { readFile } from 'node:fs/promises'
const app = express()
app.get('/a', async (req, res) => { res.send(await readFile(join('/srv', req.query.f as string))) }) // VULN
app.get('/b', async (req, res) => { const target = resolve('/srv', String(req.query.f)); res.send(await readFile(target)) }) // VULN
app.get('/c', async (req, res) => { res.send(await readFile(p.join('/srv', req.params.name))) }) // VULN
app.get('/d', async (req, res) => { res.send(await readFile(join('/srv', 'static', 'index.html'))) })
`,
  },
  {
    rule: 'js.path-traversal',
    name: 'Fastify route reading a joined request parameter',
    path: 'src/fastify-app.ts',
    code: `import Fastify from 'fastify'
import { readFile } from 'node:fs/promises'
import { join } from 'node:path'
const fastify = Fastify()
fastify.get('/files/:name', async (request, reply) => {
  const data = await readFile(join('/srv/files', request.params.name)) // VULN
  return reply.send(data)
})
`,
  },
  {
    rule: 'js.path-traversal',
    name: 'NestJS controller sending a joined route parameter',
    path: 'src/users/users.controller.ts',
    code: `import { Controller, Get, Param, Res } from '@nestjs/common'
import type { Response } from 'express'
import { join } from 'path'
@Controller('users')
export class UsersController {
  @Get('avatar/:file')
  avatar(@Param('file') file: string, @Res() res: Response) {
    return res.sendFile(join(process.cwd(), 'uploads', file)) // VULN
  }
}
`,
  },
  {
    rule: 'js.sql-injection',
    name: 'destructuring defaults do not make request values constant',
    code: `app.get('/d1', async (req, res) => { const { name: userName } = req.query; res.json(await db.query(\`SELECT \${userName}\`)) }) // VULN
app.get('/d2', async (req, res) => { const { name = 'x' } = req.query; res.json(await db.query(\`SELECT \${name}\`)) }) // VULN
app.get('/d3', async (req, res) => { const { name: userName = 'x' } = req.query; res.json(await db.query(\`SELECT \${userName}\`)) }) // VULN
app.get('/d4', async (req, res) => { const { name, limit = 10 } = req.query; res.json(await db.query(\`SELECT \${limit}\`)) }) // VULN
app.get('/d5', async (req, res) => {
  let sort
  ;({ sort = 'id' } = req.query)
  res.json(await db.query(\`SELECT * FROM t ORDER BY \${sort}\`)) // VULN
})
app.get('/d6', async (req, res) => {
  const { filters: { status = 'open' } = {} } = req.body
  res.json(await db.query(\`SELECT * FROM t WHERE status = '\${status}'\`)) // VULN
})
app.get('/d7', async (req, res) => {
  let { sort = 'id' } = req.query
  sort = 'name'
  res.json(await db.query(\`SELECT * FROM t ORDER BY \${sort}\`))
})
`,
  },
  {
    rule: 'js.xss',
    name: 'a conditional reflects only its branches, not its condition',
    code: `app.get('/a', (req, res) => {
  res.send(req.query.callback ? 'ok' : 'missing')
  res.send(\`<p>\${req.query.debug ? 'on' : 'off'}</p>\`)
  res.send(req.query.flag ? req.query.name : 'anonymous') // VULN
})`,
  },
  {
    rule: 'js.xss',
    name: 'numbers and booleans derived from input are not reflected text',
    code: `app.post('/cart', (req, res) => {
  res.send(\`Added \${req.body.items.length} items to your cart\`)
  res.send(\`Match: \${req.query.q === 'all'}\`)
  res.send('<b>' + req.query.n * 2 + '</b>')
  res.send(\`Found \${req.body.tags.includes('x')}\`)
  res.send(\`Hello \${req.body.name}\`) // VULN
  res.send('<b>' + req.query.n + '</b>') // VULN
})`,
  },
  {
    rule: 'js.sql-injection',
    name: 'arrays mapped to numbers are not injectable text',
    code: `router.post('/bulk', async (req, res) => {
  const ids = req.body.ids.map(Number)
  await pool.query(\`SELECT id FROM users WHERE id IN (\${ids.join(',')})\`) // SINK
  const parsed = req.body.ids.map(id => parseInt(id, 10))
  await pool.query(\`SELECT id FROM users WHERE id IN (\${parsed.join(',')})\`) // SINK
  const names = req.body.names.map(n => n.trim())
  await pool.query(\`SELECT id FROM users WHERE name IN ('\${names.join("','")}')\`) // VULN
})`,
  },
  {
    rule: 'js.path-traversal',
    name: 'a value restricted to an allow-list by a conditional is not attacker-chosen',
    code: `const fs = require('fs')
const path = require('path')
const LOCALES = path.join(__dirname, 'locales')
const SUPPORTED = new Set(['en', 'ja'])
router.get('/locale', (req, res) => {
  const lang = ['en', 'ja', 'zh'].includes(req.query.lang) ? req.query.lang : 'en'
  fs.readFile(path.join(LOCALES, \`\${lang}.json\`), 'utf8', cb) // SINK
  const other = SUPPORTED.has(req.query.lang) ? req.query.lang : 'en'
  fs.readFile(path.join(LOCALES, \`\${other}.json\`), 'utf8', cb) // SINK
  const inverted = !SUPPORTED.has(req.query.lang) ? 'en' : req.query.lang
  fs.readFile(path.join(LOCALES, \`\${inverted}.json\`), 'utf8', cb) // SINK
  const equal = req.query.lang === 'ja' || req.query.lang === 'zh' ? req.query.lang : 'en'
  fs.readFile(path.join(LOCALES, \`\${equal}.json\`), 'utf8', cb) // SINK
  const fallback = req.query.lang ? req.query.lang : 'en'
  fs.readFile(path.join(LOCALES, \`\${fallback}.json\`), 'utf8', cb) // VULN
  const wrong = SUPPORTED.has(req.query.lang) ? req.query.other : 'en'
  fs.readFile(path.join(LOCALES, \`\${wrong}.json\`), 'utf8', cb) // VULN
})`,
  },
  {
    rule: 'js.command-injection',
    name: 'an anchored allow-list regex with an early exit keeps shell syntax out',
    code: `const cp = require('child_process')
const SAFE_REF = /^[\\w./-]+$/
router.post('/checkout', (req, res) => {
  const branch = String(req.body.branch)
  if (!/^[\\w.-]+$/.test(branch)) return res.status(400).json({ error: 'bad branch' })
  cp.exec(\`git -C /srv/repo checkout \${branch}\`, cb) // SINK
})
router.post('/tag', (req, res) => {
  if (!SAFE_REF.test(req.body.tag)) {
    res.status(400).end()
    return
  }
  cp.exec('git tag ' + req.body.tag, cb) // SINK
})
router.post('/positive', (req, res) => {
  const branch = String(req.body.branch)
  if (/^[\\w.-]+$/.test(branch)) {
    cp.exec(\`git checkout \${branch}\`, cb) // SINK
  }
  cp.exec(\`git log \${branch}\`, cb) // VULN
})
router.post('/spaces', (req, res) => {
  const branch = String(req.body.branch)
  if (!/^[\\w .;-]+$/.test(branch)) return res.status(400).end()
  cp.exec(\`git checkout \${branch}\`, cb) // VULN
})
router.post('/no-exit', (req, res) => {
  const branch = String(req.body.branch)
  if (!/^[\\w.-]+$/.test(branch)) console.warn('odd branch')
  cp.exec(\`git checkout \${branch}\`, cb) // VULN
})
router.post('/unanchored', (req, res) => {
  const branch = String(req.body.branch)
  if (!/[\\w.-]+/.test(branch)) return res.status(400).end()
  cp.exec(\`git checkout \${branch}\`, cb) // VULN
})
router.post('/reassigned', (req, res) => {
  let branch = String(req.body.branch)
  if (!/^[\\w.-]+$/.test(branch)) return res.status(400).end()
  branch = req.body.other
  cp.exec(\`git checkout \${branch}\`, cb) // VULN
})
router.post('/mixed', (req, res) => {
  const branch = String(req.body.branch)
  if (!/^[\\w.-]+$/.test(branch)) return res.status(400).end()
  cp.exec(\`git checkout \${branch} \${req.body.extra}\`, cb) // VULN
})`,
  },
  {
    rule: 'js.path-traversal',
    name: 'an allow-list regex without separators confines the file name',
    code: `const fs = require('fs')
const path = require('path')
router.get('/a', (req, res) => {
  if (!/^[\\w-]+$/.test(req.query.name)) return res.status(400).end()
  fs.readFile(path.join(DIR, req.query.name), cb) // SINK
})
router.get('/b', (req, res) => {
  if (!/^[\\w.-]+$/.test(req.query.name)) return res.status(400).end()
  fs.readFile(path.join(DIR, req.query.name), cb) // SINK
})
router.get('/c', (req, res) => {
  if (!/^[\\w./-]+$/.test(req.query.name)) return res.status(400).end()
  fs.readFile(path.join(DIR, req.query.name), cb) // VULN
})`,
  },
  {
    rule: 'js.cookie-without-httponly',
    name: 'preference cookies may be readable by scripts; session cookies may not',
    code: `router.post('/theme', (req, res) => {
  res.cookie('theme', String(req.body.theme), { httpOnly: false, sameSite: 'lax', secure: true })
  res.cookie('locale', 'ja', { httpOnly: false })
  res.cookie('sessionId', id, { httpOnly: false }) // VULN
  res.cookie(name, value, { httpOnly: false }) // VULN
  app.use(session({ cookie: { httpOnly: false } })) // VULN
})`,
  },
]

const PY_CASES: readonly Case[] = [
  {
    rule: 'py.path-traversal',
    name: 'os.path helpers imported by name keep the taint of their arguments',
    code: `from os.path import join
from flask import Flask, request, send_file
app = Flask(__name__)
@app.get("/f")
def f():
    return send_file(join("/srv", request.args["name"]))  # VULN
@app.get("/g")
def g():
    return send_file(join("/srv", "static", "index.html"))
`,
  },
  {
    rule: 'py.path-traversal',
    name: 'a value restricted to an allow-list by a conditional is not attacker-chosen',
    code: `import os
from flask import request
LOCALES = "/srv/locales"
@app.route("/locale")
def locale():
    lang = request.args.get("lang") if request.args.get("lang") in ("en", "ja") else "en"
    with open(os.path.join(LOCALES, f"{lang}.json")) as fh:  # SINK
        return fh.read()
@app.route("/other")
def other():
    lang = request.args.get("lang") if request.args.get("lang") else "en"
    with open(os.path.join(LOCALES, f"{lang}.json")) as fh:  # VULN
        return fh.read()
`,
  },
  {
    rule: 'py.command-injection',
    name: 'an anchored allow-list pattern with an early exit keeps shell syntax out',
    code: `import re
import subprocess
from flask import abort, request
SAFE = re.compile(r"[\\w.-]+")
@app.post("/checkout")
def checkout():
    branch = request.form["branch"]
    if not re.fullmatch(r"[\\w.-]+", branch):
        abort(400)
    subprocess.run(f"git -C /srv/repo checkout {branch}", shell=True, check=True)  # SINK
    return "ok"
@app.post("/match")
def match():
    branch = request.form["branch"]
    if not re.match(r"^[\\w.-]+$", branch):
        return "bad", 400
    subprocess.run(f"git checkout {branch}", shell=True)  # SINK
    return "ok"
@app.post("/compiled")
def compiled():
    branch = request.form["branch"]
    if not SAFE.fullmatch(branch): abort(400)
    subprocess.run(f"git checkout {branch}", shell=True)  # SINK
    return "ok"
@app.post("/digits")
def digits():
    pid = request.form["pid"]
    if not pid.isdigit():
        return "bad", 400
    subprocess.run(f"kill {pid}", shell=True)  # SINK
    return "ok"
@app.post("/search")
def search():
    branch = request.form["branch"]
    if not re.search(r"[\\w.-]+", branch):
        abort(400)
    subprocess.run(f"git checkout {branch}", shell=True)  # VULN
    return "ok"
@app.post("/no-exit")
def no_exit():
    branch = request.form["branch"]
    if not re.fullmatch(r"[\\w.-]+", branch):
        print("odd")
    subprocess.run(f"git checkout {branch}", shell=True)  # VULN
    return "ok"
`,
  },
  {
    rule: 'py.sql-injection',
    name: 'comprehension elements that all go through int() are not injectable text',
    code: `from flask import request
@app.route("/a")
def a():
    ids = request.args.getlist("id")
    return db.execute(f"SELECT * FROM t WHERE id IN ({','.join(str(int(i)) for i in ids)})")  # SINK
@app.route("/b")
def b():
    ids = [int(i) for i in request.args.getlist("id")]
    return db.execute("SELECT * FROM t WHERE id IN (%s)" % ",".join(str(i) for i in ids))  # SINK
@app.route("/c")
def c():
    names = [n.strip() for n in request.args.getlist("n")]
    return db.execute("SELECT * FROM t WHERE name IN ('%s')" % "','".join(names))  # VULN
@app.route("/d")
def d():
    count = len(request.args.getlist("id"))
    return db.execute(f"SELECT * FROM t LIMIT {count}")  # SINK
`,
  },
]

describe.each(MODES)('JavaScript taint through expression shapes (%s mode)', (_mode, handle) => {
  it.each(JS_CASES)('$rule: $name', async ({ rule, path, code }) => {
    const signals = await sast({ [path ?? 'src/server.js']: code }, handle)
    expect(hits(signals, rule)).toEqual(expectedHits(code))
  })
})

describe.each(PY_MODES)('Python taint through expression shapes (%s mode)', (_mode, handle) => {
  it.each(PY_CASES)('$rule: $name', async ({ rule, path, code }) => {
    const signals = await sast({ [path ?? 'app/views.py']: code }, handle)
    expect(hits(signals, rule)).toEqual(expectedHits(code))
  })
})
