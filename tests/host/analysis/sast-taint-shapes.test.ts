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
