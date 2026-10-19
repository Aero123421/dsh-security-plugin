import { describe, expect, it } from 'vitest'
import { expectedHits, hits, MODES, PY_MODES, sast } from './sast-helpers.ts'

/**
 * Sinks and sources of common libraries. Lines marked `VULN`/`SINK` must be reported for the rule; unmarked
 * lines must not.
 */
interface Case {
  readonly rule: string
  readonly name: string
  readonly path: string
  readonly code: string
}

const JS_CASES: readonly Case[] = [
  {
    rule: 'js.sql-injection',
    name: 'postgres.js sql.unsafe() runs raw SQL; its tagged template does not',
    path: 'app/users/[id]/page.tsx',
    code: `import { sql } from '@/lib/db'
export default async function UserPage({ params }) {
  const rows = await sql.unsafe(\`SELECT * FROM users WHERE id = \${params.id}\`) // VULN
  const safe = await sql\`SELECT * FROM users WHERE id = \${params.id}\`
  const all = await sql.unsafe('SELECT * FROM users')
  return [rows, safe, all]
}`,
  },
  {
    rule: 'js.ssrf',
    name: 'NestJS HttpService injected into a controller',
    path: 'src/users/users.controller.ts',
    code: `import { Body, Controller, Post } from '@nestjs/common'
import { HttpService } from '@nestjs/axios'
@Controller('users')
export class UsersController {
  constructor(private readonly http: HttpService, private readonly cache: CacheService) {}
  @Post('import')
  async importFrom(@Body() dto: ImportDto) {
    const { data } = await this.http.axiosRef.get(dto.url) // VULN
    await this.http.post(dto.callback, data) // VULN
    await this.cache.get(dto.url)
    return this.http.get('https://api.example.com/status')
  }
}`,
  },
  {
    rule: 'js.xss',
    name: 'Koa answers an HTML-looking string body as HTML',
    path: 'src/koa-app.js',
    code: `router.get('/greet', async ctx => {
  ctx.type = 'html'
  ctx.body = \`<p>Hello \${ctx.query.name}</p>\` // VULN
})
router.get('/hello', async ctx => {
  ctx.body = '<h1>' + ctx.query.name + '</h1>' // VULN
})
router.get('/plain', async ctx => {
  ctx.body = \`Hello \${ctx.query.name}\`
})
router.get('/json', async ctx => {
  ctx.type = 'json'
  ctx.body = \`<p>\${ctx.query.name}</p>\`
})
router.get('/obj', async ctx => {
  ctx.body = { name: ctx.query.name }
})
router.get('/escaped', async ctx => {
  ctx.body = \`<p>\${escapeHtml(ctx.query.name)}</p>\`
})`,
  },
  {
    rule: 'js.xxe',
    name: 'libxmljs with noent substitutes external entities',
    path: 'src/routes/files.js',
    code: `const libxmljs = require('libxmljs')
router.post('/import', (req, res) => {
  const doc = libxmljs.parseXml(req.body, { noent: true, dtdload: true }) // VULN
  const plain = libxmljs.parseXml(req.body)
  const off = libxmljs.parseXml(req.body, { noent: false })
  res.json({ root: doc.root().name(), plain, off })
})
function load(xml) {
  return libxmljs.parseXmlString(xml, { noent: true }) // SINK
}
const fixed = libxmljs.parseXml('<a/>', { noent: true })`,
  },
  {
    rule: 'js.sql-injection',
    name: 'GraphQL resolver arguments and NestJS @Args() are client input',
    path: 'src/graphql/resolvers.ts',
    code: `export const resolvers = {
  Query: {
    user: async (_parent, { id }) => db.query(\`SELECT * FROM users WHERE id = '\${id}'\`), // VULN
    search(_parent, args) {
      return db.query(\`SELECT * FROM posts WHERE title LIKE '%\${args.q}%'\`) // VULN
    },
  },
}
const helpers = {
  format: (row, opts) => db.query(\`SELECT * FROM t WHERE x = '\${opts.x}'\`), // SINK
}
@Resolver()
export class UsersResolver {
  @Query(() => User)
  byName(@Args('name') name: string) {
    return this.dataSource.query(\`SELECT * FROM users WHERE name = '\${name}'\`) // VULN
  }
}`,
  },
  {
    rule: 'js.sql-injection',
    name: 'a tRPC procedure input is client input when its schema admits text',
    path: 'src/server/routers/users.ts',
    code: `export const usersRouter = router({
  byName: publicProcedure.input(z.object({ name: z.string() })).query(({ input }) => {
    return db.query(\`SELECT * FROM users WHERE name = '\${input.name}'\`) // VULN
  }),
  byId: publicProcedure.input(z.object({ id: z.number() })).query(({ input }) => {
    return db.query(\`SELECT * FROM users WHERE id = \${input.id}\`) // SINK
  }),
})`,
  },
]

const PY_CASES: readonly Case[] = [
  {
    rule: 'py.sql-injection',
    name: 'asyncpg and databases run SQL text through fetch methods',
    path: 'app/routers/items.py',
    code: `from fastapi import APIRouter, Depends
router = APIRouter()

@router.get("/owner/{owner}")
async def by_owner(owner: str, pool=Depends(get_pool)):
    async with pool.acquire() as conn:
        rows = await conn.fetch(f"SELECT * FROM items WHERE owner = '{owner}'")  # VULN
        one = await conn.fetchrow("SELECT * FROM items WHERE owner = $1", owner)
        return await database.fetch_all(query=f"SELECT * FROM items WHERE tag = '{owner}'")  # VULN

@router.get("/proxy")
async def proxy(url: str):
    return await http_client.fetch(f"https://api.example.com/items?url={url}")
`,
  },
  {
    rule: 'py.path-traversal',
    name: 'werkzeug uploads saved under their own name, and uploaded tar archives',
    path: 'app/views/files.py',
    code: `import os, tarfile, zipfile
from flask import Blueprint, request
from werkzeug.utils import secure_filename
bp = Blueprint("files", __name__)
UPLOAD_DIR = "/srv/uploads"
EXTRACT_DIR = "/srv/extract"

@bp.route("/upload", methods=["POST"])
def upload():
    f = request.files["file"]
    f.save(os.path.join(UPLOAD_DIR, secure_filename(f.filename)))
    return "ok"

@bp.route("/upload-raw", methods=["POST"])
def upload_raw():
    f = request.files["file"]
    f.save(os.path.join(UPLOAD_DIR, f.filename))  # VULN
    return "ok"

@bp.route("/extract", methods=["POST"])
def extract():
    archive = tarfile.open(fileobj=request.files["archive"].stream)
    archive.extractall(EXTRACT_DIR)  # VULN
    return "ok"

@bp.route("/extract-with", methods=["POST"])
def extract_with():
    with tarfile.open(fileobj=request.files["archive"].stream, mode="r:gz") as tar:
        tar.extractall(EXTRACT_DIR)  # VULN
    return "ok"

@bp.route("/extract-safe", methods=["POST"])
def extract_safe():
    with tarfile.open(fileobj=request.files["archive"].stream) as tar:
        tar.extractall(EXTRACT_DIR, filter="data")
    return "ok"

def unpack_release(path):
    tarfile.open(path).extractall("/opt/app")

@bp.route("/unzip", methods=["POST"])
def unzip():
    with zipfile.ZipFile(request.files["archive"].stream) as zf:
        zf.extractall(EXTRACT_DIR)
    return "ok"
`,
  },
  {
    rule: 'py.reflected-xss',
    name: 'Flask views and make_response send HTML strings',
    path: 'app/views/web.py',
    code: `from flask import Blueprint, request, make_response
from markupsafe import Markup, escape
bp = Blueprint("web", __name__)

@bp.route("/greet")
def greet():
    return f"<p>Search results for {request.args.get('q')}</p>"  # VULN

@bp.route("/banner")
def banner():
    resp = make_response("<h2>" + request.args.get("title", "") + "</h2>")  # VULN
    return resp

@bp.route("/safe")
def safe():
    return f"<p>Search results for {escape(request.args.get('q'))}</p>"

@bp.route("/text")
def text():
    return f"<p>{request.args.get('q')}</p>", 200, {"Content-Type": "text/plain"}

@bp.route("/echo")
def echo():
    return request.args.get("q", "")

@bp.route("/count")
def count():
    return f"<p>{len(request.args)}</p>"

@bp.route("/markup")
def markup():
    return Markup("<p>{}</p>").format(request.args["q"])

def helper():
    return f"<p>{request.args.get('q')}</p>"
`,
  },
  {
    rule: 'py.reflected-xss',
    name: 'Django HttpResponse and FastAPI HTMLResponse',
    path: 'shop/views.py',
    code: `from django.http import HttpResponse, JsonResponse
from fastapi.responses import HTMLResponse

def hello(request):
    return HttpResponse("<h1>Hello %s</h1>" % request.GET.get("name", "guest"))  # VULN

def plain(request):
    return HttpResponse("<h1>Hello %s</h1>" % request.GET.get("name"), content_type="text/plain")

def data(request):
    return JsonResponse({"name": request.GET.get("name")})

@app.get("/hi")
def hi(name: str):
    return HTMLResponse(f"<b>{name}</b>")  # VULN
`,
  },
  {
    rule: 'py.cors-misconfiguration',
    name: 'Starlette/FastAPI CORSMiddleware reflecting any origin with credentials',
    path: 'app/main.py',
    code: `from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"])  # VULN
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"])
app.add_middleware(CORSMiddleware, allow_origins=["https://app.example.com"], allow_credentials=True)
app.add_middleware(CORSMiddleware, allow_origin_regex=".*", allow_credentials=True)  # VULN
app.add_middleware(CORSMiddleware, allow_origin_regex=r"https://.*\\.example\\.com", allow_credentials=True)
`,
  },
  {
    rule: 'py.cors-misconfiguration',
    name: 'Flask-CORS with credentials and no origin list',
    path: 'app/__init__.py',
    code: `from flask import Flask
from flask_cors import CORS
app = Flask(__name__)
CORS(app, supports_credentials=True)  # VULN
CORS(app, supports_credentials=True, origins=["https://app.example.com"])
CORS(app, resources={r"/api/*": {"origins": "*"}}, supports_credentials=True)  # VULN
CORS(app, resources={r"/api/*": {"origins": ["https://app.example.com"]}}, supports_credentials=True)
CORS(app)
`,
  },
  {
    rule: 'py.cors-misconfiguration',
    name: 'django-cors-headers allowing every origin with credentials',
    path: 'mysite/settings.py',
    code: `INSTALLED_APPS = ["corsheaders", "django.contrib.auth"]
CORS_ALLOW_ALL_ORIGINS = True  # VULN
CORS_ALLOW_CREDENTIALS = True
`,
  },
  {
    rule: 'py.template-injection',
    name: 'Jinja2 Environment.from_string compiles a template',
    path: 'app/views/render.py',
    code: `from jinja2 import Environment, sandbox
from flask import request, current_app
env = Environment()
sandboxed = sandbox.SandboxedEnvironment()

@app.route("/render")
def render():
    tpl = env.from_string(request.args["t"])  # VULN
    safe = sandboxed.from_string(request.args["t"])
    flask_tpl = current_app.jinja_env.from_string(request.args["t"])  # VULN
    fixed = env.from_string("Hello {{ name }}")
    return tpl.render()
`,
  },
  {
    rule: 'py.xxe',
    name: 'lxml parsers created with resolve_entities=True',
    path: 'app/views/xml.py',
    code: `from lxml import etree
from flask import request
parser = etree.XMLParser(resolve_entities=True)
safe_parser = etree.XMLParser(resolve_entities=False, no_network=True)

@app.route("/xml", methods=["POST"])
def xml():
    doc = etree.fromstring(request.data, parser)  # VULN
    ok = etree.fromstring(request.data, safe_parser)
    plain = etree.fromstring(request.data)
    return "ok"

def load(text):
    return etree.fromstring(text, parser=parser)  # SINK
`,
  },
]

describe.each(MODES)('JavaScript library sinks and sources (%s mode)', (_mode, handle) => {
  it.each(JS_CASES)('$rule: $name', async ({ rule, path, code }) => {
    const signals = await sast({ [path]: code }, handle)
    expect(hits(signals, rule)).toEqual(expectedHits(code))
  })
})

describe.each(PY_MODES)('Python library sinks and sources (%s mode)', (_mode, handle) => {
  it.each(PY_CASES)('$rule: $name', async ({ rule, path, code }) => {
    const signals = await sast({ [path]: code }, handle)
    expect(hits(signals, rule)).toEqual(expectedHits(code))
  })
})
