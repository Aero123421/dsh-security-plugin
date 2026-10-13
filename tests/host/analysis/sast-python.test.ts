import { describe, expect, it } from 'vitest'
import { type AstGrepHandle, createAstGrepHandle } from '../../../src/host/analysis/astgrep.ts'
import { expectedHits, hits, ofRule, PY_MODES, sast } from './sast-helpers.ts'

interface Case {
  readonly rule: string
  readonly name: string
  readonly path?: string
  readonly code: string
}

const CASES: readonly Case[] = [
  {
    rule: 'py.sql-injection',
    name: 'f-strings, % formatting, concatenation and .format(); parameterized queries are safe',
    code: `
from flask import request
from sqlalchemy import text

@app.route('/u')
def users():
    name = request.args.get('name')
    cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")  # VULN
    cursor.execute("SELECT * FROM users WHERE name = '%s'" % request.args['n'])  # VULN
    cursor.execute("SELECT * FROM users WHERE name = '" + name + "'")  # VULN
    cursor.execute("SELECT * FROM users WHERE name = '{}'".format(name))  # VULN
    db.session.execute(text(f"SELECT * FROM t WHERE x = {request.form['x']}"))  # VULN
    User.objects.raw(f"SELECT * FROM auth_user WHERE name = '{name}'")  # VULN
    cursor.execute(f"SELECT * FROM t WHERE id = {compute()}")  # SINK
    cursor.execute("SELECT * FROM users WHERE name = %s", (name,))
    cursor.execute("SELECT * FROM users WHERE name = :n", {"n": name})
    db.session.execute(text("SELECT * FROM t WHERE x = :x"), {"x": name})
    cursor.execute(f"SELECT * FROM {TABLE}")
    return 'ok'
`,
  },
  {
    rule: 'py.sql-injection',
    name: 'FastAPI route parameters are user input; int-typed parameters are not',
    code: `
from fastapi import FastAPI, Query
app = FastAPI()

@app.get('/items/{item_id}')
async def read_item(item_id: str, n: int, q: str = Query(None)):
    cursor.execute(f"SELECT * FROM items WHERE id = '{item_id}'")  # VULN
    cursor.execute(f"SELECT * FROM items WHERE q = '{q}'")  # VULN
    cursor.execute(f"SELECT * FROM items LIMIT {n}")
    return {}

def helper(value):
    cursor.execute(f"SELECT * FROM t WHERE v = '{value}'")  # SINK
`,
  },
  {
    rule: 'py.command-injection',
    name: 'os.system and shell=True; argument lists without a shell are safe',
    code: `
import os, subprocess
from flask import request

@app.post('/run')
def run():
    os.system("ping -c1 " + request.form['host'])  # VULN
    os.popen(f"ls {request.args['d']}")  # VULN
    subprocess.run(f"tar xf {request.args['f']}", shell=True)  # VULN
    subprocess.call(["sh", "-c", request.args['cmd']])  # VULN
    subprocess.check_output(cmd_line, shell=True)  # SINK
    subprocess.run(["ls", request.args['d']])
    subprocess.run(["ls", "-la"], shell=False)
    os.system("make clean")
    return ''
`,
  },
  {
    rule: 'py.code-injection',
    name: 'eval, exec and compile',
    code: `
from flask import request

@app.post('/calc')
def calc():
    eval(request.form['expr'])  # VULN
    exec(request.json['code'])  # VULN
    exec(script_text)  # SINK
    eval("1 + 1")
    ast.literal_eval(request.form['expr'])
    return ''
`,
  },
  {
    rule: 'py.insecure-deserialization',
    name: 'pickle, marshal, unsafe yaml.load and jsonpickle',
    code: `
import pickle, yaml, marshal, jsonpickle
from flask import request

@app.post('/load')
def load():
    pickle.loads(request.data)  # VULN
    yaml.load(request.data)  # VULN
    jsonpickle.decode(request.form['state'])  # VULN
    marshal.loads(blob)  # SINK
    pickle.load(open('cache.pkl', 'rb'))  # SINK
    yaml.load(request.data, Loader=yaml.SafeLoader)
    yaml.safe_load(request.data)
    json.loads(request.data)
    return ''
`,
  },
  {
    rule: 'py.path-traversal',
    name: 'open/send_file with request paths; secure_filename and basename sanitize',
    code: `
import os
from flask import request, send_file, send_from_directory
from werkzeug.utils import secure_filename

@app.get('/f')
def files():
    open(os.path.join('/srv/files', request.args['f'])).read()  # VULN
    send_file(request.args['path'])  # VULN
    open(os.path.join('/srv/files', secure_filename(request.args['f'])))
    open(os.path.join('/srv/files', os.path.basename(request.args['f'])))
    send_from_directory('/srv/files', request.args['f'])
    open('/etc/app.conf')
    return ''
`,
  },
  {
    rule: 'py.ssrf',
    name: 'requests/httpx/urllib with request URLs',
    code: `
import requests, httpx, urllib.request
from flask import request

@app.post('/fetch')
def fetch():
    requests.get(request.json['url'])  # VULN
    httpx.post(request.args.get('callback'), json={})  # VULN
    urllib.request.urlopen(request.form['u'])  # VULN
    requests.get(f"https://api.example.com/items/{request.args['id']}")  # SINK
    requests.get('https://api.example.com/health')
    return ''
`,
  },
  {
    rule: 'py.template-injection',
    name: 'render_template_string and Template from request data',
    code: `
from flask import request, render_template_string
from jinja2 import Template

@app.get('/t')
def t():
    render_template_string(request.args['tpl'])  # VULN
    Template(request.form['body']).render()  # VULN
    render_template_string(page_source)  # SINK
    render_template_string('<p>{{ name }}</p>', name=request.args['name'])
    return ''
`,
  },
  {
    rule: 'py.xss',
    name: 'Markup/mark_safe on dynamic values',
    code: `
from flask import request
from markupsafe import Markup
from django.utils.safestring import mark_safe

@app.get('/b')
def bio():
    Markup(request.args['bio'])  # VULN
    mark_safe(user.bio)  # SINK
    mark_safe('<br>')
    Markup(bleach.clean(request.args['bio']))
    return ''
`,
  },
  {
    rule: 'py.open-redirect',
    name: 'redirect to request URLs',
    code: `
from flask import request, redirect

@app.get('/login')
def login():
    return redirect(request.args.get('next'))  # VULN

@app.get('/logout')
def logout():
    return redirect('/login')
`,
  },
  {
    rule: 'py.debug-enabled',
    name: 'Flask app.run(debug=True)',
    code: `
app = Flask(__name__)
if __name__ == '__main__':
    app.run(debug=True)  # VULN
    app.run(debug=False)
`,
  },
  {
    rule: 'py.tls-verification-disabled',
    name: 'verify=False',
    code: `
import requests
requests.get('https://internal', verify=False)  # VULN
requests.get('https://internal', verify='/etc/ca.pem')
`,
  },
  {
    rule: 'py.jwt-unverified',
    name: 'signature verification disabled or none algorithm',
    code: `
import jwt
jwt.decode(token, options={"verify_signature": False})  # VULN
jwt.decode(token, key, algorithms=["none"])  # VULN
jwt.decode(token, key, algorithms=["HS256"])
`,
  },
  {
    rule: 'py.weak-password-hash',
    name: 'md5/sha1 of passwords only',
    code: `
import hashlib
digest = hashlib.md5(password.encode()).hexdigest()  # VULN
etag = hashlib.sha1(body).hexdigest()
digest2 = hashlib.sha256(password.encode()).hexdigest()
`,
  },
  {
    rule: 'py.insecure-random',
    name: 'random for tokens',
    code: `
import random
reset_token = ''.join(random.choice(ALPHABET) for _ in range(32))  # VULN
otp = random.randint(100000, 999999)  # VULN
session_key = random.random()  # SINK
delay = random.uniform(0.1, 0.5)
`,
  },
  {
    rule: 'py.mass-assignment',
    name: 'request data expanded into models',
    code: `
from flask import request

@app.post('/u')
def create():
    User(**request.json)  # VULN
    User.objects.create(**request.POST.dict())  # VULN
    data = request.get_json()
    Item(**data)  # VULN
    User(name=request.json['name'])
    return ''
`,
  },
  {
    rule: 'py.hardcoded-credential-check',
    name: 'literal password and header comparisons',
    code: `
from flask import request

@app.post('/admin')
def admin():
    if request.form['password'] == 'Adm1n-P@ss':  # VULN
        pass
    if request.headers.get('X-Admin-Token') == 'backdoor-123':  # VULN
        pass
    if request.form['role'] == 'admin':
        pass
    return ''
`,
  },
]

describe.each(PY_MODES)('Python rules (%s mode)', (_mode, handle) => {
  it.each(CASES.map(c => [`${c.rule}: ${c.name}`, c] as const))('%s', async (_label, c) => {
    const signals = await sast({ [c.path ?? 'app/views.py']: c.code }, handle)
    expect(hits(signals, c.rule)).toEqual(expectedHits(c.code))
  })
})

describe.each(PY_MODES)('Django settings (%s mode)', (_mode, handle) => {
  const settings = [
    "INSTALLED_APPS = ['django.contrib.admin']",
    'DEBUG = True',
    "ALLOWED_HOSTS = ['*']",
    "SECRET_KEY = 'k3j4h5-kj34h5kj3h45-kj3h45k3j4'",
  ].join('\n')

  it('flags DEBUG, ALLOWED_HOSTS and a hard-coded SECRET_KEY', async () => {
    const signals = await sast({ 'mysite/settings.py': settings }, handle)
    expect(signals.map(s => `${s.ruleId} ${s.location.startLine} ${s.severity}`)).toEqual([
      'py.debug-enabled 2 medium',
      'py.allowed-hosts-wildcard 3 low',
      'py.hardcoded-secret-key 4 high',
    ])
    const key = ofRule(signals, 'py.hardcoded-secret-key')[0]!
    expect(key.snippet).toBe('SECRET_KEY = ***')
    expect(key.fingerprintParts.join(' ')).not.toContain('kj34h5')
  })

  it('lowers severity for development settings', async () => {
    const signals = await sast({ 'mysite/settings/dev.py': settings }, handle)
    expect(ofRule(signals, 'py.debug-enabled')[0]?.severity).toBe('low')
    expect(ofRule(signals, 'py.hardcoded-secret-key')[0]?.severity).toBe('low')
  })

  it('ignores environment-driven settings and placeholders', async () => {
    const signals = await sast(
      {
        'mysite/settings.py': [
          "INSTALLED_APPS = ['django.contrib.admin']",
          "DEBUG = os.environ.get('DEBUG') == '1'",
          "ALLOWED_HOSTS = ['example.com']",
          "SECRET_KEY = os.environ['SECRET_KEY']",
          "OTHER_SECRET_KEY = 'changeme'",
        ].join('\n'),
        'app.py': "app.config['SECRET_KEY'] = 'changeme'\n",
      },
      handle,
    )
    expect(signals).toEqual([])
  })

  it('flags Flask SECRET_KEY literals and env fallbacks', async () => {
    const signals = await sast(
      {
        'app.py': [
          "app.config['SECRET_KEY'] = 'a8f5f167f44f4964e6c998dee827110c'",
          "app.secret_key = os.environ.get('SECRET_KEY', 'super-secret-fallback-value')",
        ].join('\n'),
      },
      handle,
    )
    expect(hits(signals, 'py.hardcoded-secret-key')).toEqual(['1 vulnerability', '2 vulnerability'])
  })
})

describe.each(PY_MODES)('Python taint details (%s mode)', (_mode, handle) => {
  it('treats sys.argv and input() as local input', async () => {
    const signals = await sast({ 'tools/run.py': 'import os, sys\nos.system("ls " + sys.argv[1])\n' }, handle)
    expect(hits(signals, 'py.command-injection')).toEqual(['2 sink'])
  })

  it('treats Django function-view parameters as URL input', async () => {
    const signals = await sast(
      {
        'shop/views.py': 'def detail(request, slug):\n    cursor.execute(f"SELECT * FROM p WHERE slug = \'{slug}\'")\n',
      },
      handle,
    )
    expect(hits(signals, 'py.sql-injection')).toEqual(['2 vulnerability'])
  })

  it('respects Flask <int:...> converters', async () => {
    const signals = await sast(
      {
        'app.py': [
          "@app.route('/u/<int:uid>/<name>')",
          'def user(uid, name):',
          '    cursor.execute(f"SELECT * FROM u WHERE id = {uid}")',
          '    cursor.execute(f"SELECT * FROM u WHERE name = \'{name}\'")',
        ].join('\n'),
      },
      handle,
    )
    // Flask converts `<int:uid>` before the view runs, so formatting it into SQL cannot inject.
    expect(hits(signals, 'py.sql-injection')).toEqual(['4 vulnerability'])
  })
})

describe.each(PY_MODES)('Python precision (%s mode)', (_mode, handle) => {
  it('ignores non-secret random values and keeps weak/strong distinctions', async () => {
    const code = `
import random
shuffle_key = random.randint(0, 10)
backoff = random.uniform(0.1, 0.5)
api_key = ''.join(random.choices(ALPHABET, k=32))  # VULN
pin = random.randint(1000, 9999)  # SINK
`
    expect(hits(await sast({ 'app/x.py': code }, handle), 'py.insecure-random')).toEqual(expectedHits(code))
  })

  it('downgrades SSRF to a review hint when a host allow-list is visible', async () => {
    const code = `
import requests
from urllib.parse import urlparse
from flask import request

@app.get('/proxy')
def proxy():
    url = request.args['url']
    if urlparse(url).hostname not in ALLOWED_HOSTS:
        abort(400)
    return requests.get(url).text  # SINK

@app.get('/open')
def open_proxy():
    return requests.get(request.args['url']).text  # VULN
`
    expect(hits(await sast({ 'app/x.py': code }, handle), 'py.ssrf')).toEqual(expectedHits(code))
  })

  it('treats FastAPI Query/Body/Form/Path parameters as request input', async () => {
    const code = `
from fastapi import FastAPI, Query, Body, Form, Path, Depends
api = FastAPI()

def helper(name: str = Query(None), body: dict = Body(...), c: str = Form(...), p: str = Path(...), db=Depends(get_db)):
    os.system('a ' + name)  # VULN
    os.system('b ' + c)  # VULN
    os.system('c ' + p)  # VULN
    os.system('d ' + str(db))  # SINK
`
    expect(hits(await sast({ 'app/x.py': code }, handle), 'py.command-injection')).toEqual(expectedHits(code))
  })
})

describe('Jinja templates', () => {
  it('flags |safe on variables and autoescape off', async () => {
    const signals = await sast(
      {
        'templates/page.html':
          '<p>{{ name }}</p>\n<div>{{ bio|safe }}</div>\n{% autoescape off %}{{ x }}{% endautoescape %}\n<p>{{ "<br>"|safe }}</p>\n',
      },
      undefined,
    )
    expect(hits(signals, 'py.xss')).toEqual(['2 sink', '3 sink'])
  })
})

describe('Python grammar registration', () => {
  it('refuses a missing or invalid grammar library instead of crashing the process', async () => {
    const napi = await import('@ast-grep/napi').catch(() => undefined)
    if (!napi) return
    for (const libraryPath of ['/nonexistent/parser.so', import.meta.filename]) {
      const handle = createAstGrepHandle(napi, { libraryPath, extensions: ['py'] })
      expect(handle?.supportsPython).toBe(false)
      expect(handle?.Lang.Python).toBeUndefined()
      // Python files still go through the token fallback.
      const signals = await sast(
        { 'a.py': 'import os\nfrom flask import request\nos.system(request.args["c"])\n' },
        handle as AstGrepHandle,
      )
      expect(hits(signals, 'py.command-injection')).toEqual(['3 vulnerability'])
    }
  })
})
