import { describe, expect, it } from 'vitest'
import { SAST_RULES } from '../../../src/host/analysis/sast/index.ts'
import { MODES, ofRule, PY_MODES, sast } from './sast-helpers.ts'

/**
 * One minimal positive and one minimal negative example per rule id. Every
 * rule in the catalog must appear here, so a new rule cannot ship without a
 * test that it fires and a test that its look-alike safe form does not.
 */
interface Example {
  readonly path: string
  /** Must produce at least one signal of the rule, of this kind. */
  readonly positive: string
  readonly kind: 'vulnerability' | 'sink'
  /** Must produce no signal of the rule. */
  readonly negative: string
}

const JS = 'src/server.js'
const PY = 'app/views.py'
const FLASK =
  "from flask import request\nimport os, subprocess, pickle, json, requests, hashlib, random, ast, jwt\n@app.post('/x')\ndef view():\n"

const EXAMPLES: Readonly<Record<string, Example>> = {
  'js.sql-injection': {
    path: JS,
    positive: "app.get('/u', (req, res) => db.query('SELECT * FROM users WHERE id = ' + req.query.id))",
    kind: 'vulnerability',
    negative: "app.get('/u', (req, res) => db.query('SELECT * FROM users WHERE id = ?', [req.query.id]))",
  },
  'js.nosql-injection': {
    path: JS,
    positive:
      "app.post('/l', async (req, res) => { await User.findOne({ name: req.body.name, pass: req.body.pass }) })",
    kind: 'vulnerability',
    negative: "app.post('/l', async (req, res) => { await User.findOne({ name: String(req.body.name) }) })",
  },
  'js.command-injection': {
    path: JS,
    positive: "const { exec } = require('child_process')\napp.get('/p', (req, res) => exec('ping ' + req.query.host))",
    kind: 'vulnerability',
    negative:
      "const { execFile } = require('child_process')\napp.get('/p', (req, res) => execFile('ping', ['-c1', req.query.host]))",
  },
  'js.code-injection': {
    path: JS,
    positive: "app.post('/c', (req, res) => res.json(eval(req.body.expr)))",
    kind: 'vulnerability',
    negative: "app.post('/c', (req, res) => res.json(JSON.parse(req.body.expr)))",
  },
  'js.path-traversal': {
    path: JS,
    positive: "const fs = require('fs')\napp.get('/f', (req, res) => fs.readFile('/srv/' + req.query.name, cb))",
    kind: 'vulnerability',
    negative:
      "const fs = require('fs')\nconst path = require('path')\napp.get('/f', (req, res) => fs.readFile(path.join('/srv', path.basename(req.query.name)), cb))",
  },
  'js.ssrf': {
    path: JS,
    positive: "app.post('/h', async (req, res) => { await fetch(req.body.url) })",
    kind: 'vulnerability',
    negative:
      "app.post('/h', async (req, res) => { await fetch('https://api.example.com/hooks', { body: req.body.url }) })",
  },
  'js.open-redirect': {
    path: JS,
    positive: "app.get('/go', (req, res) => res.redirect(req.query.next))",
    kind: 'vulnerability',
    negative: "app.get('/go', (req, res) => res.redirect('/home?from=' + req.query.next))",
  },
  'js.xss': {
    path: JS,
    positive: "app.get('/hi', (req, res) => res.send('<h1>' + req.query.name + '</h1>'))",
    kind: 'vulnerability',
    negative: "app.get('/hi', (req, res) => res.json({ name: req.query.name }))",
  },
  'js.template-unescaped-output': {
    path: 'views/profile.ejs',
    positive: '<div><%- user.bio %></div>',
    kind: 'sink',
    negative: '<div><%= user.bio %></div>\n<%- include("footer") %>',
  },
  'js.insecure-deserialization': {
    path: JS,
    positive: "const s = require('node-serialize')\napp.post('/x', (req, res) => s.unserialize(req.body.data))",
    kind: 'vulnerability',
    negative: "app.post('/x', (req, res) => JSON.parse(req.body.data))",
  },
  'js.unsafe-yaml-load': {
    path: JS,
    positive: "const yaml = require('js-yaml')\napp.post('/y', (req, res) => yaml.load(req.body.doc))",
    kind: 'sink',
    negative:
      "const yaml = require('js-yaml')\napp.post('/y', (req, res) => yaml.load(req.body.doc, { schema: yaml.JSON_SCHEMA }))",
  },
  'js.weak-password-hash': {
    path: JS,
    positive:
      "const crypto = require('crypto')\nconst hashed = crypto.createHash('md5').update(password).digest('hex')",
    kind: 'vulnerability',
    negative: "const crypto = require('crypto')\nconst etag = crypto.createHash('md5').update(body).digest('hex')",
  },
  'js.weak-cipher': {
    path: JS,
    positive: "const crypto = require('crypto')\nconst c = crypto.createCipher('aes-256-cbc', key)",
    kind: 'vulnerability',
    negative: "const crypto = require('crypto')\nconst c = crypto.createCipheriv('aes-256-gcm', key, iv)",
  },
  'js.insecure-random': {
    path: JS,
    positive: 'const resetToken = Math.random().toString(36).slice(2)',
    kind: 'vulnerability',
    negative: 'const keyframes = Math.random() * 1000',
  },
  'js.jwt-none-algorithm': {
    path: JS,
    positive: "jwt.verify(token, key, { algorithms: ['none'] })",
    kind: 'vulnerability',
    negative: "jwt.verify(token, key, { algorithms: ['RS256'] })",
  },
  'js.jwt-decode-without-verify': {
    path: JS,
    positive:
      "const jwt = require('jsonwebtoken')\nfunction auth(req, res, next) {\n  req.user = jwt.decode(req.headers.authorization)\n  next()\n}",
    kind: 'vulnerability',
    negative:
      "const jwt = require('jsonwebtoken')\nfunction auth(req, res, next) {\n  req.user = jwt.verify(req.headers.authorization, KEY)\n  next()\n}",
  },
  'js.jwt-ignore-expiration': {
    path: JS,
    positive: 'jwt.verify(token, key, { ignoreExpiration: true })',
    kind: 'vulnerability',
    negative: "jwt.verify(token, key, { ignoreExpiration: false, maxAge: '1h' })",
  },
  'js.tls-verification-disabled': {
    path: JS,
    positive: 'const agent = new https.Agent({ rejectUnauthorized: false })',
    kind: 'vulnerability',
    negative: 'const agent = new https.Agent({ ca: CA_BUNDLE, rejectUnauthorized: true })',
  },
  'js.cors-misconfiguration': {
    path: JS,
    positive: 'app.use(cors({ origin: true, credentials: true }))',
    kind: 'vulnerability',
    negative: "app.use(cors({ origin: ['https://app.example.com'], credentials: true }))",
  },
  'js.cookie-insecure': {
    path: JS,
    positive: "res.cookie('sid', id, { secure: false })",
    kind: 'vulnerability',
    negative: "res.cookie('sid', id, { secure: true })\nconst smtp = { secure: false, host: 'mail' }",
  },
  'js.cookie-without-httponly': {
    path: JS,
    positive: "res.cookie('sid', id, { httpOnly: false })",
    kind: 'vulnerability',
    negative: "res.cookie('sid', id, { httpOnly: true })",
  },
  'js.hardcoded-session-secret': {
    path: JS,
    positive: "app.use(session({ secret: 'keyboard cat' }))",
    kind: 'vulnerability',
    negative: 'app.use(session({ secret: process.env.SESSION_SECRET }))',
  },
  'js.mass-assignment': {
    path: JS,
    positive: "app.post('/u', async (req, res) => { await User.create(req.body) })",
    kind: 'vulnerability',
    negative: "app.post('/u', async (req, res) => { await User.create({ name: req.body.name }) })",
  },
  'js.prototype-pollution': {
    path: JS,
    positive: "const _ = require('lodash')\napp.post('/c', (req, res) => _.merge(config, req.body))",
    kind: 'sink',
    negative: "const _ = require('lodash')\napp.post('/c', (req, res) => _.merge(config, defaults))",
  },
  'js.regex-injection': {
    path: JS,
    positive: "app.get('/s', (req, res) => res.json(new RegExp(req.query.q).test(x)))",
    kind: 'vulnerability',
    negative: "app.get('/s', (req, res) => res.json(new RegExp(escapeRegExp(req.query.q)).test(x)))",
  },
  'js.hardcoded-credential-check': {
    path: JS,
    positive: "app.post('/a', (req, res) => { if (req.body.password === 'hunter2!') ok() })",
    kind: 'vulnerability',
    negative: "app.post('/a', async (req, res) => { if (await bcrypt.compare(req.body.password, hash)) ok() })",
  },
  'py.sql-injection': {
    path: PY,
    positive: `${FLASK}    cursor.execute("SELECT * FROM users WHERE name = '%s'" % request.args['n'])\n`,
    kind: 'vulnerability',
    negative: `${FLASK}    cursor.execute("SELECT * FROM users WHERE name = %s", (request.args['n'],))\n`,
  },
  'py.command-injection': {
    path: PY,
    positive: `${FLASK}    os.system('ping ' + request.args['h'])\n`,
    kind: 'vulnerability',
    negative: `${FLASK}    subprocess.run(['ping', request.args['h']])\n`,
  },
  'py.code-injection': {
    path: PY,
    positive: `${FLASK}    eval(request.form['x'])\n`,
    kind: 'vulnerability',
    negative: `${FLASK}    ast.literal_eval(request.form['x'])\n`,
  },
  'py.insecure-deserialization': {
    path: PY,
    positive: `${FLASK}    pickle.loads(request.data)\n`,
    kind: 'vulnerability',
    negative: `${FLASK}    json.loads(request.data)\n`,
  },
  'py.path-traversal': {
    path: PY,
    positive: `${FLASK}    open('/srv/' + request.args['f'])\n`,
    kind: 'vulnerability',
    negative: `from werkzeug.utils import secure_filename\n${FLASK}    open(os.path.join('/srv', secure_filename(request.args['f'])))\n`,
  },
  'py.ssrf': {
    path: PY,
    positive: `${FLASK}    requests.get(request.args['url'])\n`,
    kind: 'vulnerability',
    negative: `${FLASK}    requests.get('https://api.example.com/x', params={'q': request.args['q']})\n`,
  },
  'py.template-injection': {
    path: PY,
    positive: `from flask import render_template_string\n${FLASK}    render_template_string(request.args['t'])\n`,
    kind: 'vulnerability',
    negative: `from flask import render_template_string\n${FLASK}    render_template_string('<p>{{ n }}</p>', n=request.args['n'])\n`,
  },
  'py.xss': {
    path: PY,
    positive: `from markupsafe import Markup\n${FLASK}    Markup(request.args['bio'])\n`,
    kind: 'vulnerability',
    negative: `from markupsafe import Markup, escape\n${FLASK}    Markup('<b>%s</b>') % escape(request.args['bio'])\n`,
  },
  'py.open-redirect': {
    path: PY,
    positive: `from flask import redirect\n${FLASK}    return redirect(request.args['next'])\n`,
    kind: 'vulnerability',
    negative: `from flask import redirect, url_for\n${FLASK}    return redirect(url_for('index', q=request.args['next']))\n`,
  },
  'py.debug-enabled': {
    path: 'app.py',
    positive: 'app = Flask(__name__)\napp.run(debug=True)\n',
    kind: 'vulnerability',
    negative: "app = Flask(__name__)\napp.run(debug=os.environ.get('FLASK_DEBUG') == '1')\n",
  },
  'py.allowed-hosts-wildcard': {
    path: 'mysite/settings.py',
    positive: "INSTALLED_APPS = []\nALLOWED_HOSTS = ['*']\n",
    kind: 'vulnerability',
    negative: "INSTALLED_APPS = []\nALLOWED_HOSTS = ['example.com', '.example.com']\n",
  },
  'py.hardcoded-secret-key': {
    path: 'mysite/settings.py',
    positive: "INSTALLED_APPS = []\nSECRET_KEY = 'x8f7s6d5f4g3h2j1k0l9m8n7'\n",
    kind: 'vulnerability',
    negative: "INSTALLED_APPS = []\nSECRET_KEY = os.environ['SECRET_KEY']\n",
  },
  'py.tls-verification-disabled': {
    path: PY,
    positive: 'import requests\nrequests.get(URL, verify=False)\n',
    kind: 'vulnerability',
    negative: 'import requests\nrequests.get(URL, verify=CA_BUNDLE)\n',
  },
  'py.jwt-unverified': {
    path: PY,
    positive: "import jwt\njwt.decode(token, options={'verify_signature': False})\n",
    kind: 'vulnerability',
    negative: "import jwt\njwt.decode(token, KEY, algorithms=['HS256'])\n",
  },
  'py.weak-password-hash': {
    path: PY,
    positive: 'import hashlib\nhashed = hashlib.md5(password.encode()).hexdigest()\n',
    kind: 'vulnerability',
    negative: 'import hashlib\netag = hashlib.md5(file_bytes).hexdigest()\n',
  },
  'py.insecure-random': {
    path: PY,
    positive: 'import random\nreset_token = str(random.getrandbits(64))\n',
    kind: 'vulnerability',
    negative: 'import random\nbackoff = random.uniform(0, 1)\n',
  },
  'py.mass-assignment': {
    path: PY,
    positive: `${FLASK}    User(**request.json)\n`,
    kind: 'vulnerability',
    negative: `${FLASK}    User(name=request.json['name'])\n`,
  },
  'py.hardcoded-credential-check': {
    path: PY,
    positive: `${FLASK}    if request.form['password'] == 'Adm1n!pass':\n        return 'ok'\n`,
    kind: 'vulnerability',
    negative: `${FLASK}    if check_password_hash(user.pw_hash, request.form['password']):\n        return 'ok'\n`,
  },
  'docker.add-remote-url': {
    path: 'Dockerfile',
    positive: 'FROM alpine:3\nADD https://example.com/tool.tgz /opt/\n',
    kind: 'vulnerability',
    negative:
      'FROM alpine:3\nADD --checksum=sha256:0123abcd https://example.com/tool.tgz /opt/\nADD ./local.tgz /opt/\n',
  },
  'docker.curl-pipe-shell': {
    path: 'Dockerfile',
    positive: 'FROM alpine:3\nRUN curl -fsSL https://get.example.sh | sh\n',
    kind: 'vulnerability',
    negative:
      'FROM alpine:3\nRUN curl -fsSLo /tmp/i.sh https://get.example.sh && sha256sum -c i.sha256 && sh /tmp/i.sh\n',
  },
  'docker.secret-in-env': {
    path: 'Dockerfile',
    positive: 'FROM alpine:3\nENV API_TOKEN=abcd1234efgh5678\n',
    kind: 'vulnerability',
    negative: 'FROM alpine:3\nENV API_TOKEN_FILE=/run/secrets/token\nARG NPM_TOKEN\n',
  },
  'container.privileged': {
    path: 'docker-compose.yml',
    positive: 'services:\n  app:\n    image: app\n    privileged: true\n',
    kind: 'vulnerability',
    negative: 'services:\n  app:\n    image: app\n    privileged: false\n',
  },
  'container.host-network': {
    path: 'docker-compose.yml',
    positive: 'services:\n  app:\n    network_mode: host\n',
    kind: 'vulnerability',
    negative: 'services:\n  app:\n    network_mode: bridge\n',
  },
  'k8s.allow-privilege-escalation': {
    path: 'k8s/pod.yaml',
    positive:
      'apiVersion: v1\nkind: Pod\nspec:\n  containers:\n    - name: a\n      securityContext:\n        allowPrivilegeEscalation: true\n',
    kind: 'vulnerability',
    negative:
      'apiVersion: v1\nkind: Pod\nspec:\n  containers:\n    - name: a\n      securityContext:\n        allowPrivilegeEscalation: false\n',
  },
}

describe('SAST rule catalog', () => {
  it('has a positive and a negative example for every rule id', () => {
    expect(Object.keys(EXAMPLES).sort()).toEqual(SAST_RULES.map(rule => rule.id))
  })

  it.each(SAST_RULES.map(rule => [rule.id, rule] as const))('%s has complete beginner-facing metadata', (_id, rule) => {
    expect(rule.id).toMatch(/^(?:js|py|docker|container|k8s)\.[a-z0-9-]+$/)
    expect(rule.title.length).toBeGreaterThan(5)
    expect(rule.cwe).toMatch(/^CWE-\d+$/)
    expect(rule.message.length).toBeGreaterThan(60)
    expect(rule.recommendation.length).toBeGreaterThan(30)
    expect(rule.references.some(url => url.startsWith('https://owasp.org/'))).toBe(true)
    expect(rule.references).toContain(`https://cwe.mitre.org/data/definitions/${rule.cwe.slice(4)}.html`)
  })
})

const CASES = Object.entries(EXAMPLES).map(([id, example]) => [id, example] as const)

describe.each(MODES)('rule examples, JavaScript and config (%s mode)', (_mode, handle) => {
  const cases = CASES.filter(([id]) => !id.startsWith('py.'))

  it.each(cases)('%s fires on the positive example', async (id, example) => {
    const signals = ofRule(await sast({ [example.path]: example.positive }, handle), id)
    expect(signals.length).toBeGreaterThan(0)
    expect(signals.map(s => s.kind)).toContain(example.kind)
  })

  it.each(cases)('%s stays quiet on the negative example', async (id, example) => {
    expect(ofRule(await sast({ [example.path]: example.negative }, handle), id)).toEqual([])
  })
})

describe.each(PY_MODES)('rule examples, Python (%s mode)', (_mode, handle) => {
  const cases = CASES.filter(([id]) => id.startsWith('py.'))

  it.each(cases)('%s fires on the positive example', async (id, example) => {
    const signals = ofRule(await sast({ [example.path]: example.positive }, handle), id)
    expect(signals.length).toBeGreaterThan(0)
    expect(signals.map(s => s.kind)).toContain(example.kind)
  })

  it.each(cases)('%s stays quiet on the negative example', async (id, example) => {
    expect(ofRule(await sast({ [example.path]: example.negative }, handle), id)).toEqual([])
  })
})
