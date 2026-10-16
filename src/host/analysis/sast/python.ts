/**
 * Python rules (Flask, Django, FastAPI and plain scripts), plus a text rule
 * for the Jinja/Django `|safe` filter in template files.
 */

import { Checker, isCredentialComparison, isSanitizerCall, secretContext } from './helpers.ts'
import type { CallFact, FileModel, Span } from './model.ts'
import { type Classification, cweUrl, type FileContext, REF, type RuleMeta } from './rule.ts'
import { callAt, type Taint } from './taint.ts'

// ---------------------------------------------------------------------------
// Rule metadata
// ---------------------------------------------------------------------------

const SQLI: RuleMeta = {
  id: 'py.sql-injection',
  title: 'SQL injection',
  sinkTitle: 'SQL query built from a dynamic string',
  category: 'injection',
  cwe: 'CWE-89',
  severity: 'high',
  sinkSeverity: 'medium',
  message:
    'This SQL statement is built with an f-string, `%` formatting, `.format()` or `+` using data from the HTTP request. An attacker can send input containing SQL syntax that changes the query: reading other users’ data, bypassing login, or modifying records.',
  sinkMessage:
    'This SQL statement is built by formatting a string with a value whose origin is not visible here. If that value can contain user input, it allows SQL injection.',
  recommendation:
    'Pass values as parameters instead of formatting them into the SQL: `cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))`, SQLAlchemy `text("... :id")` with `{"id": user_id}`, or the ORM query API. Choose dynamic table/column names from a fixed allow-list.',
  references: [REF.injection, cweUrl('CWE-89')],
}

const CMDI: RuleMeta = {
  id: 'py.command-injection',
  title: 'OS command injection',
  sinkTitle: 'Shell command built from a dynamic value',
  category: 'command-execution',
  cwe: 'CWE-78',
  severity: 'critical',
  sinkSeverity: 'medium',
  message:
    'Request data ends up in a command run by a shell (`os.system`, `os.popen`, or `subprocess` with `shell=True`). Shell characters such as `;`, `|`, `&&` or `$(...)` in the input let an attacker run any program on the server.',
  sinkMessage:
    'A command is run through a shell with a value that is not a fixed string. If that value can contain user input, an attacker could inject extra shell commands.',
  recommendation:
    'Call `subprocess.run(["program", arg1, arg2])` with a list and without `shell=True`, so arguments are never interpreted by a shell. Validate arguments against an allow-list; `shlex.quote()` helps only when a shell is unavoidable.',
  references: [REF.injection, cweUrl('CWE-78')],
}

const CODEI: RuleMeta = {
  id: 'py.code-injection',
  title: 'Code injection (eval/exec of user input)',
  sinkTitle: 'Dynamic code evaluation',
  category: 'injection',
  cwe: 'CWE-95',
  severity: 'critical',
  sinkSeverity: 'medium',
  message:
    'Request data is executed as Python code (`eval`, `exec` or `compile`). An attacker can run arbitrary code with the application’s permissions, for example `__import__("os").system(...)`.',
  sinkMessage:
    'A value that is not a fixed string is executed as Python code. If it can contain user input, an attacker could run their own code.',
  recommendation:
    'Do not evaluate strings. Use `ast.literal_eval` for Python literals, `json.loads` for data, and a dictionary of allowed functions for dispatch.',
  references: [REF.injection, cweUrl('CWE-95'), cweUrl('CWE-94')],
}

const DESER: RuleMeta = {
  id: 'py.insecure-deserialization',
  title: 'Insecure deserialization',
  sinkTitle: 'Unsafe deserializer used on dynamic data',
  category: 'deserialization',
  cwe: 'CWE-502',
  severity: 'critical',
  sinkSeverity: 'medium',
  message:
    'Request data is passed to a deserializer that can construct arbitrary objects (`pickle`, `marshal`, `jsonpickle`, `shelve`, or `yaml.load` without a safe loader). A crafted payload runs code on the server while it is being loaded.',
  sinkMessage:
    'An unsafe deserializer (`pickle`, `marshal`, `jsonpickle`, `shelve` or `yaml.load` without `SafeLoader`) loads data whose origin is not visible here. If that data can ever come from users, files they upload, caches or queues they can write to, it allows remote code execution.',
  recommendation:
    'Use JSON (`json.loads`) for untrusted data and validate it. For YAML use `yaml.safe_load` or `Loader=yaml.SafeLoader`. If you must exchange pickles, sign them with HMAC and verify before loading.',
  references: [REF.integrity, cweUrl('CWE-502')],
}

const PATH: RuleMeta = {
  id: 'py.path-traversal',
  title: 'Path traversal',
  sinkTitle: 'File path from user input (check the containment logic)',
  category: 'path-traversal',
  cwe: 'CWE-22',
  severity: 'high',
  sinkSeverity: 'low',
  message:
    'A file path is built from request data and then opened, sent or deleted. `../` sequences or an absolute path (note that `os.path.join(base, "/etc/passwd")` drops `base`) let an attacker reach files outside the intended folder.',
  sinkMessage:
    'A file path from request data reaches a file operation, but a containment check or a safe helper appears nearby. Make sure the check runs on the final, resolved path.',
  recommendation:
    'Use `werkzeug.utils.secure_filename()` or `os.path.basename()` for names, or resolve with `Path(base, name).resolve()` and reject it unless `is_relative_to(base)`. Flask `send_from_directory` is safer than `send_file` with a joined path.',
  references: [REF.accessControl, cweUrl('CWE-22')],
}

const SSRF: RuleMeta = {
  id: 'py.ssrf',
  title: 'Server-side request forgery (SSRF)',
  sinkTitle: 'Outgoing request to a partly user-controlled URL',
  category: 'ssrf',
  cwe: 'CWE-918',
  severity: 'high',
  sinkSeverity: 'low',
  message:
    'The server fetches a URL taken from the incoming request. An attacker can make it call internal services, cloud metadata endpoints (`http://169.254.169.254/`) or `localhost` admin interfaces.',
  sinkMessage:
    'An outgoing request URL contains user-controlled parts but the host appears fixed. Check that the input cannot change the host (for example with `@`, `//` or encoded characters).',
  recommendation:
    'Map user choices to known URLs, or parse with `urllib.parse.urlparse` and allow only expected schemes and hosts. Block private, loopback and link-local addresses after DNS resolution and disable automatic redirects.',
  references: [REF.ssrf, cweUrl('CWE-918')],
}

const SSTI: RuleMeta = {
  id: 'py.template-injection',
  title: 'Server-side template injection',
  sinkTitle: 'Template rendered from a dynamic string',
  category: 'injection',
  cwe: 'CWE-1336',
  severity: 'critical',
  sinkSeverity: 'medium',
  message:
    'A template is compiled from request data (`render_template_string`, `jinja2.Template`, Django `Template`). Template syntax such as `{{ ... }}` in the input is executed, which in Jinja2 can lead to remote code execution.',
  sinkMessage:
    'A template is compiled from a string that is not fixed. If any part of it comes from users, template syntax in it will be executed.',
  recommendation:
    'Keep templates as fixed files and pass user data only as variables: `render_template("page.html", name=name)` or `render_template_string(FIXED, name=name)`. Use a sandboxed environment if users must author templates.',
  references: [REF.injection, cweUrl('CWE-1336')],
}

const XSS: RuleMeta = {
  id: 'py.xss',
  title: 'Cross-site scripting (XSS): escaping disabled',
  sinkTitle: 'HTML marked as safe without escaping',
  category: 'xss',
  cwe: 'CWE-79',
  severity: 'high',
  sinkSeverity: 'low',
  message:
    'User-controlled text is marked as safe HTML (`Markup`, `mark_safe`, `format_html` misuse or the `|safe` filter), which turns off auto-escaping. Markup in the input runs as script in other users’ browsers.',
  sinkMessage:
    'A dynamic value is marked as safe HTML, which turns off escaping. If it can contain user input, it allows cross-site scripting.',
  recommendation:
    'Let the template engine escape values. Use `format_html("<b>{}</b>", value)` (Django) or `Markup("<b>{}</b>").format(value)` (Markupsafe), which escape the arguments, or sanitize with `bleach`/`nh3`.',
  references: [REF.injection, cweUrl('CWE-79')],
}

const REDIRECT: RuleMeta = {
  id: 'py.open-redirect',
  title: 'Open redirect',
  sinkTitle: 'Redirect to a user-controlled URL (check the validation)',
  category: 'business-logic',
  cwe: 'CWE-601',
  severity: 'medium',
  sinkSeverity: 'low',
  message:
    'The response redirects to a URL taken from the request (for example `?next=`). Attackers can use links on your domain to send victims to phishing pages.',
  sinkMessage:
    'A redirect target comes from the request, but some URL validation appears nearby. Confirm it rejects other hosts and `//evil.com`.',
  recommendation:
    'Redirect only to relative paths or allow-listed hosts. Django provides `url_has_allowed_host_and_scheme()`; in Flask, check `urlparse(target).netloc == ""` and that the path starts with a single `/`.',
  references: [REF.accessControl, cweUrl('CWE-601')],
}

const DEBUG: RuleMeta = {
  id: 'py.debug-enabled',
  title: 'Debug mode enabled',
  category: 'misconfiguration',
  cwe: 'CWE-489',
  severity: 'medium',
  message:
    'Debug mode is turned on. Error pages then reveal source code, settings and secrets, and the Flask/Werkzeug debugger even lets visitors run Python code in the browser.',
  recommendation:
    'Read debug settings from the environment (e.g. `DEBUG = os.environ.get("DJANGO_DEBUG") == "1"`) and never enable them in production. Run Flask behind a production server such as gunicorn instead of `app.run(debug=True)`.',
  references: [REF.misconfig, cweUrl('CWE-489'), cweUrl('CWE-215')],
}

const HOSTS: RuleMeta = {
  id: 'py.allowed-hosts-wildcard',
  title: 'Django ALLOWED_HOSTS allows any host',
  category: 'misconfiguration',
  cwe: 'CWE-16',
  severity: 'low',
  message:
    '`ALLOWED_HOSTS = ["*"]` disables Django’s Host header validation, which enables host-header attacks such as poisoned password-reset links and cache poisoning.',
  recommendation: 'List the real domain names of the site, e.g. `ALLOWED_HOSTS = ["example.com", "www.example.com"]`.',
  references: [REF.misconfig, cweUrl('CWE-16')],
}

const COOKIE_SECURE: RuleMeta = {
  id: 'py.cookie-insecure',
  title: 'Cookie sent without the Secure flag',
  category: 'misconfiguration',
  cwe: 'CWE-614',
  severity: 'low',
  message:
    '`SESSION_COOKIE_SECURE = False` or `CSRF_COOKIE_SECURE = False` allows the browser to send the cookie over plain HTTP, where someone on the network can intercept it.',
  recommendation:
    'Set `SESSION_COOKIE_SECURE = True` and, for Django CSRF cookies, `CSRF_COOKIE_SECURE = True` in production, and serve the application over HTTPS.',
  references: [REF.misconfig, cweUrl('CWE-614')],
}

const COOKIE_HTTPONLY: RuleMeta = {
  id: 'py.cookie-without-httponly',
  title: 'Session cookie readable by JavaScript',
  category: 'misconfiguration',
  cwe: 'CWE-1004',
  severity: 'low',
  message:
    '`SESSION_COOKIE_HTTPONLY = False` lets JavaScript read the session cookie. An injected script can steal it and impersonate the user.',
  recommendation: 'Set `SESSION_COOKIE_HTTPONLY = True` so browser scripts cannot read the session cookie.',
  references: [REF.misconfig, cweUrl('CWE-1004')],
}

const SECRET_KEY: RuleMeta = {
  id: 'py.hardcoded-secret-key',
  title: 'Hard-coded framework secret key',
  category: 'misconfiguration',
  cwe: 'CWE-798',
  severity: 'high',
  message:
    'The framework secret key (Django `SECRET_KEY` or Flask `SECRET_KEY`) is written in the source. It signs sessions, password-reset tokens and CSRF tokens; anyone who sees it can forge them and log in as any user.',
  recommendation:
    'Load it from the environment or a secret manager (e.g. `SECRET_KEY = os.environ["DJANGO_SECRET_KEY"]`), generate a new long random value, and treat the old one as compromised.',
  references: [REF.misconfig, cweUrl('CWE-798')],
}

const TLS: RuleMeta = {
  id: 'py.tls-verification-disabled',
  title: 'TLS certificate verification disabled',
  category: 'crypto',
  cwe: 'CWE-295',
  severity: 'medium',
  message:
    '`verify=False` (or an unverified SSL context) skips certificate checks, so anyone on the network path can impersonate the server and read or change the traffic, including credentials and tokens.',
  recommendation:
    'Remove `verify=False`. For internal or self-signed certificates pass the CA bundle path: `verify="/path/to/ca.pem"`.',
  references: [REF.crypto, cweUrl('CWE-295')],
}

const JWT: RuleMeta = {
  id: 'py.jwt-unverified',
  title: 'JWT signature not verified',
  category: 'authn',
  cwe: 'CWE-347',
  severity: 'high',
  message:
    'The JWT is decoded without checking its signature (`verify_signature: False`, `verify=False` or the `none` algorithm). Anyone can create a token with any user ID or role and it will be accepted.',
  recommendation:
    'Always verify: `jwt.decode(token, key, algorithms=["HS256"])` with the exact algorithm you sign with, and never include `none`.',
  references: [REF.authn, cweUrl('CWE-347')],
}

const WEAK_HASH: RuleMeta = {
  id: 'py.weak-password-hash',
  title: 'Weak hash used for passwords',
  category: 'crypto',
  cwe: 'CWE-328',
  severity: 'medium',
  message:
    'MD5 and SHA-1 are fast, broken hashes. Passwords hashed with them can be cracked quickly if the database leaks, even with a salt.',
  recommendation:
    'Use a password hashing function: `argon2-cffi`, `bcrypt`, `hashlib.scrypt`, or Django’s/Werkzeug’s built-in password hashers (`make_password`, `generate_password_hash`).',
  references: [REF.crypto, cweUrl('CWE-328'), cweUrl('CWE-916')],
}

const WEAK_RANDOM: RuleMeta = {
  id: 'py.insecure-random',
  title: 'Predictable random value used as a secret',
  sinkTitle: '`random` module used near a security-sensitive name',
  category: 'crypto',
  cwe: 'CWE-330',
  severity: 'medium',
  sinkSeverity: 'low',
  message:
    'The `random` module is not cryptographically secure; its output can be predicted. Tokens, passwords, OTPs or reset codes built from it can be guessed.',
  sinkMessage:
    'The `random` module is used where the surrounding names suggest a key, session or code. If the value protects anything, it can be predicted.',
  recommendation:
    'Use the `secrets` module: `secrets.token_urlsafe(32)`, `secrets.token_hex()`, or `secrets.choice()`.',
  references: [REF.crypto, cweUrl('CWE-330'), cweUrl('CWE-338')],
}

const MASS: RuleMeta = {
  id: 'py.mass-assignment',
  title: 'Mass assignment from request data',
  category: 'authz',
  cwe: 'CWE-915',
  severity: 'medium',
  message:
    'All request fields are passed as keyword arguments to a model or update call (`**request.json`). An attacker can add fields such as `is_admin`, `role` or `owner_id` that the form never shows.',
  recommendation:
    'Pick the allowed fields explicitly, or validate with a schema that rejects unknown fields (Pydantic models, marshmallow `unknown=RAISE`, Django forms/serializers with explicit `fields`).',
  references: [REF.accessControl, cweUrl('CWE-915')],
}

const BACKDOOR: RuleMeta = {
  id: 'py.hardcoded-credential-check',
  title: 'Hard-coded credential or backdoor check',
  category: 'authn',
  cwe: 'CWE-798',
  severity: 'medium',
  message:
    'A password, token or special header is compared with a fixed string in the code. Anyone who reads the source learns the value and can use it to get in, and it cannot be rotated without a deployment.',
  recommendation:
    'Remove fixed credentials. Check passwords against salted hashes stored per user, keep API keys in a secret store, and compare secrets with `hmac.compare_digest`.',
  references: [REF.authn, cweUrl('CWE-798'), cweUrl('CWE-287')],
}

/** Every rule of this rule set (several matchers may share one id). */
export const PY_RULES: readonly RuleMeta[] = [
  SQLI,
  CMDI,
  CODEI,
  DESER,
  PATH,
  SSRF,
  SSTI,
  XSS,
  REDIRECT,
  DEBUG,
  HOSTS,
  COOKIE_SECURE,
  COOKIE_HTTPONLY,
  SECRET_KEY,
  TLS,
  JWT,
  WEAK_HASH,
  WEAK_RANDOM,
  MASS,
  BACKDOOR,
]

// ---------------------------------------------------------------------------
// Patterns
// ---------------------------------------------------------------------------

const SQL_EXEC = /^(?:execute|executemany|executescript|raw|extra|exec_driver_sql|from_statement|mogrify)$/
const SQL_RECEIVER =
  /(?:^|\.)(?:cursor|cur|c|conn|connection|db|database|session|engine|con|objects|manager|tx|transaction|[A-Za-z]*(?:cursor|Cursor|conn|Conn|session|Session|db|DB|engine|Engine))$/
const SQL_WORDS =
  /\b(?:select\s[\s\S]*\bfrom|insert\s+into|update\s+[\w"`.]+\s+set|delete\s+from|where\s|order\s+by|group\s+by|union\s+select|create\s+table|drop\s+table|alter\s+table|values\s*\()/i

const SHELL_FUNCS =
  /^(?:os\.(?:system|popen|popen2|popen3|popen4)|commands\.(?:getoutput|getstatusoutput)|subprocess\.(?:getoutput|getstatusoutput))$/
const SUBPROCESS = /^(?:subprocess\.(?:run|call|Popen|check_output|check_call)|asyncio\.create_subprocess_shell)$/

const DESER_FUNCS =
  /^(?:pickle|cPickle|_pickle|dill|cloudpickle|joblib)\.(?:loads?|Unpickler)$|^marshal\.loads?$|^jsonpickle\.(?:decode|loads)$|^shelve\.open$|^pandas\.read_pickle$|^numpy\.load$|^torch\.load$/
const YAML_UNSAFE = /^yaml\.(?:load|load_all|unsafe_load|full_load|unsafe_load_all|full_load_all)$/

const FILE_FUNCS =
  /^(?:open|io\.open|codecs\.open|os\.(?:remove|unlink|rmdir|removedirs|rename|replace|listdir|scandir|chmod|chown|makedirs|mkdir|stat)|shutil\.(?:rmtree|copy|copy2|copyfile|copytree|move)|flask\.send_file|send_file|aiofiles\.open|fastapi\.responses\.FileResponse|starlette\.responses\.FileResponse|FileResponse|django\.http\.FileResponse|pathlib\.Path\.(?:open|read_text|read_bytes|write_text|write_bytes|unlink))$/
const PATH_METHODS = /^(?:read_text|read_bytes|write_text|write_bytes|unlink|open|rmdir|iterdir|glob)$/
const PATH_SAFE_CALL =
  /^(?:secure_filename|werkzeug\.utils\.secure_filename|os\.path\.basename|basename|safe_join|werkzeug\.security\.safe_join|flask\.safe_join|get_valid_filename|django\.utils\.text\.get_valid_filename)$/
const CONTAINMENT_CHECK =
  /\.startswith\s*\(|is_relative_to\s*\(|os\.path\.commonpath|commonprefix|safe_join|realpath[^\n]*startswith/

const HTTP_FUNCS =
  /^(?:requests|httpx)\.(?:get|post|put|patch|delete|head|options|request|stream)$|^requests\.(?:Session|session)\(\)\.(?:get|post|put|patch|delete|head|request)$|^httpx\.(?:Client|AsyncClient)\(\)\.(?:get|post|put|patch|delete|head|request)$|^urllib\.request\.(?:urlopen|Request|urlretrieve)$|^urllib2\.urlopen$|^urllib\.urlopen$|^aiohttp\.ClientSession\(\)\.(?:get|post|put|patch|delete|head|request)$|^aiohttp\.request$/
const SESSION_RECEIVER = /^(?:session|client|http|sess|s|http_client|httpx_client|async_client)$/i

const TEMPLATE_FUNCS =
  /^(?:flask\.render_template_string|render_template_string|jinja2\.Template|jinja2\.Environment\(\)\.from_string|django\.template\.Template|mako\.template\.Template|Template)$/
const SAFE_HTML_FUNCS =
  /^(?:markupsafe\.Markup|flask\.Markup|jinja2\.Markup|Markup|django\.utils\.safestring\.mark_safe|mark_safe|SafeString|django\.utils\.safestring\.SafeString)$/

const REDIRECT_FUNCS =
  /^(?:flask\.redirect|redirect|django\.shortcuts\.redirect|django\.http\.HttpResponseRedirect|HttpResponseRedirect|HttpResponsePermanentRedirect|fastapi\.responses\.RedirectResponse|starlette\.responses\.RedirectResponse|RedirectResponse)$/
const REDIRECT_CHECK =
  /url_has_allowed_host_and_scheme|is_safe_url|urlparse\([^)]*\)\.netloc|allowed_hosts|ALLOWED_REDIRECT|startswith\s*\(\s*['"]\/['"]\s*\)/

const PASSWORD_CONTEXT = /passw(?:or)?d|passwd|\bpwd\b|passphrase/i
const MODEL_CALL =
  /^(?:[A-Z]\w*|[\w.]+\.objects\.(?:create|update|update_or_create|get_or_create|filter\(\)\.update)|[\w.]+\.(?:create|update|insert|update_one|insert_one|update_many|update_or_create|get_or_create|model_validate|parse_obj))$/

// ---------------------------------------------------------------------------
// Entry points
// ---------------------------------------------------------------------------

/** Run the Python rules over one file model. */
export function pyRules(model: FileModel, ctx: FileContext): void {
  const chk = new Checker(model, ctx)
  for (const call of model.calls) {
    if (call.decorator) continue
    const q = chk.qualify(call.callee)
    sqlInjection(chk, call)
    commandInjection(chk, call, q)
    codeInjection(chk, call, q)
    deserialization(chk, call, q)
    pathTraversal(chk, call, q)
    ssrf(chk, call, q)
    templateInjection(chk, call, q)
    safeHtml(chk, call, q)
    openRedirect(chk, call, q)
    debugRun(chk, call)
    tlsVerify(chk, call, q)
    jwtDecode(chk, call, q)
    weakCrypto(chk, call, q)
    massAssignment(chk, call)
  }
  settings(chk)
  for (const cmp of chk.literalComparisons()) {
    if (isCredentialComparison(chk, cmp)) chk.certain(BACKDOOR, cmp.span, 'medium', { mask: [cmp.literalSpan] })
  }
}

/** Jinja2/Django templates: `{{ value|safe }}` and `{% autoescape off %}`. */
export function pyTemplateRules(ctx: FileContext): void {
  const { file } = ctx
  if (!/\.(?:html?|jinja2?|j2|djhtml|tmpl|tpl)$/i.test(file.path)) return
  const content = file.content
  if (!content.includes('{{') && !content.includes('{%')) return
  for (const m of content.matchAll(/\{\{-?\s*([^{}]*?)\|\s*safe\b[^{}]*?-?\}\}/g)) {
    const expr = (m[1] ?? '').trim()
    if (expr === '' || /^(['"])[^'"]*\1$/.test(expr)) continue
    ctx.report({ rule: XSS, kind: 'sink', span: { start: m.index, end: m.index + m[0].length }, confidence: 'low' })
  }
  for (const m of content.matchAll(/\{%-?\s*autoescape\s+(?:off|false)\s*-?%\}/gi)) {
    ctx.report({ rule: XSS, kind: 'sink', span: { start: m.index, end: m.index + m[0].length }, confidence: 'low' })
  }
}

// ---------------------------------------------------------------------------
// Rules
// ---------------------------------------------------------------------------

function sqlInjection(chk: Checker, call: CallFact): void {
  let query: Span | undefined
  let queryBuilderText = false
  if (SQL_EXEC.test(call.name) && call.receiver !== '') {
    if (call.name === 'extra')
      query = chk.keyword(call, 'where') ?? chk.keyword(call, 'select') ?? chk.positional(call, 0)
    else
      query =
        chk.positional(call, 0) ??
        chk.keyword(call, 'sql') ??
        chk.keyword(call, 'query') ??
        chk.keyword(call, 'operation')
    if (!query) return
    // session.execute(text(f"...")) / engine.execute(sqlalchemy.text(...))
    const inner = callAt(chk.model, query)
    if (
      inner &&
      /^(?:text|sqlalchemy\.text|sa\.text|sql\.SQL|SQL)$/.test(
        chk.qualify(inner.callee).replace(/^sqlalchemy\.sql\.(?:expression\.)?/, 'sqlalchemy.'),
      )
    ) {
      const arg = chk.positional(inner, 0)
      if (arg) query = arg
    }
  } else if (
    /^(?:sqlalchemy\.text|text|sqlalchemy\.sql\.text)$/.test(chk.qualify(call.callee)) &&
    chk.imports(/^sqlalchemy/)
  ) {
    // Execute sinks unwrap text() themselves. Query-builder predicates also
    // execute raw text, even when it contains no full SELECT statement.
    const parent = chk.model.calls.find(
      p =>
        /^(?:filter|where|having)$/.test(p.name) &&
        p.receiver !== '' &&
        p.args.some(a => a.start <= call.start && call.end <= a.end),
    )
    if (!parent) return
    queryBuilderText = true
    query = chk.positional(call, 0)
    if (!query) return
  } else return
  const values = chk.values(query)
  const built = values.some(v => chk.ex.isStringBuilt(v) && !chk.ex.isConstant(v))
  if (!built) return
  const text = values.map(v => chk.text(v)).join(' ')
  if (
    !SQL_WORDS.test(text) &&
    !SQL_RECEIVER.test(call.receiver) &&
    call.name !== 'raw' &&
    call.name !== 'extra' &&
    !queryBuilderText
  )
    return
  const taint = chk.ex.taintResolved(query)
  chk.check(SQLI, call, taint, true)
}

function commandInjection(chk: Checker, call: CallFact, q: string): void {
  if (SHELL_FUNCS.test(q)) {
    const cmd = chk.positional(call, 0)
    if (cmd) chk.check(CMDI, call, chk.ex.taintResolved(cmd), chk.dynamic(cmd))
    return
  }
  if (!SUBPROCESS.test(q)) return
  const cmd = chk.positional(call, 0) ?? chk.keyword(call, 'args')
  if (!cmd) return
  if (q === 'asyncio.create_subprocess_shell') {
    chk.check(CMDI, call, chk.ex.taintResolved(cmd), chk.dynamic(cmd))
    return
  }
  const shell = chk.keyword(call, 'shell')
  if (!shell || chk.ex.isWord(shell, 'False', 'None', '0')) {
    // `subprocess.run(["sh", "-c", cmd])` runs a shell explicitly.
    if (chk.ex.isArrayLiteral(cmd)) {
      const items = chk.ex.elements(cmd)
      const prog = chk.ex.literal(items[0] ?? { start: 0, end: 0 })
      const flag = chk.ex.literal(items[1] ?? { start: 0, end: 0 })
      const script = items[2]
      if (
        prog &&
        /^(?:\/(?:usr\/)?bin\/)?(?:sh|bash|zsh|dash|ksh|cmd(?:\.exe)?)$/.test(prog) &&
        flag &&
        /^(?:-c|\/c)$/i.test(flag) &&
        script
      ) {
        chk.check(CMDI, call, chk.ex.taintResolved(script), chk.dynamic(script))
      }
    }
    return
  }
  chk.check(CMDI, call, chk.ex.taintResolved(cmd), chk.dynamic(cmd), {
    note: '`shell=True` makes the command go through a shell.',
  })
}

function codeInjection(chk: Checker, call: CallFact, q: string): void {
  if (!/^(?:eval|exec|compile|builtins\.(?:eval|exec|compile))$/.test(q)) return
  if (call.receiver !== '' && !q.startsWith('builtins.')) return
  const code = chk.positional(call, 0)
  if (!code) return
  chk.check(CODEI, call, chk.ex.taintResolved(code), chk.dynamic(code))
}

function deserialization(chk: Checker, call: CallFact, q: string): void {
  if (DESER_FUNCS.test(q)) {
    const data = chk.positional(call, 0) ?? call.args[0]
    if (!data) return
    if (q === 'numpy.load' && !/allow_pickle\s*=\s*True/.test(chk.text(call))) return
    if (q === 'torch.load' && /weights_only\s*=\s*True/.test(chk.text(call))) return
    const taint = chk.ex.taintResolved(data)
    const cls: Classification =
      taint && taint.origin === 'request'
        ? { kind: 'vulnerability', confidence: taint.direct ? 'high' : 'medium', taint }
        : { kind: 'sink', confidence: 'low', ...(taint ? { taint } : {}) }
    chk.report(DESER, call, cls)
    return
  }
  if (YAML_UNSAFE.test(q)) {
    const loader = chk.keyword(call, 'Loader') ?? chk.positional(call, 1)
    if (loader && /\b(?:Safe|CSafe|Base)Loader\b/.test(chk.text(loader))) return
    if (q.endsWith('safe_load')) return
    const data = chk.positional(call, 0) ?? chk.keyword(call, 'stream')
    if (!data) return
    const taint = chk.ex.taintResolved(data)
    const cls: Classification =
      taint && taint.origin === 'request'
        ? { kind: 'vulnerability', confidence: taint.direct ? 'high' : 'medium', taint }
        : { kind: 'sink', confidence: 'low', ...(taint ? { taint } : {}) }
    chk.report(DESER, call, cls, {
      ...(cls.kind === 'sink' && !chk.dynamic(data) ? { severity: 'low' } : {}),
      note: '`yaml.load` without `Loader=yaml.SafeLoader` can construct arbitrary Python objects.',
    })
  }
}

function pathTraversal(chk: Checker, call: CallFact, q: string): void {
  let target: Span | undefined
  if (FILE_FUNCS.test(q) || FILE_FUNCS.test(call.callee)) {
    target =
      chk.positional(call, 0) ??
      chk.keyword(call, 'path') ??
      chk.keyword(call, 'file') ??
      chk.keyword(call, 'path_or_file')
  } else if (/^(?:flask\.)?send_from_directory$/.test(q) || q === 'send_from_directory') {
    // Flask joins safely; only the directory argument matters.
    target = chk.positional(call, 0)
  } else if (PATH_METHODS.test(call.name) && /^(?:pathlib\.)?Path\(/.test(chk.qualify(call.receiver))) {
    const inner = chk.text({ start: call.calleeSpan.start, end: call.calleeSpan.end })
    void inner
    target = { start: call.calleeSpan.start, end: call.calleeSpan.end }
  } else return
  if (!target) return
  const values = chk.values(target)
  if (
    values.every(v => {
      const c = callAt(chk.model, v)
      return c !== undefined && PATH_SAFE_CALL.test(chk.qualify(c.callee))
    })
  )
    return
  const taint = chk.ex.taintResolved(target)
  if (!taint) return
  const cls = classify(PATH, taint)
  if (!cls) return
  if (CONTAINMENT_CHECK.test(chk.scopeText(call.start))) {
    chk.report(
      PATH,
      call,
      { kind: 'sink', confidence: 'low', taint },
      { note: 'A containment check appears in the same function; confirm it runs on the resolved path.' },
    )
  } else chk.report(PATH, call, cls)
}

function ssrf(chk: Checker, call: CallFact, q: string): void {
  const ok =
    HTTP_FUNCS.test(q) ||
    (/^(?:get|post|put|patch|delete|head|request|stream)$/.test(call.name) &&
      SESSION_RECEIVER.test(call.receiver) &&
      chk.imports(/^(?:requests|httpx|aiohttp)$/))
  if (!ok) return
  let url = chk.positional(call, call.name === 'request' && !q.startsWith('urllib') ? 1 : 0) ?? chk.keyword(call, 'url')
  if (!url) return
  if (call.name === 'request' && chk.positional(call, 1) === undefined) url = chk.positional(call, 0) ?? url
  const taint = chk.ex.taintResolved(url)
  if (!taint) return
  if ([url, ...chk.values(url)].some(v => chk.ex.hasFixedOrigin(v))) {
    if (taint.origin === 'request') chk.report(SSRF, call, { kind: 'sink', confidence: 'low', taint })
    return
  }
  const cls = classify(SSRF, taint)
  if (!cls) return
  if (cls.kind === 'vulnerability' && URL_CHECK.test(chk.scopeText(call.start))) {
    chk.report(
      SSRF,
      call,
      { kind: 'sink', confidence: 'low', taint },
      {
        note: 'Some URL validation (an allow-list or host check) appears in the same function; confirm it cannot be bypassed.',
      },
    )
    return
  }
  chk.report(SSRF, call, cls)
}

/** Allow-list or host validation of an outgoing URL. */
const URL_CHECK =
  /allow(?:ed)?_?(?:list|hosts?|origins?|domains?|urls?)|white_?list|ALLOWED_|is_allowed\w*\s*\(|is_safe_url|validate_url|\.(?:hostname|netloc)\s*(?:==|!=|not\s+in|in)\s/i

function templateInjection(chk: Checker, call: CallFact, q: string): void {
  if (!TEMPLATE_FUNCS.test(q)) return
  if (
    q === 'Template' &&
    !chk.imports(/^(?:jinja2|django\.template|mako\.template)$/) &&
    !chk.importedFrom('Template', /jinja2|django|mako/)
  )
    return
  if (q === 'string.Template' || chk.importedFrom('Template', /^string\./)) return
  const source = chk.positional(call, 0) ?? chk.keyword(call, 'source')
  if (!source) return
  chk.check(SSTI, call, chk.ex.taintResolved(source), chk.dynamic(source))
}

function safeHtml(chk: Checker, call: CallFact, q: string): void {
  if (!SAFE_HTML_FUNCS.test(q)) return
  const value = chk.positional(call, 0)
  if (!value) return
  if (chk.values(value).every(v => isSanitizerCall(chk, v))) return
  chk.check(XSS, call, chk.ex.taintResolved(value), chk.dynamic(value))
}

function openRedirect(chk: Checker, call: CallFact, q: string): void {
  if (!REDIRECT_FUNCS.test(q)) return
  const target =
    chk.positional(call, 0) ??
    chk.keyword(call, 'url') ??
    chk.keyword(call, 'location') ??
    chk.keyword(call, 'redirect_to')
  if (!target) return
  const taint = chk.ex.taintResolved(target)
  if (!taint) return
  if ([target, ...chk.values(target)].some(v => chk.ex.hasFixedOrigin(v))) return
  const cls = classify(REDIRECT, taint)
  if (!cls) return
  if (REDIRECT_CHECK.test(chk.scopeText(call.start))) {
    chk.report(
      REDIRECT,
      call,
      { kind: 'sink', confidence: 'low', taint },
      { note: 'Some URL validation appears in the same function.' },
    )
  } else chk.report(REDIRECT, call, cls)
}

function debugRun(chk: Checker, call: CallFact): void {
  if (
    call.name !== 'run' ||
    call.receiver === '' ||
    !/(?:^|\.)(?:app|application|server|socketio)$/.test(call.receiver)
  )
    return
  const debug = chk.keyword(call, 'debug') ?? chk.keyword(call, 'use_debugger')
  if (!debug || !chk.ex.isWord(debug, 'True', '1')) return
  const devPath = /(?:^|\/)(?:dev|local)[^/]*|(?:^|[/_.-])(?:dev|local|debug)(?:[/_.-]|$)/i.test(chk.path)
  const inMain = /if\s+__name__\s*==\s*['"]__main__['"]/.test(
    chk.model.source.slice(Math.max(0, call.start - 2000), call.start),
  )
  chk.certain(DEBUG, call, 'high', {
    severity: devPath ? 'low' : 'medium',
    ...(inMain
      ? {
          note: 'It is inside `if __name__ == "__main__":`, so it applies when the file is started directly (often in development).',
        }
      : {}),
  })
}

function tlsVerify(chk: Checker, call: CallFact, q: string): void {
  const verify = chk.keyword(call, 'verify')
  if (
    (verify && chk.ex.isWord(verify, 'False') && /^(?:requests|httpx|aiohttp)\b/.test(q)) ||
    (verify &&
      chk.ex.isWord(verify, 'False') &&
      /^(?:get|post|put|patch|delete|head|request|options|stream|Client|AsyncClient|Session)$/.test(call.name) &&
      chk.imports(/^(?:requests|httpx)$/))
  ) {
    chk.certain(TLS, call, 'high')
    return
  }
  if (/^ssl\._create_unverified_context$/.test(q)) {
    chk.certain(TLS, call, 'high')
    return
  }
  const ssl = chk.keyword(call, 'ssl')
  if (ssl && chk.ex.isWord(ssl, 'False') && /^aiohttp\./.test(q)) chk.certain(TLS, call, 'high')
}

function jwtDecode(chk: Checker, call: CallFact, q: string): void {
  if (!/^(?:jwt|jose\.jwt|PyJWT)\.decode$/.test(q) && !(call.callee === 'jwt.decode')) return
  const options = chk.keyword(call, 'options')
  if (options && /['"]verify_signature['"]\s*:\s*False/.test(chk.text(options))) {
    chk.certain(JWT, call, 'high')
    return
  }
  const verify = chk.keyword(call, 'verify')
  if (verify && chk.ex.isWord(verify, 'False')) {
    chk.certain(JWT, call, 'high')
    return
  }
  const algorithms = chk.keyword(call, 'algorithms')
  if (algorithms && chk.ex.elements(algorithms).some(v => chk.ex.literal(v)?.toLowerCase() === 'none'))
    chk.certain(JWT, call, 'high')
}

function weakCrypto(chk: Checker, call: CallFact, q: string): void {
  let weakHash = /^hashlib\.(?:md5|sha1|md4)$/.test(q)
  if (!weakHash && /^hashlib\.new$/.test(q)) {
    const alg = chk.ex.literal(chk.positional(call, 0) ?? { start: 0, end: 0 })
    weakHash = alg !== undefined && /^(?:md5|sha1|md4)$/i.test(alg)
  }
  if (weakHash) {
    if (/usedforsecurity\s*=\s*False/.test(chk.text(call))) return
    if (PASSWORD_CONTEXT.test(chk.statementText(call))) chk.certain(WEAK_HASH, call, 'medium')
    return
  }
  if (
    /^random\.(?:random|randint|randrange|choice|choices|sample|getrandbits|uniform|shuffle)$/.test(q) ||
    (/^(?:randint|randrange|choice|choices|getrandbits)$/.test(call.callee) &&
      chk.importedFrom(call.callee, /^random\./))
  ) {
    const kind = secretContext(chk.contextNames(call))
    if (kind === 'strong') chk.certain(WEAK_RANDOM, call, 'medium')
    else if (kind === 'weak') chk.report(WEAK_RANDOM, call, { kind: 'sink', confidence: 'low' })
  }
}

function massAssignment(chk: Checker, call: CallFact): void {
  if (!MODEL_CALL.test(call.callee)) return
  if (
    /^(?:dict|Response|JsonResponse|jsonify|HttpResponse|Exception|ValueError|TypeError|KeyError|HTTPException|JSONResponse)$/.test(
      call.callee,
    )
  )
    return
  for (const arg of call.args) {
    if (arg.splat !== '**') continue
    const whole = chk.ex.wholeBody(arg)
    if (whole) {
      chk.report(MASS, call, {
        kind: 'vulnerability',
        confidence: chk.wholeBodyConfidence(arg, whole),
        taint: { source: whole, direct: true, origin: 'request' },
      })
      return
    }
  }
  if (call.name === 'update' || call.name === 'update_one') {
    const arg = chk.positional(call, call.name === 'update_one' ? 1 : 0)
    const whole = arg ? chk.ex.wholeBody(arg) : undefined
    if (whole)
      chk.report(MASS, call, {
        kind: 'vulnerability',
        confidence: 'medium',
        taint: { source: whole, direct: true, origin: 'request' },
      })
  }
}

/** Django/Flask settings: DEBUG, ALLOWED_HOSTS, cookie flags and SECRET_KEY. */
function settings(chk: Checker): void {
  const settingsFile =
    /(?:^|\/)(?:settings|config|conf|configuration|local_settings|base)(?:\/[^/]*)?\.py$|(?:^|\/)settings\/[^/]+\.py$/.test(
      chk.path,
    )
  const devPath = /(?:^|[/_.-])(?:dev|development|local|test|testing|debug)(?:[/_.-]|$)/i.test(chk.path)
  const isDjango =
    settingsFile &&
    (chk.model.source.includes('INSTALLED_APPS') ||
      chk.model.source.includes('MIDDLEWARE') ||
      /django/i.test(chk.model.source) ||
      /settings/.test(chk.path))
  for (const assign of chk.model.assigns) {
    if (assign.fn || assign.op !== '=' || assign.targets.length !== 1) continue
    const name = assign.targets[0]!.name
    cookieSetting(chk, name, assign.value, assign)
    if (name === 'DEBUG' && isDjango && chk.ex.isWord(assign.value, 'True')) {
      chk.certain(DEBUG, assign, 'high', { severity: devPath ? 'low' : 'medium' })
    } else if (
      name === 'ALLOWED_HOSTS' &&
      isDjango &&
      chk.ex.elements(assign.value).some(v => chk.ex.literal(v) === '*')
    ) {
      chk.certain(HOSTS, assign, 'high', { severity: devPath ? 'info' : 'low' })
    } else if (name === 'SECRET_KEY') {
      secretKey(chk, assign.value, assign, devPath)
    }
  }
  for (const assign of chk.model.memberAssigns) {
    if (assign.op !== '=') continue
    cookieSetting(chk, assign.prop, assign.value, assign)
    if (
      assign.prop === 'SECRET_KEY' ||
      (assign.prop === 'secret_key' && /(?:^|\.)app$/.test(assign.target.replace(/\.secret_key$/, '')))
    ) {
      secretKey(chk, assign.value, assign, devPath)
    }
  }
  for (const call of chk.model.calls) {
    if (call.name !== 'update' || !/(?:^|\.)config$/.test(call.receiver)) continue
    for (const name of ['SESSION_COOKIE_SECURE', 'CSRF_COOKIE_SECURE', 'SESSION_COOKIE_HTTPONLY']) {
      const flag = chk.keyword(call, name)
      if (flag) cookieSetting(chk, name, flag, flag)
    }
    const value = chk.keyword(call, 'SECRET_KEY')
    if (value) secretKey(chk, value, call, devPath)
  }
}

function cookieSetting(chk: Checker, name: string, value: Span, at: Span): void {
  if (!chk.ex.isWord(value, 'False')) return
  if (name === 'SESSION_COOKIE_SECURE' || name === 'CSRF_COOKIE_SECURE') chk.certain(COOKIE_SECURE, at, 'high')
  else if (name === 'SESSION_COOKIE_HTTPONLY') chk.certain(COOKIE_HTTPONLY, at, 'high')
}

const PLACEHOLDER_SECRET =
  /^(?:|changeme|change[-_ ]?me|replace[-_ ]?me|secret|dev|development|test|testing|example|dummy|placeholder|insecure|unsafe|xxx+|\*+|your[-_ ]?secret[-_ ]?key(?:[-_ ]?here)?|todo|none|null)$/i

function secretKey(chk: Checker, value: Span, at: Span, devPath: boolean): void {
  const lit = chk.ex.literal(value)
  if (lit === undefined) {
    // `os.environ.get("SECRET_KEY", "fallback-literal")`
    const call = callAt(chk.model, value)
    if (
      !call ||
      !/^(?:os\.environ\.get|os\.getenv|environ\.get|env|config)$/.test(
        chk.qualify(call.callee).replace(/^os\.environ\.get$/, 'os.environ.get'),
      )
    )
      return
    const fallback = chk.positional(call, 1) ?? chk.keyword(call, 'default')
    const fb = fallback ? chk.ex.literal(fallback) : undefined
    if (!fallback || fb === undefined || fb.length < 8 || PLACEHOLDER_SECRET.test(fb.trim())) return
    chk.certain(SECRET_KEY, at, 'medium', {
      severity: devPath ? 'low' : 'medium',
      mask: [fallback],
      note: 'The key comes from the environment, but a hard-coded fallback is used whenever the variable is missing.',
    })
    return
  }
  const trimmed = lit.trim()
  if (trimmed.length < 8 || PLACEHOLDER_SECRET.test(trimmed) || /^django-insecure-?$/.test(trimmed)) return
  const insecure = trimmed.startsWith('django-insecure-')
  chk.certain(SECRET_KEY, at, 'high', {
    severity: devPath ? 'low' : insecure ? 'medium' : 'high',
    mask: [value],
    ...(insecure
      ? {
          note: 'The `django-insecure-` prefix marks a generated development key; make sure production uses a different one.',
        }
      : {}),
  })
}

function classify(rule: RuleMeta, taint: Taint): Classification | undefined {
  const origins = rule.origins ?? ['request']
  if (origins.includes(taint.origin))
    return { kind: 'vulnerability', confidence: taint.direct ? 'high' : 'medium', taint }
  if (!rule.sinkSeverity) return undefined
  return {
    kind: 'sink',
    confidence: 'low',
    taint,
    note: 'The value comes from command-line arguments or standard input, so it only matters if untrusted people can run this program or control its input.',
  }
}
