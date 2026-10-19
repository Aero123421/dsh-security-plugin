/**
 * JavaScript/TypeScript (JSX/TSX included) rules, plus text rules for
 * server-side template files (EJS, Handlebars, Pug) and Vue/Svelte markup.
 *
 * Every rule works on the shared code model, so it behaves the same whether
 * the model came from the native AST or from the token fallback.
 */

import {
  Checker,
  isCredentialComparison,
  isSanitizerCall,
  lastName,
  type PropMatch,
  rootName,
  secretContext,
} from './helpers.ts'
import type { ArgFact, CallFact, FileModel, Span } from './model.ts'
import {
  type Classification,
  cweUrl,
  type FileContext,
  DOT_SEGMENT_NOTE,
  GUARDED_NOTE,
  REF,
  type RuleMeta,
  sanitizedBy,
} from './rule.ts'
import { callAt, type Taint } from './taint.ts'

// ---------------------------------------------------------------------------
// Rule metadata
// ---------------------------------------------------------------------------

const SQLI: RuleMeta = {
  id: 'js.sql-injection',
  title: 'SQL injection',
  sinkTitle: 'SQL query built from a dynamic string',
  category: 'injection',
  cwe: 'CWE-89',
  severity: 'high',
  sinkSeverity: 'medium',
  message:
    'This database query is built by gluing text together (string concatenation or a template literal with substitutions) with data from the HTTP request. ' +
    "An attacker can send input containing SQL syntax (for example `' OR 1=1 --`) that changes what the query does: reading other users' data, skipping login checks, or changing and deleting records.",
  sinkMessage:
    'This database query is built by gluing text together with a value whose origin is not visible here. If that value can ever contain user input, an attacker could change the meaning of the query (SQL injection).',
  recommendation:
    'Never build SQL with `+` or template-literal substitutions. Pass values separately as query parameters (placeholders such as `?` or `$1` plus a values array), or use a safe tagged template such as Prisma `$queryRaw`...`` or the `sql` tag. If a table or column name must vary, choose it from a fixed allow-list.',
  references: [REF.injection, cweUrl('CWE-89')],
}

const NOSQLI: RuleMeta = {
  id: 'js.nosql-injection',
  title: 'NoSQL (MongoDB) query injection',
  sinkTitle: 'MongoDB `$where` with a dynamic string',
  category: 'injection',
  cwe: 'CWE-943',
  severity: 'high',
  sinkSeverity: 'medium',
  message:
    'A MongoDB query filter is taken from the request body or query string. JSON bodies and `?a[$ne]=` style query strings can contain objects, so an attacker can send operators such as `{"$ne": null}` or `{"$gt": ""}` instead of a plain value and match records they should not (for example logging in without the right password).',
  sinkMessage:
    'MongoDB `$where` runs JavaScript on the database server. Building it from a dynamic string lets anyone who controls that string run arbitrary database-side code.',
  recommendation:
    'Build the filter yourself from expected fields and force each value to the expected type, e.g. `{ username: String(req.body.username) }`. Validate input with a schema (zod, Joi, express-validator), enable Mongoose `sanitizeFilter`, or use `express-mongo-sanitize`. Avoid `$where` entirely.',
  references: [REF.injection, cweUrl('CWE-943')],
}

const CMDI: RuleMeta = {
  id: 'js.command-injection',
  title: 'OS command injection',
  sinkTitle: 'Shell command built from a dynamic value',
  category: 'command-execution',
  cwe: 'CWE-78',
  severity: 'critical',
  sinkSeverity: 'medium',
  message:
    'Request data ends up in a command that is run through a shell (`child_process.exec`, or `spawn`/`execFile` with `shell: true`). Shell syntax such as `;`, `&&`, `|` or `$(...)` in the input lets an attacker run any program on the server.',
  sinkMessage:
    'A command is run through a shell with a value that is not a fixed string. If that value can contain user input, an attacker could inject extra shell commands.',
  recommendation:
    'Use `execFile`/`spawn` with the program name and an array of arguments and without `shell: true`, so input is never interpreted by a shell. Validate arguments against an allow-list and put `--` before user-supplied file names so they cannot be read as options.',
  references: [REF.injection, cweUrl('CWE-78')],
  origins: ['request'],
}

const CODEI: RuleMeta = {
  id: 'js.code-injection',
  title: 'Code injection (dynamic evaluation of user input)',
  sinkTitle: 'Dynamic code evaluation',
  category: 'injection',
  cwe: 'CWE-95',
  severity: 'critical',
  sinkSeverity: 'medium',
  message:
    'Request data is executed as JavaScript (`eval`, `new Function`, the `vm` module, or a string passed to `setTimeout`/`setInterval`). An attacker can send code that runs with the full permissions of the application: reading files and secrets, or taking over the server.',
  sinkMessage:
    'A value that is not a fixed string is executed as JavaScript. If it can ever contain user input, an attacker could run their own code. Note that the `vm` module is not a security sandbox.',
  recommendation:
    'Do not evaluate strings as code. Parse data with `JSON.parse`, map allowed operation names to functions with a lookup table, and pass functions (not strings) to `setTimeout`/`setInterval`.',
  references: [REF.injection, cweUrl('CWE-95'), cweUrl('CWE-94')],
}

const PATH: RuleMeta = {
  id: 'js.path-traversal',
  title: 'Path traversal',
  sinkTitle: 'File operation on a dynamic path (check where it comes from)',
  category: 'path-traversal',
  cwe: 'CWE-22',
  severity: 'high',
  sinkSeverity: 'low',
  message:
    'A file path is built from request data and then read, written, deleted or sent back. Sequences like `../` (or an absolute path) let an attacker reach files outside the intended folder, such as source code, `.env` files or system files.',
  sinkMessage:
    'A file operation receives a path that is not a fixed value. If any part of it can come from users (a request, an upload name, a stored record), `../` or an absolute path can reach files outside the intended folder.',
  recommendation:
    'Strip directories with `path.basename()`, or resolve the full path with `path.resolve(baseDir, input)` and reject it unless it starts with `baseDir + path.sep`. For downloads prefer `res.sendFile(name, { root: baseDir })`, or map IDs to file names on the server.',
  references: [REF.accessControl, cweUrl('CWE-22')],
}

const SSRF: RuleMeta = {
  id: 'js.ssrf',
  title: 'Server-side request forgery (SSRF)',
  sinkTitle: 'Outgoing request to a dynamic URL (check where it comes from)',
  category: 'ssrf',
  cwe: 'CWE-918',
  severity: 'high',
  sinkSeverity: 'low',
  message:
    'The server makes an HTTP request to a URL taken from the incoming request. An attacker can point it at internal services, cloud metadata endpoints (such as `http://169.254.169.254/`) or `localhost` admin panels that are not reachable from the internet.',
  sinkMessage:
    'The server sends a request to a URL that is not a fixed value. If users can influence it (a request parameter, a webhook or callback URL they registered, a stored record), they can make the server call internal services or cloud metadata endpoints.',
  recommendation:
    'Do not fetch arbitrary URLs. Map user choices to known URLs, or parse the URL with `new URL()` and allow only expected schemes and host names. Block private and link-local IP ranges after DNS resolution, and disable redirects or re-check every redirect target.',
  references: [REF.ssrf, cweUrl('CWE-918')],
}

const REDIRECT: RuleMeta = {
  id: 'js.open-redirect',
  title: 'Open redirect',
  sinkTitle: 'Redirect to a dynamic URL (check where it comes from and how it is validated)',
  category: 'business-logic',
  cwe: 'CWE-601',
  severity: 'medium',
  sinkSeverity: 'low',
  message:
    'The response redirects the browser to a URL taken from the request. Attackers can craft links on your trusted domain that bounce victims to a phishing site, or leak tokens in OAuth-style flows.',
  sinkMessage:
    'The response redirects to a URL that is not a fixed value. If users can influence it, they can send victims to another site; confirm that only relative paths or allow-listed hosts pass and that protocol-relative (`//evil.com`) and `javascript:` URLs are rejected.',
  recommendation:
    'Redirect only to relative paths you control or to an allow-list of hosts. Parse the target with `new URL(target, base)` and check its origin, or accept a short key and map it to a known URL on the server.',
  references: [REF.accessControl, cweUrl('CWE-601')],
}

const XSS_SERVER: RuleMeta = {
  id: 'js.xss',
  title: 'Reflected cross-site scripting (XSS)',
  category: 'xss',
  cwe: 'CWE-79',
  severity: 'high',
  message:
    'Request data is written into an HTTP response as raw text/HTML (`res.send`/`res.write`). An attacker can make a victim open a link whose input contains `<script>`, which then runs in the victim’s browser with their session on your site.',
  recommendation:
    'Return JSON with `res.json()`, or render HTML with a template engine that escapes by default. If you must build HTML by hand, escape every dynamic value (for example with `escape-html`) and set a Content Security Policy.',
  references: [REF.injection, cweUrl('CWE-79')],
}

const XSS_DOM: RuleMeta = {
  id: 'js.xss',
  title: 'Cross-site scripting (XSS) via an HTML sink',
  sinkTitle: 'Dynamic HTML written to the page',
  category: 'xss',
  cwe: 'CWE-79',
  severity: 'high',
  sinkSeverity: 'low',
  message:
    'Data an attacker controls (for example the URL or request input) is inserted into the page as HTML (`innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write` or React `dangerouslySetInnerHTML`). Markup such as `<img src=x onerror=...>` in that data runs as script in the user’s browser.',
  sinkMessage:
    'A dynamic value is inserted into the page as raw HTML. If it can contain user-controlled text that is not sanitized, it allows cross-site scripting.',
  recommendation:
    'Insert text with `textContent` or normal JSX `{value}` (both escape automatically). If you really need HTML, sanitize it with a maintained library such as DOMPurify right before inserting it.',
  references: [REF.injection, cweUrl('CWE-79')],
  origins: ['request', 'browser'],
}

/** Markdown rendered to HTML by a renderer that passes raw HTML through, then inserted unsanitized. */
const XSS_MARKDOWN: RuleMeta = {
  id: 'js.xss',
  title: 'Cross-site scripting (XSS) via Markdown rendered as raw HTML',
  category: 'xss',
  cwe: 'CWE-79',
  severity: 'high',
  message:
    'Markdown is converted to HTML and inserted into the page as raw HTML (`dangerouslySetInnerHTML`, `innerHTML`) without sanitizing the result. The renderer used here (`marked`, `showdown`, `markdown-it` with `html: true`, or a remark/rehype pipeline that allows raw HTML) copies HTML written inside the Markdown straight into its output, so text such as `<img src=x onerror=...>` from whoever wrote the Markdown runs as script in every reader’s browser.',
  recommendation:
    'Sanitize the generated HTML right before inserting it, for example `DOMPurify.sanitize(marked.parse(text))`, `sanitize-html`, or `rehype-sanitize` in a unified pipeline. Or render Markdown without raw HTML: `markdown-it` with its default `html: false`, or `react-markdown` without `rehype-raw`.',
  references: [REF.injection, cweUrl('CWE-79')],
}

const XSS_TEMPLATE: RuleMeta = {
  id: 'js.template-unescaped-output',
  title: 'Unescaped template output',
  sinkTitle: 'Unescaped template output (possible XSS)',
  category: 'xss',
  cwe: 'CWE-79',
  severity: 'medium',
  sinkSeverity: 'low',
  message:
    'This template prints a value without HTML escaping (EJS `<%-`, Handlebars `{{{ }}}`, Pug `!=`/`!{}`, Vue `v-html` or Svelte `{@html}`). If the value can contain user input, it allows cross-site scripting.',
  recommendation:
    'Use the escaping form (`<%=`, `{{ }}`, `=`/`#{}`, text interpolation) unless the value is trusted HTML. Sanitize user-provided HTML (for example with DOMPurify or sanitize-html) before printing it unescaped.',
  references: [REF.injection, cweUrl('CWE-79')],
}

const DESER: RuleMeta = {
  id: 'js.insecure-deserialization',
  title: 'Insecure deserialization (node-serialize)',
  sinkTitle: 'node-serialize unserialize() on dynamic data',
  category: 'deserialization',
  cwe: 'CWE-502',
  severity: 'critical',
  sinkSeverity: 'medium',
  message:
    '`node-serialize` `unserialize()` can recreate functions and run them (the `_$$ND_FUNC$$_` marker). Passing it data an attacker controls lets them execute code on the server.',
  recommendation:
    'Use `JSON.parse` for data exchange and validate the result with a schema. Remove `node-serialize`; it has a known, unfixed remote code execution issue.',
  references: [REF.integrity, cweUrl('CWE-502')],
}

const YAML_LOAD: RuleMeta = {
  id: 'js.unsafe-yaml-load',
  title: 'js-yaml load() on dynamic data',
  sinkTitle: 'js-yaml load() on dynamic data',
  category: 'deserialization',
  cwe: 'CWE-502',
  severity: 'medium',
  sinkSeverity: 'low',
  message:
    'In js-yaml before version 4, `load()` understands JavaScript-specific tags (such as `!!js/function`) and can create functions from YAML. The installed version is not visible here, so this is a review hint.',
  recommendation:
    'Upgrade to js-yaml 4 or later (where `load` is safe), or use `safeLoad` on 3.x. Never feed untrusted YAML to a loader that supports custom tags.',
  references: [REF.integrity, cweUrl('CWE-502')],
  origins: [],
}

const WEAK_HASH: RuleMeta = {
  id: 'js.weak-password-hash',
  title: 'Weak hash used for passwords',
  category: 'crypto',
  cwe: 'CWE-328',
  severity: 'medium',
  message:
    'MD5 and SHA-1 are fast, broken hash functions. Passwords hashed with them (even with a salt) can be cracked quickly with GPUs or looked up in precomputed tables if the database leaks.',
  recommendation:
    'Hash passwords with a slow, salted password hashing function: Argon2id (`argon2`), `bcrypt`, or `crypto.scrypt`. Use SHA-256 or better for non-password integrity checks.',
  references: [REF.crypto, cweUrl('CWE-328'), cweUrl('CWE-916')],
}

const WEAK_CIPHER: RuleMeta = {
  id: 'js.weak-cipher',
  title: 'Weak or deprecated encryption',
  category: 'crypto',
  cwe: 'CWE-327',
  severity: 'medium',
  message:
    '`crypto.createCipher`/`createDecipher` derive the key with a single MD5 pass and use no random IV, so identical messages encrypt identically and keys are easy to brute-force. DES, RC4, Blowfish and ECB mode are similarly weak.',
  recommendation:
    'Use `crypto.createCipheriv` with an authenticated mode such as `aes-256-gcm`, a random 12-byte IV per message, and a key derived with `crypto.scrypt` or loaded from a key manager.',
  references: [REF.crypto, cweUrl('CWE-327')],
}

const WEAK_RANDOM: RuleMeta = {
  id: 'js.insecure-random',
  title: 'Predictable random value used as a secret',
  sinkTitle: 'Math.random() used near a security-sensitive name',
  category: 'crypto',
  cwe: 'CWE-330',
  severity: 'medium',
  sinkSeverity: 'low',
  message:
    '`Math.random()` is not cryptographically secure: its output can be predicted after observing a few values. Tokens, passwords, reset codes or session IDs built from it can be guessed by an attacker.',
  sinkMessage:
    '`Math.random()` is used where the surrounding names suggest a key, session or code. If the value protects anything, it can be predicted.',
  recommendation:
    'Use `crypto.randomBytes(32).toString("hex")`, `crypto.randomUUID()`, or `crypto.getRandomValues()` in the browser for anything that must be unguessable.',
  references: [REF.crypto, cweUrl('CWE-330'), cweUrl('CWE-338')],
}

const JWT_NONE: RuleMeta = {
  id: 'js.jwt-none-algorithm',
  title: 'JWT "none" algorithm allowed',
  category: 'authn',
  cwe: 'CWE-347',
  severity: 'high',
  message:
    'The JWT configuration allows the `none` algorithm, which means "no signature". Anyone can then create a token with any user ID or role and it will be accepted.',
  recommendation:
    'List only the algorithm you actually sign with, e.g. `jwt.verify(token, key, { algorithms: ["HS256"] })`, and never `none`.',
  references: [REF.authn, cweUrl('CWE-347')],
}

const JWT_DECODE: RuleMeta = {
  id: 'js.jwt-decode-without-verify',
  title: 'JWT decoded without signature verification',
  category: 'authn',
  cwe: 'CWE-347',
  severity: 'medium',
  message:
    'This function reads the `Authorization` header and calls `jwt.decode()`, which only base64-decodes the token and does not check its signature. If the decoded claims are used for authentication, anyone can forge a token.',
  recommendation:
    'Use `jwt.verify(token, key, { algorithms: [...] })` and trust only its result. Use `decode()` only for non-security purposes such as logging.',
  references: [REF.authn, cweUrl('CWE-347')],
}

const JWT_EXPIRY: RuleMeta = {
  id: 'js.jwt-ignore-expiration',
  title: 'JWT expiration ignored',
  category: 'authn',
  cwe: 'CWE-613',
  severity: 'low',
  message:
    '`ignoreExpiration: true` accepts tokens after their `exp` time, so a stolen or old token keeps working forever.',
  recommendation: 'Remove `ignoreExpiration`, keep token lifetimes short, and use refresh tokens for long sessions.',
  references: [REF.authn, cweUrl('CWE-613')],
}

const TLS: RuleMeta = {
  id: 'js.tls-verification-disabled',
  title: 'TLS certificate verification disabled',
  category: 'crypto',
  cwe: 'CWE-295',
  severity: 'medium',
  message:
    'Certificate checking is turned off (`rejectUnauthorized: false`, `strictSSL: false` or `NODE_TLS_REJECT_UNAUTHORIZED=0`). Anyone on the network path can impersonate the server and read or change the traffic, including credentials.',
  recommendation:
    'Keep verification on. For internal or self-signed certificates, pass the trusted CA with the `ca` option (or `NODE_EXTRA_CA_CERTS`) instead of disabling checks.',
  references: [REF.crypto, cweUrl('CWE-295')],
}

const CORS: RuleMeta = {
  id: 'js.cors-misconfiguration',
  title: 'Permissive CORS with credentials',
  category: 'misconfiguration',
  cwe: 'CWE-942',
  severity: 'medium',
  message:
    'CORS is configured to accept any origin (reflecting the request’s `Origin`) while also allowing credentials. Any website a logged-in user visits can then call this API with the user’s cookies and read the responses.',
  recommendation:
    'Set `origin` to an explicit allow-list of your front-end origins (for example `["https://app.example.com"]`), and enable `credentials` only for those.',
  references: [REF.misconfig, cweUrl('CWE-942')],
}

const COOKIE_SECURE: RuleMeta = {
  id: 'js.cookie-insecure',
  title: 'Cookie sent without the Secure flag',
  category: 'misconfiguration',
  cwe: 'CWE-614',
  severity: 'low',
  message:
    '`secure: false` lets the browser send this cookie over plain HTTP, where it can be intercepted on public networks.',
  recommendation:
    'Set `secure: true` in production (behind a proxy also set `app.set("trust proxy", 1)`), together with `httpOnly: true` and `sameSite: "lax"` or `"strict"`.',
  references: [REF.misconfig, cweUrl('CWE-614')],
}

const COOKIE_HTTPONLY: RuleMeta = {
  id: 'js.cookie-without-httponly',
  title: 'Cookie readable by JavaScript (httpOnly disabled)',
  category: 'misconfiguration',
  cwe: 'CWE-1004',
  severity: 'low',
  message:
    '`httpOnly: false` lets page scripts read this cookie, so any XSS bug can steal it (for example a session cookie).',
  recommendation: 'Set `httpOnly: true` for session and authentication cookies.',
  references: [REF.misconfig, cweUrl('CWE-1004')],
}

const SESSION_SECRET: RuleMeta = {
  id: 'js.hardcoded-session-secret',
  title: 'Hard-coded session secret',
  category: 'secrets',
  cwe: 'CWE-798',
  severity: 'medium',
  message:
    'The session/cookie signing secret is written in the source. Anyone who can read the code can forge signed session cookies and log in as any user.',
  recommendation:
    'Load the secret from an environment variable or secret manager (e.g. `secret: process.env.SESSION_SECRET`), make it long and random, and rotate it now.',
  references: [REF.authn, cweUrl('CWE-798')],
}

const MASS: RuleMeta = {
  id: 'js.mass-assignment',
  title: 'Mass assignment from the request body',
  category: 'authz',
  cwe: 'CWE-915',
  severity: 'medium',
  message:
    'The whole request body is copied into a database record or object. An attacker can add extra fields the form never shows, such as `isAdmin`, `role`, `ownerId` or `balance`, and change them.',
  recommendation:
    'Copy only the fields you expect (e.g. `const { name, email } = req.body`), or validate with a schema that strips unknown keys (zod `.strict()`/`.pick()`, Joi `stripUnknown`). Restrict writable fields in the ORM where possible.',
  references: [REF.accessControl, cweUrl('CWE-915')],
}

const PROTO: RuleMeta = {
  id: 'js.prototype-pollution',
  title: 'Deep merge of user input (prototype pollution)',
  sinkTitle: 'Deep merge of user input (possible prototype pollution)',
  category: 'injection',
  cwe: 'CWE-1321',
  severity: 'medium',
  sinkSeverity: 'medium',
  message:
    'User input is deep-merged or set by path into an object. Keys such as `__proto__`, `constructor` or `prototype` can then modify `Object.prototype` for the whole process, which can bypass checks or crash the app, depending on the library version.',
  recommendation:
    'Copy only expected fields, validate input with a schema, use up-to-date merge libraries, and reject `__proto__`, `constructor` and `prototype` keys. Objects created with `Object.create(null)` or `Map` are not affected.',
  references: [REF.injection, cweUrl('CWE-1321')],
  origins: [],
}

const REDOS: RuleMeta = {
  id: 'js.regex-injection',
  title: 'Regular expression built from user input (ReDoS)',
  category: 'injection',
  cwe: 'CWE-1333',
  severity: 'medium',
  message:
    'A regular expression is created from request data. An attacker can submit a pattern with catastrophic backtracking (for example `(a+)+$`) that freezes the Node.js event loop, or a pattern that matches far more than intended.',
  recommendation:
    'Escape user input before putting it in a pattern (for example lodash `escapeRegExp`), or use plain string methods like `includes()`. Never accept whole patterns from users.',
  references: [REF.injection, cweUrl('CWE-1333')],
}

const BACKDOOR: RuleMeta = {
  id: 'js.hardcoded-credential-check',
  title: 'Hard-coded credential or backdoor check',
  category: 'authn',
  cwe: 'CWE-798',
  severity: 'medium',
  message:
    'A password, token or special header is compared with a fixed string in the code. Anyone who reads the source (or a leaked build) learns the value and can use it to get in; it also cannot be rotated without a deployment.',
  recommendation:
    'Remove fixed credentials. Verify passwords against salted hashes stored per user, keep API keys in a secret store, and compare secrets with `crypto.timingSafeEqual`.',
  references: [REF.authn, cweUrl('CWE-798'), cweUrl('CWE-287')],
}

/** Every rule of this rule set (several matchers may share one id). */
export const JS_RULES: readonly RuleMeta[] = [
  SQLI,
  NOSQLI,
  CMDI,
  CODEI,
  PATH,
  SSRF,
  REDIRECT,
  XSS_SERVER,
  XSS_TEMPLATE,
  DESER,
  YAML_LOAD,
  WEAK_HASH,
  WEAK_CIPHER,
  WEAK_RANDOM,
  JWT_NONE,
  JWT_DECODE,
  JWT_EXPIRY,
  TLS,
  CORS,
  COOKIE_SECURE,
  COOKIE_HTTPONLY,
  SESSION_SECRET,
  MASS,
  PROTO,
  REDOS,
  BACKDOOR,
]

// ---------------------------------------------------------------------------
// Patterns
// ---------------------------------------------------------------------------

const SQL_METHODS: ReadonlySet<string> = new Set([
  'query',
  'execute',
  'raw',
  '$queryRawUnsafe',
  '$executeRawUnsafe',
  'whereRaw',
  'havingRaw',
  'orderByRaw',
  'groupByRaw',
  'joinRaw',
  'fromRaw',
])
const SQL_ALWAYS =
  /^(?:\$queryRawUnsafe|\$executeRawUnsafe|raw|whereRaw|havingRaw|orderByRaw|groupByRaw|joinRaw|fromRaw)$/
const SQL_RECEIVER =
  /(?:^|\.)(?:db|database|pool|conn|connection|client|sequelize|knex|sql|pg|mysql|sqlite|sqlite3|prisma|tx|trx|transaction|cursor|queryRunner|manager|entityManager|dataSource|repo|repository|[A-Za-z]*(?:Db|DB|Pool|Client|Connection|Repository))$/
const SQL_WORDS =
  /\b(?:select\s[\s\S]*\bfrom|insert\s+into|update\s+[\w"`.]+\s+set|delete\s+from|where\s|order\s+by|group\s+by|union\s+select|create\s+table|drop\s+table|alter\s+table|values\s*\()/i

const MONGO_METHODS: ReadonlySet<string> = new Set([
  'find',
  'findOne',
  'findOneAndUpdate',
  'findOneAndDelete',
  'findOneAndRemove',
  'findOneAndReplace',
  'updateOne',
  'updateMany',
  'update',
  'deleteOne',
  'deleteMany',
  'remove',
  'replaceOne',
  'countDocuments',
  'count',
  'aggregate',
  'distinct',
  'exists',
  'where',
])

/** Receivers whose `update`/`find`/`count`... are not database queries (hashes, arrays, UI state). */
const NOT_A_COLLECTION =
  /(?:^|\.)(?:create(?:Hash|Hmac|Cipher|Cipheriv|Decipher|Decipheriv|Sign|Verify)\(.*\)|hash|hasher|hmac|digest|md5|sha\d*|cipher|decipher|signer|verifier|progress\w*|bar|spinner|state|setState|store|form|editor|chart|cache|map|set|params|searchParams|headers|cookies|res|response|req|request|ctx|router|app|crypto|_|lodash|Array\.prototype|Object)$|^(?:crypto|node:crypto)\.|^\[/i
/** Mongo methods whose first argument is a filter only when an update document follows. */
const MONGO_UPDATE = /^(?:update|updateOne|updateMany|replaceOne|findOneAndUpdate|findOneAndReplace)$/

const CP_SHELL =
  /^(?:child_process\.(?:exec|execSync)|shelljs\.exec|execa\.(?:execaCommand|execaCommandSync|command|commandSync))$/
const CP_SPAWN = /^(?:child_process\.(?:spawn|spawnSync|execFile|execFileSync)|execa(?:\.(?:execa|execaSync|sync))?)$/

const FS_OPS =
  /^(?:fs|fs\.promises)\.(?:readFile|readFileSync|createReadStream|createWriteStream|writeFile|writeFileSync|appendFile|appendFileSync|unlink|unlinkSync|rm|rmSync|rmdir|rmdirSync|readdir|readdirSync|open|openSync|copyFile|copyFileSync|rename|renameSync|mkdir|mkdirSync|access|accessSync|stat|statSync|lstat|lstatSync|exists|existsSync|readlink|readlinkSync|symlink|symlinkSync|truncate|truncateSync|chmod|chmodSync|chown|chownSync|cp|cpSync|opendir|opendirSync|outputFile|outputFileSync|remove|removeSync|readJson|readJsonSync|writeJson|writeJsonSync|readJSON|writeJSON|pathExists|ensureFile|move|moveSync|copy|copySync)$/
/** File-system calls that only inspect or prepare paths (no file content is read, written or removed). */
const FS_METADATA =
  /^(?:readdir|mkdir|access|stat|lstat|exists|readlink|chmod|chown|opendir|pathExists|ensureDir|mkdirp)(?:Sync)?$/
const RES_RECEIVER = /^(?:res|response|resp|ctx\.res|reply\.raw)$/
const CONTAINMENT_CHECK =
  /\.startsWith\s*\(|\.indexOf\s*\(\s*['"`]\.\.|\.includes\s*\(\s*['"`]\.\.|isPathInside|path\.relative\s*\(|is_relative_to|commonpath/

const HTTP_GLOBALS =
  /^(?:fetch|window\.fetch|globalThis\.fetch|axios(?:\.(?:get|post|put|patch|delete|head|options|request))?)$/
const HTTP_IMPORTED =
  /^(?:undici\.(?:request|fetch|stream)|got(?:\.(?:get|post|put|patch|delete|head|stream))?|needle(?:\.(?:get|post|put|patch|delete|head|request))?|superagent(?:\.(?:get|post|put|patch|delete|head))?|request(?:-promise(?:-native)?)?(?:\.(?:get|post|put|patch|del|delete|head))?|(?:http|https)\.(?:get|request)|ky(?:\.(?:get|post|put|patch|delete|head))?|phin|axios\.(?:get|post|put|patch|delete|head|options|request))$/

const REDIRECT_RECEIVER = /^(?:res|response|ctx|reply|context|c)$/
const REDIRECT_CHECK =
  /allow(?:ed)?(?:list|Hosts?|Origins?|Domains?|Redirects?)|white_?list|isSafe(?:Url|Redirect)|isValid(?:Url|Redirect)|isRelative|isLocalUrl|\.startsWith\s*\(\s*['"`]\/['"`]|new URL\([^)]*\)\.(?:host|hostname|origin)/i

const PLAIN_CONTENT_TYPE =
  /(?:\.type|\.contentType|\.set(?:Header)?|\.header|\.writeHead)\s*\([^)]*['"`](?:text\/plain|application\/json|json|text)['"`]|['"`]Content-Type['"`]\s*[:,]\s*['"`](?:text\/plain|application\/json)/i

const MERGE_QUALIFIED =
  /^(?:lodash|underscore)\.(?:merge|mergeWith|defaultsDeep|set|setWith|zipObjectDeep)$|^(?:lodash\.merge|lodash\.set|merge-deep|deepmerge|deep-extend|defaults-deep|mixin-deep|set-value|dset|dot-prop\.set)(?:\.default)?$/
const MERGE_BARE =
  /^(?:_\.(?:merge|mergeWith|defaultsDeep|set|setWith)|merge|deepmerge|deepMerge|mergeDeep|deepExtend|defaultsDeep)$/

/**
 * Receivers that write records: model classes (`User`, `db.User`), Prisma delegates (`prisma.user`), model and
 * repository instances (`userModel`, `this.orderRepository`, `repo`, `em`, `entityManager`), and Knex query
 * builders (`knex('users')`).
 */
const ORM_RECEIVER =
  /^(?:(?:[\w$]+\.)*[A-Z][A-Za-z0-9]*|[\w$]*(?:Model|Models|Repository|Repo|Entity|Collection|Dao|DAO)|(?:prisma|tx|trx|db|database)\.[a-z][\w$]*|(?:repo|repository|em|entityManager|manager|model|collection|queryRunner\.manager)|(?:knex|db|trx|tx|database|qb|sql)\((['"`])[\w.]+\1\))$/
/** Names that are services, controllers, clients or framework objects even when capitalized. */
const NOT_A_MODEL =
  /(?:Service|Services|Controller|Handler|Client|Api|API|Error|Exception|Response|Request|Router|Factory|Helper|Manager|Validator|Schema|Dto|DTO|Store|Cache|Map|Set)$|^(?:res|response|req|request|ctx|map|cache|headers|searchParams|params|formData|localStorage|sessionStorage|Object|Array|Promise|Reflect|JSON|Math|Date)$/
const PASSWORD_CONTEXT = /passw(?:or)?d|passwd|\bpwd\b|passphrase/i
const AUTH_HEADER_READ =
  /headers\s*(?:\.\s*authorization|\[\s*['"`]authorization['"`]\s*\])|\.(?:get|header)\s*\(\s*['"`]authorization['"`]\s*\)/i
const SAFE_SENTINEL_OBJECT = /^\{\s*\}$/

// ---------------------------------------------------------------------------
// Entry points
// ---------------------------------------------------------------------------

/** Run the JavaScript/TypeScript rules over one file model. */
export function jsRules(model: FileModel, ctx: FileContext): void {
  const chk = new Checker(model, ctx)
  for (const call of model.calls) {
    if (call.decorator) continue
    const q = chk.qualify(call.callee)
    sqlInjection(chk, call)
    nosqlInjection(chk, call)
    commandInjection(chk, call, q)
    codeInjection(chk, call, q)
    pathTraversal(chk, call, q)
    ssrf(chk, call, q)
    openRedirect(chk, call, q)
    serverXss(chk, call)
    domXssCall(chk, call)
    deserialization(chk, call, q)
    weakCrypto(chk, call, q)
    jwtDecode(chk, call, q)
    corsReflection(chk, call)
    massAssignment(chk, call, q)
    prototypePollution(chk, call, q)
    regexInjection(chk, call)
    sessionSecret(chk, call, q)
  }
  propertyRules(chk)
  memberAssignRules(chk)
  for (const cmp of chk.literalComparisons()) {
    if (isCredentialComparison(chk, cmp)) chk.certain(BACKDOOR, cmp.span, 'medium', { mask: [cmp.literalSpan] })
  }
}

/**
 * Text rules for template files: EJS (`<%-`), Handlebars (`{{{`), Pug
 * (`!=`, `!{}`), Vue `v-html`, Svelte `{@html}`.
 */
export function templateRules(ctx: FileContext): void {
  const { file } = ctx
  const lower = file.path.toLowerCase()
  const content = file.content
  const report = (start: number, end: number, expr: string): void => {
    const e = expr.trim()
    if (e === '' || /^(['"`])[^'"`]*\1$/.test(e) || /^\d+$/.test(e)) return
    ctx.report({ rule: XSS_TEMPLATE, kind: 'sink', span: { start, end }, confidence: 'low' })
  }
  if (lower.endsWith('.ejs')) {
    for (const m of content.matchAll(/<%-([\s\S]*?)[-_]?%>/g)) {
      const expr = m[1] ?? ''
      if (/^\s*(?:include|partial|block|defineContent|contentFor|body\s*$|script\s*$|style\s*$)/.test(expr)) continue
      report(m.index, m.index + m[0].length, expr)
    }
  } else if (/\.(?:hbs|handlebars|mustache)$/.test(lower)) {
    for (const m of content.matchAll(/\{\{\{~?\s*([^}]*?)\s*~?\}\}\}/g)) {
      const expr = m[1] ?? ''
      if (/^(?:>|body$|yield$|\{)/.test(expr.trim())) continue
      report(m.index, m.index + m[0].length, expr)
    }
  } else if (/\.(?:pug|jade)$/.test(lower)) {
    for (const m of content.matchAll(/^[ \t]*[\w.#:-]*(?:\([^)\n]*\))?!=[ \t]*(.+)$/gm))
      report(m.index, m.index + m[0].length, m[1] ?? '')
    for (const m of content.matchAll(/!\{([^}\n]+)\}/g)) report(m.index, m.index + m[0].length, m[1] ?? '')
  } else if (lower.endsWith('.vue')) {
    for (const m of content.matchAll(/\bv-html\s*=\s*"([^"]*)"/g)) report(m.index, m.index + m[0].length, m[1] ?? '')
  } else if (lower.endsWith('.svelte')) {
    for (const m of content.matchAll(/\{@html\s+([^}]+)\}/g)) report(m.index, m.index + m[0].length, m[1] ?? '')
  }
}

// ---------------------------------------------------------------------------
// Call rules
// ---------------------------------------------------------------------------

function sqlInjection(chk: Checker, call: CallFact): void {
  const predicate = /^(?:where|andWhere|orWhere)$/.test(call.name)
  const literal = /^(?:sequelize|@sequelize\/core)\.literal$/.test(chk.qualify(call.callee))
  if (call.tagged || (!predicate && !literal && !SQL_METHODS.has(call.name)) || (!literal && call.receiver === ''))
    return
  const arg = chk.positional(call, 0)
  if (!arg || chk.ex.isObjectLiteral(arg) || chk.ex.isArrayLiteral(arg)) return
  const values = chk.values(arg)
  const exact = chk.ex.exactSource(arg)
  const built = values.some(v => chk.ex.isStringBuilt(v) && !chk.ex.isConstant(v))
  if ((!built && !exact) || (predicate && !built && !isSqlQueryBuilder(chk, call))) return
  if (!predicate && !literal && !SQL_ALWAYS.test(call.name)) {
    const text = values.map(v => chk.text(v)).join(' ')
    if (!SQL_WORDS.test(text) && !SQL_RECEIVER.test(call.receiver)) return
  }
  const taint = exact ?? chk.ex.taintResolved(arg)
  chk.check(SQLI, call, taint, true)
}

/** Structural SQL-builder evidence; do not turn ambiguous Mongo where(object) into SQL. */
function isSqlQueryBuilder(chk: Checker, call: CallFact): boolean {
  return (
    /^(?:andWhere|orWhere)$/.test(call.name) ||
    /\.createQueryBuilder\(/.test(call.receiver) ||
    chk.model.calls.some(
      c => c.fn === call.fn && c.receiver === call.receiver && /^(?:andWhere|orWhere)$/.test(c.name),
    ) ||
    chk.model.assigns.some(
      a =>
        a.fn === call.fn &&
        a.targets.some(t => t.name === call.receiver) &&
        /\bcreateQueryBuilder\s*\(/.test(chk.text(a.value)),
    )
  )
}

function nosqlInjection(chk: Checker, call: CallFact): void {
  if (!MONGO_METHODS.has(call.name) || call.receiver === '' || call.tagged) return
  if (call.name === 'where' && isSqlQueryBuilder(chk, call)) return
  if (NOT_A_COLLECTION.test(call.receiver) || NOT_A_COLLECTION.test(chk.qualify(call.receiver))) return
  // `instance.update(values)` (Sequelize, TypeORM) is mass assignment, not a query filter, and
  // Sequelize `Model.update(values, { where })` takes the filter second.
  if (MONGO_UPDATE.test(call.name)) {
    const second = chk.positional(call, 1)
    if (!second || (chk.ex.isObjectLiteral(second) && chk.ex.prop(second, 'where'))) return
  }
  // `fs.remove(path)` / `fs.exists(path)` (fs-extra) are file operations.
  if (/^fs(?:\.promises)?$/.test(chk.qualify(call.receiver))) return
  const filter = chk.positional(call, 0)
  if (!filter) return
  const exact = chk.ex.exactSource(filter)
  if (exact && exact.origin === 'request' && /body|query|json/i.test(exact.source)) {
    chk.report(NOSQLI, call, { kind: 'vulnerability', confidence: exact.direct ? 'high' : 'medium', taint: exact })
    return
  }
  if (!chk.ex.isObjectLiteral(filter)) return
  for (const entry of chk.ex.objectEntries(filter)) {
    if (!entry.value) continue
    if (entry.key === '$where') {
      if (chk.ex.isFunctionLike(entry.value)) continue
      const taint = chk.ex.taintResolved(entry.value)
      chk.check(NOSQLI, call, taint, chk.dynamic(entry.value))
      return
    }
    if (entry.spread) {
      const whole = chk.ex.wholeBody(entry.value)
      if (whole) {
        chk.report(NOSQLI, call, {
          kind: 'vulnerability',
          confidence: 'medium',
          taint: { source: whole, direct: true, origin: 'request' },
        })
        return
      }
      continue
    }
    const src = chk.ex.exactSource(entry.value)
    if (src && src.origin === 'request' && /body|query|json/i.test(src.source)) {
      chk.report(NOSQLI, call, { kind: 'vulnerability', confidence: 'medium', taint: src })
      return
    }
  }
}

function commandInjection(chk: Checker, call: CallFact, q: string): void {
  if (CP_SHELL.test(q)) {
    const cmd = chk.positional(call, 0)
    if (!cmd) return
    chk.check(CMDI, call, chk.ex.taintResolved(cmd), chk.dynamic(cmd))
    return
  }
  if (!CP_SPAWN.test(q)) return
  const cmd = chk.positional(call, 0)
  if (!cmd) return
  const argv = call.args[1] && chk.ex.isArrayLiteral(call.args[1]) ? call.args[1] : undefined
  // `spawn('sh', ['-c', cmd])` runs a shell explicitly.
  const program = chk.ex.literal(cmd)
  if (
    program &&
    argv &&
    /^(?:\/(?:usr\/)?bin\/)?(?:sh|bash|zsh|dash|ksh|cmd(?:\.exe)?|powershell(?:\.exe)?|pwsh)$/i.test(program)
  ) {
    const elements = chk.ex.elements(argv)
    const flag = elements.findIndex(e => /^(?:-c|\/c|-Command)$/i.test(chk.ex.literal(e) ?? ''))
    const script = flag >= 0 ? elements[flag + 1] : undefined
    if (script) chk.check(CMDI, call, chk.ex.taintResolved(script), chk.dynamic(script))
    return
  }
  const options = [...call.args].reverse().find(arg => !arg.splat && chk.ex.isObjectLiteral(arg))
  if (!options) return
  const shell = chk.ex.prop(options, 'shell')
  if (!shell || chk.ex.isWord(shell, 'false', 'undefined', 'null')) return
  const taint = chk.ex.taintResolved(cmd) ?? (argv ? chk.ex.taintResolved(argv) : undefined)
  const dynamic = chk.dynamic(cmd) || (argv !== undefined && chk.dynamic(argv))
  chk.check(CMDI, call, taint, dynamic, { note: 'The `shell: true` option makes the arguments go through a shell.' })
}

function codeInjection(chk: Checker, call: CallFact, q: string): void {
  let code: Span[] = []
  if (/^(?:window\.|globalThis\.)?eval$/.test(call.callee)) code = call.args.slice(0, 1)
  else if (call.callee === 'Function' || call.callee === 'window.Function') code = [...call.args]
  else if (/^vm\.(?:runInNewContext|runInThisContext|runInContext|compileFunction|Script|SourceTextModule)$/.test(q)) {
    code = call.args.slice(0, 1)
  } else if (/^(?:window\.|globalThis\.)?(?:setTimeout|setInterval)$/.test(call.callee)) {
    const arg = call.args[0]
    if (!arg || !chk.ex.isStringBuilt(arg)) return
    code = [arg]
  }
  if (code.length === 0) return
  const taint = chk.taintAny(code.map(span => span)) ?? code.map(span => chk.ex.taintResolved(span)).find(Boolean)
  const dynamic = code.some(span => chk.dynamic(span))
  chk.check(CODEI, call, taint, dynamic)
}

function pathTraversal(chk: Checker, call: CallFact, q: string): void {
  let paths: (Span | undefined)[] = []
  let protectedBy: string | undefined
  if (FS_OPS.test(q))
    paths = [
      chk.positional(call, 0),
      /rename|copy|move|cp|symlink/i.test(call.name) ? chk.positional(call, 1) : undefined,
    ]
  else if ((call.name === 'sendFile' || call.name === 'download') && RES_RECEIVER.test(call.receiver)) {
    paths = [chk.positional(call, 0)]
    const options = call.args.slice(1).find(arg => chk.ex.isObjectLiteral(arg))
    if (options && chk.ex.prop(options, 'root'))
      protectedBy = 'The `root` option is set, which makes Express reject paths that escape it.'
  } else return
  let taint: Taint | undefined
  for (const span of paths) {
    if (!span) continue
    taint = chk.ex.taintResolved(span)
    if (taint) break
  }
  if (taint && sanitizedBy(PATH, taint.guard)) {
    if (!protectedBy) chk.report(PATH, call, { kind: 'sink', confidence: 'low' }, { note: GUARDED_NOTE })
    return
  }
  if (taint?.guard?.segmentSafe) {
    // An allow-list that keeps out separators still lets `..` through: a review hint, not a finding.
    chk.report(PATH, call, { kind: 'sink', confidence: 'low', taint }, { note: DOT_SEGMENT_NOTE })
    return
  }
  if (!taint) {
    // Origin unknown: steer review to content reads, writes, deletes and downloads of dynamic paths that are
    // not confined by `root` or `path.basename()` (metadata calls such as `stat` or `mkdir` are left out).
    if (
      !protectedBy &&
      !FS_METADATA.test(call.name) &&
      paths.some(span => span !== undefined && chk.dynamic(span) && !isConfinedPath(chk, span))
    )
      chk.report(PATH, call, { kind: 'sink', confidence: 'low' }, { note: UNKNOWN_ORIGIN })
    return
  }
  if (!protectedBy && CONTAINMENT_CHECK.test(chk.scopeText(call.start))) {
    protectedBy = 'A prefix or `..` check appears in the same function; confirm it checks the final resolved path.'
  }
  const cls = classifyTaint(PATH, taint)
  if (!cls) return
  if (protectedBy) chk.report(PATH, call, { kind: 'sink', confidence: 'low', taint }, { note: protectedBy })
  else chk.report(PATH, call, cls)
}

function ssrf(chk: Checker, call: CallFact, q: string): void {
  const head = rootName(call.callee)
  const imported = chk.model.imports.some(imp => imp.bindings.some(b => b.local === head))
  if (!(HTTP_GLOBALS.test(q) || (imported && HTTP_IMPORTED.test(q)))) return
  if (call.isNew) return
  let target = chk.positional(call, 0)
  if (!target) return
  if (chk.ex.isObjectLiteral(target)) {
    target =
      chk.ex.prop(target, 'url') ??
      chk.ex.prop(target, 'baseURL') ??
      chk.ex.prop(target, 'uri') ??
      chk.ex.prop(target, 'hostname') ??
      chk.ex.prop(target, 'host')
    if (!target) return
  }
  reportUrlTaint(chk, SSRF, call, target)
}

function openRedirect(chk: Checker, call: CallFact, q: string): void {
  if (call.name !== 'redirect') return
  const receiverRoot = rootName(call.receiver)
  const ok =
    (REDIRECT_RECEIVER.test(receiverRoot) && call.receiver.split('.').length <= 2) ||
    /^(?:NextResponse|Response)$/.test(call.receiver) ||
    /^(?:next\/navigation|@remix-run\/\w+|react-router(?:-dom)?|@sveltejs\/kit)\.redirect$/.test(q)
  if (!ok) return
  let target = chk.positional(call, 0)
  if (!target) return
  if (/^\d+$/.test(chk.text(target).trim()) && call.args.length > 1) target = chk.positional(call, 1)
  if (!target) return
  const taint = chk.ex.taintResolved(target)
  const values = [target, ...chk.values(target)]
  const fixed = values.some(v => chk.ex.hasFixedOrigin(v)) || hasFixedOriginUrlCall(chk, target)
  if (!taint) {
    if (!fixed && chk.dynamic(target) && !isSameOriginUrlCall(chk, target))
      chk.report(REDIRECT, call, { kind: 'sink', confidence: 'low' }, { note: UNKNOWN_ORIGIN })
    return
  }
  if (fixed) return
  const cls = classifyTaint(REDIRECT, taint)
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

function serverXss(chk: Checker, call: CallFact): void {
  if (!/^(?:send|write|end)$/.test(call.name)) return
  const root = rootName(call.receiver)
  if (root !== 'res' && root !== 'response') return
  // Walk bracket partners rather than a regex whose repeated wildcard can
  // repartition every `status(...)` on a failing chain suffix.
  const [a, b] = chk.ex.range(call.calleeSpan)
  const { tokens, match } = chk.model
  let i = a + 1
  while (i < b - 2) {
    if (tokens[i]?.value === '!') {
      i++
      continue
    } // TypeScript non-null receiver
    if (
      !/^(?:\.|\?\.)$/.test(tokens[i]?.value ?? '') ||
      !/^(?:status|set|type|header|append|cookie|vary|location|links)$/.test(tokens[i + 1]?.value ?? '')
    )
      return
    const open = tokens[i + 2]?.value === '?.' ? i + 3 : i + 2
    if (tokens[open]?.value !== '(') return
    const close = match[open]!
    if (close <= open || close >= b - 2) return
    i = close + 1
  }
  if (i !== b - 2 || !/^(?:\.|\?\.)$/.test(tokens[i]?.value ?? '')) return
  const body = chk.positional(call, 0)
  if (!body || chk.ex.isObjectLiteral(body) || chk.ex.isArrayLiteral(body) || chk.ex.wholeBody(body)) return
  const exact = chk.ex.exactSource(body)
  if (exact && /\.(?:body|query|cookies|signedCookies|headers|files?)$/.test(exact.source)) return
  const taint = chk.ex.taintResolved(body)
  if (taint?.origin !== 'request') return
  if (PLAIN_CONTENT_TYPE.test(chk.scopeText(call.start))) return
  chk.report(XSS_SERVER, call, { kind: 'vulnerability', confidence: taint.direct ? 'high' : 'medium', taint })
}

function domXssCall(chk: Checker, call: CallFact): void {
  let html: Span | undefined
  if (call.name === 'insertAdjacentHTML') html = chk.positional(call, 1)
  else if (/^(?:window\.)?document\.(?:write|writeln)$/.test(call.callee)) html = chk.positional(call, 0)
  else return
  if (html) htmlSink(chk, call, html)
}

function htmlSink(chk: Checker, at: Span, value: Span): void {
  const values = chk.values(value)
  if (values.every(v => isSafeHtml(chk, v))) return
  const markdown = markdownHtml(chk, values)
  if (markdown === 'safe') return
  if (markdown) {
    chk.report(XSS_MARKDOWN, at, markdown)
    return
  }
  const taint = chk.ex.taintResolved(value)
  if (!taint && chk.ex.isConstant(value)) return
  chk.check(XSS_DOM, at, taint, true)
}

// ---------------------------------------------------------------------------
// Markdown rendered to raw HTML
// ---------------------------------------------------------------------------

const MD_PASS_THROUGH = /^(?:String|toString|trim|trimEnd|trimStart)$/
const MD_REPO_FILE = /readFileSync|readFile\s*\(|import\.meta\.glob|\.mdx?['"`]/
const MD_UNSAFE_PIPELINE = /allowDangerousHtml\s*:\s*true|sanitize\s*:\s*false|rehype-?raw|rehypeRaw/
const MD_SANITIZED_PIPELINE = /rehype-?sanitize|rehypeSanitize/i
const MD_HOOK_SANITIZER = /sanitize|DOMPurify|filterXSS|\bxss\b/i

/** A Markdown render call: its Markdown argument, and whether the renderer keeps raw HTML. */
interface MarkdownRender {
  readonly input: Span
  readonly raw: boolean
}

/**
 * How an HTML sink's `values` relate to Markdown rendering:
 * - a vulnerability when one of them is the output of a renderer that keeps
 *   raw HTML (`marked`, `showdown`, `markdown-it` created with `html: true`,
 *   a remark/unified pipeline with `allowDangerousHtml` or `sanitize: false`)
 *   applied to dynamic, unsanitized Markdown;
 * - `'safe'` when every value that is not sanitized HTML is a Markdown render
 *   that cannot carry raw HTML (escaping renderer, sanitized pipeline or
 *   hook, constant Markdown, Markdown read from repository files);
 * - `undefined` otherwise (the generic HTML-sink rule decides).
 */
function markdownHtml(chk: Checker, values: readonly Span[]): Classification | 'safe' | undefined {
  let allSafe = true
  for (const value of values) {
    if (isSafeHtml(chk, value)) continue
    const render = markdownRender(chk, value, 0)
    if (!render) {
      allSafe = false
      continue
    }
    const { input } = render
    if (!render.raw || chk.ex.isConstant(input) || isSanitizerCall(chk, input) || MD_REPO_FILE.test(chk.text(input)))
      continue
    const taint = chk.ex.taintResolved(input)
    if (taint && taint.origin !== 'cli') {
      return { kind: 'vulnerability', confidence: taint.direct ? 'high' : 'medium', taint }
    }
    return {
      kind: 'vulnerability',
      confidence: 'medium',
      note: 'The Markdown is not a constant; if users can write it (a profile, comment, or description stored in the database), any of them can attack the readers.',
    }
  }
  return allSafe ? 'safe' : undefined
}

/** The Markdown render behind `value`, looking through pass-through wrappers and up to two identifiers. */
function markdownRender(chk: Checker, value: Span, depth: number): MarkdownRender | undefined {
  const inside = chk.model.calls.filter(c => c.start >= value.start && c.end <= value.end)
  for (const call of inside) {
    const render = markdownRenderCall(chk, call)
    if (!render) continue
    // Every call around the render inside this value must pass its result through unchanged.
    const around = inside.filter(c => c !== call && c.start <= call.start && c.end >= call.end)
    if (around.every(c => MD_PASS_THROUGH.test(c.name) && !isSanitizerCall(chk, c))) return render
  }
  if (depth >= 2 || inside.some(c => !MD_PASS_THROUGH.test(c.name))) return undefined
  // `String(file)`, `file.toString()`, `file.value`, `await x as string`: follow the identifier.
  const m = /^\s*(?:String\s*\(\s*)?(?:\(\s*)?(?:await\s+)?([A-Za-z_$][\w$]*)\b/.exec(chk.text(value))
  if (!m?.[1]) return undefined
  const start = value.start + m[0].length - m[1].length
  const id: Span = { start, end: start + m[1].length }
  for (const resolved of chk.values(id)) {
    if (resolved.start === id.start && resolved.end === id.end) continue
    const render = markdownRender(chk, resolved, depth + 1)
    if (render) return render
  }
  return undefined
}

/** `call` as a Markdown render, if it is one. */
function markdownRenderCall(chk: Checker, call: CallFact): MarkdownRender | undefined {
  const q = chk.qualify(call.callee)
  const input = chk.positional(call, 0)
  if (!input) return undefined
  if (chk.imports(/^marked$/) && /^marked(?:\.marked)?(?:\.(?:parse|parseInline))?$/.test(q)) {
    // marked keeps raw HTML; a `marked.use({ hooks: { postprocess: DOMPurify.sanitize } })` setup removes it.
    const hooked = chk.model.calls.some(
      c =>
        /^marked(?:\.marked)?\.(?:use|setOptions)$/.test(chk.qualify(c.callee)) && MD_HOOK_SANITIZER.test(chk.text(c)),
    )
    return { input, raw: !hooked }
  }
  if (call.name === 'makeHtml' && chk.imports(/^showdown$/)) return { input, raw: true }
  if ((call.name === 'render' || call.name === 'renderInline') && chk.imports(/^markdown-it$/)) {
    // markdown-it escapes raw HTML unless created with `html: true` (or the `commonmark` preset).
    return { input, raw: /\bhtml\s*:\s*true\b|['"`]commonmark['"`]/.test(initializerText(chk, call)) }
  }
  if (
    (call.name === 'process' || call.name === 'processSync') &&
    chk.imports(/^(?:remark|unified|remark-html|remark-rehype|rehype-stringify)$/)
  ) {
    const pipeline = `${chk.text(call)}\n${initializerText(chk, call)}`
    return { input, raw: MD_UNSAFE_PIPELINE.test(pipeline) && !MD_SANITIZED_PIPELINE.test(pipeline) }
  }
  return undefined
}

/** Source of the expression that initialized a call's receiver (`md` in `md.render(x)`), or the call itself. */
function initializerText(chk: Checker, call: CallFact): string {
  const receiver = call.receiver
  if (!/^[A-Za-z_$][\w$]*$/.test(receiver)) return chk.text(call)
  const source = chk.model.source
  const decl = new RegExp(`\\b${receiver.replace(/\$/g, '\\$')}\\s*=\\s*`, 'g')
  for (let m = decl.exec(source); m; m = decl.exec(source)) {
    const from = m.index + m[0].length
    const init = chk.model.calls.filter(c => c.start >= from && c.start <= from + 4).sort((a, b) => b.end - a.end)[0]
    if (init) return source.slice(from, init.end)
  }
  return chk.text(call)
}

/** A sanitizer call, or a template/concatenation whose every dynamic part is sanitized or constant. */
function isSafeHtml(chk: Checker, value: Span): boolean {
  if (isSanitizerCall(chk, value)) return true
  const parts = chk.ex.dynamicParts(value)
  return parts?.every(p => isSanitizerCall(chk, p) || chk.ex.isConstant(p)) === true
}

function deserialization(chk: Checker, call: CallFact, q: string): void {
  if (/^node-serialize\.unserialize$/.test(q) || (call.callee === 'unserialize' && chk.imports(/^node-serialize$/))) {
    const data = chk.positional(call, 0)
    if (data) chk.check(DESER, call, chk.ex.taintResolved(data), chk.dynamic(data))
    return
  }
  if (/^js-yaml\.load(?:All)?$/.test(q)) {
    const data = chk.positional(call, 0)
    if (!data || !chk.dynamic(data)) return
    const options = chk.positional(call, 1)
    if (options && /\bschema\s*:\s*[\w.]*(?:FAILSAFE|JSON|CORE)_SCHEMA/.test(chk.text(options))) return
    chk.check(YAML_LOAD, call, chk.ex.taintResolved(data), true)
  }
}

function weakCrypto(chk: Checker, call: CallFact, q: string): void {
  if (/^crypto\.createHash$/.test(q) || (call.callee === 'createHash' && chk.importedFrom('createHash', /^crypto/))) {
    const alg = chk.ex.literal(chk.positional(call, 0) ?? { start: 0, end: 0 })
    if (alg && /^(?:md5|md4|sha1|sha-1|ripemd160)$/i.test(alg) && PASSWORD_CONTEXT.test(chk.statementText(call))) {
      chk.certain(WEAK_HASH, call, 'medium')
    }
    return
  }
  if (/^crypto\.(?:createCipher|createDecipher)$/.test(q)) {
    chk.certain(WEAK_CIPHER, call, 'high')
    return
  }
  if (/^crypto\.(?:createCipheriv|createDecipheriv)$/.test(q)) {
    const alg = chk.ex.literal(chk.positional(call, 0) ?? { start: 0, end: 0 })
    if (alg && /^(?:des(?:-|$)|des-ede|rc2|rc4|bf(?:-|$)|blowfish|cast)|-ecb$/i.test(alg))
      chk.certain(WEAK_CIPHER, call, 'high')
    return
  }
  if (call.callee === 'Math.random') {
    const kind = secretContext(chk.contextNames(call))
    if (kind === 'strong') chk.certain(WEAK_RANDOM, call, 'medium')
    else if (kind === 'weak') chk.report(WEAK_RANDOM, call, { kind: 'sink', confidence: 'low' })
  }
}

function jwtDecode(chk: Checker, call: CallFact, q: string): void {
  if (call.name !== 'decode') return
  if (!/^jsonwebtoken\.decode$/.test(q) && !/^(?:jwt|JWT|jsonwebtoken)$/.test(call.receiver)) return
  const fn = chk.fnAt(call.start)
  if (!fn) return
  const body = chk.text(fn)
  if (!AUTH_HEADER_READ.test(body) || /\b(?:verify|jwtVerify|verifyToken|verifyJwt)\s*\(/.test(body)) return
  chk.certain(JWT_DECODE, call, 'medium')
}

function corsReflection(chk: Checker, call: CallFact): void {
  if (!/^(?:setHeader|header|set|append)$/.test(call.name)) return
  if (!/^(?:res|response|reply|ctx|c)$/.test(rootName(call.receiver))) return
  const name = chk.ex.literal(chk.positional(call, 0) ?? { start: 0, end: 0 })
  if (name?.toLowerCase() !== 'access-control-allow-origin') return
  const value = chk.positional(call, 1)
  if (!value || !/origin/i.test(chk.text(value))) return
  const taint = chk.ex.taintResolved(value)
  if (!taint) return
  if (!/Access-Control-Allow-Credentials['"`]\s*,\s*(?:['"`]true['"`]|true)/i.test(chk.scopeText(call.start, 10)))
    return
  chk.report(CORS, call, { kind: 'vulnerability', confidence: 'medium', taint })
}

function massAssignment(chk: Checker, call: CallFact, q: string): void {
  const name = call.name
  let candidates: ArgFact[] = []
  if (
    call.isNew &&
    /^[A-Z]/.test(lastName(call.callee)) &&
    !NOT_A_MODEL.test(lastName(call.callee)) &&
    !/^(?:Error|Map|Set|URL|URLSearchParams|Date|Promise|Response|Request|Headers|FormData|Blob)$/.test(call.callee)
  ) {
    candidates = call.args.slice(0, 1)
  } else if (q === 'Object.assign') {
    const target = call.args[0]
    if (!target || SAFE_SENTINEL_OBJECT.test(chk.text(target).replace(/\s+/g, ''))) return
    candidates = call.args.slice(1)
  } else if (
    /^(?:create|update|insert|build|upsert|findByIdAndUpdate|findOneAndUpdate|updateOne|updateMany|insertMany|bulkCreate|createMany)$/.test(
      name,
    ) &&
    call.receiver !== ''
  ) {
    // Only data-layer receivers write records; a service or controller method picks its own fields.
    if (!isRecordWriter(chk, call)) return
    candidates = [...call.args]
  } else return
  for (const arg of candidates) {
    if (arg.splat) continue
    const whole = chk.ex.wholeBody(arg)
    if (whole) {
      chk.report(MASS, call, {
        kind: 'vulnerability',
        confidence: chk.wholeBodyConfidence(arg, whole),
        taint: { source: whole, direct: true, origin: 'request' },
      })
      return
    }
    if (chk.ex.isObjectLiteral(arg)) {
      for (const entry of chk.ex.objectEntries(arg)) {
        if (!entry.value) continue
        const spreadWhole = entry.spread ? chk.ex.wholeBody(entry.value) : undefined
        const dataWhole =
          entry.key === 'data' && /^(?:create|update|upsert|createMany|updateMany)$/.test(name)
            ? chk.ex.wholeBody(entry.value)
            : undefined
        const found = spreadWhole ?? dataWhole
        if (found) {
          chk.report(MASS, call, {
            kind: 'vulnerability',
            confidence: 'medium',
            taint: { source: found, direct: true, origin: 'request' },
          })
          return
        }
      }
    }
  }
}

/**
 * The receiver of `create`/`update`/`insert`… writes database records: a model class, a Prisma delegate, a
 * model or repository instance, a Knex builder, or a record loaded through one of those
 * (`const user = await User.findByPk(id)`; an unassigned `user` parameter counts too). Services, controllers,
 * API clients and imported modules other than models do not.
 */
function isRecordWriter(chk: Checker, call: CallFact): boolean {
  const receiver = call.receiver.replace(/^this\./, '')
  const last = lastName(receiver)
  if (NOT_A_MODEL.test(last) && !/^(?:entityManager|manager)$/.test(last)) return false
  if (ORM_RECEIVER.test(receiver)) return true
  if (receiver !== call.receiver || !/^[a-z_$][\w$]*$/.test(receiver) || NOT_A_RECORD.test(receiver)) return false
  if (chk.model.imports.some(imp => imp.bindings.some(b => b.local === receiver))) return false
  const values = chk.values({ start: call.calleeSpan.start, end: call.calleeSpan.start + receiver.length })
  const assigned = values.filter(v => v.start !== call.calleeSpan.start)
  if (assigned.length === 0) return !chk.model.assigns.some(a => a.targets.some(t => t.name === receiver))
  return assigned.some(value =>
    chk.model.calls.some(
      c =>
        c.start >= value.start &&
        c.end <= value.end &&
        (c.isNew
          ? /^[A-Z]/.test(lastName(c.callee)) && !NOT_A_MODEL.test(lastName(c.callee))
          : ORM_RECEIVER.test(c.receiver.replace(/^this\./, ''))),
    ),
  )
}

/** Lower-case names of things that are not records: clients, framework objects, utilities. */
const NOT_A_RECORD =
  /^(?:api|http|https|axios|client|service|services|controller|router|app|server|store|cache|queue|bus|emitter|events?|logger|log|mailer|transport|stripe|twilio|sendgrid|s3|sns|sqs|redis|socket|io|ws|fs|path|util|utils|helpers?|lodash|_)$/

function prototypePollution(chk: Checker, call: CallFact, q: string): void {
  let args: Span[]
  if (MERGE_QUALIFIED.test(q) || MERGE_BARE.test(call.callee)) args = [...call.args]
  else if (/^(?:\$|jQuery)\.extend$/.test(call.callee) && call.args[0] && chk.ex.isWord(call.args[0], 'true'))
    args = call.args.slice(1)
  else return
  for (const arg of args) {
    const taint = chk.ex.taint(arg) ?? chk.ex.exactSource(arg)
    if (taint?.origin !== 'request') continue
    chk.report(PROTO, call, { kind: 'sink', confidence: taint.direct ? 'medium' : 'low', taint })
    return
  }
}

function regexInjection(chk: Checker, call: CallFact): void {
  if (call.callee !== 'RegExp') return
  const pattern = chk.positional(call, 0)
  if (!pattern) return
  const taint = chk.ex.taintResolved(pattern)
  const cls = taint ? classifyTaint(REDOS, taint) : undefined
  if (cls) chk.report(REDOS, call, cls)
}

function sessionSecret(chk: Checker, call: CallFact, q: string): void {
  if (
    !/^(?:express-session|cookie-session|session|cookieSession|expressSession|koa-session|@fastify\/(?:session|secure-session|cookie))$/.test(
      q,
    ) &&
    !/^(?:session|cookieSession|expressSession)$/.test(call.callee)
  )
    return
  const options = call.args.find(arg => chk.ex.isObjectLiteral(arg))
  if (!options) return
  for (const key of ['secret', 'secrets', 'keys', 'key']) {
    const value = chk.ex.prop(options, key)
    if (!value) continue
    const literals = chk.ex.isArrayLiteral(value) ? chk.ex.elements(value) : [value]
    const fixed = literals.filter(v => {
      const lit = chk.ex.literal(v)
      return lit !== undefined && lit.length > 0
    })
    if (fixed.length > 0 && fixed.length === literals.length) {
      chk.certain(SESSION_SECRET, value, 'high', { mask: fixed })
      return
    }
  }
}

// ---------------------------------------------------------------------------
// Property and assignment rules
// ---------------------------------------------------------------------------

const PROP_KEYS: ReadonlySet<string> = new Set([
  '__html',
  'rejectUnauthorized',
  'strictSSL',
  'algorithms',
  'algorithm',
  'ignoreExpiration',
  'credentials',
  'secure',
  'httpOnly',
  '$where',
])

function propertyRules(chk: Checker): void {
  const byObject = new Map<number, PropMatch[]>()
  const all: PropMatch[] = []
  for (const prop of chk.props(PROP_KEYS)) {
    all.push(prop)
    if (prop.objectStart >= 0) {
      const list = byObject.get(prop.objectStart)
      if (list) list.push(prop)
      else byObject.set(prop.objectStart, [prop])
    }
  }
  for (const prop of all) {
    switch (prop.key) {
      case '__html':
        htmlSink(chk, prop.span, prop.value)
        break
      case 'rejectUnauthorized':
      case 'strictSSL':
        if (chk.ex.isWord(prop.value, 'false')) chk.certain(TLS, prop.span, 'high')
        break
      case 'algorithms': {
        const values = chk.ex.isArrayLiteral(prop.value) ? chk.ex.elements(prop.value) : [prop.value]
        if (values.some(v => chk.ex.literal(v)?.toLowerCase() === 'none')) chk.certain(JWT_NONE, prop.span, 'high')
        break
      }
      case 'algorithm':
        if (chk.ex.literal(prop.value)?.toLowerCase() === 'none')
          chk.certain(JWT_NONE, prop.span, 'medium', { severity: 'medium' })
        break
      case 'ignoreExpiration':
        if (chk.ex.isWord(prop.value, 'true')) chk.certain(JWT_EXPIRY, prop.span, 'high')
        break
      case 'credentials': {
        if (!chk.ex.isWord(prop.value, 'true')) break
        const origin = (byObject.get(prop.objectStart) ?? []).length > 0 ? originProp(chk, prop.objectStart) : undefined
        if (!origin) break
        if (chk.ex.isWord(origin.value, 'true') || reflectsAnyOrigin(chk, origin.value)) {
          chk.certain(CORS, origin.span, 'high')
        } else if (chk.ex.literal(origin.value) === '*') {
          chk.certain(CORS, origin.span, 'medium', {
            severity: 'low',
            note: 'Browsers refuse `*` together with credentials, so this mostly signals that the intended policy is unclear.',
          })
        }
        break
      }
      case 'secure':
      case 'httpOnly':
        if (chk.ex.isWord(prop.value, 'false') && isCookieOptions(chk, prop.objectStart)) {
          // Page scripts are meant to read a preference cookie (`res.cookie('theme', …, { httpOnly: false })`).
          if (prop.key === 'httpOnly' && namesPlainCookie(chk, prop.objectStart)) break
          chk.certain(prop.key === 'secure' ? COOKIE_SECURE : COOKIE_HTTPONLY, prop.span, 'medium')
        }
        break
    }
  }
}

/**
 * A CORS `origin` callback that accepts every origin unconditionally:
 * `(origin, cb) => cb(null, true)` or `cb(null, origin)` with no other logic.
 */
function reflectsAnyOrigin(chk: Checker, value: Span): boolean {
  if (!chk.ex.isFunctionLike(value)) return false
  const text = chk.text(value).replace(/\s+/g, ' ')
  const m =
    /^(?:async\s*)?(?:function\s*\w*\s*)?\(\s*([A-Za-z_$][\w$]*)\s*,\s*([A-Za-z_$][\w$]*)\s*\)\s*(?:=>)?\s*\{?\s*(?:return\s+)?([A-Za-z_$][\w$]*)\s*\(\s*null\s*,\s*([A-Za-z_$][\w$]*)\s*\)\s*;?\s*\}?$/.exec(
      text,
    )
  if (!m) return false
  const [, originParam, cbParam, called, granted] = m
  return called === cbParam && (granted === 'true' || granted === originParam)
}

/** The `origin` property of the object literal starting at `objectStart`. */
function originProp(chk: Checker, objectStart: number): { value: Span; span: Span } | undefined {
  const { tokens, match } = chk.model
  let lo = 0
  let hi = tokens.length
  while (lo < hi) {
    const mid = (lo + hi) >>> 1
    if (tokens[mid]!.start < objectStart) lo = mid + 1
    else hi = mid
  }
  const open = lo
  const close = match[open] ?? -1
  if (close < 0) return undefined
  const span = { start: tokens[open]!.start, end: tokens[close]!.end }
  for (const entry of chk.ex.objectEntries(span)) {
    if (entry.key === 'origin' && entry.value)
      return { value: entry.value, span: { start: entry.keySpan.start, end: entry.value.end } }
  }
  return undefined
}

/** Whether the object literal at `objectStart` is cookie options (value of `cookie:` or an argument of a cookie/session call). */
function isCookieOptions(chk: Checker, objectStart: number): boolean {
  if (objectStart < 0) return false
  const { tokens } = chk.model
  let lo = 0
  let hi = tokens.length
  while (lo < hi) {
    const mid = (lo + hi) >>> 1
    if (tokens[mid]!.start < objectStart) lo = mid + 1
    else hi = mid
  }
  const colon = tokens[lo - 1]
  const key = tokens[lo - 2]
  if (
    colon?.type === 'punct' &&
    colon.value === ':' &&
    key &&
    /^(?:cookie|cookies|cookieOptions|sessionCookie)$/i.test(key.value.replace(/['"]/g, ''))
  ) {
    return true
  }
  for (const call of chk.model.calls) {
    if (call.start > objectStart) break
    if (call.end < objectStart) continue
    if (!call.args.some(arg => arg.start === objectStart)) continue
    return (
      /^(?:cookie|setCookie|serialize|session|cookieSession|expressSession|clearCookie)$/.test(call.name) ||
      /cookie|session/i.test(chk.qualify(call.callee))
    )
  }
  return false
}

/** Cookie names that may carry a session, a credential or a CSRF token. */
const AUTH_COOKIE_NAME = /sess|sid|auth|token|jwt|remember|login|user|account|csrf|xsrf|secret|key|(?:^|[._-])id$/i

/**
 * The cookie options at `objectStart` belong to `res.cookie('<name>', …)` (or `setCookie`/`serialize`) with a
 * literal name that does not suggest a session or credential (`theme`, `locale`, `consent`).
 */
function namesPlainCookie(chk: Checker, objectStart: number): boolean {
  const call = chk.model.calls.find(c => c.args.some(arg => arg.start === objectStart))
  if (!call || !/^(?:cookie|setCookie|serialize)$/.test(call.name)) return false
  const first = chk.positional(call, 0)
  const name = first ? chk.ex.literal(first) : undefined
  return name !== undefined && name !== '' && !AUTH_COOKIE_NAME.test(name)
}

function memberAssignRules(chk: Checker): void {
  for (const assign of chk.model.memberAssigns) {
    if (assign.prop === 'innerHTML' || assign.prop === 'outerHTML') {
      if (assign.op === '=' || assign.op === '+=') htmlSink(chk, assign, assign.value)
      continue
    }
    if (assign.prop === 'NODE_TLS_REJECT_UNAUTHORIZED' && /^process\.env/.test(assign.target)) {
      const lit = chk.ex.literal(assign.value) ?? chk.text(assign.value).trim()
      if (lit === '0')
        chk.certain(TLS, assign, 'high', {
          severity: 'high',
          note: 'This disables certificate checks for every HTTPS request the process makes.',
        })
    }
  }
}

// ---------------------------------------------------------------------------
// Shared
// ---------------------------------------------------------------------------

function classifyTaint(rule: RuleMeta, taint: Taint): Classification | undefined {
  const origins = rule.origins ?? ['request']
  if (origins.includes(taint.origin))
    return { kind: 'vulnerability', confidence: taint.direct ? 'high' : 'medium', taint }
  if (!rule.sinkSeverity) return undefined
  return {
    kind: 'sink',
    confidence: 'low',
    taint,
    note:
      taint.origin === 'cli'
        ? 'The value comes from command-line arguments, so it only matters if untrusted people can run this program.'
        : 'The value comes from the browser (for example the page URL), so the impact depends on where this code runs.',
  }
}

/**
 * Report SSRF-style URL taint: fixed origin or browser input becomes a sink. A dynamic URL of unknown origin
 * is a sink too, except in browser code, where the request leaves from the user's machine.
 */
function reportUrlTaint(chk: Checker, rule: RuleMeta, call: CallFact, target: Span): void {
  const taint = chk.ex.taintResolved(target)
  const values = [target, ...chk.values(target)]
  const fixed = values.some(v => chk.ex.hasFixedOrigin(v)) || hasFixedOriginUrlCall(chk, target)
  if (!taint) {
    if (!fixed && chk.dynamic(target) && !isBrowserCode(chk.model))
      chk.report(rule, call, { kind: 'sink', confidence: 'low' }, { note: UNKNOWN_ORIGIN })
    return
  }
  if (fixed) {
    if (taint.origin !== 'request') return
    chk.report(
      rule,
      call,
      { kind: 'sink', confidence: 'low', taint },
      {
        note: 'The scheme and host are fixed, so input can only change the path; check that it cannot change the host (for example via `@`, `//` or encoded characters).',
      },
    )
    return
  }
  const cls = classifyTaint(rule, taint)
  if (!cls) return
  if (cls.kind === 'vulnerability' && URL_CHECK.test(chk.scopeText(call.start))) {
    chk.report(
      rule,
      call,
      { kind: 'sink', confidence: 'low', taint },
      {
        note: 'Some URL validation (an allow-list or host check) appears in the same function; confirm it cannot be bypassed.',
      },
    )
    return
  }
  chk.report(rule, call, cls)
}

/** Allow-list or host validation of an outgoing URL. */
const URL_CHECK =
  /allow(?:ed)?_?(?:list|Hosts?|Origins?|Domains?|Urls?)|white_?list|ALLOWED_|isAllowed\w*\s*\(|isSafeUrl|isValidUrl|validateUrl|\.hostname\s*(?:===|!==|==|!=)|\.host\s*(?:===|!==|==|!=)|\.origin\s*(?:===|!==|==|!=)|\b\w*(?:allow|white|safe|trusted|permitted|hosts|domains|origins|urls)\w*\.(?:includes|has|indexOf|some)\s*\(/i

/** Note for sinks whose value has no visible source. */
const UNKNOWN_ORIGIN =
  'Where the value comes from is not visible here (a parameter, a stored record or another module); review the callers.'

/** Browser code: a `'use client'` module, a JSX/TSX/Vue/Svelte file, or one importing a UI library. */
function isBrowserCode(model: FileModel): boolean {
  const first = model.tokens[0]
  if (first?.type === 'str' && /^['"]use client['"]$/.test(first.value)) return true
  if (/\.(?:jsx|tsx|vue|svelte|html?)$/i.test(model.path)) return true
  return model.imports.some(imp =>
    /^(?:react|react-dom(?:\/client)?|vue|svelte|@angular\/[\w-]+|preact|solid-js|swr|@tanstack\/[\w-]+)$/.test(
      imp.source,
    ),
  )
}

/**
 * A path whose dynamic parts are all stripped of directories (`path.basename(name)`, also inside
 * `path.join(dir, path.basename(name))` or a template), looking through one level of local assignment.
 */
function isConfinedPath(chk: Checker, span: Span, depth = 0): boolean {
  if (depth > 3) return false
  return chk.values(span).every(value => {
    if (!chk.dynamic(value)) return true
    const call = callAt(chk.model, value)
    if (call) {
      const q = chk.qualify(call.callee)
      if (/^(?:path\.(?:posix\.|win32\.)?)?basename$/.test(q)) return true
      if (!/^path\.(?:posix\.|win32\.)?(?:join|resolve|normalize)$/.test(q)) return false
      return call.args.every(arg => !chk.dynamic(arg) || isConfinedPath(chk, arg, depth + 1))
    }
    const parts = chk.ex.dynamicParts(value)
    return parts?.every(part => !chk.dynamic(part) || isConfinedPath(chk, part, depth + 1)) === true
  })
}

/** `new URL('/login', req.url)`: a same-site path resolved against the request's own URL or a constant base. */
function isSameOriginUrlCall(chk: Checker, target: Span): boolean {
  const call = callAt(chk.model, target)
  if (call?.callee !== 'URL' || call.args.length < 2) return false
  const base = chk.text(call.args[1]!).replace(/\s+/g, '')
  return (
    chk.ex.hasFixedOrigin(call.args[0]!) &&
    (/^(?:req|request)\.(?:url|nextUrl)$/.test(base) || chk.ex.isConstant(call.args[1]!))
  )
}

/** `new URL(path, 'https://fixed.example')` with a constant base and a path-only input. */
function hasFixedOriginUrlCall(chk: Checker, target: Span): boolean {
  const call = callAt(chk.model, target)
  if (call?.callee !== 'URL' || call.args.length < 2) return false
  const first = call.args[0]!
  const base = call.args[1]!
  return chk.ex.hasFixedOrigin(first) && chk.ex.isConstant(base)
}
