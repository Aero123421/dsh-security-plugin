# Analyzers

The deterministic half of every scan runs on the in-memory snapshot (`src/host/scan/analysis.ts`). Its output has
two uses:

- **Findings.** `vulnerability`, `secret` and `dependency` signals are recorded as findings right away, starting
  as *Possible* (`potential`). High-confidence secrets start as *Confirmed in code*.
- **Steering.** `sink` signals (a dangerous API receiving a value whose origin is unknown) are not reported. They
  only rank and focus AI tasks. Every signal, reported or not, appears as a hint in the AI tasks.

Rules favor **precision over recall**. A rule fires as a `vulnerability` only when request data visibly reaches the
sink in the same function or expression. Confidence is high when the source is written inside the sink call, and
medium when it arrives through a local alias or a route parameter. Otherwise the match is a lower-severity `sink`,
or nothing.

Request data stops counting as attacker-chosen text when the code visibly constrains it:

- only the branches of a conditional reach its value (`req.query.debug ? 'on' : 'off'` is constant), and a branch
  the condition restricts to an allow-list is clean (`LIST.includes(x) ? x : 'en'`, `SET.has(x)`, `x in OBJ`,
  `x === 'a' || x === 'b'`, Python `x if x in ("en", "ja") else "en"`);
- numbers and booleans derived from it are not text: `.length`, `.includes(…)`, comparisons, arithmetic,
  `.map(Number)`/`.map(x => parseInt(x, 10))`, and Python comprehensions whose elements go through `int()`;
- an anchored allow-list pattern checked before the sink with an early exit (`if (!/^[\w.-]+$/.test(x)) return …`,
  `if not re.fullmatch(r"[\w.-]+", x): abort(400)`, `if not x.isdigit(): return …`), or wrapping the sink in the
  positive form, turns command-injection and path-traversal hits into review `sink`s when its characters keep out
  shell syntax (command) or `..` and separators (path). A pattern that admits `.` but no separator leaves a path
  hit as a `sink`. Other rules keep the taint: an allow-listed host name is still an SSRF target.

Files that look generated (`@generated`, `DO NOT EDIT`, minified) are skipped. Test, fixture and example files
are scanned with severity capped at **Low**. SAST confidence becomes **low**; secret confidence drops one level
(high → medium, medium → low). Findings remain visible.

| Analyzer id | Kind | Network | Default |
| --- | --- | --- | --- |
| `secrets` | built in | none | always |
| `sast` (+ `ast-grep` engine status) | built in | none | always |
| `routes` | built in | none | always |
| `dependencies` | built in | none | always |
| `osv` | built in | OSV API (names and versions only) | off (`privacy.allowDependencyLookup`) |
| `gitleaks`, `osv-scanner`, `semgrep` | external programs | see below | on if installed (`privacy.useExternalAnalyzers`) |

## Secrets (`src/host/analysis/secrets.ts`)

25 rules. The same rules drive redaction of everything shown to models. Generic rules (`generic-secret`,
`env-secret`) are scan-only and use entropy, placeholder and key-name filters. `generic-secret` also excludes prose
values dominated by non-ASCII letters, which can have high entropy without being tokens, and values that read as
names (`dotted.or-kebab_identifiers`, `ENV_VAR_NAMES`) unless one part looks random (Mailgun `key-…`), the value
starts with `whsec`, or it calls itself a secret and carries a number (`app-jwt-secret-2024`). Keys that point at a
stored secret (Helm `existingSecret`) are ignored. Known example values (AWS
docs keys, the jwt.io sample, the Azurite key) and template values are ignored. Every secret finding is CWE-798.

When a specific secret rule or a CWE-798 SAST rule covers the same sensitive span as `generic-secret`, they produce
one finding under the specific rule. Both rule observations remain as supporting evidence, and the generic
fingerprint is retained for matching across scans. Different credentials, even on the same line, stay separate.

| Rule id | Detects | Severity | Confidence |
| --- | --- | --- | --- |
| `gcp-service-account` | Google Cloud service-account private key | critical | high |
| `private-key` | Private key block (PEM) | critical | high |
| `aws-access-key-id` | AWS access key ID | high | high |
| `aws-secret-access-key` | AWS secret access key | critical | high |
| `github-token` | GitHub token | high | high |
| `github-fine-grained-token` | GitHub fine-grained PAT | high | high |
| `gitlab-token` | GitLab personal access token | high | high |
| `slack-token` | Slack token | high | high |
| `slack-webhook` | Slack incoming webhook URL | medium | high |
| `stripe-secret-key` | Stripe live secret key | critical | high |
| `stripe-restricted-key` | Stripe live restricted key | high | high |
| `google-api-key` | Google API key | medium | medium |
| `anthropic-api-key` | Anthropic API key | high | high |
| `openai-api-key` | OpenAI API key | high | high |
| `deepseek-api-key` | DeepSeek API key | high | high |
| `twilio-api-key` | Twilio API key | high | medium |
| `twilio-auth-token` | Twilio auth token | high | high |
| `sendgrid-api-key` | SendGrid API key | high | high |
| `npm-token` | npm access token | high | high |
| `pypi-token` | PyPI upload token | high | high |
| `azure-storage-key` | Azure storage or service-bus key | critical | high |
| `jwt` | JSON Web Token | medium | medium |
| `database-url` | DB / broker URL with inline password, including driver schemes such as `postgresql+asyncpg://` (placeholder and default passwords dropped or downgraded) | high | high |
| `generic-secret` | Hard-coded password / token / API key assignment (keys with `password`, `pass`, `pwd`, `secret`, `api_key`, `token`, `private_key` or `credentials`) | medium | low |
| `env-secret` | Secret value in an `.env`-style file, or an unquoted upper-case environment setting in YAML (compose `environment:`, CI `env:`, Kubernetes Secret data) | medium | medium |

## Pattern rules (SAST, `src/host/analysis/sast/`)

56 rules. JS/TS and Python files are modeled with the native tree-sitter engine (`@ast-grep/napi`) when it is
available, and with a built-in tokenizer otherwise. Both modes run the same rules and are tested side by side.
Template and config rules match text. "Sink severity" is the severity of the `sink` variant; rules without one only
report when request data reaches them. Rules marked "review hint only" never produce a finding: their matches are
always `sink`s, because whether they are exploitable depends on facts the rule cannot see (the library version for
js-yaml and deep-merge helpers, where a template variable's value comes from).

### JavaScript / TypeScript (`js.ts`)

Files: `.js .jsx .ts .tsx .mjs .cjs .mts .cts`, plus scripts embedded in `.vue`, `.svelte` and `.html`. Template
rules cover `.ejs`, `.hbs/.handlebars/.mustache`, `.pug/.jade`, Vue `v-html` and Svelte `{@html}`.

| Rule id | Title | CWE | Severity | Sink severity |
| --- | --- | --- | --- | --- |
| `js.sql-injection` | SQL injection | CWE-89 | high | medium |
| `js.nosql-injection` | NoSQL (MongoDB) query injection | CWE-943 | high | medium |
| `js.command-injection` | OS command injection | CWE-78 | critical | medium |
| `js.code-injection` | Code injection (dynamic evaluation) | CWE-95 | critical | medium |
| `js.path-traversal` | Path traversal | CWE-22 | high | low |
| `js.ssrf` | Server-side request forgery | CWE-918 | high | low |
| `js.open-redirect` | Open redirect | CWE-601 | medium | low |
| `js.xss` | Reflected / DOM cross-site scripting, including Markdown rendered as raw HTML (`marked`, `showdown`, `markdown-it` with `html: true`, remark/rehype with raw HTML) without a sanitizer | CWE-79 | high | – |
| `js.template-unescaped-output` | Unescaped template output | CWE-79 | – (review hint only) | low |
| `js.insecure-deserialization` | Insecure deserialization (node-serialize) | CWE-502 | critical | medium |
| `js.unsafe-yaml-load` | js-yaml `load()` on dynamic data | CWE-502 | – (review hint only) | low |
| `js.weak-password-hash` | Weak hash used for passwords | CWE-328 | medium | – |
| `js.weak-cipher` | Weak or deprecated encryption | CWE-327 | medium | – |
| `js.insecure-random` | Predictable random value used as a secret | CWE-330 | medium | low |
| `js.jwt-none-algorithm` | JWT "none" algorithm allowed | CWE-347 | high | – |
| `js.jwt-decode-without-verify` | JWT decoded without signature verification | CWE-347 | medium | – |
| `js.jwt-ignore-expiration` | JWT expiration ignored | CWE-613 | low | – |
| `js.tls-verification-disabled` | TLS certificate verification disabled | CWE-295 | medium | – |
| `js.cors-misconfiguration` | Permissive CORS with credentials | CWE-942 | medium | – |
| `js.cookie-insecure` | Cookie sent without the Secure flag | CWE-614 | low | – |
| `js.cookie-without-httponly` | Cookie readable by JavaScript | CWE-1004 | low | – |
| `js.hardcoded-session-secret` | Hard-coded session secret | CWE-798 | medium | – |
| `js.mass-assignment` | Mass assignment from the request body | CWE-915 | medium | – |
| `js.prototype-pollution` | Deep merge of user input | CWE-1321 | – (review hint only) | medium |
| `js.regex-injection` | Regular expression built from user input (ReDoS) | CWE-1333 | medium | – |
| `js.hardcoded-credential-check` | Hard-coded credential or backdoor check | CWE-798 | medium | – |
| `js.xxe` | XML external entity (XXE) processing: libxmljs `parseXml`/`parseXmlString` with `noent: true` | CWE-611 | high | low |

SQL injection checks include TypeORM-style `where`/`andWhere`/`orWhere` string construction, Sequelize
`literal(...)` (including named imports) and postgres.js `sql.unsafe(...)` (its tagged template is parameterized
and not a sink). Static placeholder predicates with separate parameter objects and object filters are not SQL
text sinks. Existing Mongo object-filter checks still apply to Mongo-shaped calls.

Besides Express-style request objects, Next.js `params`/`searchParams` and NestJS parameter decorators, request data
includes GraphQL resolver arguments (functions in a `Query`/`Mutation`/`Subscription` map, NestJS and type-graphql
`@Args()`/`@Arg()`) and a tRPC procedure's `input` when its `.input()` schema admits strings. `js.ssrf` also covers
NestJS `HttpService` (`this.http.get(url)`, `this.http.axiosRef.post(url)`), and `js.xss` covers a Koa `ctx.body`
string that starts with markup or is sent with `ctx.type = 'html'`.

`js.mass-assignment` needs a receiver that writes records: a model class (`User.create`, `db.User.update`), a Prisma
delegate (`prisma.user`), a model or repository instance (`this.userRepository`, `userModel`, `em`), a Knex builder
(`knex('users')`) or a record loaded through one of those. A service, controller or API client method
(`teamService.create(req.body)`) chooses its own fields and is not reported.

`js.cookie-without-httponly` leaves out `res.cookie('<name>', …)` (and `setCookie`/`serialize`) when the literal
name does not suggest a session, credential or CSRF token (`theme`, `locale`): page scripts are meant to read those.

`js.jwt-decode-without-verify` reports `jwt.decode()` in a function that never calls a `verify` function when
the function reads the `Authorization` header or the decoded token comes from a cookie or request header: directly
(`req.cookies.session`, `req.get('x-access-token')`), through Next.js `cookies()`, or from a helper in the same file
that reads one without verifying it (`jwt.decode(getBearer(req))`). A token passed in as a parameter or taken from
the body is not reported, since decoding it may be for display or logging.

`js.weak-password-hash` and `py.weak-password-hash` need a password word (`password`, `passwd`, `pwd`, `pw`,
`passphrase`) in the statement that computes the MD5/SHA-1 digest (with chained calls on the following lines), in
a later line of the same function that uses the variable holding the digest or hash object (`h.update(pw)`,
`return digest == user.password_hash`), or in the name of the function that returns the digest when that name
says it hashes or checks (`hashPassword`, `verify_password`). `js.insecure-random` and `py.insecure-random` read
the names the value is assigned to and the enclosing function's name; inside anonymous callbacks
(`.map(() => …)`) they use the nearest named function when each callback returns the value and the outermost one
is in that function's `return`. A random number that is compared or subtracted (`Math.random() < 0.1`,
`sort(() => Math.random() - 0.5)`) is not reported.

`js.path-traversal`, `js.ssrf` and `js.open-redirect` also emit a low `sink` when the value is dynamic but its
origin is not visible (a parameter, a stored record, another module): file reads, writes, deletes and downloads
(not `stat`, `mkdir`, `exists`-style calls) unless `root` is set or every dynamic part goes through
`path.basename()`; outgoing requests outside browser code (`'use client'`, JSX/TSX/Vue/Svelte files, UI-library
imports) unless the scheme and host are fixed; redirects unless the target is a same-site path or
`new URL('/path', req.url)`. These steer AI review only and never become findings.

### Python (`python.ts`)

Files: `.py .pyi .pyw`. Template rules cover `.html .jinja .jinja2 .j2 .djhtml .tmpl .tpl` (`|safe`,
`{% autoescape off %}`); those template matches are review `sink`s only. `py.xss` reports a vulnerability only when
request data reaches `Markup`/`mark_safe` (or another listed HTML sink) in Python code. `py.reflected-xss` reports
request data in an HTML string (a literal with markup) that a Flask view returns (in files that import Flask and not
FastAPI) or that `make_response`, Django `HttpResponse` or `HTMLResponse` sends; a plain-text or JSON content type
and values built by `Markup(…)`, `format_html()` or `escape()` are left out.

Django view parameters count as request data, except those that every URLconf route in the snapshot fills through
an `<int:…>` or `<uuid:…>` converter (or a digits-only `re_path` group): those are numbers or UUIDs.

| Rule id | Title | CWE | Severity | Sink severity |
| --- | --- | --- | --- | --- |
| `py.sql-injection` | SQL injection | CWE-89 | high | medium |
| `py.command-injection` | OS command injection | CWE-78 | critical | medium |
| `py.code-injection` | Code injection (eval/exec) | CWE-95 | critical | medium |
| `py.insecure-deserialization` | Insecure deserialization | CWE-502 | critical | medium |
| `py.path-traversal` | Path traversal | CWE-22 | high | low |
| `py.ssrf` | Server-side request forgery | CWE-918 | high | low |
| `py.template-injection` | Server-side template injection | CWE-1336 | critical | medium |
| `py.xss` | Cross-site scripting: escaping disabled | CWE-79 | high | low |
| `py.open-redirect` | Open redirect | CWE-601 | medium | low |
| `py.debug-enabled` | Debug mode enabled | CWE-489 | medium | – |
| `py.allowed-hosts-wildcard` | Django `ALLOWED_HOSTS` allows any host | CWE-16 | low | – |
| `py.cookie-insecure` | Explicit `False` for session/CSRF cookie Secure settings | CWE-614 | low | – |
| `py.cookie-without-httponly` | Explicit `False` for session cookie HttpOnly settings | CWE-1004 | low | – |
| `py.hardcoded-secret-key` | Hard-coded framework secret key | CWE-798 | high | – |
| `py.tls-verification-disabled` | TLS certificate verification disabled | CWE-295 | medium | – |
| `py.jwt-unverified` | JWT signature not verified | CWE-347 | high | – |
| `py.weak-password-hash` | Weak hash used for passwords | CWE-328 | medium | – |
| `py.insecure-random` | Predictable random value used as a secret | CWE-330 | medium | low |
| `py.mass-assignment` | Mass assignment from request data | CWE-915 | medium | – |
| `py.hardcoded-credential-check` | Hard-coded credential or backdoor check | CWE-798 | medium | – |
| `py.reflected-xss` | Reflected cross-site scripting (XSS) | CWE-79 | high | – |
| `py.cors-misconfiguration` | Permissive CORS with credentials (`CORSMiddleware` with `"*"` or a catch-all regex, Flask-CORS without an origin list, django-cors-headers allow-all) | CWE-942 | medium | – |
| `py.xxe` | XML external entity (XXE) processing: lxml parser with `resolve_entities=True` | CWE-611 | high | low |

SQLAlchemy `text(...)` is also checked inside `filter(...)`, `where(...)` and `having(...)`. Request data
interpolated or concatenated into a predicate is a SQL injection sink; constant text with bound parameters is not.
Standalone text construction, without a recognized execution/query-builder context, is not reported. asyncpg and
`databases` fetch methods (`fetch`, `fetchrow`, `fetchval`, `fetch_all`, `fetch_one`, `fetch_val`, `iterate`) are
sinks when their text contains SQL.

`py.path-traversal` also covers werkzeug `FileStorage.save()` of an upload whose destination is built from request
data such as the upload's own `filename`, and `tarfile` `extractall()`/`extract()` of an archive opened from request
data without `filter=` (tar slip; with `members=` it is a review hint). `zipfile` extraction strips `..` and is not
reported. `py.template-injection` also covers Jinja2 `Environment().from_string()` and Flask
`app.jinja_env.from_string()`; a `SandboxedEnvironment` is not reported.

`py.path-traversal`, `py.ssrf` and `py.open-redirect` also emit a low `sink` for a dynamic value whose origin is
not visible: file operations other than listing and `stat`/`mkdir`/`chmod`-style calls unless every dynamic part
goes through `secure_filename()`/`os.path.basename()`, outgoing requests unless the scheme and host are fixed, and
redirects unless the target is a same-site path or built by `url_for()`/`reverse()`. They steer AI review only.

Cookie rules cover top-level/class assignments, member or dict-style assignments (such as
`app.config['SESSION_COOKIE_SECURE'] = False`), and keyword arguments to `app.config.update(...)`. Only the explicit
Python literal `False` fires; `True` and environment-derived values do not. `CSRF_COOKIE_HTTPONLY = False` is not
reported because JavaScript may need to read the CSRF cookie.

### Containers and Kubernetes (`config.ts`)

Files: Dockerfiles (`Dockerfile*`, `*.dockerfile`), Compose files (`compose.y(a)ml`, `docker-compose*.y(a)ml`), and
YAML documents with both `apiVersion:` and `kind:`.

| Rule id | Title | CWE | Severity |
| --- | --- | --- | --- |
| `docker.add-remote-url` | Dockerfile `ADD` downloads from a URL | CWE-829 | low |
| `docker.curl-pipe-shell` | Remote script piped into a shell | CWE-494 | low |
| `docker.secret-in-env` | Secret value baked into the image | CWE-798 | medium |
| `container.privileged` | Privileged container | CWE-250 | medium |
| `container.host-network` | Container shares the host network | CWE-668 | low |
| `k8s.allow-privilege-escalation` | Privilege escalation allowed | CWE-250 | low |

## Routes (`src/host/analysis/routes/`)

Endpoint extraction feeds the attack surface: AI task planning, the Planner's and Hunters' endpoint lists, and the
*Endpoints reviewed* coverage figure. Each endpoint records method, full route (mount prefixes resolved, up to 8
levels), declaring file and line, handler range, middleware, **auth hints** and path parameters.

A JavaScript handler passed by name is looked up in the route file, then through relative imports in the module
that defines it: an exported function (`import { getUser }`, `import * as users` then `users.getUser`), a method or
function property of an exported object, class or instance (`export default { list }`,
`const users = new UsersController()`), CommonJS `exports.list = ...`, and `export *` / `export { … } from`
barrels, through `asyncHandler(fn)`-style wrappers and `.bind(...)`. Endpoint review tasks then target the handler
file and the route file together. Handlers from packages, or behind dynamic dispatch, stay unresolved.

| Framework | What is recognized |
| --- | --- |
| Express | `app.METHOD`, `router.METHOD`, `router.route(path).get(…)` chains (preceding `.all(mw)` applies to subsequent methods, without a phantom ANY route), `app.use(prefix, …mw, router)` mounts across files, ordered `router.use(mw)` (applies only to later routes) |
| Fastify | Shorthand methods, `fastify.route({ … })`, `onRequest`/`preHandler`/`preValidation`/`preParsing` hooks (route options and `addHook`), `register(plugin, { prefix })` |
| Koa | `@koa/router` / `koa-router` / `koa-tree-router` methods and nested routers |
| Hono | `app.METHOD`, `app.all`, `app.route(prefix, sub)` |
| NestJS | `@Controller(prefix)` + `@Get/@Post/…` methods, `@UseGuards` as middleware |
| Next.js | App Router `route.ts` exports (`GET`, `POST`, …, including `export { h as GET }`), Pages Router `pages/api/**` default exports, route groups, dynamic and catch-all segments, middleware/proxy auth checks as hints only for statically covered paths |
| Flask | `@app.route` / `@bp.route` / `@app.get` …, `add_url_rule`, blueprint `url_prefix` via `register_blueprint` |
| FastAPI | `@app.get` / `@router.post` …, `include_router(prefix=…, dependencies=[…])`, `Depends(…)` / `Security(…)` parameters and decorators |
| Django | `urlpatterns` with `path`, `re_path`, `url`, `include(...)` (followed within the snapshot), class-based `as_view()`, URLconf-local DRF `DefaultRouter`/`SimpleRouter` registrations (CRUD list/detail routes; literal prefixes with or without basename) |

Auth hints are middleware, guard, decorator or dependency names that match
`auth|login|session|jwt|token|passport|guard|protect|require(User|Admin|Role)|isAuthenticated|verify|acl|permission|rbac|admin|role|current_user|signed_in|logged_in|api_key|passes_test|staff|superuser`.
Names that also say rate limiting, throttling or logging (`limit`, `throttl`, `slowdown`, `logger`, `logging`, as in
`loginLimiter` or `authRateLimit`) are never auth hints. Neither is middleware that only loads state and never
rejects a request: session stores (`session(...)`, `cookieSession(...)`, `require('express-session')(...)`),
`passport.initialize()`, `passport.session()` and database-session dependencies such as `Depends(get_session)`.
Enforcing names such as `requireSession`, `verifySession` and `passport.authenticate(...)` still count.
They are hints for ranking and for the model, not proof of protection. Mounts or includes that cannot be resolved
in the snapshot produce warnings, and a scan that finds no endpoints records a coverage gap.

Next.js middleware must contain an auth-ish check, not just exist. An exported literal `config.matcher` string
or array grants a hint only to covered paths; simple literal segments and named parameters (including a final
`:path*`) are supported. Dynamic, object and regex matchers, spread configs and unreadable middleware do not grant
a blanket hint. Without a matcher, an auth-ish middleware check can cover all routes in that Next.js project,
unless the middleware reads the request path: then only routes under the literal prefixes of
`pathname.startsWith('/prefix')` conditions get the hint, and any other use of the path (a negated prefix, an
equality test, a list lookup) grants no hint at all.
DRF router endpoints inherit cheaply resolved ViewSet permission/authentication class names as hints; known
read-only bases, CRUD mixins and explicit action methods constrain the emitted CRUD methods. Unresolved router
includes produce the existing unresolved-mount warning. Custom DRF actions and runtime router generation are not
expanded.

## Dependencies (`src/host/analysis/dependencies.ts`)

| Ecosystem | Files |
| --- | --- |
| npm | `package-lock.json` / `npm-shrinkwrap.json` (v1–v3), `pnpm-lock.yaml` (v6–v9), `yarn.lock` (v1 and Berry), `package.json` (only when no lock file is next to it; ranges are recorded but not queried) |
| PyPI | `poetry.lock`, `uv.lock`, `Pipfile.lock`, `requirements*.txt` and `requirements/**/*.txt` (also parsed next to a lock); `-r`/`--requirement` includes follow snapshot files only, to a maximum depth of 16 |
| Go | `go.mod` (`require` blocks, `// indirect`) |
| crates.io | `Cargo.lock` |

Parsers are tolerant: a malformed file yields a warning and whatever could be read. Lock files win over manifests.
Names are normalized (PEP 503 for PyPI). Direct, transitive and dev dependencies are tracked.
Requirement include cycles, missing/excluded files, depth-limit exhaustion and paths outside the snapshot produce
warnings. Includes never fetch URLs or read files from the live filesystem.

Conventional manifest/lock basenames in this table are exempt from `maxFileBytes` up to 32 MiB each (they still
count toward `maxTotalBytes`), because real lock files often exceed 1 MiB. Other split requirements/include targets
retain the ordinary snapshot limits. A larger one is left out of the snapshot with a scan warning naming it.
Parsing is linear in file size and yields to the event loop: pnpm and Yarn Berry locks are read by a reader for
the block-YAML subset lock files use, which falls back to the full YAML parser for anything else.

### OSV lookup (`src/host/analysis/osv.ts`)

Lookup is off by default for privacy; New Scan links to the Privacy toggle, and Coverage calls out unchecked dependencies unless OSV-Scanner returned package results.

When `privacy.allowDependencyLookup` is on, each unique **exact** version is sent to
`<osvEndpoint>/v1/querybatch` (up to 1,000 per request), and advisory details come from `/v1/vulns/<id>` (at most
300 fetches, 4 at a time, 30 s timeout per request, 32 MiB response cap, schema-validated). Only ecosystem, package
name and version leave the machine. Severity comes from the database's label, else a CVSS v3 score or vector, else
*medium*. Each finding names the fixed versions when OSV lists them, and records "reachability not analyzed" as a
limitation. Network failures become warnings, and the scan continues offline.

## External analyzers (`src/host/analysis/external/`)

All three are optional. They are used when `privacy.useExternalAnalyzers` is on (the default) and the tool is
found, either as a managed install in `$DSH_HOME/security/toolkit/<id>/<version>/` or on `PATH`. The managed copy
takes priority. They run as child processes without a shell, with a scrubbed environment, in a temp working
directory, and under `externalTimeoutMs`. Their results are limited to files in the snapshot and redacted. See
[security-model.md](security-model.md#external-analyzers).

| Tool | How it runs | Produces |
| --- | --- | --- |
| **Gitleaks** (8.19+ uses `gitleaks dir`, older uses `detect --no-git`) | Plugin-written config with the default rules (the repository's `.gitleaks.toml` and ignore file have no effect), `--redact`, `--ignore-gitleaks-allow` (inline suppression disabled), max target 10 MB per file; a private JSON report is checked every 25 ms and the process tree is killed immediately once observed over 128 MiB (the final read rechecks the cap) | `secret` signals (critical for private keys, medium/low for generic rules, high otherwise) |
| **OSV-Scanner** (v2 preferred, v1 supported) | Targets only staged, non-withheld snapshot dependency files, never the live repository. `scan source --recursive --no-resolve --no-call-analysis=all --config <empty plugin-written file>` (the repository's `osv-scanner.toml` ignores have no effect), plus `--offline` unless OSV lookups are on. Offline with no local database → reported unavailable. | `dependency` signals, same shape as the built-in OSV lookup |
| **Semgrep** | Only if `semgrepConfig` is set: `semgrep scan --json --metrics=off --disable-version-check --disable-nosem --no-git-ignore --config <path>`, 2 MB per file, 30 s per rule. Registry rules are never used; `nosemgrep` comments are ignored, but a `.semgrepignore` file in the project still applies. | `vulnerability` signals, categorized from CWE metadata |

Semgrep's `--no-git-ignore` avoids git-aware target discovery: repository-local `core.fsmonitor` must not run.
The flag is present in [Semgrep 0.40.0](https://github.com/semgrep/semgrep/blob/v0.40.0/semgrep/semgrep/cli.py),
predating the `scan` CLI used here, and was exercised with Semgrep 1.181.0. Unsupported older tools fail closed;
there is no retry without the safety flag. Local rules, disabled metrics and disabled version checks remain in force.
Gitleaks' suppression flag was verified with the pinned 8.30.1 binary; versions that reject it fail rather than
retrying with suppression enabled. Gitleaks directory mode (and legacy `--no-git`) do not scan git history.
OSV-Scanner 1.9.2 reads repository state with go-git rather than invoking Git; 2.7.0 source scanning was also checked
against a repository fsmonitor hook. No equivalent Git-command execution reproduced in these runners. OSV's
staged target contains no repository Git configuration; disabled package-manager resolution and call/build analysis
remain defense in depth in both runner versions. Report polling bounds ongoing growth, but
writes between polls can exceed the threshold briefly; the oversized report is never parsed.

A built-in and an external result for the same issue (same file, start line, kind and category; for secrets
also overlapping columns when both report them) become one signal: the built-in one, preferring a hit with the
same CWE, with the higher of the two severities. Different rules on one line, such as a JWT `none` algorithm next
to `ignoreExpiration: true`, and different credentials on one line stay separate.

### Installing external tools

- **From the UI.** Settings → *Analyzers* shows each tool's status and license. For Gitleaks and OSV-Scanner, when
  this release pins a SHA-256 for your platform and the operator allows it (`allowManagedToolkit`), tick the
  license checkbox and press *Install*. The download is verified against `toolkit.lock.json` before it is
  installed. Pinned versions: Gitleaks 8.30.1 (linux/darwin x64+arm64, win32 x64) and OSV-Scanner 2.7.0
  (linux/darwin x64+arm64, win32 x64+arm64).
- **Manually** (any platform, or when no pin is available), then make sure the binary is on the `PATH` of the DSH
  Host process:
  - Gitleaks: `brew install gitleaks`, or a release binary from <https://github.com/gitleaks/gitleaks/releases>.
  - OSV-Scanner: `brew install osv-scanner`, `go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest`,
    or a release binary from <https://github.com/google/osv-scanner/releases>.
  - Semgrep: `pipx install semgrep` or `brew install semgrep`, then set `semgrepConfig` to a local rules file or
    directory in the operator config.
- On Windows only `.exe` files are considered (`.cmd`/`.bat` would need a shell), and only absolute `PATH` entries
  are searched.

## The ast-grep engine

`@ast-grep/napi` (optional dependency) gives tree-sitter ASTs for JavaScript, TypeScript and TSX. Python ASTs also
need `@ast-grep/lang-python` (also a pinned optional dependency). Its bundled platform prebuild is loaded without
requiring tree-sitter-cli; unsupported platforms fall back to the tokenizer. Files over 512 KiB, and files whose
parse has large error regions, also use the tokenizer. The `ast-grep` analyzer status in bootstrap and Coverage
states whether Python ASTs are available separately from the JavaScript/TypeScript engine. Set
`disableAstGrep: true` to force the tokenizer everywhere.
