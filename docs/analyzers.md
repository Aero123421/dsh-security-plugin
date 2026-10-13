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

Files that look generated (`@generated`, `DO NOT EDIT`, minified) are skipped. Test, fixture and example files
are scanned with severity capped at **Low** and confidence **low**.

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
`env-secret`) are scan-only and use entropy, placeholder and key-name filters. Known example values (AWS docs keys,
the jwt.io sample, the Azurite key) and template values are ignored. Every secret finding is CWE-798.

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
| `database-url` | DB / broker URL with inline password (placeholder and default passwords dropped or downgraded) | high | high |
| `generic-secret` | Hard-coded password / token / API key assignment | medium | low |
| `env-secret` | Secret value in an `.env`-style file | medium | medium |

## Pattern rules (SAST, `src/host/analysis/sast/`)

50 rules. JS/TS and Python files are modeled with the native tree-sitter engine (`@ast-grep/napi`) when it is
available, and with a built-in tokenizer otherwise. Both modes run the same rules and are tested side by side.
Template and config rules match text. "Sink severity" is the severity of the `sink` variant; rules without one only
report when request data reaches them.

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
| `js.template-unescaped-output` | Unescaped template output | CWE-79 | medium | low |
| `js.insecure-deserialization` | Insecure deserialization (node-serialize) | CWE-502 | critical | medium |
| `js.unsafe-yaml-load` | js-yaml `load()` on dynamic data | CWE-502 | medium | low |
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
| `js.prototype-pollution` | Deep merge of user input | CWE-1321 | medium | medium |
| `js.regex-injection` | Regular expression built from user input (ReDoS) | CWE-1333 | medium | – |
| `js.hardcoded-credential-check` | Hard-coded credential or backdoor check | CWE-798 | medium | – |

### Python (`python.ts`)

Files: `.py .pyi .pyw`. Template rules cover `.html .jinja .jinja2 .j2 .djhtml .tmpl .tpl` (`|safe`,
`{% autoescape off %}`).

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
| `py.hardcoded-secret-key` | Hard-coded framework secret key | CWE-798 | high | – |
| `py.tls-verification-disabled` | TLS certificate verification disabled | CWE-295 | medium | – |
| `py.jwt-unverified` | JWT signature not verified | CWE-347 | high | – |
| `py.weak-password-hash` | Weak hash used for passwords | CWE-328 | medium | – |
| `py.insecure-random` | Predictable random value used as a secret | CWE-330 | medium | low |
| `py.mass-assignment` | Mass assignment from request data | CWE-915 | medium | – |
| `py.hardcoded-credential-check` | Hard-coded credential or backdoor check | CWE-798 | medium | – |

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

| Framework | What is recognized |
| --- | --- |
| Express | `app.METHOD`, `router.METHOD`, `router.route(path).get(…)` chains, `app.use(prefix, …mw, router)` mounts across files, ordered `router.use(mw)` (applies only to later routes) |
| Fastify | Shorthand methods, `fastify.route({ … })`, `onRequest`/`preHandler`/`preValidation`/`preParsing` hooks (route options and `addHook`), `register(plugin, { prefix })` |
| Koa | `@koa/router` / `koa-router` / `koa-tree-router` methods and nested routers |
| Hono | `app.METHOD`, `app.all`, `app.route(prefix, sub)` |
| NestJS | `@Controller(prefix)` + `@Get/@Post/…` methods, `@UseGuards` as middleware |
| Next.js | App Router `route.ts` exports (`GET`, `POST`, …, including `export { h as GET }`), Pages Router `pages/api/**` default exports, route groups, dynamic and catch-all segments, root `middleware.ts` as an auth hint |
| Flask | `@app.route` / `@bp.route` / `@app.get` …, `add_url_rule`, blueprint `url_prefix` via `register_blueprint` |
| FastAPI | `@app.get` / `@router.post` …, `include_router(prefix=…, dependencies=[…])`, `Depends(…)` / `Security(…)` parameters and decorators |
| Django | `urlpatterns` with `path`, `re_path`, `url`, `include(...)` (followed within the snapshot), class-based `as_view()` |

Auth hints are middleware, guard, decorator or dependency names that match
`auth|login|session|jwt|token|passport|guard|protect|require(User|Admin|Role)|isAuthenticated|verify|acl|permission|rbac|admin|role|current_user|signed_in|logged_in|api_key|passes_test|staff|superuser`.
Names that also say rate limiting, throttling or logging (`limit`, `throttl`, `slowdown`, `logger`, `logging`, as in
`loginLimiter` or `authRateLimit`) are never auth hints.
They are hints for ranking and for the model, not proof of protection. Mounts or includes that cannot be resolved
in the snapshot produce warnings, and a scan that finds no endpoints records a coverage gap.

## Dependencies (`src/host/analysis/dependencies.ts`)

| Ecosystem | Files |
| --- | --- |
| npm | `package-lock.json` / `npm-shrinkwrap.json` (v1–v3), `pnpm-lock.yaml` (v6–v9), `yarn.lock` (v1 and Berry), `package.json` (only when no lock file is next to it; ranges are recorded but not queried) |
| PyPI | `poetry.lock`, `uv.lock`, `Pipfile.lock`, `requirements*.txt` (also parsed next to a lock, since pip-compile output is often what gets deployed) |
| Go | `go.mod` (`require` blocks, `// indirect`) |
| crates.io | `Cargo.lock` |

Parsers are tolerant: a malformed file yields a warning and whatever could be read. Lock files win over manifests.
Names are normalized (PEP 503 for PyPI). Direct, transitive and dev dependencies are tracked.

The files in this table are exempt from `maxFileBytes` up to 32 MiB each (they still count toward `maxTotalBytes`),
because real lock files often exceed 1 MiB. A larger one is left out of the snapshot with a scan warning naming it.
Parsing is linear in file size and yields to the event loop: pnpm and Yarn Berry locks are read by a reader for
the block-YAML subset lock files use, which falls back to the full YAML parser for anything else.

### OSV lookup (`src/host/analysis/osv.ts`)

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
| **Gitleaks** (8.19+ uses `gitleaks dir`, older uses `detect --no-git`) | Plugin-written config with the default rules (the repository's `.gitleaks.toml` and ignore file have no effect), `--redact`, max target 10 MB per file | `secret` signals (critical for private keys, medium/low for generic rules, high otherwise) |
| **OSV-Scanner** (v2 preferred, v1 supported) | `scan source --recursive --no-resolve --no-call-analysis=all --config <empty plugin-written file>` (the repository's `osv-scanner.toml` ignores have no effect), plus `--offline` unless OSV lookups are on. Offline with no local database → reported unavailable. | `dependency` signals, same shape as the built-in OSV lookup |
| **Semgrep** | Only if `semgrepConfig` is set: `semgrep scan --json --metrics=off --disable-version-check --disable-nosem --config <path>`, 2 MB per file, 30 s per rule. Registry rules are never used; `nosemgrep` comments are ignored, but a `.semgrepignore` file in the project still applies. | `vulnerability` signals, categorized from CWE metadata |

Builtin and external results for the same location and category are de-duplicated (the first one wins).

### Installing external tools

- **From the UI.** Settings → *Analyzers* shows each tool's status and license. For Gitleaks and OSV-Scanner, when
  this release pins a SHA-256 for your platform and the operator allows it (`allowManagedToolkit`), tick the
  license checkbox and press *Install*. The download is verified against `toolkit.lock.json` before it is
  installed. Pinned versions: Gitleaks 8.28.0 (linux/darwin x64+arm64, win32 x64) and OSV-Scanner 2.2.2
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
need `@ast-grep/lang-python`, which is used when it is installed. Files over 512 KiB, and files whose parse has
large error regions, use the tokenizer. The status appears as the `ast-grep` analyzer in Coverage. Set
`disableAstGrep: true` to force the tokenizer everywhere.
