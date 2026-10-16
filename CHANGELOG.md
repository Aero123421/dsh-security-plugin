# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Before 1.0, minor versions may contain breaking
changes; they are called out explicitly.

## [Unreleased]

### Fixed

- The project picker now uses a themed dropdown in the page header and New Scan dialog instead of an OS-native
  popup. Project titles and paths appear on separate lines, with keyboard navigation and the selected project marked.

## [0.2.0] - 2026-10-16

This minor release contains breaking changes, as allowed before 1.0: the Host/client contract is now version 2
(mixed old/new pages show the existing reload banner) and the local store migrates to schema v2 (see
*Upgrade notes* below).

### Added

- Add a project folder from the Security page or New Scan dialog when DSH’s folder services are available.
  The folder is registered in DSH’s project list and selected for scanning; the dialog always shows its project.
- Coverage calls out parsed dependencies not checked for known vulnerabilities when online OSV lookup is off and
  OSV-Scanner returned no package results. The New Scan dialog explains the default-off lookup and links to Settings.
- Python SAST rules detect explicitly disabled Secure flags on session/CSRF cookies and HttpOnly on session
  cookies, including Flask config assignments and `config.update(...)`. There are now 52 SAST rules.
- Scan an optional subfolder (for example `packages/app`) without scanning an entire umbrella workspace.
  History labels show the selected folder. Findings keep workspace-relative paths, and triage is shared with
  whole-project scans. History and triage now survive DSH re-registering the same project with a new workspace id.

### Fixed

- Generic secret detection no longer reports high-entropy natural-language messages dominated by non-ASCII
  letters, including Japanese and Chinese message catalogs. Opaque tokens in the same files remain detectable.
- Secrets in test, fixture and example files remain visible but now have severity capped at Low, matching SAST;
  their confidence downgrade is unchanged.
- A generic secret and a specific secret/SAST credential rule covering the same sensitive span now produce one
  finding, preserving both observations as evidence and the merged fingerprint. Adjacent credentials stay separate.

### Upgrade notes

- Store schema v2 migrates automatically on startup. Older plugin versions refuse the newer database.
  Before updating, back up `$DSH_HOME/security/security.db` if you may downgrade (stop DSH before copying or
  restoring the database). If the page shows a mixed-version banner after updating, reload it.

### Changed

- Deep and Research AI review now sweep otherwise-untargeted source files within the existing task budget,
  after higher-priority review work. Configuration, settings, cookie and security-related names also steer file review.
- Quick AI review now fills spare task slots with the riskiest endpoints after rule-hit triage, without raising
  its task or model-call limits. Unguarded mutating and sensitive routes steer review but are not findings.
- Hunters can retry rejected citations three times (was two). Ambiguous-quote errors list candidate lines so
  the model can correct its citation; evidence verification requirements are unchanged.

- Managed analyzer downloads now pin Gitleaks 8.30.1 (was 8.28.0) and OSV-Scanner 2.7.0 (was 2.2.2) in
  `toolkit.lock.json`, with SHA-256 hashes verified against the upstream checksums files. Newer OSV-Scanner
  releases enable more lockfile extractors by default, so scans may report packages older pins did not see.

## [0.1.1] - 2026-10-15

### Fixed

- SQLite writes that use numbered `?NNN` parameters now succeed on Node.js 22.19.0, the lower bound of `engines.node`.
  That release names `?NNN` parameters and skips them when a statement is given a positional argument list
  (`ERR_SQLITE_ERROR`, errcode 25, column index out of range), so scans could not be stored. Node.js 22.20.0 and
  later accept the positional list; the store binds `?1`, `?2`, … by name, which both releases accept.
  ([#4](https://github.com/Aero123421/dsh-security-plugin/issues/4))

### Documentation

- Inventoried the plugin's loopback checks (`isLoopbackRequest`) against the DSH Host-header issue. The check only
  decides which settings a browser page may change; authentication stays with DSH. No behaviour change; regression
  tests pin that `X-Forwarded-*` headers do not affect it.
  ([#5](https://github.com/Aero123421/dsh-security-plugin/issues/5))

## [0.1.0] - 2026-10-13

First public release.

### Added

- **DSH integration.** A bundle layer for DSH `>=0.2.1-alpha.2 <0.3.0-0`: a Host plugin (`lib/index.js`) and a Web
  client (`lib/client.js`). The client adds a Security sidebar entry, a Security page (Overview, Findings, History,
  Settings) and a Security section in DSH Settings. The UI is available in English, Japanese and Chinese.
- **Scan pipeline** with Quick, Deep and Research modes, plus a "built-in checks only" option that sends nothing to
  models. Phases: snapshot, inventory, built-in checks, entry points, threat model, AI review, second opinion, attack
  chains, reconcile, report. Each mode has budgets for AI requests, tokens, minutes, requests per reviewer and review
  tasks; the time budget aborts in-flight requests, and requests with no stream data for `llmIdleTimeoutMs` are
  retried. Scans run in a queue limited by `maxConcurrentScans`.
- **Pause, resume, cancel and crash recovery.** Stable task keys make a resumed scan skip completed AI work.
  Scans interrupted by a DSH shutdown can be resumed.
- **Built-in analyzers.**
  - Secret detection with 25 rules, which also drive redaction.
  - 50 SAST rules for JavaScript/TypeScript (including EJS, Handlebars, Pug, Vue and Svelte templates), Python
    (including Jinja and Django templates), Dockerfiles, Compose and Kubernetes manifests, using an optional
    tree-sitter engine (`@ast-grep/napi`) or a built-in tokenizer. `js.xss` also covers Markdown rendered to raw HTML
    without a sanitizer.
  - HTTP route extraction with middleware and auth hints for Express, Fastify, Koa, Hono, NestJS, Next.js, Flask,
    FastAPI and Django, including routers mounted from other files (`app.use('/api', requireAuth, router)`,
    `include_router`, `register_blueprint`, Django `include`). Rate limiters and loggers are not counted as guards.
  - Dependency parsing for npm, pnpm, Yarn, Poetry, uv, Pipenv, requirements files, Go modules and Cargo, with
    single-pass lock-file indexing (a 16k-package lock file parses in well under a second). Lock files are exempt
    from `maxFileBytes` up to 32 MiB; a lock file left out for size is named in a scan warning.
- **Optional analyzers.**
  - OSV.dev lookups (off by default; only package names and versions are sent).
  - Gitleaks, OSV-Scanner and Semgrep when installed, run without a shell, with a scrubbed environment and with
    repository overrides blocked (`.gitleaks.toml`, `osv-scanner.toml` ignores, `nosemgrep` comments).
  - Managed downloads of pinned Gitleaks and OSV-Scanner builds, verified by SHA-256 against `toolkit.lock.json`.
- **Read-only AI review** using DSH's LLM registry directly, with per-role models (Planner, Hunter, Skeptic, Chain
  analyst) and optional reasoning effort and output caps. Workers get six read-only snapshot tools, at most 16 tool
  calls per reply, and no shell, network or write access.
- **Host-verified evidence.** Every model citation is checked against the redacted snapshot, and its location is
  narrowed to the quoted lines. Citations wider than the quote + 40 lines are rejected, and a quote that occurs more
  than once in a loose range is ambiguous. Findings without a verified step are discarded and counted in Coverage.
- **Independent skeptic review** in a fresh context. A refutation needs verified counter-evidence that is code, not
  only comments or documentation; a confirmation needs verified code on the attack path. A hunter alone never rules
  out a rule hit. Severity changes apply only to confirmed verdicts with verified code, and lower a deterministic
  critical/high rule hit by at most one level.
- **Separate severity and verification ratings** (Confirmed in code, Possible, Undecided, Ruled out), with closure
  derived from verification.
- **Triage** (Open, Accepted risk, False positive, Fixed) stored per project and line-independent fingerprint, and
  carried across scans. Findings that are new since the previous scan are marked.
- **"Fix in DSH chat"** hands a fix prompt to a normal DSH chat, with model-written text and code fenced and labelled
  as untrusted data. "Copy fix prompt" and a Quick re-scan action are also available.
- **Reports:** Markdown (English, Japanese or Chinese), JSON (`schemaVersion: 1`), and SARIF 2.1.0 with stable
  `partialFingerprints` and suppressions for refuted or triaged-away findings.
- **Privacy controls:** explicit consent before code is sent to models (turning it off stops AI work in queued,
  paused and running scans), built-in and user-defined withheld files that never reach a model through tools or task
  messages, redaction of secrets and the project path in everything sent to models, and masking of Host paths in
  everything sent to the browser. Operators can restrict the high-risk switches to pages served on the Host machine
  (`allowRemoteHighRiskSettings: false`); this is a browser-page policy, not a boundary against clients holding the
  DSH credentials.
- **Local storage** in `$DSH_HOME/security/security.db` (`node:sqlite`, owner-only permissions on POSIX), with
  retention and optional AI transcripts.
- **Distribution through GitHub:** install with `github:Aero123421/dsh-security-plugin#vX.Y.Z` (the built `lib/` is
  committed and checked against a fresh build in CI) or the release tarball with `SHA256SUMS`. The Settings tab
  shows the running version and how to update; the plugin makes no update checks of its own.
- **Fixtures and tests:** four intentionally vulnerable fixture apps with ground truth, a benchmark harness
  (`pnpm bench`, `bench/score.ts` for real-model runs), and a deterministic scripted model for end-to-end tests
  without API keys.

### Known limitations

- Code-only scans never assign the *Reproduced* (`proven_dynamic`) verification.
- Route extraction and SAST rules cover JavaScript/TypeScript and Python only; other languages get secret,
  dependency and AI review coverage.
- Text written by the Host (activity log, analyzer messages, built-in rule descriptions) is in English; the UI and
  report labels are localized.

[Unreleased]: https://github.com/Aero123421/dsh-security-plugin/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/Aero123421/dsh-security-plugin/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/Aero123421/dsh-security-plugin/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/Aero123421/dsh-security-plugin/releases/tag/v0.1.0
