# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Before 1.0, minor versions may contain breaking
changes; they are called out explicitly.

## [Unreleased]

## [0.1.0] - 2026-10-13

First public release.

### Added

- **DSH integration.** A bundle layer for DSH `>=0.2.1-alpha.2 <0.3.0-0`: a Host plugin (`lib/index.js`) and a Web
  client (`lib/client.js`). The client adds a Security sidebar entry, a Security page (Overview, Findings, History,
  Settings) and a Security section in DSH Settings. The UI is available in English, Japanese and Chinese.
- **Scan pipeline** with Quick, Deep and Research modes. Phases: snapshot, inventory, built-in checks, entry points,
  threat model, AI review, second opinion, attack chains, reconcile, report. Each mode has budgets for AI requests,
  tokens, minutes, requests per reviewer and review tasks. Scans run in a queue limited by `maxConcurrentScans`.
- **Pause, resume, cancel and crash recovery.** Stable task keys make a resumed scan skip completed AI work.
  Scans interrupted by a DSH shutdown can be resumed.
- **Built-in analyzers.**
  - Secret detection with 25 rules, which also drive redaction.
  - 50 SAST rules for JavaScript/TypeScript (including EJS, Handlebars, Pug, Vue and Svelte templates), Python
    (including Jinja and Django templates), Dockerfiles, Compose and Kubernetes manifests, using an optional
    tree-sitter engine (`@ast-grep/napi`) or a built-in tokenizer.
  - HTTP route extraction with middleware and auth hints for Express, Fastify, Koa, Hono, NestJS, Next.js, Flask,
    FastAPI and Django.
  - Dependency parsing for npm, pnpm, Yarn, Poetry, uv, Pipenv, requirements files, Go modules and Cargo.
- **Optional analyzers.**
  - OSV.dev lookups (off by default; only package names and versions are sent).
  - Gitleaks, OSV-Scanner and Semgrep when installed, run without a shell, with a scrubbed environment and with
    repository config overrides blocked.
  - Managed downloads of pinned Gitleaks and OSV-Scanner builds, verified by SHA-256 against `toolkit.lock.json`.
- **Read-only AI review** using DSH's LLM registry directly, with per-role models (Planner, Hunter, Skeptic, Chain
  analyst) and optional reasoning effort and output caps. Workers get six read-only snapshot tools and no shell,
  network or write access.
- **Host-verified evidence.** Every model citation is checked against the redacted snapshot. Findings without a
  verified step are discarded and counted in Coverage.
- **Independent skeptic review** in a fresh context. A refutation needs a verified counter-evidence quote, and a
  confirmation needs verified code on the attack path.
- **Separate severity and verification ratings** (Confirmed in code, Possible, Undecided, Ruled out), with closure
  derived from verification.
- **Triage** (Open, Accepted risk, False positive, Fixed) stored per project and line-independent fingerprint, and
  carried across scans. Findings that are new since the previous scan are marked.
- **"Fix in DSH chat"** hands a fix prompt to a normal DSH chat. "Copy fix prompt" and a Quick re-scan action are
  also available.
- **Reports:** Markdown (English or Japanese), JSON (`schemaVersion: 1`), and SARIF 2.1.0 with stable
  `partialFingerprints` and suppressions for refuted or triaged-away findings.
- **Privacy controls:** explicit consent before code is sent to models, built-in and user-defined withheld files,
  and redaction of secrets and the project path in every tool output. Operators can restrict the high-risk switches
  to the Host machine (`allowRemoteHighRiskSettings: false`).
- **Local storage** in `$DSH_HOME/security/security.db` (`node:sqlite`, owner-only permissions on POSIX), with
  retention and optional AI transcripts.
- **Fixtures and tests:** four intentionally vulnerable fixture apps with ground truth, a benchmark harness, and a
  deterministic scripted model for end-to-end tests without API keys.

### Known limitations

- `toolkit.lock.json` may ship without pinned SHA-256 values for some platforms. Managed installs are then refused
  for those assets; tools installed on `PATH` still work.
- Code-only scans never assign the *Reproduced* (`proven_dynamic`) verification.
- Route extraction and SAST rules cover JavaScript/TypeScript and Python only; other languages get secret,
  dependency and AI review coverage.

[Unreleased]: https://github.com/dsh-security/dsh-security-plugin/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/dsh-security/dsh-security-plugin/releases/tag/v0.1.0
