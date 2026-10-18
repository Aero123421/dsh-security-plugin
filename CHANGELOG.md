# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Before 1.0, minor versions may contain breaking
changes; they are called out explicitly.

## [Unreleased]

## [0.4.0] - 2026-10-18

### Changed

- Bump the browser/Host contract to version 4 for on-demand model details. Reload open DSH pages after updating.
  The database schema and saved scan history, consent, settings and triage remain compatible with 0.3.0.
- One Security controller owns a data directory at a time. A second DSH instance refuses to start Security
  against the same database instead of interrupting the first instance's work. Stop the other instance or
  configure a different `dataDir` for an independent profile. Ownership is recovered after its process exits.
- Model lists include all models. Reasoning and context metadata is fetched for selected models, with retry
  after failure, instead of resolving up to 100 models concurrently while discarding the remaining entries.
- Check both the `alpha` and `next` DSH channels in CI; `check:dsh --dsh-version=VERSION` also accepts an exact version.

### Fixed

- Use primary-key lookups for canonical and merged triage fingerprints when counting open findings, avoiding
  repeated scans through the project's historical triage decisions.
- Keep process-group SIGKILL escalation alive when an analyzer's parent exits before its descendants. On
  Windows, let taskkill enumerate the tree before directly terminating the parent as a fallback.
- Persist incomplete OSV lookups as analyzer failures, coverage limitations and report notices, including
  network failures, partial responses and missing advisory details.
- Add a Web-compatible project-folder browser using DSH's Host-directory API. Native-only DSH compositions
  retain their OS picker. Folder browsing handles cancellation, retry, hidden folders and bounded rendering.


## [0.3.0] - 2026-10-18

### Added

- Continue a budget-starved scan in place: when scheduled AI work was skipped because a budget ran
  out, the results page offers **Continue with more budget** (+50% / +100% / +300% of whichever
  dimensions ran out, still clamped to the operator ceilings). The scan keeps its findings, usage
  and completed tasks; only budget-skipped work runs again. This adds the `extendScanBudget` RPC
  method and bumps the wire contract to version 3, so an outdated page now shows the reload banner
  instead of failing individual requests.

### Changed

- Redesign the completed-scan summary as a plain report: severity counts are hairline rows
  (label left, count right, click to filter) in the same style as the coverage list, certainty is a
  single key/value line, and the not-complete caveat is a quiet footnote — no dashboard cards,
  charts, or big numbers. Finding titles clamp to two lines with the full text on hover. Coverage
  now shows only localized limitation sentences in primary copy, with every raw Host reason
  collected under a single technical-details disclosure instead of one toggle per analyzer or gap.
- Charge cache-read tokens at a tenth of the token budget (uncached input, cache writes and output
  still count in full), approximating typical provider cache pricing. Multi-turn workers resend
  mostly cached history, so full-rate charging drained token budgets roughly ten times faster than
  the underlying spend and ended scans with most tasks skipped while request and time budgets were
  barely touched. Reported input-token usage is the same charge; raw per-request counts remain in
  transcripts. Usage recorded by earlier versions stays counted at the old rate.

- Triple the default per-mode scan budgets (model requests, tokens, minutes, worker turns and tasks),
  the default operator token/request ceilings, the short-role turn cap (16 → 48), and the per-reply
  tool-call cap (16 → 48). Existing saved budgets and explicit operator overrides are preserved;
  scans already created keep their original budgets. Concurrency, privacy and retry limits are unchanged.

### Fixed

- Separate scan execution completion from AI review coverage: built-in-only, not-run, failed,
  partial and completed scheduled work are distinguished. Completed results retain notices,
  usage, workers and the latest activity, with retry on log-loading errors. Independent review
  is checked per finding, not inferred from another worker's completion.
- Localize structured coverage gaps and analyzer diagnostics in English, Japanese and Chinese;
  retain original and legacy messages in expandable technical details. Structured diagnostics
  use the same host-path masking as existing results.
- Preserve triage edits made during a save and prevent stale reads from undoing saved decisions.
  Reconnect revalidates completed findings, while cross-project responses and deleted-scan reads
  cannot replace the current selection or revive deleted results.
- Disable closing the New Scan dialog while its start request is pending. Lost creation responses
  are reported as result-unknown and trigger a history refresh, without automatic resubmission
  or rolling back consent for a potentially accepted scan. Disposed clients start no new work.
- Re-scan findings at the original depth. Chat handoff preserves existing unsent input and reports
  only that opening was requested; if DSH did not insert the prompt, use the existing copy action.
- Add history pagination beyond the first 50 scans, keep export menus outside clipping containers,
  and preserve keyboard navigation when menus are portaled. Show model-refresh errors and retry
  even when a previously loaded model list remains available.
- Activity entries name the actual phase instead of "Unknown", and scan lifecycle events (created,
  resumed, interrupted, notices, discarded evidence, budget extended) have localized primary text
  instead of a generic diagnostic label. The independent-review warning only fires for findings the
  Host would actually schedule for review. A detail cached before a scan's status changed no longer
  shadows the fresher outcome. Bootstrap analyzer statuses carry the same localized reason codes as
  scan coverage, and the New Scan dialog always releases its busy state after a start attempt.

## [0.2.2] - 2026-10-16

### Fixed

- Settings saves preserve edits made while saving. Superseded scan and finding loads no longer replace newer results;
  finding selection stays scoped to the scan being viewed.
- Dialog focus stays inside while a focused control is busy, and returns to that control after a failed action.
- Scan estimates expire after 30 seconds and refresh with the project list. Large finding lists initially show
  200 rows with a Show more button, and reuse search fields and unchanged rows.
- New Scan explains that AI code-sharing consent is saved for future scans until disabled in Settings. Failed
  scan creation best-effort restores consent enabled by that attempt without overwriting newer settings.
- Evidence gates reject comment-led mixed citations, string-literal prose, nested-comment text, and punctuation
  alone as verified code. New AI findings and confirmation upgrades require real code evidence; stored supporting
  steps retain their non-code classification. Code-led citations containing strings or explanatory comments still work.
- Finding identities use verified source quotes without tool line numbers. Hunter deduplication requires intersecting
  ranges, keeping adjacent vulnerabilities separate. Identical SAST sinks receive distinct occurrence identities;
  adding/removing identical sinks may require re-triage rather than hiding a surviving issue.
- Triage follows primary and merged fingerprints across scans in finding lists, details, reports, and open counts.
- Reconcile legacy symlink/trailing-slash project roots at startup and when registered projects first become
  available, including stores already migrated by 0.2.0/0.2.1. History and triage use the canonical project path;
  the newest triage decision wins (canonical rows win timestamp ties). No schema version change is required.
  Paused and queued legacy scans accept canonical-equivalent workspace roots when starting again.
- Recover interrupted scans atomically, repair partial recovery from older versions on the next startup, and
  close stale running workers when an attempt resumes or finishes. Resuming clears the previous finished time.
- Install the optional Python AST grammar alongside ast-grep, report Python fallback separately from JS/TS AST
  availability, and reject undeclared Host bundle runtime modules during package verification.
- Run npm/pnpm/npx through their Windows command launchers in `check:dsh`.
- Retry transient stream termination from bundled adapters without tripping the route-rejection breaker after
  streamed content/reasoning/tool activity. Immediate zero-data request rejections still stop unopened same-route tasks.
- Recognize bundled pi-ai Anthropic/OpenAI/Gemini refusal shapes without confusing structural `content` field errors
  with policy refusals. Assemble delta-only replies, tolerate nonempty clean EOF, and never wait indefinitely for
  iterator cleanup after a finish chunk.
- Validate exact model routes, supported reasoning efforts, and reported context bounds before creating AI scans.
  DSH does not expose a separate output ceiling through its public resolved-model API.
- Explicit resume retries failed tasks within a three-worker-run total cap, refreshes pending task inputs, skips
  vanished targets without model calls, and enforces the same per-project busy rule as new scans.
- Apply the time deadline to deterministic analysis and external tool process trees, including analyzer-only scans.
  Analysis interrupted by the deadline remains resumable with an explicit coverage gap; resume re-analysis still
  consumes the original budget. Transcript storage follows the current setting at each worker completion.
- Continue snapshot packing after non-fitting files, bound traversal (including excluded-only trees) with
  `maxEntries`, count observed exclusions beyond the displayed list cap, respect platform-default ignore casing,
  and keep hand-written components analyzable when only one line is unusually long.
- When remote high-risk settings are reserved for same-machine pages, remote pages cannot change withheld-file
  patterns or model provider/model routes while code upload is enabled before or after the change. Authenticated
  remote pages may still start scans using existing consent.
- Workspace tools now mask copies of all built-in detected secret values, including generic secrets copied into
  documentation, header dictionaries, generated files and oversized files. Known-value matching is deduplicated,
  bounded and fails closed at its limit; values shorter than eight characters still rely on spans and patterns.
- OSV lookups omit withheld manifests. OSV-Scanner now scans staged, non-withheld snapshot dependency files instead
  of the live workspace, so excluded and subsequently added files cannot disclose packages.
- Corrupt settings JSON now falls back to defaults with a Host warning; a settings update repairs the row while
  retaining optimistic revision checks.
- Model requests and workspace tools mask both registered and canonical workspace root spellings, including
  Windows/macOS-style case variants, without changing `<root>` suffix semantics.
- Fix-in-chat drafts now fence the finding title as untrusted report text instead of including it in a heading.

- Remove exponential regex backtracking from leading JavaScript comment headers and Express response chains.
- Disable Semgrep's Git-aware target discovery so repository-local fsmonitor hooks cannot execute. Gitleaks ignores
  inline suppression comments and terminates over-limit report writers instead of allowing unbounded report growth.
- Extract DRF router CRUD endpoints at Django include mounts, with resolvable ViewSet permission hints and warnings
  for unresolved routers. Follow split requirements and snapshot-confined requirement includes, reporting missing
  targets, cycles and depth limits.
- Detect SQLAlchemy raw text in query-builder predicates and TypeORM/Sequelize string SQL sinks without treating
  parameter bindings or object filters as SQL strings.
- Apply Express route-chain `.all(...)` middleware to subsequent method routes. Next.js middleware auth hints now
  require an auth-ish check and a statically covering matcher, rather than middleware presence alone.

### Performance

- Cache the ordered findings list within a hunter-output transaction instead of reloading and sorting it for every
  finding; preserve same-batch overlap precedence and evidence updates.
- Reuse per-function alias-state cursors for increasing taint-query offsets, retaining exact backward-query and
  parameter-shadowing behavior without quadratic event replay.

## [0.2.1] - 2026-10-16

### Fixed

- The project picker now uses a themed dropdown in the page header and New Scan dialog instead of an OS-native
  popup. Project titles and paths appear on separate lines, with keyboard navigation and the selected project marked.
- AI review now sends a session id with model requests, required by some providers such as OpenCode Go,
  which previously rejected every request. Failed review tasks now show the provider error. Scans stop
  launching hunt/review tasks on a model route whose provider rejects the first request outright without
  reporting any token usage; already-running workers and other routes are unaffected.

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

[Unreleased]: https://github.com/Aero123421/dsh-security-plugin/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/Aero123421/dsh-security-plugin/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/Aero123421/dsh-security-plugin/compare/v0.2.2...v0.3.0
[0.2.2]: https://github.com/Aero123421/dsh-security-plugin/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/Aero123421/dsh-security-plugin/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/Aero123421/dsh-security-plugin/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/Aero123421/dsh-security-plugin/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/Aero123421/dsh-security-plugin/releases/tag/v0.1.0
