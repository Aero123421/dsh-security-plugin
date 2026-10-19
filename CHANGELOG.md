# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Before 1.0, minor versions may contain breaking
changes; they are called out explicitly.

## [Unreleased]

### Added

- `pnpm e2e` runs every fixture app as its own project in a scratch DSH with the scripted model, scans them at
  the same time, and checks each report (completion, AI tasks, recall, negative controls, discarded fabricated
  claims, no file paths from another project) and the shared scan queue. CI runs it against the DSH `alpha` and
  `next` dist-tags. The scripted model now answers per fixture app, so several fixture projects can share one DSH.
- The project picker shows each project's state: scanning, queued, paused, or the open findings of its last scan.
  A queued scan names the project whose scan it waits for and links to it. While any scan is queued or running,
  the page polls the active scans of all projects (every 5 seconds, 10 seconds while the tab is hidden).
- Operator setting `llmFirstChunkTimeoutMs` (default 10 minutes): how long a model request may wait for its first
  stream chunk. `llmIdleTimeoutMs` (default 2 minutes) now applies only once the stream has started, so queued
  requests at busy providers are no longer abandoned after 2 minutes.
- New SAST rules `js.xxe` (libxmljs with `noent: true`), `py.xxe` (lxml parser with `resolve_entities=True`),
  `py.reflected-xss` (request data in an HTML string returned by a Flask view or sent with `make_response`,
  Django `HttpResponse` or `HTMLResponse`) and `py.cors-misconfiguration` (`CORSMiddleware` with `"*"` or a
  catch-all regex plus credentials, Flask-CORS with credentials and no origin list, django-cors-headers allowing
  all origins with credentials).
- More sinks and sources: postgres.js `sql.unsafe()`, asyncpg and `databases` fetch methods with SQL text,
  werkzeug `FileStorage.save()` under the upload's own name, `tarfile` extraction of an uploaded archive without
  `filter=` (tar slip), Jinja2 `Environment().from_string()`, NestJS `HttpService`, Koa `ctx.body` HTML strings,
  and GraphQL resolver arguments, NestJS/type-graphql `@Args()` and tRPC procedure `input` as request data.
- Give the AI review a hint for SSRF, path traversal and open redirect sinks whose value has no visible source,
  such as a webhook URL loaded from the database or a file name passed in by a caller. These rules used to stay
  silent unless request data was visible; they now emit a low-severity `sink` (never a finding) for dynamic
  values, except for fixed hosts, same-site paths, sanitized file names, framework-built URLs, metadata-only file
  calls and requests made from browser code. Findings are unchanged.
- Scan unquoted upper-case environment settings in YAML for secrets (`- JWT_SECRET=…` and `POSTGRES_PASSWORD: …`
  in docker-compose, CI `env:` blocks, Kubernetes Secret data), reported as `env-secret`. These values are now
  also redacted when a compose file or manifest is shown to the AI review. Values that only point at a secret
  (`${VAR}`, YAML anchors and tags, SOPS `ENC[…]`, ARNs and secret-manager paths) and the example passwords of
  container image docs (`mysecretpassword`) are ignored.
- Coverage ledger: the results page lists the parts of the project the AI review was planned to examine and what
  became of each (examined, with findings, undecided, not examined, with the reason), plus the number of source
  files that belong to no part. The Markdown report has a *Review units* table and the JSON report the same data
  (`coverage.units`, `coverage.unassignedFiles`); SARIF does not. New coverage gaps: `unassigned-files` and
  `excluded-by-plan`. Hunters may state how completely they examined their part (complete, partial, needs
  runtime), which marks the part *Undecided*. Titles of parts the Host adds itself (endpoint, rule-hit and sweep
  tasks) are shown in the UI language.
- Coverage critic: after the first hunt wave, Deep runs one pass and Research up to two in which the Planner's model
  reads the ledger, the source files no reviewer opened and the endpoints no task reviewed, and adds up to 8 (Deep)
  or 16 (Research) parts for real gaps. The passes are paid out of the hunt budget: waves stop at a ceiling that
  keeps up to 20% of the hunt requests for them, and a fifth of the task limit stays free for their parts. A pass
  that fails or adds no valid part ends the passes; the critic's `done` flag does not, if it also submits parts.

### Changed

- Rework the Security page to follow DSH's own patterns: severity and status as a colored dot with plain text
  instead of pill badges and signal bars; a centered empty state; one Export menu; filter menus for severity,
  status, decision and source instead of rows of chips; a segmented review-depth control with a one-line
  description instead of mode cards; a one-line scope estimate; and one "Usage and activity" disclosure for usage,
  reviewers and the activity log. Results start with how complete the AI review was, then the open findings, then
  coverage.
- Order the finding detail as Problem, Evidence, Independent review, Fix and Decision. Repeated evidence excerpts
  are shown once, and the re-scan button names the depth it reuses.
- The activity log shows the Host's own sentence for reviewer, warning and failure events (after a localized
  label in Japanese and Chinese) instead of "check technical details" placeholders.
- Adding a project folder from the header selects it without opening New scan.
- Offer **Add budget** only when a budget limit stopped scheduled AI work, not for every incomplete review.
- Tasks skipped because their target file no longer exists no longer count as unfinished AI review work.
- Deep and Research scans keep part of the budget for the independent review. Hunting stops at a ceiling that
  reserves about 6 AI requests per finding awaiting review (at most 30% in Deep, 35% in Research), the Research
  attack-chain run, and 2 wrap-up requests per worker running in parallel (at most 5%). Lower-priority hunt tasks
  that do not fit are skipped with the notice `hunt-budget-reserved` and run after **Add budget**; low-priority file
  sweeps are planned only as far as the budget pays for them. Before, hunters could spend the whole budget and
  leave most findings without a review (8 of 56 reviewed in a Deep probe; 46 of 56 now).
- A reviewer stopped by the budget mid-task now gets one wrap-up request to submit what it found, instead of
  losing all of its work. On its last request, a submission is accepted with what verifies, list entries that do
  not fit the schema are dropped, and other tool calls are refused with a note instead of discarding the run. A
  missed last turn gets one grace request.
- Workers see the same tool list on every request (stable prompt cache), are reminded to submit at 75% of their
  turns, and are told how many replies a task allows. Plain-text replies end a run only when three come in a row,
  not three over the whole run.
- Quote verification undoes harmless copy mistakes before matching: line-number prefixes of other formats
  (`12: `, `12 | `, `12→`, `L12: `, `cat -n`, `path:12: `), code fences, escaped or typographic quotes, HTML
  entities, full-width punctuation, a trailing `;`, and `...`/`…` for skipped lines (every fragment with a letter or
  digit must occur in order in the cited window, however short, and one fragment must have 12 or more characters;
  fragments of punctuation alone are skipped). The stored quote and snippet are always the file's own span.
  Rejected citations now come back with where the quote stops matching and the file's actual lines. In a probe of
  313 realistic citation variants, 275 verify instead of 149.
- A cited range much wider than its quote is no longer rejected outright: it verifies when the quote occurs once in
  the file. A quote that repeats in the file is bound only to the copy on the cited lines; a few lines off, it is
  reported as ambiguous with the candidate lines instead of being bound to a nearby identical line.
- Hunter submissions keep their verified findings across resubmissions (up to 3), ask once for missing rule-hit
  verdicts, and send back an empty submission made before reading any code once. The unused `confidence`,
  `reviewed_paths` and `notes` fields were removed from `submit_findings`; models that still send them are accepted.
  Submit tools accept common argument mistakes (`null`, JSON-encoded strings, numeric strings, enum spelling, camelCase
  keys) instead of rejecting the whole submission.
- `search_code` runs a pattern that looks like a regular expression as one when a literal search finds nothing,
  within the same per-call limits, and says so.
- Workers ask for temperature 0.2 when the model's details show it is not a reasoning model; a provider that
  rejects it is retried without one.
- When a planned independent review did not complete (budget, failure, review cap), a hunter's verified-code
  dismissal of a rule hit now makes it `inconclusive`, as it already did without a reviewer.
- Endpoint review tasks of layered apps target the handler file and the route file instead of only the
  `*.routes.ts` file. Task keys of such endpoint groups change from the route file to the handler file.
- Tell every endpoint and sweep review to look for injection, OS command execution, SSRF, path traversal and XSS.
  Sweeps were asked only about authentication, authorization, business logic, crypto and configuration, and
  endpoint reviews added other categories only from rule hits in the handler file; rule hits in the route file
  now count too.
- Quick scans also verify medium sinks of high and critical rules (dynamic SQL, shell commands, code evaluation,
  unsafe deserialization), which in layered code are often the only trace of an injection; before, Quick
  triaged only vulnerability hits.
- AI-led planning replaces rule-driven task planning. The `threat-model` phase, now shown as *Review plan*, is
  reconnaissance in every AI mode: the Planner maps the repository in any language (directory overview, manifests,
  endpoints with auth hints, rule hits per file, read-only workspace tools) and submits `submit_review_plan` with
  the threat model, components, coverage units (up to 8 in Quick, 40 in Deep, 80 in Research, never above the task
  limit, at most 8 files each) and exclusions (vendored, generated, documentation or fixtures only). Units
  beyond the mode's limit are dropped instead of sending the whole plan back. Target paths are resolved against
  the snapshot (directories, near matches, symbol names); a unit none of whose paths exists is sent back once with
  suggestions and otherwise dropped. Each unit becomes a hunt task that carries the unit's rationale and optional
  hypothesis (unverified), the threat model's actors and trust boundaries, and the rule hits in the unit's files;
  the unit's priority ranks it in Deep and Research. The Host still plans what the units leave out: endpoint
  tasks, a verdict task for every reportable rule hit, and a sweep of source files no task targets (all modes,
  within the task limit and what the hunt budget can pay for; production files and files whose names say what
  they enforce, such as `requireRole.ts`, `tenantScope.ts` or `upload.ts`, come first). The Planner gets up to 10
  replies in Quick (plus a grace request if its last reply submits nothing, and retries of failed requests), and
  a Quick scan with no rule hits can run AI tasks. The plan is stored with the scan and never planned again on
  resume. Source files that no task covers are reported as unassigned instead of being left unmentioned.
- Downgrade caveat: scans from this version store `hunt-unit` and `critic` tasks and the review plan in the threat
  model record. An older plugin version that opens a database with such scans treats those task rows as corrupt, so
  do not downgrade over a database that holds them. Scans from older versions (hypothesis and file tasks) still
  resume. No database migration is needed.

### Security

- The review plan's exclusions can no longer take hand-written code out of the AI review. A path is excluded from
  the sweep only when the Planner's reason claims vendored, generated, documentation or fixture code and every
  visible file under it carries a marker the Host sees itself: a vendor or third-party directory, generated
  content or a generator's directory or file name, a documentation directory or `.md`/`.rst`/`.txt` file, or a
  fixture, example, sample or mock directory. Paths with detected endpoints or rule hits and the workspace root are
  never excluded. The check runs again on every run, so resumed scans and plans stored by earlier versions are
  covered. Refused entries stay in the review and are logged as the info event `plan-exclusions-refused`. The
  `excluded-by-plan` diagnostic now lists the excluded paths (`params.paths`, the first 10 and `(+N more)`). Before,
  words like "external" or "docker" in the reason and any existing path were enough.

### Fixed

- A task the model provider refused (content policy) now keeps the error code `blocked_by_provider`, with the
  provider's code at the start of the message, so the coverage ledger shows its unit as *provider-rejected*. It
  stored the provider's own code (such as `CONTENT_FILTER`) and showed as failed.
- The coverage critic listed hunt tasks that were still waiting for a later wave as not run and their files and
  endpoints as never opened or given, so it planned duplicates. It now sees them in a separate *queued* list ("will
  run, do not plan again") and their files and endpoints are left out of the gap lists. In the final ledger a hunt
  task still pending or running without an error counts as not examined for `budget`, not as failed.
- The critic reserve now holds under parallel hunters. Wave hunters work under the wave ceiling and get the usual
  wrap-up request there; before, they ran under the full hunt ceiling and tasks started just below the wave
  ceiling could use up the reserve, so the critic never ran. A wave hunter refused before its first request goes
  back to pending for a later pool instead of being skipped. The final pool keeps the full hunt ceiling.
- A resumed scan could plan duplicate sweeps. Sweep groups of 4 files are now built from the files the plan's own
  tasks leave and keyed by all of their files; files that other stored hunt tasks target (critic units, legacy
  `file:` and `hypothesis:` tasks) are removed afterwards without regrouping, so re-planning finds the same tasks.
- Closing a dialog no longer moves focus back to its opener when another dialog has already taken focus. Escape
  closes the topmost dialog even when focus has left it.
- The folder browser's breadcrumb has its own accessible name instead of repeating "Folder path".
- In Deep and Research, rule hits beyond the 12 attached to an endpoint file's first task were never assigned to a
  hunter. They now get their own tasks.
- Tool calls of a reply cut off at the output limit were parsed from partial arguments and replayed. They are now
  dropped, and the model is told which calls to resend.
- Context compaction kept only the last two tool results, including in the middle of the latest reply's batch. It
  now elides the oldest results first, never the latest reply's, names the elided call, and runs before a request
  would exceed a known context window.
- A model route that answers without ever calling a tool no longer burns every task: after two such tasks in a row
  its remaining tasks are skipped with the notice `model-no-tools`.
- Tool schemas no longer carry meaningless `minimum`/`maximum` bounds of ±(2^53 − 1) on integer fields.
- Skeptic task messages label host-checked excerpts as "quote found in the repository (not a verdict)", and the
  reviewer is told that a SQL string alone or a search without callers does not refute a finding.
- Keep every distinct rule hit and credential on a line. Scan-level de-duplication merged any two signals of
  the same kind and category on one line, so a JWT `none` algorithm next to `ignoreExpiration: true`,
  `httpOnly: false` next to `secure: false`, an AWS secret key next to its key ID, or a Slack token next to a
  database URL lost a finding (sometimes the more severe one). Now only a built-in and an external result for
  the same issue are merged, and the merged signal keeps the higher severity.
- Stop treating `session()`, `cookieSession()`, `passport.initialize()`, `passport.session()` and database-session
  dependencies (`Depends(get_session)`) as auth hints. They load state but never reject a request, so an app
  that installs them globally had every route presented as guarded, and the unguarded-route steering signal
  never fired.
- Next.js middleware whose auth check sits behind `pathname.startsWith('/prefix')` gives auth hints only to routes
  under that prefix instead of to every route; other reads of the request path give none.
- Locate route handlers imported from controller modules (`import * as controller` then `controller.getUser`,
  named and default imports, exported objects, classes and instances, CommonJS exports, `export *` barrels).
  Layered Express apps had almost no handler located.
- Follow request data through helpers imported by name, such as `import { join } from 'node:path'` then
  `readFile(join(dir, req.params.name))`, `import * as p from 'path'`, and Python `from os.path import join`.
  Taint only passed through these helpers when they were called as `path.join(...)`.
- Treat destructuring defaults the same without the native engine: the built-in tokenizer (used when ast-grep is
  unavailable, for files over 512 KiB and for files with parse errors) recorded `name = 'x'` in
  `const { name = 'x' } = req.query` as a constant assignment and missed the injection. It also now records
  destructuring assignments such as `({ sort = 'id' } = req.query)`, as the AST mode does.
- Stop reporting common validation idioms as injections. The condition of `req.query.x ? 'a' : 'b'` no longer
  taints its result, a branch restricted by an allow-list (`LIST.includes(x) ? x : 'en'`) is clean, numbers and
  booleans derived from input (`items.length`, comparisons, `.map(Number)`, Python comprehensions over `int()`)
  are not text, and an anchored allow-list pattern with an early exit before `exec`/`subprocess` or a file call
  turns the hit into a review hint (not in Python with `re.M`/`re.MULTILINE` or an unreadable flags argument,
  where `$` also matches before a newline: `"main\n;id"` passes). Some of these were reported as critical command injection. A preference
  cookie such as `theme` set with `httpOnly: false` is no longer reported.
- Report JavaScript mass assignment only on receivers that write records (model classes, Prisma delegates, model
  and repository instances, Knex builders, records loaded through them). `teamService.create(req.body)` and
  other service or controller calls were reported, and in a layered app one controller pattern produced most of
  the rule hits that Quick mode triages.
- Stop reporting SQL injection for a Django view parameter that every URLconf route fills through `<int:…>` or
  `<uuid:…>` (or a digits-only `re_path` group); the URLconf in another file is now read before the views.
- Find MD5/SHA-1 password hashing split over statements or named by its function (`const h =
  createHash('md5')` then `h.update(pw)`, `def hash_password(raw): return md5(...)`, a digest compared with
  `user.password_hash`), and random tokens built in callbacks (`newApiKey() { return [...].map(() =>
  Math.random()...) }`). Only the statement computing the digest or the random value was read before. Random
  numbers that are compared or subtracted (`Math.random() < 0.1`, `sort(() => Math.random() - 0.5)`) are no
  longer reported in functions named after tokens.
- Report `jwt.decode()` without verification also when the token comes from a cookie or a request header, from
  Next.js `cookies()`, or from a same-file helper that reads the `Authorization` header or a cookie
  (`jwt.decode(getBearer(req))`). Only functions that read the `Authorization` header themselves were checked,
  so admin checks on a decoded cookie token were missed.
- Find hard-coded secrets that were dropped: database URLs with a driver scheme (`postgresql+asyncpg://`),
  Mailgun `key-…` keys and hand-written secrets such as `app-jwt-secret-2024`, which the identifier filter took
  for names, and passwords under a `pass` key (nodemailer `auth: { user, pass }`, `smtpPass`). Helm
  `existingSecret` references are ignored.
- Correct the analyzer reference: `js.prototype-pollution`, `js.template-unescaped-output`, `js.unsafe-yaml-load`
  and the Jinja/Django `|safe` and `autoescape off` template checks only produce review hints, never findings.

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
