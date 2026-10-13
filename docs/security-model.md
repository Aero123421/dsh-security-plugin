# Security model of the plugin itself

This document describes threats **to and through DSH Security**, not threats in the code it scans. A security
reviewer reads hostile input by design, runs inside the DSH Host process with the user's privileges, holds the
user's source code, and can send it to third-party model providers. That makes it a high-value target. This
document lists what we defend against, how, and what remains.

## Assets

- The user's source code, and especially secrets inside it.
- Model-provider credentials and quota (held by DSH; the plugin uses them through `ctx.llm`).
- The integrity of findings. A false "ruled out" or a hidden finding is a security failure, not a cosmetic one.
- The Host machine: its filesystem, processes and network position.
- Scan history, triage decisions and transcripts in `security.db`.

## Trust boundaries and attackers

| Attacker | Controls | Example goal |
| --- | --- | --- |
| **Author of the scanned repository** (malicious dependency, contributor, third-party code under review) | File contents, file names, directory layout, symlinks, `.gitignore`, tool config files such as `.gitleaks.toml`, git metadata | Hide a vulnerability, make the AI exfiltrate secrets, run code on the Host, read files outside the repo |
| **Remote browser page on the DSH Web UI** (authenticated by DSH, but opened on another machine) | RPC requests from that page | Turn on code upload or downloads the operator reserved for the Host machine, read Host paths |
| **Network attacker** between the Host and OSV / GitHub | Responses to the plugin's HTTPS requests | Plant a malicious analyzer binary, inject content through advisory text |
| **Model provider or a compromised model** | Model output | Fabricate findings, suppress real ones, call tools in abusive ways |

DSH itself (its authentication, Host/Origin fence, plugin loader and LLM registry) is trusted. Other DSH plugins run
in the same process and are also trusted. Cordis scopes isolate registries, not memory.

## Untrusted repository content and prompt injection

Everything read from the repository is data. The controls:

- **Snapshot, not live tree.** The plugin reads the workspace once into memory (`analysis/snapshot.ts`). Symlinks
  are never followed: entries that are symlinks are excluded, files are opened with `O_NOFOLLOW`, and paths that
  resolve outside the real root are excluded. Size limits (`maxFiles`, `maxFileBytes`, `maxTotalBytes`) bound
  memory. Git metadata is read only to record the commit id, with ref names validated.
- **Workers only see the snapshot.** The six worker tools (`list_files`, `read_file`, `search_code`, `find_symbol`,
  `file_outline`, `list_endpoints`) read only that in-memory copy. Paths are normalized, and absolute paths, `..`
  and NUL are rejected. Output is capped per call.
- **Regex from the model is hostile.** `search_code` limits patterns to 200 characters, matches one line at a time,
  caps scanned bytes per call (50 MB), and runs each batch in a `node:vm` script with a time budget (2 s per call),
  so catastrophic backtracking is interrupted. A search cut short returns the matches found so far with a "search
  stopped early" note.
- **Tool use is bounded per reply.** At most 16 tool calls run per model reply; further calls get an error result
  asking the model to batch fewer. The worker yields to the event loop after every tool execution, so one worker's
  synchronous search cannot starve the Host's other work.
- **Prompting.** The shared system preamble tells every role that repository content (code, comments, strings,
  docs, configuration) is untrusted. It says instructions found there must not be followed, and that manipulation
  attempts should be reported in the notes. Text taken from the repository and placed in task messages (route
  names, middleware names, rule-hit snippets, finding titles) is clipped and kept on a single line.
- **Prompt injection is mitigated, not solved.** No prompt reliably stops a determined injection. The real controls
  are structural: what a manipulated worker *can do* is limited (next section), and what it *claims* is checked
  against code (Evidence integrity, below).

## Exfiltration channels closed by design

A worker that has been fully taken over by injected text still has:

- **No network.** No fetch, browser or web-search tool. The plugin's own HTTP use (OSV, toolkit downloads) is
  deterministic Host code. Its inputs are structured package coordinates or pinned URLs from `toolkit.lock.json`,
  never model output.
- **No execution.** No shell, no interpreter, no package installation, no test running. External analyzers are
  started by Host code with fixed arguments, never at a model's request.
- **No writes.** No file-write tool, and no tool that changes plugin state. Model output reaches the store only
  through the `submit_*` terminal tools, whose schemas bound every string and array. Host code then decides what
  their contents mean.
- **No other agents or global tools.** Workers call `ctx.llm.stream` directly instead of creating DSH chat sessions,
  so they do not inherit DSH's global tool registry, MCP servers, other plugins' tools, memories or instructions.
  The tool list sent to the model is exactly the six read-only tools plus one submit tool.

The remaining path to the outside is the model provider itself. Anything a worker reads is, by definition, sent to
the provider the user chose. The next section covers how that content is reduced.

## Consent and budgets apply to running scans

- **Withdrawing consent stops AI work.** Each scan keeps the settings it was created with, but turning off
  *Send code to the AI model* applies to scans that are already queued, paused, interrupted or running. The
  current setting is read again when a scan starts or resumes and before every worker starts, and saving the setting
  notifies running scans at once: their in-flight model requests are aborted like a pause, the remaining AI tasks are
  skipped (`consent-revoked`), and the scan completes with its deterministic results and a `consent-revoked` notice.
- **Withheld files follow the current settings too.** A scan withholds the union of its frozen `withheldGlobs` and
  the current ones, recomputed on every start and resume.
- **Stalled and overlong requests end.** A model request that sends no stream chunk for `llmIdleTimeoutMs` (default
  2 minutes) is abandoned and retried as a transient `TIMEOUT`. A provider that ignores the abort signal no longer
  holds the worker. When a scan's time budget (`maxMinutes`) runs out, its in-flight model requests are aborted and
  the scan completes with the time-budget notice.

## Redaction and withheld files

- **Secret scanner as redactor.** The built-in secret scan (25 rules) runs before any AI phase. Its matches are
  replaced with `[REDACTED:<rule-id>]` in everything a worker sees. `Redactor.redactFile` uses the recorded spans
  and verifies each span by hash before replacing it. A stateless pass (`redactText`) then applies every
  high-confidence pattern again to all tool output, snippets and error messages. Replacements keep line counts, so
  citations still line up.
- **No secret values at rest.** Secret findings store a SHA-256 fingerprint and a masked preview (at most the first
  4 characters), never the value. SAST snippets mask hard-coded literals. Gitleaks runs with `--redact`, and its
  excerpts are redacted again.
- **Withheld files** (built-in credential files such as `.env*`, keys, certificates, `.npmrc`, `.pypirc`, `.netrc`,
  `.git-credentials`, `.pgpass`, `.htpasswd`, cloud and container client credentials (`.aws/credentials`,
  `.aws/config`, `.docker/config.json`, `.kube/config`, `kubeconfig`), service-account JSON, Terraform state, plus the
  user's `withheldGlobs`) are scanned by the built-in analyzers but
  never returned by any worker tool. They are skipped by search, marked `[withheld]` in listings, and cannot be
  quoted as evidence. Paths that are malformed or escape the root are treated as withheld. Task messages are
  held to the same rule (`scan/privacy.ts`): a signal or finding in a withheld file keeps only its path and rule id,
  with `[content withheld by privacy settings]` in place of its code, title and message; no Hunter task targets a
  withheld file; endpoints declared, handled or mounted in one (route prefixes and middleware names are file
  content) are not listed, in task messages or by `list_endpoints`; and a finding whose only evidence is in withheld files gets
  no Skeptic review or chain analysis (it keeps its deterministic verification).
- **Task messages are redacted too.** Every excerpt the host writes into a task (rule-hit snippets, attack-path
  excerpts, finding text) passes through the scan's `Redactor` (every secret value the built-in scan found, wherever
  it occurs, including SAST and external-analyzer snippets) and `redactText`, and the whole task message is scrubbed
  once more before it is sent.
- **Root masking.** The absolute snapshot root is replaced in every tool output, so the model does not learn the
  user's home path or user name from tool output.
- **Limits.** Redaction is pattern-based. A credential in an unknown format, in a file not on the withheld list,
  can reach the provider. Users should add such files to `withheldGlobs`.

## Evidence integrity

- Every model citation is verified against the same redacted text the tools served (`evidence/quote.ts`). An AI
  finding with no verified step is discarded. The count of discarded findings is shown under Coverage, so a model
  that invents code is visible.
- **"Verified" means the location holds the quote.** The stored location and snippet are the lines the quote
  occupies, not the cited range. A citation much wider than its quote is rejected, and a quote that occurs more than
  once in a loose cited range is ambiguous, so citing "the whole file" cannot verify anything.
- **Suppression needs proof.** A Skeptic `refuted` verdict needs at least one verified counter-evidence quote of
  code, or the host downgrades it to `inconclusive`. Quotes that are only comments, docstrings or documentation
  (`// input sanitized upstream`) never count. A Hunter cannot rule out a rule hit on its own: without a following
  review, its verified defense makes the hit `inconclusive` at most. A manipulated model can make a finding look
  *less* certain, but it cannot make a rule hit disappear without an independent reviewer quoting real code.
- **Confirmation needs proof too.** `confirmed` without any verified step on the attack path becomes
  `inconclusive`. A severity change needs a confirmed verdict with verified supporting code and lowers a
  deterministic critical/high rule hit by one level at most.
- Rule findings come from deterministic code and are recorded before any AI phase runs. The AI cannot delete them.
- Ruled-out findings stay in the store and reports (as SARIF suppressions with a justification), so a reviewer can
  audit every dismissal. Transcripts are kept by default for the same reason.

## Authenticated RPC and strict validation

- The browser talks to the Host only through exact routes `POST /api/dsh-security/<method>` registered on DSH's
  Connection service. DSH applies its Host/Origin trust fence and browser authentication before a route runs. The
  plugin opens no listener of its own.
- **Transport checks:** POST only (`405`), `Content-Type: application/json` (`415`), body ≤ 1 MiB (checked on
  `Content-Length` and while streaming, `413`), strict UTF-8 JSON (`400`), envelope `type`/`method` must match the
  route, and `rpcId` ≤ 128 characters without control characters.
- **Payload schemas** (`rpc/schemas.ts`) are `zod` strict objects: unknown keys are rejected, ids match
  `[A-Za-z0-9_-]{1,64}`, every string and array has a length limit, single-line fields reject control characters,
  numbers are integers within ranges, and enums are closed.
- **Error hygiene.** Only `RpcError` messages and sanitized validation paths reach the browser. Unrecognized-key
  messages report a count, not the attacker's key names. Any other exception becomes `security/internal` with a
  generic message and is logged on the Host. Responses carry `cache-control: no-store` and
  `x-content-type-options: nosniff`.
- **High-risk switches.** Turning on code upload, OSV lookups or external analyzers, and installing managed tools,
  can be restricted to same-machine pages (`allowRemoteHighRiskSettings: false`). The rule is enforced on the Host;
  the UI lock only explains it. It is a **policy for browser pages, not a security boundary**:
  - "Same machine" is decided from the request's `Host` header (`rpc/loopback.ts`). Browsers cannot forge `Host`,
    so a page opened through a LAN address, a tunnel or a reverse proxy counts as remote; `Forwarded` and
    `X-Forwarded-*` are ignored, so a proxy header cannot make it local.
  - A non-browser client can send any `Host` header and be classified as local. That client has already passed DSH's
    authentication, so it is the DSH operator, who can run shell commands through DSH's own agents anyway.
  - The peer's network address is not available: DSH passes exact Fetch routes a Web `Request` without connection
    information. `ctx.connection.allowsRemoteAuthorities` does not settle the question either: when it is `false`,
    DSH still admits the listener's own bind address (for example a LAN IP) as `Host`.
- **Concurrency.** Settings use compare-and-set on a revision, so a stale page cannot silently overwrite newer
  settings.

## What the browser sees

- Paths in findings, evidence, coverage and reports are workspace-relative. The one deliberate absolute path is the
  project's **display path** (`WorkspaceSummary.displayPath`): home-relative (`~/…`) when the project is under the
  Host user's home directory, the full path otherwise.
- Free text that can quote Host paths (scan errors, reasons for unavailable or failed external analyzers and toolkit
  installs such as a tool's stderr or a spawn error, analyzer warnings, activity-log messages, `RpcError` messages and
  details) is path-masked by `host/paths.ts` when it is recorded and again when it is sent: project roots become
  `<project>`, the plugin data directory `<data>`, the temp directory `<tmp>` and the home directory `~` (longest
  first, `/` and `\` spellings, case-insensitive for Windows paths).
- Transcript contents and raw secrets are never sent to the browser.
- Text from the repository and from models is rendered as text. The client never uses `dangerouslySetInnerHTML` or
  `innerHTML`. External links (tool homepages) open only after a URL check, with `rel="noopener noreferrer"`.
- SARIF locations are relative to `%SRCROOT%`, which is deliberately left without a URI. Markdown reports escape
  repository- and model-supplied text.

## Fix in chat

*Fix in chat* hands a draft to the user's normal coding agent, which is more privileged than the review workers (it
edits files and usually runs commands). Most of the draft was written by a model that read hostile code, and the
snippets are repository content, so `fix-prompt.ts` keeps the title on one line (at most 200 characters), puts the
summary, impact, attack-path descriptions, recommendation and every snippet in fenced blocks labelled as untrusted
(each fence is longer than any backtick run inside it, so the text cannot close it), and tells the agent, in the
scan's language, to treat that text as data: not to run commands or open URLs it contains, and to verify every claim
against the code. The user reviews the draft before sending it.

## Store

- `security.db` lives in `dataDir` (default `$DSH_HOME/security/`). The directory is created with mode `0700` and
  the database is set to `0600` on Linux and macOS. On Windows it relies on the user profile's ACLs.
- Contents: settings, scans with their frozen settings, findings, evidence (redacted excerpts), triage, events, and
  (if `keepTranscripts`) full worker transcripts. Transcripts contain redacted code excerpts and model output, so
  treat the database like the source code itself. Deleting a scan removes its transcripts. Triage survives on
  purpose.
- Schema migrations are append-only. A database from a newer plugin version is refused instead of being
  downgraded.

## Managed toolkit integrity

- `toolkit.lock.json` pins one version per tool and, per platform, an HTTPS URL, a SHA-256 and a size. It ships in
  the npm package and is compiled into `lib/index.js`. It is validated by schema on load: HTTPS only, hex digests,
  plain binary file names.
- An install happens only after an explicit click and license acceptance, only if `allowManagedToolkit` is on, and
  only when that platform's entry has a SHA-256. An unpinned asset is refused (`toolkit-unpinned`).
- The download is streamed into a new private file (`O_EXCL`, `0600`) with a size cap (the pinned size or 200 MiB)
  and a timeout. It is hashed and compared with the pin **before** anything is extracted or marked executable.
  Redirects are allowed (GitHub serves releases from a CDN) because integrity comes from the hash, not the host.
- Archives are extracted with the system `tar` (no shell, `--no-same-owner`), naming exactly one member. The result
  must be a regular file with a single hard link inside the staging directory. It is then made executable (`0755`),
  its own SHA-256 is recorded, and it is moved into place with an atomic rename.
- Before each use, the managed binary is re-hashed whenever its size or mtime changed. A binary that no longer
  matches its recorded hash is ignored.
- **Maintainer step:** `pnpm toolkit:pin` (`scripts/pin-toolkit.mjs`) downloads every asset over HTTPS, computes
  its SHA-256 and size, and cross-checks the hash against the upstream checksums file before writing the lock.
  `pnpm toolkit:pin --check` re-verifies without writing. Pins are reviewed in a pull request (see
  [releasing.md](releasing.md)). Until pinned, the lock carries `null` hashes and managed installs are refused.
- Tools found on `PATH` are the user's responsibility. Only absolute `PATH` entries are searched (so `.` cannot
  resolve a binary planted in the repository), and on Windows only `.exe` files are considered.

## External analyzers

- They are started with `spawn(…, { shell: false })` and a fixed argument vector. Repository-controlled strings
  never become arguments other than the root path.
- They get a **scrubbed environment**: only `PATH`, `HOME`, `USERPROFILE`, `SystemRoot`, `TEMP`, `TMP`, `TMPDIR`
  and `LANG` are inherited. Tokens, proxy settings, `NODE_OPTIONS` and everything else are dropped.
- The working directory is a neutral temp directory, never the scanned repository. Stdout and stderr are capped
  (64 MiB each). On timeout or abort the whole process tree is killed (a process group on POSIX).
- **Gitleaks** runs with a plugin-written config (default rules) and the plugin's own ignore path, so a repository's
  `.gitleaks.toml` or `.gitleaksignore` cannot turn detection off. Output is redacted.
- **OSV-Scanner** runs with call analysis disabled for all languages (Go call analysis would invoke the repository's
  `go` toolchain directive, and Rust's would run `build.rs`) and with transitive resolution disabled. It gets an
  empty, plugin-written config with `--config`, which replaces every `osv-scanner.toml` in the repository, so
  `[[IgnoredVulns]]` and `[[PackageOverrides]]` there cannot hide advisories. It runs `--offline` unless the user
  enabled OSV lookups.
- **Semgrep** runs only with an operator-configured local rules path, `--metrics=off`, `--disable-version-check` and
  `--disable-nosem`, so `nosemgrep` comments in the repository cannot silence a rule. It never uses `--config auto` or
  the registry.
- Results are parsed with schemas. Findings outside the snapshot (ignored, excluded or vendored files) are dropped.

## Residual risks

- **The model provider sees code.** That is the product. Redaction reduces what is sent but is not complete, and
  the provider's own data handling is outside this plugin's control.
- **Prompt injection can reduce quality.** A hostile repository can push a model to miss issues, waste budget, or
  argue findings down to *inconclusive*. It cannot make the model reach the network, run code or write files, and
  it cannot suppress a rule hit without quoting real code.
- **Same-process trust.** The plugin runs inside the DSH Host process. A malicious DSH plugin, or a compromise of
  DSH itself, can read everything this plugin can. Cordis scopes are not an OS security boundary.
- **Parsers process hostile input.** The tree-sitter native engine (`@ast-grep/napi`), YAML/TOML/JSON lock-file
  parsers and the snapshot walker all handle attacker-controlled bytes. Size limits, timeouts for external tools
  and exception isolation per file reduce the impact, but bugs in these components are possible.
- **`allowRemoteHighRiskSettings` defaults to `true`.** On a DSH instance shared with others, operators should set it
  to `false`. Even then it only constrains browser pages: anyone holding the DSH credentials can classify a request
  as local, and is the DSH operator anyway.
- **Static analysis limits.** Route extraction and rules cover common JS/TS and Python frameworks. Missing coverage
  shows up as gaps, not as safety.
- **Local data.** `security.db` holds redacted code excerpts and transcripts. Anyone with access to the user's
  account can read it.
Report vulnerabilities in the plugin as described in [SECURITY.md](../SECURITY.md).
