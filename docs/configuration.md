# Configuration

DSH Security has two layers of configuration:

| Layer | Who sets it | Where | Purpose |
| --- | --- | --- | --- |
| **Operator config** | Whoever runs DSH | The profile's `cordis.patch.yml` (`id: dsh-security` row) | Ceilings, paths, and what remote pages may enable. Read once when the plugin starts. |
| **User settings** | Anyone who can open the DSH Web UI | Security page → *Settings* tab, or DSH Settings → Security | Models, scan preferences, budgets, privacy switches, storage, language. Stored in `security.db` and always clamped to the operator ceilings. |

## Operator config

Source: `src/host/config.ts`. Unknown keys are ignored. Invalid values (wrong type, out of range) stop the plugin
from starting, and the reason is written to the DSH log.

| Key | Type | Default | Allowed | Meaning |
| --- | --- | --- | --- | --- |
| `dataDir` | path | `$DSH_HOME/security` (bundle layer sets `!!js dshHomePath('security')`; if unset, `$DSH_HOME` or `~/.dsh`, plus `/security`) | non-empty | Where `security.db` and the managed `toolkit/` live. |
| `maxParallelWorkers` | integer | `4` | 1–32 | Ceiling for AI workers running at once in one scan. The user's *Reviewers working at once* is clamped to it. |
| `maxConcurrentScans` | integer | `1` | 1–8 | Scans running at once across all projects. Others wait in a FIFO queue. |
| `maxFiles` | integer | `20000` | 1–1,000,000 | Files read into one snapshot. Beyond this the snapshot is truncated, and both a notice and a coverage gap say so. |
| `maxFileBytes` | integer (bytes) | `1048576` (1 MiB) | 1–64 MiB | Largest single file read. Larger files are excluded as `too-large`, except dependency manifests and lock files, which may be up to 32 MiB (an oversized one is named in a scan warning). |
| `maxTotalBytes` | integer (bytes) | `209715200` (200 MiB) | 1 B–4 GiB | Total bytes read into one snapshot. |
| `maxTokensPerScan` | integer | `20000000` | 1–1,000,000,000 | Ceiling for every mode's *Tokens* budget. |
| `maxLlmCallsPerScan` | integer | `2000` | 1–1,000,000 | Ceiling for every mode's *AI requests* budget. |
| `allowRemoteHighRiskSettings` | boolean | `true` | | Whether pages not on the Host machine may **turn on** the high-risk switches (below) and install managed tools. Turning them off is always allowed. |
| `allowManagedToolkit` | boolean | `true` | | Whether the Analyzers section may download pinned, hash-verified Gitleaks and OSV-Scanner builds into `dataDir/toolkit`. Tools already on `PATH` are used either way. |
| `osvEndpoint` | URL | `https://api.osv.dev` | valid URL | OSV API base, for example an internal mirror. Requests go to `<osvEndpoint>/v1/querybatch` and `/v1/vulns/<id>`. |
| `semgrepConfig` | path | unset | absolute path to a file or directory | Local Semgrep rules. Without it Semgrep never runs, even if installed. Registry rules (`--config auto`, `p/…`) are never used. |
| `externalTimeoutMs` | integer (ms) | `600000` (10 min) | 1 ms–24 h | Timeout for one Gitleaks / OSV-Scanner / Semgrep run. The process tree is killed when it expires. |
| `llmIdleTimeoutMs` | integer (ms) | `120000` (2 min) | 1 s–1 h | A model request whose stream sends nothing for this long (the wait for the first chunk included) is abandoned and retried with backoff as a transient `TIMEOUT` (at most 4 attempts per turn). Raise it for slow reasoning models that stay silent for long stretches. |
| `disableAstGrep` | boolean | `false` | | Never load the native `@ast-grep/napi` engine and always use the built-in tokenizer. |

### Overriding operator config

The bundle layer (`cordis.patch.yml` in this package) inserts:

```yaml
- insert:
    - id: dsh-security
      name: dsh-security-plugin
      config:
        dataDir: !!js dshHomePath('security')
```

To override it, add a patch to the profile's own file, `$DSH_HOME/profiles/<profile>/cordis.patch.yml` (for the
`web` profile: `~/.dsh/profiles/web/cordis.patch.yml`). **A patch replaces the row's whole `config`**, so restate
`dataDir` whenever you change anything else. Otherwise the store moves to the fallback location.

```yaml
# ~/.dsh/profiles/web/cordis.patch.yml
- id: dsh-security
  config:
    dataDir: !!js dshHomePath('security')
    maxParallelWorkers: 2
    maxConcurrentScans: 2
    allowRemoteHighRiskSettings: false
```

Check the result with `dsh --profile web --dump-config`. The `# == dsh-security-plugin` layer shows the bundle's
row, and your profile layer follows it. Restart DSH to apply changes.

More examples:

```yaml
# Shared server: nothing high-risk can be turned on remotely, no downloads, OSV via a mirror.
- id: dsh-security
  config:
    dataDir: !!js dshHomePath('security')
    allowRemoteHighRiskSettings: false
    allowManagedToolkit: false
    osvEndpoint: https://osv-mirror.internal.example
```

```yaml
# Large monorepo with local Semgrep rules.
- id: dsh-security
  config:
    dataDir: !!js dshHomePath('security')
    maxFiles: 100000
    maxTotalBytes: 1073741824   # 1 GiB
    semgrepConfig: /opt/semgrep-rules/company.yml
    externalTimeoutMs: 1800000  # 30 min
```

## User settings

Source: `src/shared/settings.ts` (types and defaults) and `src/host/settings.ts` (validation and clamping). Every
change is a partial patch with optimistic concurrency. If two pages edit at the same time, the second save gets
`security/conflict`, the page reloads the latest values, and the user saves again.

### Models

| Setting | Default | Meaning |
| --- | --- | --- |
| `models.default` | unset | Provider/model used by every role without its own model. |
| `models.planner` / `hunter` / `skeptic` / `chain` | unset (inherit Default) | Per-role override. |
| per route: `reasoningEffort` | model default | Adapter-specific effort id, offered when the model reports reasoning support. |
| per route: `maxOutputTokens` | model default | Per-request output cap (1–1,000,000 in the UI). |

An AI scan needs a Hunter route (its own or Default). Without a Planner route the threat model is skipped; without a
Skeptic route, independent review; without a Chain route, attack chains.

### Scanning

| Setting | Default | Range | Meaning |
| --- | --- | --- | --- |
| `scan.defaultMode` | `deep` | quick / deep / research | Preselected mode in the New scan dialog. |
| `scan.excludeGlobs` | `[]` | ≤ 200 patterns, ≤ 300 chars each | Extra gitignore-style excludes for every scan (on top of `.gitignore` and built-in ignores such as `node_modules`, `dist`, `.git`). |
| `scan.includeTests` | `false` | | Let AI workers see test, fixture and example files. Built-in analyzers always scan them, with severity capped at Low. |
| `scan.parallelWorkers` | `2` | 1–64, clamped to `maxParallelWorkers` | AI workers running at once in one scan. |
| `scan.reviewThreshold` | `medium` | critical … info | *Second opinion from*: Deep mode reviews findings at or above this severity. Research always uses Low. |

### Budgets

Per mode (`budgets.quick`, `budgets.deep`, `budgets.research`). A scan stops starting new work as soon as it reaches
any limit. `maxMinutes` is also a deadline: when it passes, model requests still in flight are aborted, and the scan
completes with what it has and a time-budget notice.

| Setting | Quick | Deep | Research | Clamp |
| --- | --- | --- | --- | --- |
| `maxLlmCalls` (AI requests) | 40 | 300 | 1,200 | ≤ `maxLlmCallsPerScan` |
| `maxTokens` | 400,000 | 3,000,000 | 12,000,000 | ≤ `maxTokensPerScan` |
| `maxMinutes` | 10 | 60 | 240 | UI: 1–1,440 |
| `maxTurnsPerWorker` (requests per reviewer) | 12 | 24 | 40 | 1–500. Planner, Skeptic and Chain analyst also stop at 16. |
| `maxTasks` (review tasks) | 6 | 40 | 150 | UI: 1–1,000. The review phase may schedule up to `max(maxTasks, 10)`. |

Clamping happens when settings are read and written. A stored value above a lowered operator ceiling is reduced the
next time settings load. Each scan copies its settings and budget when it is created, with two exceptions (next
section).

### Privacy

| Setting | Default | High-risk | Meaning |
| --- | --- | --- | --- |
| `privacy.sendCodeToModel` | `false` | yes | Consent to send redacted code excerpts to the selected providers. Required for AI scans. The New scan dialog asks for it and saves it here. Turning it off also applies to scans already queued, paused or running (see below). |
| `privacy.withheldGlobs` | `[]` | | Extra gitignore-style patterns for files the workers' tools never return, on top of the built-in credential files. A scan uses the patterns it was created with plus the current ones, read again whenever it starts or resumes. |

These two settings are not frozen into a scan:

- **Turning off `sendCodeToModel`** stops AI work in every scan that uses it. A running scan aborts its in-flight
  model requests at once and skips its remaining AI tasks. A queued, paused or interrupted scan checks the setting
  when it starts or resumes. Either way the scan completes with its built-in analyzer results, keeps AI results
  recorded before that, and shows the notice `consent-revoked`. Turning the setting on again does not restart that
  work; start a new scan.
- **`withheldGlobs`** added after a scan was created take effect when it next starts or resumes.
| `privacy.allowDependencyLookup` | `false` | yes | Send ecosystem, package name and exact version (never code or paths) to `osvEndpoint`. Also lets OSV-Scanner go online. |
| `privacy.useExternalAnalyzers` | `true` | yes | Run Gitleaks, OSV-Scanner and Semgrep when they are available (managed install or `PATH`). They run locally. |

### Storage and display

| Setting | Default | Range | Meaning |
| --- | --- | --- | --- |
| `storage.retentionDays` | `90` | 0–3650 | At startup, delete scans older than this (0 keeps everything). Queued, running and paused scans are kept. Triage decisions are kept regardless. |
| `storage.keepTranscripts` | `true` | | Store each AI worker's full conversation (gzip) for audit. |
| `ui.language` | `auto` | auto / en / ja / zh | UI language. `auto` follows DSH's locale, then the browser's first choice among en/ja/zh. New scans ask models to write in this language. Markdown reports follow the scan language (English, Japanese or Simplified Chinese). |

## High-risk switches and the loopback rule

`privacy.sendCodeToModel`, `privacy.allowDependencyLookup` and `privacy.useExternalAnalyzers` widen what leaves the
machine or what runs on it. When `allowRemoteHighRiskSettings` is `false`, these switches can only be turned
**on**, and managed tools only installed, from a page on the Host machine itself. A remote page gets
`security/forbidden-remote`, and the UI shows the switch as locked with an explanation. Turning a switch off is
always allowed.

This rule is a **policy for browser pages, not an access control**. Every request that reaches the plugin has
already passed DSH's Host/Origin fence and browser authentication, so it speaks for the one DSH operator, who can
also run shell commands through DSH's own agents. The rule keeps a page opened on another machine from widening
what leaves this one; it does not stop someone who holds the DSH credentials.

The Host decides "same machine" for each request (`src/host/rpc/loopback.ts`):

- If DSH Desktop's in-process carrier delivers the request (any URL scheme other than `http:`/`https:`), it is
  loopback.
- Otherwise the `Host` header (or the URL hostname if there is none) must be `localhost`, `*.localhost`,
  `127.0.0.0/8` or `::1`.
- `Forwarded` and `X-Forwarded-*` are ignored on purpose. A request through a reverse proxy, a tunnel or a LAN
  address counts as remote, even if the proxy runs on the same machine.

Limits of that decision:

- Browsers cannot forge `Host`, so a remote page is classified correctly. A non-browser client (for example `curl`
  with the DSH credentials) can send `Host: localhost` from anywhere and is classified as local.
- The peer's network address is not available to the plugin: DSH hands exact Fetch routes a Web `Request` without
  connection information.
- DSH's `allowsRemoteAuthorities` (true when `trustedHosts` names a non-loopback host) is not used: even when it is
  `false`, DSH admits the listener's own bind address (for example a LAN IP) as `Host`, so it does not mean every
  page is local.

With the default (`true`), any authenticated DSH page may enable these switches, which suits a single-user setup.
Set it to `false` when people other than the Host's owner can open the DSH Web UI. Do not rely on it to separate
people who share the DSH credentials.

## Excluding files

| Mechanism | Effect |
| --- | --- |
| `.gitignore` files (nested, deepest match wins) | Not read into the snapshot at all. |
| Built-in ignores | `.git`, `node_modules`, `vendor`, `dist`, `build`, `out`, `target`, `coverage`, caches, IDE folders, Python virtualenvs, `.dsh-security`, minified bundles, source maps, binaries, symlinks. |
| `scan.excludeGlobs` | Not read into the snapshot. Counted as `user-exclude`. |
| `privacy.withheldGlobs` and built-in credential files | Read and scanned by the built-in analyzers (so secrets in them are still found), but never returned by the workers' tools and never quotable as evidence. Redacted rule-hit excerpts can still appear in task messages ([security-model.md](security-model.md#residual-risks)). |
