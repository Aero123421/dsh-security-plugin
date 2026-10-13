# Benchmark

Scores DSH Security against the intentionally vulnerable fixture apps in
`tests/fixtures/apps/<app>/`. Each app's `expected.json` lists planted
findings (with the detectors expected to catch them) and negative controls:
code that looks risky but is safe and must not be reported.

| File | Purpose |
| --- | --- |
| `run.ts` | `pnpm bench`: runs the real scan pipeline in-process and scores it |
| `score.ts` | scores a JSON report exported from a real DSH scan |
| `prepare.ts` | copies a fixture app without its answer keys, for a real DSH scan |
| `scoring.ts`, `report.ts` | matching rules and the `report-v1` reader shared by both |
| `fixtures.ts` | manifest loader and `matchesExpected` |

Results are written to `bench/results/` (git-ignored).

## Run the built-in benchmark

```sh
pnpm bench                              # every app, every configuration
pnpm bench --config deterministic       # built-in analyzers only (with and without ast-grep)
pnpm bench --config oracle              # scripted model, deep mode
pnpm bench --app express-shop --details # one app, with per-finding tables
pnpm bench --json                       # machine-readable result on stdout
pnpm bench --save-reports               # also keep each scan's exported JSON report
```

Each run uses `ScanController` with an in-memory store, a temporary copy of
the app (without `expected.json` and `README.md`), no external analyzers, and
no network. The finished scan is exported through the same `exportReport`
handler as the Security page's Export → JSON, and that file is what gets
scored. The command exits non-zero if any scan fails.

| Configuration | What it measures |
| --- | --- |
| `deterministic` | Built-in secrets, SAST and route analysis with the ast-grep engine. No model. |
| `deterministic-builtin` | The same with ast-grep off (the fallback lexer used where the native module is unavailable). |
| `oracle` | A Deep scan driven by the scripted model in `tests/e2e/scripted-llm`. |

> **The oracle configuration is a plumbing test, not a quality claim.** The
> scripted "model" reads `expected.json` and answers from it. It shows how
> much the pipeline loses between a perfect answer and the stored result:
> tool calls, host-side quote verification, independent review, merging and
> export. A high oracle score says nothing about DeepSeek, Claude or any other
> model. It also submits one fabricated finding per hunter run, so the
> `discarded` column should be non-zero.

## Read the numbers

A report matches a planted finding or negative control when it is in the same
file, the expected line is within 3 lines of the reported start line (or
inside the reported range), and the category or CWE is the same
(`--tolerance` changes the line window). Each report counts toward at most one
entry, the nearest one.

| Column | Meaning |
| --- | --- |
| `TP` / `FN` / `recall` | Planted findings detected / missed, out of all planted findings. |
| `in-scope` | Recall over the planted findings at least one detector that ran is expected to catch. Dependency findings need OSV, which the bench keeps off, and the route extractor only feeds AI review, so a deterministic scan cannot reach 100% overall recall. |
| `reports` | Findings that were not ruled out. |
| `FP` | Reports that match no planted finding. `on-neg` is the subset on documented negative controls, which is the worst kind. |
| `dup` | Extra reports of an already detected finding. They count as correct for precision but add nothing to recall. |
| `precision` | Reports matching a planted finding (duplicates included) / reports. |
| `conf/proof/out` | Every report by closure: confirmed / needs proof / ruled out. |
| `confTP` | Planted findings with at least one confirmed report. |
| `out:neg/real` | Ruled-out reports on negative controls (correct) / on planted findings (verification loss). Ruled-out reports never count as false positives or detections. |
| `discarded` | AI candidates dropped because none of their cited code matched the source. |
| `llm`, `tokens in/out`, `wall` | Model requests, tokens, and wall time of the scan. |

The per-detector table credits a report to the analyzer that created it, plus
`ai` when an AI hunter cited source evidence for it. `planted` is how many
findings the manifest attributes to that detector, `recall` is how many of
those it caught, and `bonus` counts findings it caught that the manifest
attributes to other detectors only.

Each fixture app is small, so one finding moves recall by 10 to 100 points.
Compare runs on the same apps and plugin version, and read the per-finding
tables (`--details`) before drawing conclusions.

## Evaluate a real model in DSH

1. Build and install the plugin into your DSH profile (see the main README).
2. Copy a fixture app without its answer keys:

   ```sh
   node --experimental-strip-types bench/prepare.ts express-shop ~/dsh-bench
   ```

3. In DSH, add `~/dsh-bench/express-shop` as a project (workspace).
4. In Security → Settings, choose the model(s) to evaluate and allow sending
   code to the model. Keep the other settings at their defaults, or note what
   you changed.
5. Start a **Deep** scan of that project and wait for it to finish.
6. Export → JSON and save the file.
7. Score it:

   ```sh
   node --experimental-strip-types bench/score.ts ~/Downloads/dsh-security-express-shop-*.json express-shop
   ```

   The second argument is the fixture app name or a path to its
   `expected.json`. Add `--json` for machine-readable output.

`score.ts` prints the same metrics as `pnpm bench` and a per-finding table:
each planted finding with the report that matched it (title and verification)
or `MISSED`, each negative control, and every report that matched nothing or
was ruled out. It accepts only `report-v1` JSON (`schemaVersion` 1) and
exits with an error naming the version it found otherwise; score a report
with the bench from the same plugin release that produced it.

When you publish numbers, include the plugin version, the models per role,
the scan mode, the settings you changed, and the token usage. Run each app
more than once: model output varies between runs.
