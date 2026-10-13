# Benchmark

The benchmark measures how well a scan finds planted issues, and how often it reports safe code, on small
intentionally vulnerable apps with known ground truth. It is a regression and comparison tool for this project. It
does **not** support claims about real-world detection rates.

## Fixtures

Four apps live in `tests/fixtures/apps/`. Each has an `expected.json` (the ground truth, validated by
`bench/fixtures.ts` and `tests/host/fixtures-manifest.test.ts`) and a README that describes the app. Every source
file starts with an *INTENTIONALLY VULNERABLE TEST FIXTURE* header. Every credential-looking value is fake and
contains `FAKE`. Nothing in these apps is installed or run.

| App | Stack | Planted findings | Negative controls | Planted, by detector (a finding can list several) |
| --- | --- | --- | --- | --- |
| `express-shop` | TypeScript, Express | 10 | 7 | ai 7, sast 4, secrets 2, dependency 2, routes 1 |
| `fastapi-notes` | Python, FastAPI | 9 | 6 | ai 7, sast 5, dependency 2, secrets 1 |
| `next-saas` | TypeScript, Next.js, next-auth, Prisma | 5 | 6 | ai 4, sast 2, secrets 1 |
| `flask-secure` | Python, Flask, SQLAlchemy (mostly secure) | 1 | 10 | ai 1 |

- A **planted finding** records `path`, the key `line` (the sink or the missing check), an exact `anchor` substring
  on that line, `category`, optional `cwe`, `severity`, and `detectableBy`. The `detectableBy` values are `sast`,
  `secrets`, `dependency`, `routes` and `ai`. `ai` marks logic flaws, such as IDOR, missing authentication or
  broken business rules, that only a reviewer can find.
- A **negative control** is code that looks risky but is safe, such as a parameterized query, an ownership-checked
  lookup, a placeholder secret in `.env.example`, or an allow-listed redirect. Reporting it counts as a false
  positive.
- `flask-secure` exists to measure false positives: a good scan reports exactly one issue there.

### Matching

`matchesExpected()` in `bench/fixtures.ts` decides whether a reported finding matches an expected entry. Three
conditions must hold:

- the path is the same;
- the expected line is within ±3 lines of the reported start line, or inside the reported range;
- the category is the same, or both sides have the same CWE.

Severity and verification are scored separately from matching.

### Answer keys are hidden from the scan

The bench copies each app to a temporary directory **without** `expected.json` and `README.md`
(`copyFixtureApp()`, `ANSWER_KEY_FILES`). It then scans the copy, so neither the analyzers nor a model can read the
answers.

## Running

```sh
pnpm install
pnpm bench                                   # every app, every configuration
pnpm bench --config deterministic --app express-shop
pnpm bench --help
```

`pnpm bench` runs `bench/run.ts` under Node's type stripping. `bench/hooks.ts` registers a transform for the
TypeScript syntax that plain stripping rejects. Each fixture copy is scanned in-process by the real scan pipeline,
with an in-memory store, and the scan's JSON report is scored. Options:

| Option | Meaning |
| --- | --- |
| `--app <name>` | Score one fixture app (default: all). |
| `--config deterministic\|oracle\|all` | Which configurations to run (default `all`). |
| `--json` | Print the machine-readable result instead of tables. |
| `--details` | Also print per-finding tables. |
| `--tolerance <n>` | Line tolerance for matching (default 3). |

Configurations:

| Name | What runs | Needs |
| --- | --- | --- |
| `deterministic` | Built-in analyzers with the ast-grep engine, no model | nothing (offline) |
| `deterministic-builtin` | Built-in analyzers with the fallback tokenizer | nothing (offline) |
| `oracle` | Deep scan with the scripted, fixture-aware model from `tests/e2e/scripted-llm/` | nothing (offline) |

The `oracle` configuration tests plumbing: tool calls, quote verification, independent review, and discarding the
fabricated finding. The oracle answers from the ground truth, so its scores say **nothing** about the quality of
any real model.

All configurations run offline: OSV lookups and external analyzers are off. Planted `dependency` findings and the one `routes`
finding (which needs AI review to become a finding) show as out of scope in the per-detector table.

Each run writes `bench/results/<timestamp>.json` (git-ignored). The command exits non-zero when any scan fails.

### Scoring real models

The bench does not call real providers. To measure a real model inside DSH:

1. Copy a fixture app without its answer keys:
   `node --experimental-strip-types bench/prepare.ts express-shop ~/dsh-bench`
2. Add `~/dsh-bench/express-shop` as a project in DSH, choose the model(s) in Security → Settings and allow
   sending code to models.
3. Run a scan with the mode you want to measure, then export it as JSON (Security page → *Export* → JSON).
4. Score the export:
   `node --experimental-strip-types bench/score.ts <exported-report.json> express-shop`
   (the second argument is the app name or a path to its `expected.json`; add `--json` for machine-readable
   output).

`score.ts` uses the same scoring code as `pnpm bench` (`bench/report.ts` reads the `report-v1` JSON, and
`bench/scoring.ts` scores it), so in-process runs and real-model runs are measured in exactly the same way.
`pnpm bench --save-reports` keeps the JSON reports of in-process runs too. See [`bench/README.md`](../bench/README.md)
for details.

## What is reported

Per app, per configuration, and in total (`bench/scoring.ts`):

- **Recall**: planted findings detected by at least one live (not ruled-out) report, divided by all planted
  findings. **Scoped recall** counts only planted findings that a detector active in that configuration is
  expected to catch. For example, `ai` findings are out of scope for the deterministic configurations.
- **Per-detector scores**: recall and precision for `sast`, `secrets`, `dependency`, `routes` and `ai`, plus
  "bonus" detections of findings that the manifest does not attribute to that detector.
- **Precision**: live reports matched to a planted finding (duplicates included), divided by all live reports.
- **False positives**: live reports that match no planted finding. This includes **negative-control hits**, which
  are also counted separately. Unmatched reports are not always wrong, since the fixtures are small and not
  exhaustive; use `--details` to review them.
- **Ruled out**: reports a review refuted. They are never counted as detections or false positives. They are split
  into refutations on negative controls (correct), on planted findings (a real issue was argued away), and
  unmatched.
- **Verification mix**: confirmed / needs proof / ruled out across all reports, and how many planted findings were
  detected by at least one *confirmed* report.
- **Cost**: wall time, plus model requests and tokens for AI configurations.

Read these numbers together. More findings is not better on its own.

## Methodology notes

- Use the same mode, budget and model for every app in a run, and record them with the results. Results for
  different models, or for a different plugin version, are different experiments.
- Models are not deterministic. Repeat AI runs (at least 3) and report the spread, not the best run.
- When you change a rule, run `pnpm test` (every rule has positive and negative unit cases) and `pnpm bench`, and
  check that no negative control starts matching.

## Limitations

- **Small and synthetic.** 25 planted findings and 29 negative controls across 4 apps, 2 languages and 5 web
  frameworks. They were written by the same project that wrote the rules, so the deterministic analyzers are
  partly tuned to them. Treat deterministic recall on these fixtures as an upper bound.
- **No held-out set yet.** A model could have seen similar code in training, and future rule changes could overfit
  to these fixtures. A separate held-out set and established external benchmarks (for example OWASP Benchmark for
  Python) are planned but not part of this release.
- **Location-based matching** can credit a finding that explains the issue wrongly but points at the right line,
  and can miss one that describes the right issue at another reasonable location, such as the mount instead of the
  route.
- **No dynamic confirmation.** Code-only scans never assign *Reproduced*, so the benchmark cannot measure
  exploitability.
- **Cost depends on the provider.** Token counts come from provider usage reports, and prices differ by provider.
