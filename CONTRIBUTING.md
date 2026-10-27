# Contributing to DSH Security

Thanks for helping. Bug reports, false-positive reports, rule improvements, framework support, translations and
documentation fixes are all welcome. For anything larger than a small fix, please open an issue first so we can
agree on the approach.

Security problems in the plugin itself go through [SECURITY.md](SECURITY.md), not public issues. This project
follows the [Code of Conduct](CODE_OF_CONDUCT.md).

## Setup

Requirements: Node.js `^22.19.0 || >=24.0.0`, pnpm 10.28 (`corepack enable` picks it up from `packageManager`),
and git.

```sh
pnpm install
pnpm build          # lib/index.js + lib/client.js
pnpm test           # or: pnpm test:watch
pnpm check          # lint + typecheck + test + build + package verification (what CI runs)
pnpm check:lib      # committed lib/ matches a fresh build
pnpm check:dsh      # latest DSH alpha: peer range, typecheck, scratch web boot (needs network; CI runs this)
```

`lib/` is committed so users can install with `github:Aero123421/dsh-security-plugin#vX.Y.Z` without a build step.
Run `pnpm build` and commit the changed `lib/` files together with your source change; CI fails if they differ.

To try your change in DSH, see the Development section of the [README](README.md#development) and
[docs/e2e-testing.md](docs/e2e-testing.md). Read [docs/architecture.md](docs/architecture.md) before changing the
pipeline, and [docs/security-model.md](docs/security-model.md) before changing anything that touches tools,
redaction, RPC, the toolkit or external processes.

## Code conventions

These are enforced by the compiler, Biome and review.

- **TypeScript, strict.** `strict`, `noUncheckedIndexedAccess`, `verbatimModuleSyntax`, `isolatedModules`. Do not use
  `any` (Biome reports it as an error). Use `unknown` and narrow it.
- **Imports use explicit `.ts` extensions** (`import { x } from './foo.ts'`), and type-only imports use
  `import type`.
- **Biome style:** 2 spaces, 120 columns, single quotes, no semicolons, trailing commas, arrow parentheses only when
  needed. Run `pnpm lint:fix` before committing.
- **Layering.**
  - `src/shared/` holds plain data and pure functions only, because both bundles import it.
  - `src/client/` must not import Node built-ins or `@deepseek-ai/*` runtime values. The build fails if it does;
    use `import type` or a service from `ctx`.
  - The Host reaches DSH only through the small structural ports in `src/host/dsh/ports.ts`.
- **The Host validates, the browser trusts.** Every new RPC method needs a strict zod schema in
  `src/host/rpc/schemas.ts` (bounded strings and arrays, closed enums, no unknown keys), a handler in
  `src/host/service.ts`, and an entry in `RPC_METHOD_NAMES`. Bump `CONTRACT_VERSION` for incompatible changes.
- **Nothing sensitive leaves the Host by accident.** No absolute paths (except `displayPath`), no raw secrets, no
  stack traces in RPC responses. Any text from the repository or a model that reaches a model, a report or the
  browser must already be redacted.
- **Workers stay read-only.** Do not add worker tools that write, execute, or reach the network. New worker tools
  must go through the same redaction, root masking and withheld-file checks as `src/host/agents/tools/workspace.ts`.
- **Store migrations are append-only.** Add a new step to `MIGRATIONS` in `src/host/store/schema.ts`. Never edit a
  shipped step.
- Comments explain *why*. Public functions get a short JSDoc that states edge cases and what they throw.

## Tests

- **Every change needs tests.** Host tests live in `tests/host/**` (Node), browser tests in `tests/client/**`
  (happy-dom, Testing Library).
- **No network in tests.** Inject `fetch`, clocks and process runners. The Host code already takes them as
  parameters (`fetch` in `queryOsv` and `Toolkit`, `now` in the store and controller). Tests must pass offline and
  on Linux, macOS and Windows.
- **Run analyzers in both modes.** Analyzer tests use `MODES` / `PY_MODES` from `tests/host/analysis/sast-helpers.ts`,
  so they run with the native ast-grep engine (when available) and with the built-in tokenizer.
- **Fixtures with fake credentials** must be obviously fake (include `FAKE` or `EXAMPLE`) so they are not mistaken
  for leaks. Keys in a provider format that secret scanners block (e.g. Stripe `sk_live_…`, which GitHub push
  protection rejects even when fake) are stored split by the `<<fake-split>>` marker (`FAKE_SECRET_SPLIT` in
  `bench/fixtures.ts`); `copyFixtureApp`/`copyFixture` join them in the scanned copy. Files under
  `tests/fixtures/apps/` start with the *INTENTIONALLY VULNERABLE TEST FIXTURE* header. Both rules are checked by
  `tests/host/fixtures-manifest.test.ts`.

## Precision over recall

A noisy scanner trains people to ignore it. For deterministic rules we prefer missing a case to flagging safe code:

- Report a `vulnerability` only when attacker-controlled input visibly reaches the sink. A dangerous API with a
  value of unknown origin is a lower-severity `sink` (which only steers AI review), or nothing.
- **Every rule needs at least one positive and one negative test.** The negative test must be a realistic safe form
  of the same code: a parameterized query, `execFile` with an argument array, `path.basename`, a constant URL.
  `tests/host/analysis/sast-rules.test.ts` fails if a rule id in the catalog has no example pair.
- Test files are scanned with severity capped at Low. Do not write rules that rely on test code.
- Any change to a rule should leave `pnpm bench` with no new negative-control matches (see
  [docs/benchmark.md](docs/benchmark.md)).

## How to add a SAST rule

1. Choose the language module: `src/host/analysis/sast/js.ts`, `python.ts` or `config.ts`.
2. Declare a `RuleMeta` (see `rule.ts`) with:
   - a stable `id` such as `js.some-issue`;
   - `title`, `category` (from `FINDING_CATEGORIES`), `cwe`, `severity`;
   - `sinkSeverity` only if a dynamic value of unknown origin should produce a `sink`;
   - `message` and `recommendation` in plain English for non-specialists;
   - `references` (use `REF.*` and `cweUrl()`).

   Add it to `JS_RULES`, `PY_RULES` or `CONFIG_RULES`.
3. Write the matcher function and call it from `jsRules` / `pyRules` / `configRules`. Use the file model (`calls`,
   imports, and taint through `Checker` in `helpers.ts`) rather than raw regexes for code. Decide `vulnerability` vs `sink` with
   `classify()`. Mask hard-coded secret literals in the `mask` spans.
4. Add the positive/negative pair to `EXAMPLES` in `tests/host/analysis/sast-rules.test.ts`. Add focused cases to
   `sast-js.test.ts` or `sast-python.test.ts` (inline `// VULN` and `// SINK` markers with `expectedHits()` keep
   these readable).
5. Add the rule to the table in [docs/analyzers.md](docs/analyzers.md).

## How to add a route framework

1. Detection and extraction go in `src/host/analysis/routes/js.ts` or `python.ts`. Register raw routes, mounts
   (with prefixes) and receiver-scoped middleware on the `RouteSink`. The driver in `routes/index.ts` resolves mount
   chains and middleware inheritance. Add the framework's import or keyword to `ROUTE_HINT` in `routes/index.ts`
   if files using it would otherwise be skipped.
2. If the framework uses its own words for auth middleware, extend `AUTH_HINT` in `routes/common.ts`, keeping it
   specific.
3. Add a small fixture app under `tests/fixtures/routes/<framework>/`, covering mounted sub-routers or prefixes, one
   guarded and one unguarded route, and path parameters. Add a test in `tests/host/analysis/routes.test.ts` that
   asserts the exact route list and, for some endpoints, the full `Endpoint`: declaration, handler range,
   middleware, auth hints and params.
4. Add the package name to the framework maps in `src/host/analysis/inventory.ts`, and update
   [docs/analyzers.md](docs/analyzers.md) and the `list_endpoints` tool description in
   `src/host/agents/tools/workspace.ts`.

## How to add or change UI text

- Strings live in `src/client/i18n.ts`. `en` defines the keys. `ja` and `zh` must have exactly the same keys
  (enforced by `satisfies` and `tests/client/i18n.test.ts`), with no empty values.
- Add the key to all three dictionaries in the same pull request. If you cannot write one of the languages, put
  the English text there and say so in the pull request; a maintainer or translator will follow up.
- **Japanese is the primary audience.** Write for developers who are not security specialists: explain terms, keep
  sentences short, and use the existing vocabulary (for example 検出結果, 確かさ, 要確認, 除外済み). CWE ids belong
  in detail views only.
- Use `{name}` placeholders, never string concatenation.
- Error codes (`security/*`) and notice keys map to strings in the same file. Add a string whenever you add a code.
- Report text lives separately in `src/host/report/i18n.ts` (English and Japanese).

## Pull requests

- Keep each pull request focused. Describe what changed and why, and how you tested it. Fill in the template.
- `pnpm check` must pass. CI runs it on Linux (Node 22 and 24), macOS and Windows.
- Add a line under *Unreleased* in [CHANGELOG.md](CHANGELOG.md) for user-visible changes.
- Commit `lib/` when `pnpm build` changes it (`pnpm check:lib` fails if the committed output differs). Do not commit `coverage/` or `bench/results/`.
- By contributing, you agree that your contribution is licensed under the [MIT License](LICENSE).
