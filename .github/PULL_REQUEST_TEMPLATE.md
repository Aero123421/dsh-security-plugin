## What and why

<!-- What does this change, and why? Link the issue if there is one. -->

## How it was tested

<!-- Tests added or changed, manual checks in DSH (see docs/e2e-testing.md), bench results for rule changes. -->

## Checklist

- [ ] `pnpm check` passes locally (lint, typecheck, test, build, verify-package).
- [ ] Tests cover the change. New or changed rules have a positive **and** a negative example.
- [ ] No network access in tests; no real credentials in fixtures.
- [ ] UI strings were added to `en`, `ja` and `zh` in `src/client/i18n.ts`.
- [ ] Docs updated (README / `docs/`) and a line added under *Unreleased* in `CHANGELOG.md` for user-visible changes.
- [ ] For changes to worker tools, redaction, RPC, the toolkit or external processes: I checked `docs/security-model.md`
      and updated it if needed.
- [ ] For RPC or store changes: `CONTRACT_VERSION` bumped / a new migration appended, if needed.
