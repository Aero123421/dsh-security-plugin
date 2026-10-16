# Releasing

Releases are distributed through **GitHub**: users install a tag with `github:Aero123421/dsh-security-plugin#vX.Y.Z`
or the release tarball attached to the GitHub Release. The package is not published to npm unless the optional
`NPM_TOKEN` secret is set (see below); do not document an npm package name before it exists.

Because a `github:` install runs no build, the built `lib/` is **committed to git**. CI rebuilds it and fails if the
committed files differ (`scripts/check-lib.mjs`), and the package has no `prepare`/`prepack` script, so pnpm never
tries to build it on the user's machine.

## Checklist

1. **Decide the version.** The project follows semantic versioning. Before 1.0, a minor bump (0.x.0) may contain
   breaking changes; call them out in the changelog. Also bump the minor version when you change:
   - `CONTRACT_VERSION` in `src/shared/contracts.ts` (the browser and Host halves must match);
   - a store migration in `src/host/store/schema.ts` (older plugin versions refuse the newer database, so tell users
     to back up `$DSH_HOME/security/security.db` before updating if they may want to go back);
   - the supported DSH peer range.
2. **Update the toolkit pins.** Run the **Toolkit pin** workflow (Actions → *Toolkit pin* → *Run workflow*), or
   locally with network access:

   ```sh
   pnpm toolkit:pin           # downloads every asset in toolkit.lock.json, writes sha256 + size
   pnpm toolkit:pin --check   # re-download and verify without writing
   git diff toolkit.lock.json
   ```

   The script cross-checks every hash against the upstream checksums file (`checksumsUrl`) and fails on a missing
   or mismatching entry. The workflow pushes the branch `chore/toolkit-pin` and opens a pull request (if Actions may
   open pull requests in this repository; otherwise open it from the branch). Review it like code: the hashes
   decide which binaries users execute. To move to a new tool version, edit `version`, `checksumsUrl` and the asset
   URLs first, then pin.
3. **Bump the version** in `package.json` (`pnpm version <x.y.z> --no-git-tag-version`). `__PLUGIN_VERSION__` in
   both bundles comes from it at build time.
4. **Update `CHANGELOG.md`.** Move items from *Unreleased* to a new `## [x.y.z] - YYYY-MM-DD` section and update the
   compare links at the bottom. The release notes are generated from this section (`scripts/release-notes.mjs`).
5. **Rebuild, commit `lib/`, and run the full check:**

   ```sh
   pnpm install --frozen-lockfile
   pnpm build
   pnpm check       # lint, typecheck, test, build, verify-package
   pnpm check:lib   # committed lib/ == fresh build (commit lib/ first)
   ```

   `scripts/verify-package.mjs` runs `npm pack --dry-run` and fails if the tarball has a missing or unexpected
   file, if `lib/client.js` is not in DSH's module-loader format or is 300 KB or larger, or if a `package.json`
   field DSH needs is wrong.
6. **Verify in DSH by hand.** Follow [e2e-testing.md](e2e-testing.md) with the lowest supported DSH
   (`@deepseek-ai/dsh@0.2.1-alpha.2`) and, if one exists, the newest 0.2.x:
   - install the release candidate the way users will: `pnpm release:pack`, then
     `dsh plugin --profile web add -w /absolute/path/to/release/dsh-security-plugin-x.y.z.tgz` in a fresh profile;
   - the plugin loads, `--dump-config` shows the `# == dsh-security-plugin` layer, and Settings shows version x.y.z;
   - disable, re-enable and remove the plugin in the Plugins page: the sidebar entry and Settings section disappear
     and come back, and nothing keeps running after removal;
   - update from the previous release in a profile that has settings and scan history: settings, consent, triage and
     history are kept, and after the restart DSH asks for, the running version is the new one;
   - a Deep scan with the scripted model completes; one scan with a real model if available;
   - pause/resume, interrupted → resume, and export of all three formats work;
   - a remote page with `allowRemoteHighRiskSettings: false` cannot turn on code upload;
   - on at least one platform with pinned assets, *Install* for Gitleaks and OSV-Scanner succeeds.
7. **Commit, tag and push:**

   ```sh
   git commit -am "release: vX.Y.Z"
   git tag -a vX.Y.Z -m "vX.Y.Z"
   git push origin main vX.Y.Z
   ```

   Or, without pushing a tag: commit and push to `main`, then Actions → *Release* → *Run workflow* on `main` with
   the version (`X.Y.Z`). The workflow tests that commit and creates the tag `vX.Y.Z` on it.

   Never move a published tag to another commit. Fix problems in a new version.

## What the release workflow does

`.github/workflows/release.yml` runs on a `v*` tag, or from *Run workflow* on `main` with a version:

1. **build** (read-only): checks that the tag matches `package.json`; runs `pnpm lint`, `pnpm typecheck`,
   `pnpm test`, `scripts/check-lib.mjs` and `scripts/verify-package.mjs`; stops if `toolkit.lock.json` still has
   `null` hashes (set the repository variable `ALLOW_UNPINNED_TOOLKIT=true` to release anyway; managed installs of
   unpinned assets are then refused at runtime); packs `release/dsh-security-plugin-X.Y.Z.tgz` and
   `release/SHA256SUMS` (`scripts/release-pack.mjs`); writes the release notes; and installs that tarball into a
   fresh DSH `0.2.1-alpha.2` profile with `dsh plugin --profile smoke add -w` as a smoke test.
2. **release** (`contents: write` only here): downloads exactly those files, re-checks `SHA256SUMS`, and creates a
   **draft** GitHub Release with `gh release create --verify-tag --draft`, attaching only the tarball and
   `SHA256SUMS`. Tags with a pre-release suffix (`-alpha`, `-beta`, `-rc`) are marked as pre-releases.
3. **npm** (optional): if the `NPM_TOKEN` secret is set, publishes the same tarball with provenance; otherwise it
   does nothing.

Repository configuration:

- Protect `v*` tags so only maintainers can create them.
- Optional: Settings → Actions → General → *Allow GitHub Actions to create and approve pull requests*, so the
  *Toolkit pin* workflow can open its pull request. Pull requests opened by that workflow do not trigger CI on their
  own; close and reopen the pull request to run it.
- Optional: secret `NPM_TOKEN` (npm automation or granular publish token) to also publish to npm. `repository.url`
  in `package.json` must then point to this repository, or npm rejects the provenance statement.

## After the workflow

1. Open the draft release: check the title, the notes, and that the only assets are the tarball and `SHA256SUMS`.
2. Publish it.
3. Install from the published tag and from the asset URL into a scratch profile:

   ```sh
   dsh plugin --profile scratch add -w github:Aero123421/dsh-security-plugin#vX.Y.Z
   dsh plugin --profile scratch add -w https://github.com/Aero123421/dsh-security-plugin/releases/download/vX.Y.Z/dsh-security-plugin-X.Y.Z.tgz
   ```

   and check that the downloaded asset matches `SHA256SUMS`.
4. If something is wrong, say so in the release notes and release a fix as a new version. Keep old releases
   available so users can go back.

## Changing the supported DSH range

The peer range in `package.json` (`@deepseek-ai/dsh: >=0.2.1-alpha.2 <0.3.0-0`) is checked when a profile boots.
DSH skips the plugin when `semver.satisfies(runtime, range, { includePrerelease: true })` is false
(`evaluatePluginCompatibility` in `@deepseek-ai/dsh-app-boot`). With that option the range matches
`0.2.1-alpha.3`, later 0.2.x prereleases such as `0.2.2-alpha.1`, and stable 0.2.x. It does not match
`0.2.1-alpha.1` or a `0.3.0` prerelease. The `@deepseek-ai/*` devDependencies stay on the minimum supported
release, so `pnpm typecheck` covers that floor. `pnpm check:dsh` (CI job *DSH alpha compatibility*) resolves the
npm dist-tag `alpha`, checks it the same way, typechecks the structural ports against that release, and boots a
scratch web profile. Before widening the range:

- update the `@deepseek-ai/*` devDependencies to the new DSH version;
- re-check the structural DSH views in `src/host/dsh/ports.ts` and `src/client/dsh.ts` against the new DSH types,
  then run `pnpm typecheck` and `pnpm test`;
- run the manual verification above against that version.

That `package.json` change belongs to a code pull request, not a release commit.
