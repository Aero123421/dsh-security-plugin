# Releasing

Releases are published to npm as `dsh-security-plugin` by GitHub Actions (`.github/workflows/release.yml`) when a
`v*` tag is pushed. The workflow publishes with **npm provenance**. Maintainers do not publish from their own
machines.

## Checklist

1. **Decide the version.** The project follows semantic versioning. Before 1.0, a minor bump (0.x.0) may contain
   breaking changes; call them out in the changelog. Also bump the minor version when you change:
   - `CONTRACT_VERSION` in `src/shared/contracts.ts` (the browser and Host halves must match);
   - a store migration in `src/host/store/schema.ts` (older plugin versions refuse the newer database);
   - the supported DSH peer range.
2. **Update the toolkit pins** (needs network):

   ```sh
   pnpm toolkit:pin           # downloads every asset in toolkit.lock.json, writes sha256 + size
   pnpm toolkit:pin --check   # re-download and verify without writing
   git diff toolkit.lock.json
   ```

   The script cross-checks every hash against the upstream checksums file (`checksumsUrl`) and fails on a missing
   or mismatching entry. To move to a new tool version, edit `version`, `checksumsUrl` and the asset URLs first,
   then pin. You can also run the **Toolkit pin** workflow (Actions → *Toolkit pin* → *Run workflow*), which opens a
   pull request with the updated lock. Review it like code: the hashes decide which binaries users execute.
3. **Bump the version** in `package.json` (`pnpm version <x.y.z> --no-git-tag-version`). `__PLUGIN_VERSION__` in
   both bundles comes from it at build time.
4. **Update `CHANGELOG.md`.** Move items from *Unreleased* to a new `## [x.y.z] - YYYY-MM-DD` section and update the
   compare links at the bottom.
5. **Run the full check locally:**

   ```sh
   pnpm install --frozen-lockfile
   pnpm check      # lint, typecheck, test, build, verify-package
   ```

   `scripts/verify-package.mjs` runs `npm pack --dry-run` and fails if the tarball has a missing or unexpected
   file, if `lib/client.js` is not in DSH's module-loader format or is 300 KB or larger, or if a `package.json`
   field DSH needs is wrong. It prints a warning (not an error) for any unpinned toolkit asset.
6. **Verify in DSH by hand.** Follow [e2e-testing.md](e2e-testing.md) with the lowest supported DSH
   (`@deepseek-ai/dsh@0.2.1-alpha.2`) and, if one exists, the newest 0.2.x:
   - the plugin loads and `--dump-config` shows the `# == dsh-security-plugin` layer;
   - a Deep scan with the scripted model completes; one scan with a real model if available;
   - pause/resume, interrupted → resume, and export of all three formats work;
   - a remote page with `allowRemoteHighRiskSettings: false` cannot turn on code upload;
   - on at least one platform with pinned assets, *Install* for Gitleaks and OSV-Scanner succeeds.

   Also install the packed tarball the way users will (`npm pack`, then `dsh plugin --profile web add
   /path/to/dsh-security-plugin-x.y.z.tgz`) to catch anything that only works from a linked checkout.
7. **Commit, tag and push:**

   ```sh
   git commit -am "release: vX.Y.Z"
   git tag -a vX.Y.Z -m "vX.Y.Z"
   git push origin main vX.Y.Z
   ```

## What the release workflow does

On a `v*` tag, on `ubuntu-latest` with Node 24 and pnpm from `packageManager`:

1. `pnpm install --frozen-lockfile`, `pnpm lint`, `pnpm typecheck`, `pnpm test`, `pnpm build`,
   `node scripts/verify-package.mjs`.
2. Checks that the tag matches `package.json` (`vX.Y.Z` ↔ `X.Y.Z`) and stops if it does not.
3. Prints a warning annotation if `toolkit.lock.json` still has `null` hashes. Publishing continues, because an
   unpinned asset only means managed installs of that tool are refused on that platform (users can still install it
   on `PATH`). Pin before releasing whenever possible, and mention any gap in the release notes.
4. `npm publish --provenance --access public`. Tags with a pre-release suffix (`-alpha`, `-beta`, `-rc`) publish
   under the `next` dist-tag; others under `latest`.

Required repository configuration:

- Secret `NPM_TOKEN`: an npm automation (or granular publish) token for the `dsh-security-plugin` package.
- The workflow requests `id-token: write` for provenance and `contents: read` otherwise.
- Protect `v*` tags so only maintainers can create them.
- For the *Toolkit pin* workflow: enable Settings → Actions → General → *Allow GitHub Actions to create and approve
  pull requests*. Pull requests opened by that workflow do not trigger CI on their own; close and reopen the pull
  request to run it.
- `repository.url` in `package.json` must point to the GitHub repository that runs the workflow, or npm rejects
  the provenance statement.

## After publishing

- Check the package page on npm: the provenance badge links to the workflow run, and the file list matches
  `verify-package` output.
- Install from the registry into a scratch profile: `dsh plugin --profile web add dsh-security-plugin@X.Y.Z`.
- Create a GitHub release from the tag and paste the changelog section into it.
- If something is wrong, `npm deprecate dsh-security-plugin@X.Y.Z "<reason>"` and release a fix. Avoid
  `npm unpublish`.

## Changing the supported DSH range

The peer range in `package.json` (`@deepseek-ai/dsh: >=0.2.1-alpha.2 <0.3.0-0`) is checked by DSH at install and
startup. Before widening it:

- update the `@deepseek-ai/*` devDependencies to the new DSH version;
- re-check the structural DSH views in `src/host/dsh/ports.ts` and `src/client/dsh.ts` against the new DSH types,
  then run `pnpm typecheck` and `pnpm test`;
- run the manual verification above against that version.

That `package.json` change belongs to a code pull request, not a release commit.
