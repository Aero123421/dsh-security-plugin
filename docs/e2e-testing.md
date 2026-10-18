# End-to-end testing

Unit tests (`pnpm test`) cover the Host and the browser half separately, with fakes for DSH services. This guide
runs the real plugin inside a real DSH, without an API key, using a deterministic test model. Use it to check the
whole loop:

- install and bundle loading;
- RPC over DSH's authenticated `/api` channel;
- the Security page;
- worker tool calls, quote verification, independent review and persistence;
- pause, resume and export.

Everything below uses a scratch `DSH_HOME`, so your real DSH profiles and data are not touched.

## 1. Scratch DSH install

```sh
mkdir -p /tmp/dsh-e2e && cd /tmp/dsh-e2e
npm i @deepseek-ai/dsh@0.2.1-alpha.2         # the lowest supported DSH version
export DSH_HOME=/tmp/dsh-e2e/home              # isolate profiles, plugin installs and security.db
npx dsh --version                              # 0.2.1-alpha.2
```

`dsh plugin` forwards to `pnpm` in the profile directory, so `pnpm` must be on `PATH`. To test against a newer DSH
in the supported range (`>=0.2.1-alpha.2 <0.3.0-0`), install that version instead. CI runs `pnpm check:dsh`
against the npm dist-tag `alpha` (peer range, structural types, and a scratch web boot that calls `getBootstrap`).
The steps below are the manual pass, including the scripted model.

## 2. Build and link the checkout

```sh
cd /path/to/dsh-security-plugin
pnpm install && pnpm build

cd /tmp/dsh-e2e
npx dsh plugin --profile web add -w /path/to/dsh-security-plugin    # pnpm link: rebuilds are picked up on restart
npx dsh --profile web --dump-config | grep -A4 '# == dsh-security-plugin'
```

The dump should show:

```yaml
# == dsh-security-plugin
- id: dsh-security
  name: dsh-security-plugin
  config:
    dataDir: !!js dshHomePath('security')
```

## 3. Overlay the scripted model

`tests/e2e/scripted-llm/index.mjs` is a small Cordis plugin. It registers the provider `scripted` with one model,
`oracle`. The oracle plays every DSH Security role:

1. It reads the files each task points at, using the plugin's own `read_file` tool.
2. It answers from the fixtures' `expected.json`: it reports planted findings with exact quotes, refutes negative
   controls with a quoted defense, and confirms the rest.
3. In every hunter run it also submits one **fabricated** finding (`Fabricated finding that must be discarded`),
   which the host must drop.

It tests plumbing, not detection quality. Load it with a `--patch` overlay so it never ends up in a real profile:

```yaml
# /tmp/dsh-e2e/overlay.yml
- insert:
    - id: scripted-llm
      name: /path/to/dsh-security-plugin/tests/e2e/scripted-llm/index.mjs
      config:
        fixturesDir: /path/to/dsh-security-plugin/tests/fixtures/apps
        delayMs: 30          # optional, per model request
```

```sh
npx dsh --profile web --patch overlay.yml --dump-config | grep -A4 'id: scripted-llm'
npx dsh --profile web --patch overlay.yml --no-open --port 0
# prints: dsh web: http://127.0.0.1:<port>/?token=<one-time token>
```

On Node 22 the log shows `ExperimentalWarning: SQLite is an experimental feature`; this is expected.
`$DSH_HOME/security/security.db` is created at startup.

## 4. Scan a fixture

1. Copy a fixture app **without its answer key**, so that, as in a real scan, nothing in the workspace describes
   the planted issues:

   ```sh
   cd /path/to/dsh-security-plugin
   node --experimental-strip-types bench/prepare.ts express-shop /tmp/dsh-e2e/apps
   ```

   `prepare.ts` also joins the fake credentials, which the repository stores split by a `<<fake-split>>` marker
   (see `FAKE_SECRET_SPLIT` in `bench/fixtures.ts`). A plain `cp` would leave the marker in, and the secret
   detectors would then miss those planted keys.

   (The oracle reads the answers from `fixturesDir`, not from the workspace.)
2. Open the printed URL. Add `/tmp/dsh-e2e/apps/express-shop` as a project in DSH.
3. Open **Security** → *Settings* → *Models* → Default: `Scripted (tests)` / `Oracle`. Save.
4. **New scan** → *Deep*, tick the consent box, *Start scan*.

Expected results:

- Overview shows the phases running in order, with live workers (Planner, then Hunters, then Skeptics) and token
  usage.
- When the scan is done, Coverage reports dropped claims ("N possible problems were dropped because the code they
  cited couldn't be found"). That is the fabricated findings being discarded.
- Findings lists the planted issues with *Quote verified* steps. Negative controls flagged by a rule appear as
  *Ruled out*, with the defending code as evidence against.
- *Export* → Markdown / JSON / SARIF each download a file with no absolute paths in it.
- Pause while hunters run, then resume. Completed tasks are not repeated, which you can check in the activity log
  and in the request count.
- Stop DSH (Ctrl-C) during a scan and start it again. The scan shows *Interrupted*, and *Resume* continues it.
- Set Security → Settings → Language to 日本語 and run a Deep scan again. Rule-based findings that the scripted
  skeptic confirms get a localized title starting with `【検証済み】`.

## 5. API smoke test without a browser

The `?token=` URL sets an auth cookie. With that cookie every RPC is a plain POST:

```sh
URL='http://127.0.0.1:<port>/?token=<token>'
BASE=${URL%%/\?*}
curl -s -c jar.txt -o /dev/null "$URL"                       # 303 + dsh-auth cookie
rpc() {  # rpc <method> [json-payload]
  local payload=${2:-'{}'}
  curl -s -b jar.txt -H 'content-type: application/json' \
    -d "{\"type\":\"client-request\",\"rpcId\":\"1\",\"method\":\"dsh-security/$1\",\"payload\":$payload}" \
    "$BASE/api/dsh-security/$1"; echo
}

rpc getBootstrap          # pluginVersion, contractVersion 4, default settings, loopback: true
rpc listModels            # includes {"id":"scripted", "models":[{"id":"oracle", …}]}
rpc listWorkspaces
curl -s -o /dev/null -w '%{http_code}\n' -H 'content-type: application/json' \
  -d '{"type":"client-request","rpcId":"1","method":"dsh-security/getBootstrap","payload":{}}' \
  "$BASE/api/dsh-security/getBootstrap"                      # 401 without the cookie
```

## 6. Automating it (Playwright smoke test idea)

The plugin does not ship a browser test yet. A minimal smoke test would:

1. In `globalSetup`: build, create the scratch `DSH_HOME`, run `dsh plugin --profile web add <checkout>`, start
   `dsh --profile web --patch overlay.yml --no-open --port 0`, parse the printed URL, and copy a fixture app
   without its answer key.
2. Register the project through DSH's own UI (or API), then select the `scripted/oracle` model with the
   `updateSettings` RPC shown above, so the test does not depend on the Settings form.
3. In the test: open the token URL → click **Security** in the sidebar → *New scan* → *Quick* → consent →
   *Start scan*. Wait for "Completed", assert at least one finding and a "dropped" count ≥ 1, open a finding and
   check that a *Quote verified* badge is visible, then export SARIF and validate it against the SARIF 2.1.0 schema.
4. In `globalTeardown`: stop DSH and delete the scratch directory.

Keep it to one Quick scan of one fixture, so it runs in well under a minute with `delayMs: 0`.

## Cleaning up

```sh
rm -rf /tmp/dsh-e2e            # scratch DSH, profile, security.db, copied apps
```

Unset `DSH_HOME` (or open a new shell) before using your real DSH again.
