# dsh-security-plugin の開発

## 開発用Skills

DSHプラグインの実装・レビューでは [.agents/AGENTS.md](.agents/AGENTS.md) を読み、作業に合う [.agents/skills](.agents/README.md) のSkillを使います。リポジトリ固有の方針と検証コマンドは、既存の指示・README・package.json・CIに従います。

## Cursor Cloud specific instructions

- `node` は `^22.19.0 || >=24.0.0`（`node:sqlite`）。既定イメージの `/exec-daemon/node` は 22.14 なので、install が Node 22.23.3 を `/usr/local/lib/node-v22.23.3` に置き、PATH の先頭（`/usr/local/cargo/bin`）から解決する。`node -v` は 22.23.3、`pnpm -v` は 10.28.0。
- 依存関係は `pnpm install --frozen-lockfile`。確認は CI と同じ `pnpm check` と `node scripts/check-lib.mjs`。
- 起動し続けるサーバはない。DSH の中で画面まで通す手順は [docs/e2e-testing.md](docs/e2e-testing.md)。API キーは不要で、`tests/e2e/scripted-llm` の scripted/oracle を使う。解析器だけのスキャンは `pnpm bench --app express-shop --config deterministic`。
