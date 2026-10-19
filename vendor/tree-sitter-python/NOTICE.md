# tree-sitter-python prebuilds

These files are the platform prebuilds from
[@ast-grep/lang-python](https://www.npmjs.com/package/@ast-grep/lang-python)
0.0.6. That package builds them from
[tree-sitter-python](https://github.com/tree-sitter/tree-sitter-python) 0.25.0.
The plugin loads `prebuilds/prebuild-<OS>-<Arch>/parser.so` itself.
There is no install script and no dependency on `@ast-grep/lang-python`.
That package's `package.json` says `"license": "ISC"`. The `LICENSE` file
it ships, copied here, is MIT. This plugin follows the shipped MIT text.

`@ast-grep/napi` 0.51.0 registers the file as the dynamic language `python`
with `languageSymbol` `tree_sitter_python` and `expandoChar` U+00B5.

Shipped targets: Linux x64, Linux arm64, macOS x64, macOS arm64, Windows x64.
The Linux files are glibc binaries (`NEEDED` `libc.so.6`). `objdump -T` shows
GLIBC_2.2.5 for Linux x64 and GLIBC_2.17 for Linux arm64. On Linux where
Node's `process.report.getReport().header.glibcVersionRuntime` is absent,
including musl (Alpine), or where that version is older than the file, the
plugin does not load them. Any other OS, CPU, musl, or that older glibc
uses the built-in Python parser. Settings and Coverage say so.

Licenses:

- `LICENSE` — MIT, Copyright (c) 2025 ast-grep (the language package that produced these prebuilds).
- `tree-sitter-python.LICENSE` — MIT, Copyright (c) 2016 Max Brunsfeld (the grammar, tag v0.25.0).
