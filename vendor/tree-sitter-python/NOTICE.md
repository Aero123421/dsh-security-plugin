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
On musl, the plugin does not read `parser.so` and uses `python-fallback`.
This is a fail-safe change. A crash on musl was not reproduced on hardware.
Not yet checked: an old-glibc machine, an arm64 machine, macOS, Windows, and
whether `lib/` rebuilt from source matches the committed output.
`objdump -T` on the shipped Linux files shows `GLIBC_2.2.5` for x64 and
`GLIBC_2.17` for arm64. NEEDED is `libc.so.6` for both.

Licenses:

- `LICENSE` — MIT, Copyright (c) 2025 ast-grep (the language package that produced these prebuilds).
- `tree-sitter-python.LICENSE` — MIT, Copyright (c) 2016 Max Brunsfeld (the grammar, tag v0.25.0).
