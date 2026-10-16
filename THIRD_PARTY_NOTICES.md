# Third-party notices

DSH Security is MIT-licensed (see `LICENSE`). This file lists third-party
software that is bundled into the published package, loaded from it, or
downloaded by it at the user's request.

## Bundled into `lib/index.js`

The Host bundle inlines these runtime libraries. `lib/client.js` (the browser
bundle) inlines no third-party packages; React and Cordis are provided by DSH
at runtime.

| Package | Version | License |
| --- | --- | --- |
| [zod](https://github.com/colinhacks/zod) | 4.6.7 | MIT |
| [ignore](https://github.com/kaelzhang/node-ignore) | 7.0.12 | MIT |
| [yaml](https://github.com/eemeli/yaml) | 2.9.1 | ISC |

### zod — MIT

```
MIT License

Copyright (c) 2025 Colin McDonnell

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

### ignore — MIT

```
Copyright (c) 2013 Kael Zhang <i@kael.me>, contributors
http://kael.me/

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
```

### yaml — ISC

```
Copyright Eemeli Aro <eemeli@gmail.com>

Permission to use, copy, modify, and/or distribute this software for any purpose
with or without fee is hereby granted, provided that the above copyright notice
and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND
FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS
OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF
THIS SOFTWARE.
```

## Optional dependency (installed by the package manager, not bundled)

| Package | Version | License | Notes |
| --- | --- | --- | --- |
| [@ast-grep/napi](https://github.com/ast-grep/ast-grep) | 0.51.0 | MIT | Native tree-sitter engine with prebuilt binaries. When it is missing or has no binary for the platform, the plugin uses its built-in tokenizer instead. Its license text ships in its own package. |

`@ast-grep/lang-python` is loaded opportunistically if it is installed, but it
is not a declared dependency of this package.

## External tools downloaded only at the user's request

The Settings → Analyzers section can download pinned builds of these tools into
`$DSH_HOME/security/toolkit/` after the user accepts the tool's license in the
UI. Each download is checked against the SHA-256 in `toolkit.lock.json` before
it is installed. The tools are separate programs run as child processes; their
code is not part of this package.

| Tool | Pinned version | License |
| --- | --- | --- |
| [Gitleaks](https://github.com/gitleaks/gitleaks) | 8.30.1 | MIT |
| [OSV-Scanner](https://github.com/google/osv-scanner) | 2.7.0 | Apache-2.0 |

## Tools used only if the user installs them

[Semgrep](https://github.com/semgrep/semgrep) (engine: LGPL-2.1) is never
downloaded or bundled. If it is on `PATH`, it runs only with a local rules path
that the operator configures (`semgrepConfig`). No Semgrep registry rules are
shipped with, fetched by, or redistributed by this plugin.

## Data sources

The optional dependency lookup queries the public [OSV.dev](https://osv.dev)
API (or an operator-configured mirror). Advisory text shown in findings comes
from that database.
