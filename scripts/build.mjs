#!/usr/bin/env node
/**
 * Builds the two halves DSH loads:
 *
 * - `lib/index.js`: the Host plugin (ESM, Node). Runtime libraries are bundled
 *   so the installed package has no runtime dependencies except the optional
 *   native `@ast-grep/napi`.
 * - `lib/client.js`: the browser plugin in DSH's lazy-CJS factory format:
 *   `window.__ModuleLoader__.load({ id, factory: (require) => { ... } })`.
 *   Externals resolve through the module table DSH seeds for every dynamic
 *   bundle (React, Cordis). Nothing else may be required at runtime.
 */

import { readFile, rm, mkdir } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import * as esbuild from 'esbuild'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const pkg = JSON.parse(await readFile(join(root, 'package.json'), 'utf8'))
const watch = process.argv.includes('--watch')
const production = !watch

/** Module-table specifiers DSH provides to every dynamic client bundle. */
const CLIENT_EXTERNALS = ['react', 'react/jsx-runtime', 'react-dom', 'react-dom/client', '@deepseek-ai/cordis']

/** Native or peer modules the Host bundle must not inline. */
const HOST_EXTERNALS = ['@ast-grep/napi', '@ast-grep/lang-python', '@deepseek-ai/*']

const define = {
  __PLUGIN_VERSION__: JSON.stringify(pkg.version),
  __PLUGIN_NAME__: JSON.stringify(pkg.name),
}

/** @type {esbuild.BuildOptions} */
const hostOptions = {
  absWorkingDir: root,
  entryPoints: { index: 'src/host/index.ts' },
  outdir: 'lib',
  bundle: true,
  platform: 'node',
  format: 'esm',
  target: 'node22',
  sourcemap: true,
  sourcesContent: true,
  legalComments: 'linked',
  external: HOST_EXTERNALS,
  define,
  // Bundled CommonJS dependencies may call require(); give ESM output one.
  banner: {
    js: "import { createRequire as __dshSecurityCreateRequire } from 'node:module';\nconst require = __dshSecurityCreateRequire(import.meta.url);",
  },
  logLevel: 'info',
}

/** @type {esbuild.BuildOptions} */
const clientOptions = {
  absWorkingDir: root,
  entryPoints: { client: 'src/client/index.ts' },
  outdir: 'lib',
  bundle: true,
  platform: 'browser',
  format: 'cjs',
  target: 'es2022',
  jsx: 'automatic',
  sourcemap: true,
  sourcesContent: true,
  minify: production,
  legalComments: 'linked',
  external: CLIENT_EXTERNALS,
  define: {
    ...define,
    'process.env.NODE_ENV': JSON.stringify(production ? 'production' : 'development'),
  },
  banner: {
    js: `window.__ModuleLoader__.load({ id: ${JSON.stringify(pkg.name)}, factory: (require) => {\nvar module = { exports: {} }; var exports = module.exports;`,
  },
  footer: { js: 'return module.exports; } });' },
  logLevel: 'info',
  plugins: [
    {
      // The browser bundle may only reach the module table through the
      // externals above; any other @deepseek-ai value import would inline a
      // second runtime copy or require a module the table cannot answer.
      name: 'dsh-security-client-purity',
      setup(build) {
        build.onResolve({ filter: /^@deepseek-ai\// }, args => {
          if (CLIENT_EXTERNALS.includes(args.path)) return undefined
          return {
            errors: [
              {
                text: `client bundle purity: "${args.path}" is not a DSH module-table external; use \`import type\` or a Cordis service instead`,
              },
            ],
          }
        })
        build.onResolve({ filter: /^node:/ }, args => ({
          errors: [{ text: `client bundle purity: Node builtin "${args.path}" cannot run in the browser` }],
        }))
      },
    },
  ],
}

if (!watch) await rm(join(root, 'lib'), { recursive: true, force: true })
await mkdir(join(root, 'lib'), { recursive: true })

if (watch) {
  const contexts = await Promise.all([esbuild.context(hostOptions), esbuild.context(clientOptions)])
  await Promise.all(contexts.map(context => context.watch()))
  console.log('watching for changes…')
} else {
  await Promise.all([esbuild.build(hostOptions), esbuild.build(clientOptions)])
}
