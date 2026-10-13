/**
 * Lets the bench entry points load `src/` under plain Node. Node's built-in
 * type stripping (`--experimental-strip-types`) rejects TypeScript-only
 * syntax that the plugin source uses, such as constructor parameter
 * properties. This synchronous module hook re-runs every local `.ts` module
 * through `stripTypeScriptTypes` in `transform` mode instead.
 *
 * Call {@link registerTypeScriptTransform} before the first dynamic import of
 * anything under `src/`; modules imported statically by the entry point have
 * already been loaded by then.
 */

import { registerHooks, stripTypeScriptTypes } from 'node:module'

let registered = false

export function registerTypeScriptTransform(): void {
  if (registered) return
  registered = true
  registerHooks({
    load(url, context, nextLoad) {
      const result = nextLoad(url, context)
      const typescript = result.format === 'module-typescript' || result.format === 'commonjs-typescript'
      if (!typescript || result.source === undefined || url.includes('/node_modules/')) return result
      const code =
        typeof result.source === 'string' ? result.source : Buffer.from(result.source as Uint8Array).toString('utf8')
      return {
        ...result,
        format: result.format === 'module-typescript' ? 'module' : 'commonjs',
        source: stripTypeScriptTypes(code, { mode: 'transform', sourceUrl: url }),
      }
    },
  })
}
