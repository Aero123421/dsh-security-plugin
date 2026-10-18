/**
 * DSH Security — Host plugin entry.
 *
 * Mounted by the bundle patch as the `dsh-security` row. It opens the local
 * store, starts the scan controller, and serves the browser half through
 * exact routes on DSH's authenticated `/api` channel. Everything it creates
 * is tied to the plugin's Cordis context, so disabling the plugin stops
 * running scans (they become resumable), closes the database, and removes
 * the routes.
 */

import { homedir } from 'node:os'
import { join, resolve } from 'node:path'
import toolkitLockJson from '../../toolkit.lock.json' with { type: 'json' }
import { loadAstGrep, type AstGrepHandle } from './analysis/astgrep.ts'
import { loadToolkitLock, Toolkit } from './analysis/toolkit.ts'
import { Config, operatorLimits } from './config.ts'
import { asConnection, asLlm, asWorkspaceRegistry } from './dsh/adapters.ts'
import type { LoggerPort } from './dsh/ports.ts'
import { registerRpcRoutes } from './rpc/server.ts'
import { ScanController } from './scan/controller.ts'
import { createHandlers, hostPathMasker } from './service.ts'
import { SettingsService } from './settings.ts'
import { openSecurityStore } from './store/sqlite.ts'

export const name = 'dsh-security'
export { Config }

/** The slice of the Cordis context this plugin uses. */
export interface HostContext {
  get(name: string): unknown
  effect(execute: () => () => unknown, label?: string): unknown
  inject(deps: string[], callback: (ctx: HostContext) => void): unknown
  logger: ((name: string) => LoggerPort) & LoggerPort
}

/** How long unload waits for aborted toolkit installs to clean up their staging files. */
const INSTALL_SHUTDOWN_GRACE_MS = 5_000

export function apply(ctx: HostContext, input?: Partial<Config>): void {
  const config = Config.parse(input ?? {})
  const logger = namedLogger(ctx)
  const dataDir = resolveDataDir(config)
  const store = openSecurityStore(join(dataDir, 'security.db'))
  const now = () => new Date()
  /** Aborted on unload: toolkit downloads and other long handler work stop with the plugin. */
  const lifetime = new AbortController()

  let astGrep: Promise<AstGrepHandle | undefined> | undefined
  const loadEngine = () => {
    astGrep ??= loadAstGrep({ disabled: config.disableAstGrep }).catch(error => {
      logger.warn('dsh-security: ast-grep could not be loaded; using the built-in parser', error)
      return undefined
    })
    return astGrep
  }
  const llm = () => asLlm(ctx.get('llm'))
  const workspaces = () => asWorkspaceRegistry(ctx.get('workspaceRegistry'))

  const toolkit = new Toolkit({
    dir: join(dataDir, 'toolkit'),
    lock: loadToolkitLock(toolkitLockJson),
    allowManagedInstall: config.allowManagedToolkit,
    fetch: globalThis.fetch,
  })
  const settings = new SettingsService(store, operatorLimits(config), config.allowRemoteHighRiskSettings, logger)
  let controller: ScanController
  try {
    controller = new ScanController({
      store,
      settings,
      llm,
      workspaces,
      toolkit,
      config,
      logger,
      fetch: globalThis.fetch,
      astGrep: loadEngine,
      now,
      pluginVersion: __PLUGIN_VERSION__,
      dataDir,
    })
  } catch (error) {
    store.close()
    throw error
  }

  // One disposer owns the shutdown order. Cordis runs a fiber's disposers concurrently
  // (`Promise.all` in `_unload`), so separate effects could close the store while scans
  // are still writing their final `interrupted` state.
  ctx.effect(() => {
    controller.start()
    return async () => {
      lifetime.abort(new Error('dsh-security was unloaded.'))
      try {
        await controller.dispose()
        await settleWithin(toolkit.settled(), INSTALL_SHUTDOWN_GRACE_MS)
      } catch (error) {
        logger.warn('dsh-security: shutdown did not finish cleanly', error)
      } finally {
        store.close()
      }
    }
  }, 'dsh-security: lifetime')

  const handlers = createHandlers({
    store,
    settings,
    controller,
    toolkit,
    config,
    llm,
    workspaces,
    astGrep: loadEngine,
    logger,
    pluginVersion: __PLUGIN_VERSION__,
    now,
    dataDir,
    lifetime: lifetime.signal,
  })

  ctx.inject(['connection'], scoped => {
    const connection = asConnection(scoped.get('connection'))
    if (!connection) {
      logger.warn('dsh-security: this DSH build has no exact-route support; the Security page is unavailable')
      return
    }
    const maskPaths = (text: string) => hostPathMasker({ workspaces, dataDir })(text)
    scoped.effect(() => registerRpcRoutes(connection, handlers, { logger, maskPaths }), 'dsh-security: rpc routes')
  })
  logger.info(`dsh-security ${__PLUGIN_VERSION__}: data in ${dataDir}`)
}

async function settleWithin(work: Promise<unknown>, ms: number): Promise<void> {
  let timer: ReturnType<typeof setTimeout> | undefined
  try {
    await Promise.race([
      work.then(
        () => undefined,
        () => undefined,
      ),
      new Promise<void>(resolve => {
        timer = setTimeout(resolve, ms)
        timer.unref?.()
      }),
    ])
  } finally {
    if (timer !== undefined) clearTimeout(timer)
  }
}

function resolveDataDir(config: Config): string {
  if (config.dataDir) return resolve(config.dataDir)
  const home = process.env.DSH_HOME ? resolve(process.env.DSH_HOME) : join(homedir(), '.dsh')
  return join(home, 'security')
}

function namedLogger(ctx: HostContext): LoggerPort {
  try {
    const named = ctx.logger('dsh-security')
    if (named && typeof named.info === 'function') return named
  } catch {
    // Older Cordis builds expose only the shared logger.
  }
  return ctx.logger
}
