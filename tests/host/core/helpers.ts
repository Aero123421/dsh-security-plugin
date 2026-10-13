/**
 * Shared harness for the orchestration tests: an in-process copy of the
 * deterministic "oracle" model from `tests/e2e/scripted-llm`, a gate that
 * holds model calls until the test releases them, a temp copy of a fixture
 * app, and a fully wired ScanController over an in-memory store.
 */

import { cp, mkdtemp, realpath, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import type { AstGrepHandle } from '../../../src/host/analysis/astgrep.ts'
import type { Toolkit } from '../../../src/host/analysis/toolkit.ts'
import { Config, operatorLimits } from '../../../src/host/config.ts'
import type { EventRecord } from '../../../src/host/core/model.ts'
import type {
  LlmGenerateOptions,
  LlmModelInfo,
  LlmPort,
  LlmProviderInfo,
  LlmResolvedModelInfo,
  LlmStreamChunk,
  LoggerPort,
  WorkspaceEntity,
  WorkspaceRegistryPort,
} from '../../../src/host/dsh/ports.ts'
import { ScanController } from '../../../src/host/scan/controller.ts'
import { SettingsService } from '../../../src/host/settings.ts'
import { openSecurityStore } from '../../../src/host/store/sqlite.ts'
import type { SecurityStore } from '../../../src/host/store/types.ts'
import type { ScanStatus } from '../../../src/shared/domain.ts'
import type { SettingsPatch } from '../../../src/shared/settings.ts'
import { recordingLogger } from '../rpc/helpers.ts'
import { materializeFixtureDir } from '../../../bench/fixtures.ts'

export const FIXTURE_APPS = fileURLToPath(new URL('../../fixtures/apps/', import.meta.url))
const ORACLE_URL = pathToFileURL(fileURLToPath(new URL('../../e2e/scripted-llm/index.mjs', import.meta.url))).href

export const ORACLE_PROVIDER = 'scripted'
export const ORACLE_MODEL = 'oracle'

/** A network stub: every request fails, so no test can reach the internet. */
export const noNetwork: typeof fetch = async () => {
  throw new Error('network access is disabled in tests')
}

// ---------------------------------------------------------------------------
// Models
// ---------------------------------------------------------------------------

interface OracleAdapter {
  listModels(provider: string): Promise<LlmModelInfo[]>
  resolveModel(provider: string, model: string): Promise<LlmResolvedModelInfo>
  stream(options: LlmGenerateOptions): AsyncIterable<LlmStreamChunk>
}

interface OracleModule {
  apply(
    ctx: {
      effect(execute: () => unknown): void
      llm: { registerAdapter(providers: string[], adapter: OracleAdapter): () => void }
    },
    config: { fixturesDir: string; delayMs: number },
  ): void
}

/** An LlmPort that records every request. */
export interface RecordingLlm extends LlmPort {
  readonly calls: LlmGenerateOptions[]
}

/** The oracle model plugin, registered through a fake `ctx.llm` and wrapped as an LlmPort. */
export async function oracleLlm(): Promise<RecordingLlm> {
  const mod = (await import(ORACLE_URL)) as OracleModule
  let adapter: OracleAdapter | undefined
  mod.apply(
    {
      effect: execute => {
        execute()
      },
      llm: {
        registerAdapter: (_providers, registered) => {
          adapter = registered
          return () => {}
        },
      },
    },
    { fixturesDir: FIXTURE_APPS, delayMs: 0 },
  )
  const registered = adapter
  if (!registered) throw new Error('the oracle did not register an adapter')
  return scriptedLlm(options => registered.stream(options), {
    listModels: provider => registered.listModels(provider),
    resolveModelInfo: (provider, model) => registered.resolveModel(provider, model),
  })
}

/** An LlmPort whose `stream` is supplied by the test. */
export function scriptedLlm(
  stream: (options: LlmGenerateOptions) => AsyncIterable<LlmStreamChunk>,
  overrides: Partial<Omit<LlmPort, 'stream'>> & { providers?: LlmProviderInfo[] } = {},
): RecordingLlm {
  const calls: LlmGenerateOptions[] = []
  const providers = overrides.providers ?? [{ id: ORACLE_PROVIDER, name: 'Scripted (tests)' }]
  return {
    calls,
    listProviders: overrides.listProviders ?? (() => providers),
    listModels:
      overrides.listModels ??
      (async provider => [{ provider, id: ORACLE_MODEL, name: 'Oracle (fixture-aware test model)' }]),
    resolveModelInfo: overrides.resolveModelInfo ?? (async (provider, model) => ({ provider, id: model, name: model })),
    stream: options => {
      calls.push(options)
      return stream(options)
    },
  }
}

/** A model call that fails with the given provider failure. */
export async function* failingStream(code: string, message: string): AsyncGenerator<LlmStreamChunk> {
  yield { type: 'finish', reason: { kind: 'error', failure: { code, message } } }
}

export function roleOf(options: LlmGenerateOptions): 'planner' | 'hunter' | 'skeptic' | 'chain' {
  const system = options.system ?? ''
  if (system.includes('"planner"')) return 'planner'
  if (system.includes('"independent reviewer"')) return 'skeptic'
  if (system.includes('"attack-chain researcher"')) return 'chain'
  return 'hunter'
}

/**
 * Wraps a model so that matching calls wait until `open()` is called. A held
 * call ends as `aborted` as soon as its signal aborts, like a real provider.
 */
export interface GatedLlm extends RecordingLlm {
  /** Resolves once at least `count` calls are held at the same time. */
  waitForHeld(count: number): Promise<void>
  /** Let held and future calls through. */
  open(): void
}

export function gatedLlm(inner: LlmPort, hold: (options: LlmGenerateOptions) => boolean): GatedLlm {
  let opened = false
  let release: () => void = () => {}
  const gate = new Promise<void>(resolve => {
    release = resolve
  })
  let held = 0
  const waiters: { count: number; resolve: () => void }[] = []
  const notify = () => {
    for (const waiter of [...waiters]) {
      if (held >= waiter.count) {
        waiters.splice(waiters.indexOf(waiter), 1)
        waiter.resolve()
      }
    }
  }
  async function* stream(options: LlmGenerateOptions): AsyncGenerator<LlmStreamChunk> {
    if (!opened && hold(options)) {
      const signal = options.signal
      let onAbort: () => void = () => {}
      const aborted = new Promise<'aborted'>(resolve => {
        onAbort = () => resolve('aborted')
        if (signal?.aborted) resolve('aborted')
        else signal?.addEventListener('abort', onAbort, { once: true })
      })
      held++
      notify()
      const outcome = await Promise.race([gate.then(() => 'open' as const), aborted])
      held--
      signal?.removeEventListener('abort', onAbort)
      if (outcome === 'aborted') {
        yield { type: 'finish', reason: { kind: 'aborted', failure: { code: 'ABORTED', message: 'aborted' } } }
        return
      }
    }
    yield* inner.stream(options)
  }
  const recording = scriptedLlm(stream, {
    listProviders: () => inner.listProviders(),
    listModels: provider => inner.listModels(provider),
    resolveModelInfo: (provider, model, signal) => inner.resolveModelInfo(provider, model, signal),
  })
  return Object.assign(recording, {
    waitForHeld(count: number) {
      return new Promise<void>(resolve => {
        waiters.push({ count, resolve })
        notify()
      })
    },
    open() {
      opened = true
      release()
    },
  })
}

// ---------------------------------------------------------------------------
// Workspaces
// ---------------------------------------------------------------------------

export interface TempWorkspace {
  readonly root: string
  cleanup(): Promise<void>
}

/** Copy a fixture app (without its ground truth) into a fresh temp directory. */
export async function copyFixture(app: string): Promise<TempWorkspace> {
  const root = await realpath(await mkdtemp(join(tmpdir(), `dshsec-${app}-`)))
  await cp(join(FIXTURE_APPS, app), root, { recursive: true })
  await rm(join(root, 'expected.json'), { force: true })
  await materializeFixtureDir(root)
  return { root, cleanup: () => rm(root, { recursive: true, force: true }) }
}

export function registryOf(workspaces: readonly WorkspaceEntity[]): WorkspaceRegistryPort {
  return {
    list: () => workspaces,
    get: id => workspaces.find(w => w.id === id),
  }
}

// ---------------------------------------------------------------------------
// Controller harness
// ---------------------------------------------------------------------------

/** Settings that enable AI review with the oracle. */
export const AI_SETTINGS: SettingsPatch = {
  models: { default: { provider: ORACLE_PROVIDER, model: ORACLE_MODEL } },
  privacy: { sendCodeToModel: true },
}

export interface HarnessOptions {
  readonly store?: SecurityStore
  readonly llm?: LlmPort | undefined
  readonly workspaces?: readonly WorkspaceEntity[]
  readonly settings?: SettingsPatch
  readonly config?: Partial<Config>
  readonly astGrep?: () => Promise<AstGrepHandle | undefined>
  readonly logger?: LoggerPort
  readonly allowRemoteHighRisk?: boolean
  readonly toolkit?: Toolkit
  readonly dataDir?: string
}

export interface Harness {
  readonly store: SecurityStore
  readonly settings: SettingsService
  readonly controller: ScanController
  readonly config: Config
  readonly logger: ReturnType<typeof recordingLogger>
  /** Resolves when the scan is no longer queued or running and its job has finished. */
  settle(scanId: string): Promise<ScanStatus>
  /** Events of a scan, oldest first. */
  events(scanId: string): EventRecord[]
  /** Notice keys of a scan, in order. */
  notices(scanId: string): string[]
}

export const TERMINAL: readonly ScanStatus[] = ['completed', 'failed', 'cancelled', 'paused', 'interrupted']

export function createHarness(options: HarnessOptions = {}): Harness {
  const store = options.store ?? openSecurityStore(':memory:')
  const config = Config.parse(options.config ?? {})
  const logger = recordingLogger()
  const settings = new SettingsService(store, operatorLimits(config), options.allowRemoteHighRisk ?? true, logger)
  if (options.settings) settings.update(options.settings, settings.get().revision, true)
  const llm = options.llm
  const registry = registryOf(options.workspaces ?? [])
  const controller = new ScanController({
    store,
    settings,
    llm: () => llm,
    workspaces: () => registry,
    toolkit: options.toolkit,
    config,
    logger: options.logger ?? logger,
    fetch: noNetwork,
    astGrep: options.astGrep ?? (async () => undefined),
    now: () => new Date(),
    pluginVersion: '0.0.0-test',
    ...(options.dataDir ? { dataDir: options.dataDir } : {}),
  })
  const events = (scanId: string): EventRecord[] => {
    const out: EventRecord[] = []
    let after = 0
    for (;;) {
      const page = store.listEvents(scanId, after, 1000)
      out.push(...page)
      if (page.length < 1000) return out
      after = page[page.length - 1]?.seq ?? after
    }
  }
  return {
    store,
    settings,
    controller,
    config,
    logger,
    async settle(scanId) {
      await until(() => {
        const status = store.getScan(scanId)?.status
        return status !== undefined && TERMINAL.includes(status) && !controller.isRunning(scanId)
      })
      return store.getScan(scanId)?.status ?? 'failed'
    },
    events,
    notices: scanId =>
      events(scanId)
        .filter(e => e.type === 'notice')
        .map(e => String(e.data?.key)),
  }
}

/** Polls `condition` on the event loop until it holds (fails after `timeoutMs`). */
export async function until(condition: () => boolean, timeoutMs = 15_000): Promise<void> {
  const deadline = Date.now() + timeoutMs
  while (!condition()) {
    if (Date.now() > deadline) throw new Error('timed out waiting for a condition')
    await new Promise(resolve => setTimeout(resolve, 1))
  }
}
