/**
 * Scan lifecycle: creation and admission checks, a FIFO queue bounded by
 * `maxConcurrentScans`, pause/resume/cancel/delete, crash recovery, and the
 * in-memory view of running workers. Jobs are owned by the Host plugin, so a
 * closed browser tab never stops a scan.
 */

import type { ReportLanguage, WorkerView } from '../../shared/contracts.ts'
import { ROLE_NAMES, type RoleName, type ScanMode, type ScanStatus } from '../../shared/domain.ts'
import type { ModelRef } from '../../shared/settings.ts'
import type { ScanRecord } from '../core/model.ts'
import type { WorkspaceEntity, WorkspaceRegistryPort } from '../dsh/ports.ts'
import { RpcError } from '../rpc/errors.ts'
import { roleRoute, type SettingsService } from '../settings.ts'
import { resolveScanRoot } from './root.ts'
import { newId } from './findings.ts'
import { initialPhases, MAX_TASK_ATTEMPTS, type PipelineDeps, ScanJob } from './pipeline.ts'

export interface ControllerDeps extends Omit<PipelineDeps, 'live'> {
  readonly settings: SettingsService
  readonly workspaces: () => WorkspaceRegistryPort | undefined
  readonly pluginVersion: string
}

export interface CreateScanInput {
  readonly workspaceId: string
  readonly subpath?: string
  readonly mode: ScanMode
  readonly language?: ReportLanguage
  /** Default true. `false` runs only the built-in analyzers and sends nothing to models. */
  readonly aiReview?: boolean
}

const ACTIVE: readonly ScanStatus[] = ['queued', 'running']
const SHUTDOWN_GRACE_MS = 5_000

export class ScanController {
  private readonly jobs = new Map<string, { job: ScanJob; done: Promise<void> }>()
  private readonly workers = new Map<string, Map<string, WorkerView>>()
  private disposed = false
  private readonly unsubscribe: () => void

  constructor(private readonly deps: ControllerDeps) {
    // Withdrawing consent applies to scans that are already running, not only to new ones.
    this.unsubscribe = deps.settings.onChange(settings => {
      if (settings.privacy.sendCodeToModel) return
      for (const { job } of this.jobs.values()) job.revokeConsent()
    })
  }

  /** Recover from an unclean stop, apply retention, and start queued scans. */
  start(): void {
    const { store } = this.deps
    for (const scan of store.scansNeedingRecovery()) {
      const tasks = store.listTasks(scan.id, ['running'])
      const runs = store.listAgentRuns(scan.id).filter(run => run.status === 'running')
      if (scan.status !== 'running' && tasks.length === 0 && runs.length === 0) continue
      // One scan is one recovery unit. Also repair partial recovery left by
      // older versions that committed the interrupted status before cleanup.
      store.transaction(() => {
        if (scan.status === 'running') {
          store.updateScan(scan.id, { status: 'interrupted' })
          store.appendEvent(
            scan.id,
            'warn',
            'run-interrupted',
            'DSH stopped while this scan was running. Resume it to continue.',
          )
        }
        for (const task of tasks) store.updateTask(task.id, { status: 'pending' })
        const at = this.deps.now().toISOString()
        for (const run of runs) {
          store.updateAgentRun(run.id, { status: 'cancelled', stopReason: 'interrupted', finishedAt: at })
        }
      })
    }
    const retention = this.deps.settings.get().settings.storage.retentionDays
    if (retention > 0) {
      const purged = store.purgeScansOlderThan(retention, this.deps.now())
      if (purged > 0) this.deps.logger.info(`dsh-security: removed ${purged} scan(s) older than ${retention} days`)
    }
    this.kick()
  }

  /** Validate and queue a new scan. */
  async create(input: CreateScanInput): Promise<ScanRecord> {
    this.assertOpen()
    const workspace = this.workspace(input.workspaceId)
    const scope = await resolveScanRoot(workspace, input.subpath)
    const { settings } = this.deps.settings.get()
    const aiReview = input.aiReview !== false
    const models: Partial<Record<RoleName, ModelRef>> = {}
    if (aiReview) {
      const llm = this.deps.llm()
      const providers = new Set((llm?.listProviders() ?? []).map(p => p.id))
      for (const role of ROLE_NAMES) {
        const route = roleRoute(settings, role)
        if (route) models[role] = route
      }
      if (!llm || !models.hunter) {
        throw new RpcError('security/no-model', 'Choose a model for AI review in Security settings first.', {})
      }
      const missing = ROLE_NAMES.filter(role => models[role] && !providers.has(models[role].provider))
      if (missing.length > 0) {
        throw new RpcError(
          'security/no-model',
          'A selected model provider is no longer connected in DSH. Update the model settings.',
          { roles: missing },
        )
      }
      // Resolution validates exact model identity; cache only for this creation, never across settings/HMR.
      const resolved = new Map<string, Awaited<ReturnType<typeof llm.resolveModelInfo>>>()
      for (const role of ROLE_NAMES) {
        const route = models[role]
        if (!route) continue
        const key = JSON.stringify([route.provider, route.model])
        let info = resolved.get(key)
        if (!info) {
          try {
            info = await llm.resolveModelInfo(route.provider, route.model)
          } catch {
            throw new RpcError(
              'security/no-model',
              `The selected ${role} model (${route.provider}/${route.model}) could not be resolved. Update Security model settings.`,
              { role },
            )
          }
          resolved.set(key, info)
        }
        if (route.reasoningEffort !== undefined && !info.reasoning?.efforts.some(e => e.id === route.reasoningEffort)) {
          throw new RpcError(
            'security/no-model',
            `The selected ${role} model does not support reasoning effort "${route.reasoningEffort}". Update Security model settings.`,
            { role },
          )
        }
        // DSH exposes a default output count, not an output ceiling. Never mistake that default for a maximum.
        if (route.maxOutputTokens !== undefined && info.context && route.maxOutputTokens > info.context.contextWindow) {
          throw new RpcError(
            'security/no-model',
            `The selected ${role} maxOutputTokens (${route.maxOutputTokens}) exceeds the model context limit (${info.context.contextWindow}).`,
            { role },
          )
        }
      }
      if (!settings.privacy.sendCodeToModel) {
        throw new RpcError(
          'security/consent-required',
          'Allow sending redacted source code to the selected models before starting an AI review.',
          {},
        )
      }
    }
    const busy = this.deps.store
      .listScans({ workspaceId: workspace.id, workspaceRoot: scope.workspaceRoot, statuses: ACTIVE, limit: 1 })
      .at(0)
    if (busy) {
      throw new RpcError('security/busy', 'A scan of this project is already queued or running.', { scanId: busy.id })
    }
    const now = this.deps.now().toISOString()
    const scan: ScanRecord = {
      id: newId(),
      workspaceId: workspace.id,
      workspaceTitle: workspace.title,
      workspaceRoot: scope.workspaceRoot,
      ...(scope.subpath ? { subpath: scope.subpath } : {}),
      mode: input.mode,
      status: 'queued',
      phase: 'snapshot',
      createdAt: now,
      updatedAt: now,
      settings,
      budget: settings.budgets[input.mode],
      models,
      usage: { llmCalls: 0, inputTokens: 0, outputTokens: 0, toolCalls: 0, elapsedMs: 0 },
      phases: initialPhases(input.mode, aiReview),
      pluginVersion: this.deps.pluginVersion,
      language: input.language ?? 'en',
    }
    this.deps.store.insertScan(scan)
    this.deps.store.appendEvent(
      scan.id,
      'info',
      'created',
      `Scan created (${input.mode}${aiReview ? '' : ', built-in analyzers only'})`,
    )
    this.kick()
    return this.deps.store.getScan(scan.id) ?? scan
  }

  pause(id: string): ScanRecord {
    const scan = this.require(id)
    const running = this.jobs.get(id)
    if (running) {
      running.job.stop('pause')
      return scan
    }
    if (scan.status === 'queued') return this.deps.store.updateScan(id, { status: 'paused' })
    throw invalidState(scan, 'pause')
  }

  resume(id: string): ScanRecord {
    this.assertOpen()
    const scan = this.require(id)
    if (!['paused', 'interrupted', 'failed'].includes(scan.status)) throw invalidState(scan, 'resume')
    const { store } = this.deps
    const busy = store
      .listScans({ workspaceId: scan.workspaceId, workspaceRoot: scan.workspaceRoot, statuses: ACTIVE, limit: 500 })
      .find(other => other.id !== id)
    if (busy)
      throw new RpcError('security/busy', 'A scan of this project is already queued or running.', { scanId: busy.id })
    const updated = store.transaction(() => {
      for (const task of store.listTasks(id, ['running'])) store.updateTask(task.id, { status: 'pending' })
      // Explicit resume alone retries failed work. Crash recovery deliberately leaves failures untouched.
      // Attempts count worker runs, including interrupted runs, and never reset across resumes.
      for (const task of store.listTasks(id, ['failed'])) {
        if (task.attempts < MAX_TASK_ATTEMPTS) store.updateTask(task.id, { status: 'pending' })
      }
      for (const run of store.listAgentRuns(id)) {
        if (run.status === 'running') {
          store.updateAgentRun(run.id, {
            status: 'cancelled',
            stopReason: 'interrupted',
            finishedAt: this.deps.now().toISOString(),
          })
        }
      }
      if (scan.pluginVersion !== this.deps.pluginVersion) {
        store.appendEvent(
          id,
          'info',
          'plugin-version-changed',
          'The plugin version changed since scan creation. Pending tasks will be refreshed from the new analysis; completed tasks are retained.',
        )
      }
      const queued = store.updateScan(id, { status: 'queued', clearError: true, clearFinishedAt: true })
      store.appendEvent(id, 'info', 'resumed', 'Scan queued to resume')
      return queued
    })
    this.kick()
    return updated
  }

  cancel(id: string): ScanRecord {
    const scan = this.require(id)
    const running = this.jobs.get(id)
    if (running) {
      running.job.stop('cancel')
      return scan
    }
    if (scan.status === 'completed' || scan.status === 'cancelled') throw invalidState(scan, 'cancel')
    const { store } = this.deps
    for (const task of store.listTasks(id, ['pending', 'running'])) store.updateTask(task.id, { status: 'skipped' })
    store.appendEvent(id, 'info', 'run-cancelled', 'Scan cancelled')
    return store.updateScan(id, { status: 'cancelled', finishedAt: this.deps.now().toISOString() })
  }

  /** Delete a scan; a running one is cancelled first. */
  async remove(id: string): Promise<boolean> {
    const running = this.jobs.get(id)
    if (running) {
      running.job.stop('cancel')
      await running.done
    }
    return this.deps.store.deleteScan(id)
  }

  /** Live workers of a running scan. */
  liveWorkers(id: string): WorkerView[] {
    return [...(this.workers.get(id)?.values() ?? [])]
  }

  isRunning(id: string): boolean {
    return this.jobs.has(id)
  }

  /** Stop everything for plugin unload; running scans become `interrupted`. */
  async dispose(): Promise<void> {
    this.disposed = true
    this.unsubscribe()
    const pending = [...this.jobs.values()]
    for (const { job } of pending) job.stop('shutdown')
    await Promise.race([
      Promise.allSettled(pending.map(p => p.done)),
      new Promise(resolve => setTimeout(resolve, SHUTDOWN_GRACE_MS).unref?.()),
    ])
  }

  private kick(): void {
    if (this.disposed) return
    const capacity = this.deps.config.maxConcurrentScans - this.jobs.size
    if (capacity <= 0) return
    const queued = this.deps.store
      .listScans({ statuses: ['queued'], limit: 500 })
      .sort((a, b) => (a.createdAt < b.createdAt ? -1 : a.createdAt > b.createdAt ? 1 : 0))
      .slice(0, capacity)
    for (const scan of queued) this.launch(scan.id)
  }

  private launch(id: string): void {
    const live = this.workers
    const job = new ScanJob(id, {
      ...this.deps,
      currentSettings: () => this.deps.settings.get().settings,
      registeredWorkspaceRoot: workspaceId => this.deps.workspaces()?.get(workspaceId)?.path,
      live: {
        set: (scanId, view) => {
          let views = live.get(scanId)
          if (!views) {
            views = new Map()
            live.set(scanId, views)
          }
          views.set(view.id, view)
        },
        clear: scanId => live.delete(scanId),
      },
    })
    const done = job
      .run()
      .catch(error => this.deps.logger.error('dsh-security: scan job crashed', error))
      .finally(() => {
        this.jobs.delete(id)
        this.kick()
      })
    this.jobs.set(id, { job, done })
  }

  private workspace(id: string): WorkspaceEntity {
    const registry = this.deps.workspaces()
    if (!registry) {
      throw new RpcError('security/workspace-unavailable', 'DSH has no project list in this profile.', {})
    }
    const workspace = registry.get(id)
    if (!workspace)
      throw new RpcError('security/not-found', 'That project is no longer registered in DSH.', { workspaceId: id })
    return workspace
  }

  private require(id: string): ScanRecord {
    const scan = this.deps.store.getScan(id)
    if (!scan) throw new RpcError('security/not-found', 'Scan not found.', { scanId: id })
    return scan
  }

  private assertOpen(): void {
    if (this.disposed) throw new RpcError('security/invalid-state', 'The security plugin is shutting down.', {})
  }
}

function invalidState(scan: ScanRecord, action: string): RpcError {
  return new RpcError('security/invalid-state', `Cannot ${action} a scan that is ${scan.status}.`, {
    scanId: scan.id,
    status: scan.status,
  })
}
