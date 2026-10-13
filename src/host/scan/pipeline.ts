/**
 * One scan run, from snapshot to reconciliation. The control flow is plain
 * TypeScript: models only fill in the AI tasks the pipeline schedules, and
 * every model output passes host-side verification before it is stored.
 *
 * A run can be interrupted at any point (pause, cancel, shutdown, budget).
 * Deterministic phases are recomputed on resume; AI tasks have stable keys,
 * so completed work is never repeated and nothing is duplicated.
 *
 * A scan runs on the settings frozen when it was created, with two privacy
 * exceptions that always follow the user's current settings: withdrawing
 * consent to send code stops the scan's AI work (at start, on resume, and
 * promptly while it runs), and withheld-file patterns added since creation
 * apply from the next start or resume. The time budget is a deadline: when
 * it passes, in-flight model requests are aborted.
 */

import { homedir, tmpdir } from 'node:os'
import type { AnalyzerStatus, Coverage, WorkerView } from '../../shared/contracts.ts'
import { type RoleName, SCAN_PHASES, type ScanPhase } from '../../shared/domain.ts'
import type { ModelRef, SecuritySettings } from '../../shared/settings.ts'
import { chainSubmitTool, chainSystem, chainTask } from '../agents/roles/chain.ts'
import {
  type HunterOutput,
  hunterSubmitTool,
  hunterSystem,
  hunterTask,
  type TaskSignal,
} from '../agents/roles/hunter.ts'
import { plannerSubmitTool, plannerSystem, plannerTask, type ThreatModelOutput } from '../agents/roles/planner.ts'
import { type SkepticOutput, skepticSubmitTool, skepticSystem, skepticTask } from '../agents/roles/skeptic.ts'
import type { WorkerTool } from '../agents/runtime/tool.ts'
import { runWorker, type WorkerResult } from '../agents/runtime/worker.ts'
import { createWorkspaceTools } from '../agents/tools/workspace.ts'
import type { AstGrepHandle } from '../analysis/astgrep.ts'
import type { Toolkit } from '../analysis/toolkit.ts'
import type { Config } from '../config.ts'
import type { AgentRunRecord, FindingRecord, ScanRecord, TaskRecord, ThreatModelRecord } from '../core/model.ts'
import type { LlmPort, LoggerPort } from '../dsh/ports.ts'
import { createPathMasker, type PathMasker } from '../paths.ts'
import type { SecurityStore } from '../store/types.ts'
import { type AnalysisContext, type AnalysisStep, analyzeWorkspace } from './analysis.ts'
import { ScanBudgetGate } from './budget.ts'
import {
  applySkepticOutput,
  isReportableSignal,
  markNewFindings,
  newId,
  recordChains,
  recordHunterOutput,
  recordSignalFindings,
  signalFingerprint,
} from './findings.ts'
import { snapshotDigest } from './fingerprint.ts'
import { endpointPath, planHuntTasks, planReviewTasks, type PlannedTask } from './planning.ts'

/** Why a run stopped early on request. */
export type StopRequest = 'pause' | 'cancel' | 'shutdown'

export interface LiveWorkers {
  set(scanId: string, view: WorkerView): void
  clear(scanId: string): void
}

export interface PipelineDeps {
  readonly store: SecurityStore
  readonly llm: () => LlmPort | undefined
  readonly toolkit: Toolkit | undefined
  readonly config: Config
  readonly logger: LoggerPort
  readonly fetch: typeof fetch
  readonly astGrep: () => Promise<AstGrepHandle | undefined>
  readonly now: () => Date
  readonly live: LiveWorkers
  /** Plugin data directory, masked as `<data>` in recorded messages. */
  readonly dataDir?: string
  /**
   * The user's current settings. Consent to send code and withheld-file
   * patterns are re-read from here; without it the frozen settings apply.
   */
  readonly currentSettings?: () => SecuritySettings
}

const HUNT_KINDS = new Set<TaskRecord['kind']>([
  'triage-signals',
  'hunt-endpoints',
  'hunt-signals',
  'hunt-file',
  'hunt-hypothesis',
])
const MAX_HYPOTHESES = { quick: 0, deep: 8, research: 16 } as const
const MAX_SHORT_ROLE_TURNS = 16
const AI_PHASES = ['threat-model', 'hunt', 'review', 'chain'] as const satisfies readonly ScanPhase[]
/** Longest delay `setTimeout` accepts; a later deadline is left to the budget checks. */
const MAX_TIMER_MS = 2_147_483_647

interface AgentOutcome<T> {
  readonly result: WorkerResult<T>
  readonly ctx: {
    readonly scanId: string
    readonly taskId: string
    readonly agentRunId: string
    readonly model: string
    readonly now: () => string
  }
}

class Stopped extends Error {
  constructor(readonly request: StopRequest) {
    super(`scan ${request}`)
  }
}

/** Consent to send code to models was withdrawn: the AI phases end and the scan completes without them. */
class ConsentRevoked extends Error {
  constructor() {
    super('consent to send code to models was withdrawn')
  }
}

/** Runs one scan until it completes, fails, or is asked to stop. */
export class ScanJob {
  private readonly controller = new AbortController()
  /** Aborts model work only (consent withdrawn, time budget passed); the run itself continues. */
  private readonly aiController = new AbortController()
  private readonly aiSignal = AbortSignal.any([this.controller.signal, this.aiController.signal])
  private consentRevoked = false
  private deadlineReached = false
  private deadlineTimer: ReturnType<typeof setTimeout> | undefined
  private stopRequest: StopRequest | undefined
  private budget!: ScanBudgetGate
  private analysis!: AnalysisContext
  private scan: ScanRecord
  private discarded = 0
  private blockedNotified = false
  private masker: { readonly key: string; readonly mask: PathMasker } | undefined

  constructor(
    scanId: string,
    private readonly deps: PipelineDeps,
  ) {
    const scan = deps.store.getScan(scanId)
    if (!scan) throw new Error(`scan ${scanId} not found`)
    this.scan = scan
  }

  get id(): string {
    return this.scan.id
  }

  /** Ask the run to stop at the next safe point; in-flight model calls are aborted. */
  stop(request: StopRequest): void {
    this.stopRequest ??= request
    this.controller.abort(new Stopped(request))
  }

  get signal(): AbortSignal {
    return this.controller.signal
  }

  /**
   * Consent to send code to models was withdrawn. In-flight model requests of
   * an AI scan are aborted, its remaining AI tasks are skipped, and the scan
   * completes with its deterministic results and a `consent-revoked` notice.
   */
  revokeConsent(): void {
    if (this.scan.models.hunter === undefined || this.consentRevoked) return
    this.consentRevoked = true
    this.aiController.abort(new ConsentRevoked())
  }

  async run(): Promise<void> {
    const { store } = this.deps
    const resumed = this.scan.startedAt !== undefined
    this.scan = store.updateScan(this.scan.id, {
      status: 'running',
      ...(resumed ? {} : { startedAt: this.iso() }),
      clearError: true,
    })
    this.budget = new ScanBudgetGate(this.scan.budget, this.scan.usage, this.signal, () => this.deps.now().getTime())
    this.event('info', 'run-start', `Scan ${resumed ? 'resumed' : 'started'}`)
    try {
      this.armDeadline()
      await this.analyze()
      if (this.aiEnabled()) await this.aiPhases()
      this.phase('reconcile')
      this.reconcile()
      this.phase('report')
      this.finishPhase('report')
      this.complete()
    } catch (error) {
      this.handleStop(error)
    } finally {
      clearTimeout(this.deadlineTimer)
      this.persistUsage()
      this.deps.live.clear(this.scan.id)
    }
  }

  /** The AI phases; a withdrawn consent ends them early and the scan carries on without them. */
  private async aiPhases(): Promise<void> {
    try {
      this.checkConsent(true)
      await this.threatModel()
      await this.hunt()
      await this.review()
      await this.chain()
    } catch (error) {
      if (!(error instanceof ConsentRevoked) || this.signal.aborted) throw error
      const { store } = this.deps
      for (const task of store.listTasks(this.scan.id, ['pending', 'running'])) {
        store.updateTask(task.id, {
          status: 'skipped',
          finishedAt: this.iso(),
          error: { code: 'consent-revoked', message: 'Skipped because sending code to models was turned off.' },
        })
      }
      this.skipPhases(...AI_PHASES.filter(p => this.scan.phases.find(x => x.phase === p)?.state !== 'done'))
      this.notice(
        'warn',
        'consent-revoked',
        'Sending code to AI models was turned off, so this scan skipped the rest of its AI review. Built-in analyzer results are complete; AI results recorded before that are kept.',
      )
    }
  }

  /**
   * Throws {@link ConsentRevoked} once consent is withdrawn. With `reread`, the
   * user's current settings are read again (job start, resume, each worker start).
   */
  private checkConsent(reread = false): void {
    if (!this.consentRevoked && reread && this.deps.currentSettings?.().privacy.sendCodeToModel === false) {
      this.revokeConsent()
    }
    if (this.consentRevoked) throw new ConsentRevoked()
  }

  /** Abort in-flight model requests when the time budget runs out; the scan then completes as over budget. */
  private armDeadline(): void {
    if (this.scan.models.hunter === undefined) return
    const remaining = this.budget.remainingMs()
    if (remaining > MAX_TIMER_MS) return
    this.deadlineTimer = setTimeout(
      () => {
        this.deadlineReached = true
        this.aiController.abort(new Error('the time budget was used up'))
      },
      Math.max(0, remaining),
    )
    this.deadlineTimer.unref?.()
  }

  /** Frozen settings, with withheld-file patterns added since the scan was created. */
  private analysisSettings(): SecuritySettings {
    const frozen = this.scan.settings
    let current: SecuritySettings | undefined
    try {
      current = this.deps.currentSettings?.()
    } catch (error) {
      this.deps.logger.warn('dsh-security: could not read current settings; using the scan settings', error)
    }
    if (!current) return frozen
    const withheldGlobs = [...new Set([...frozen.privacy.withheldGlobs, ...current.privacy.withheldGlobs])]
    return { ...frozen, privacy: { ...frozen.privacy, withheldGlobs } }
  }

  // -------------------------------------------------------------------------
  // Phases
  // -------------------------------------------------------------------------

  private async analyze(): Promise<void> {
    const stepPhase: Record<AnalysisStep, ScanPhase> = {
      snapshot: 'snapshot',
      inventory: 'inventory',
      secrets: 'deterministic',
      sast: 'deterministic',
      dependencies: 'deterministic',
      external: 'deterministic',
      routes: 'surface',
    }
    const astGrep = await this.deps.astGrep()
    this.analysis = await analyzeWorkspace({
      root: this.scan.workspaceRoot,
      settings: this.analysisSettings(),
      config: this.deps.config,
      toolkit: this.deps.toolkit,
      fetch: this.deps.fetch,
      astGrep,
      signal: this.signal,
      onStep: step => this.phase(stepPhase[step]),
    })
    this.checkStopped()
    const digest = snapshotDigest(this.analysis.snapshot.files.values())
    if (this.scan.snapshotDigest && this.scan.snapshotDigest !== digest) {
      this.notice(
        'warn',
        'workspace-changed',
        'The workspace changed since this scan started. Evidence recorded earlier may refer to older code.',
      )
    }
    const { snapshot } = this.analysis
    this.scan = this.deps.store.updateScan(this.scan.id, {
      snapshotDigest: digest,
      analyzers: this.maskedAnalyzers(),
      ...(snapshot.commit ? { commit: snapshot.commit } : {}),
    })
    for (const warning of this.analysis.warnings.slice(0, 30)) this.event('warn', 'analysis-warning', warning)
    for (const analyzer of this.analysis.analyzers) {
      if (!analyzer.available && analyzer.source !== 'disabled') {
        this.event('warn', 'analyzer-unavailable', `${analyzer.id}: ${analyzer.reason ?? 'unavailable'}`)
      }
    }
    const recorded = recordSignalFindings(this.deps.store, this.scan.id, this.analysis.signals, () => this.iso())
    this.event(
      'info',
      'deterministic-done',
      `Analyzed ${snapshot.files.size} files: ${this.analysis.signals.length} rule hits, ${this.analysis.endpoints.length} endpoints, ${recorded.created} new findings.`,
    )
    if (snapshot.truncated) {
      this.notice('warn', 'snapshot-truncated', 'The workspace exceeded the size limits; some files were not analyzed.')
    }
    this.finishPhase('snapshot', 'inventory', 'deterministic', 'surface')
    if (!this.aiEnabled()) {
      this.skipPhases('threat-model', 'hunt', 'review', 'chain')
      this.notice('info', 'ai-disabled', 'AI review was not used for this scan; only the built-in analyzers ran.')
    }
  }

  private async threatModel(): Promise<void> {
    if (this.scan.mode === 'quick' || this.scan.threatModel) {
      if (this.scan.mode === 'quick') this.skipPhases('threat-model')
      else this.finishPhase('threat-model')
      return
    }
    this.phase('threat-model')
    const route = this.route('planner')
    if (!route) {
      this.skipPhases('threat-model')
      return
    }
    const max = MAX_HYPOTHESES[this.scan.mode]
    const task = this.ensure({
      key: 'threat-model',
      kind: 'threat-model',
      role: 'planner',
      title: 'Build threat model',
      priority: 1000,
      input: { targetPaths: [], focus: [] },
    })
    if (task.status === 'done' || task.status === 'skipped' || task.status === 'failed') {
      this.finishPhase('threat-model')
      return
    }
    const { result } = await this.runAgent<ThreatModelOutput>(task, route, {
      system: plannerSystem(this.language()),
      task: plannerTask({
        language: this.language(),
        inventory: this.analysis.inventory,
        fileCount: this.analysis.snapshot.files.size,
        endpoints: this.modelEndpoints(),
        signals: this.analysis.signals.map(signal => this.analysis.privacy.signal(signal)),
        maxHypotheses: max,
      }),
      submit: plannerSubmitTool(max),
      maxTurns: Math.min(this.scan.budget.maxTurnsPerWorker, MAX_SHORT_ROLE_TURNS),
    })
    if (result.status === 'submitted' && result.output) {
      const out = result.output
      const threatModel: ThreatModelRecord = {
        summary: out.summary,
        assets: out.assets,
        actors: out.actors,
        trustBoundaries: out.trust_boundaries,
        priorities: out.priorities,
        hypotheses: out.hypotheses.map(h => ({
          title: h.title,
          category: h.category,
          targetPaths: h.target_paths,
          rationale: h.rationale,
        })),
      }
      this.scan = this.deps.store.updateScan(this.scan.id, { threatModel })
      this.completeTask(task, { hypotheses: threatModel.hypotheses.length })
    } else {
      this.failTask(task, result)
    }
    this.finishPhase('threat-model')
  }

  private async hunt(): Promise<void> {
    this.phase('hunt')
    const route = this.route('hunter')
    if (!route) {
      this.skipPhases('hunt')
      return
    }
    const plan = planHuntTasks({
      mode: this.scan.mode,
      snapshot: this.analysis.snapshot,
      endpoints: this.modelEndpoints(),
      signals: this.analysis.signals,
      hypotheses: this.scan.threatModel?.hypotheses ?? [],
      includeTests: this.scan.settings.scan.includeTests,
      maxTasks: this.scan.budget.maxTasks,
      isWithheld: path => this.analysis.privacy.isWithheld(path),
    })
    for (const planned of plan.tasks) this.ensure(planned)
    if (plan.overflow > 0) {
      this.notice(
        'info',
        'task-limit',
        `${plan.overflow} lower-priority review areas were not scheduled because of the task limit for this mode.`,
      )
    }
    const tasks = this.deps.store.listTasks(this.scan.id).filter(t => HUNT_KINDS.has(t.kind))
    await this.runPool(tasks, task => this.runHunter(task, route))
    this.finishPhase('hunt')
  }

  private async review(): Promise<void> {
    if (this.scan.mode === 'quick') {
      this.skipPhases('review')
      return
    }
    this.phase('review')
    const route = this.route('skeptic')
    if (!route) {
      this.skipPhases('review')
      return
    }
    const findings = this.deps.store.listFindings(this.scan.id)
    const planned = planReviewTasks(
      findings,
      this.scan.mode,
      this.scan.settings.scan.reviewThreshold,
      Math.max(this.scan.budget.maxTasks, 10),
      path => this.analysis.privacy.isWithheld(path),
    )
    for (const task of planned) this.ensure(task)
    const tasks = this.deps.store.listTasks(this.scan.id).filter(t => t.kind === 'review')
    await this.runPool(tasks, task => this.runSkeptic(task, route))
    this.finishPhase('review')
  }

  private async chain(): Promise<void> {
    if (this.scan.mode !== 'research') {
      this.skipPhases('chain')
      return
    }
    this.phase('chain')
    const route = this.route('chain')
    const { privacy } = this.analysis
    const candidates = this.deps.store
      .listFindings(this.scan.id)
      .filter(
        f =>
          f.verification !== 'refuted' &&
          (f.source === 'ai' || f.source === 'sast') &&
          !(f.location && privacy.isWithheld(f.location.path)) &&
          privacy.reviewable(f),
      )
      .slice(0, 40)
    if (!route || candidates.length < 2 || this.budget.exhausted()) {
      this.skipPhases('chain')
      return
    }
    const task = this.ensure({
      key: 'chain',
      kind: 'chain',
      role: 'chain',
      title: 'Look for attack chains',
      priority: 10,
      input: { targetPaths: [], findingIds: candidates.map(f => f.id), focus: [] },
    })
    if (task.status === 'pending' || task.status === 'running') {
      const ids = new Map(candidates.map((f, index) => [`F${index + 1}`, f]))
      const { result, ctx } = await this.runAgent(task, route, {
        system: chainSystem(this.language()),
        task: chainTask([...ids.entries()].map(([id, finding]) => ({ id, finding: privacy.finding(finding) }))),
        submit: chainSubmitTool(this.analysis.quoteSource),
        maxTurns: Math.min(this.scan.budget.maxTurnsPerWorker, MAX_SHORT_ROLE_TURNS),
      })
      if (result.status === 'submitted' && result.output) {
        const outcome = recordChains(this.deps.store, result.output, ids, ctx)
        this.discarded += outcome.discarded
        this.completeTask(task, { created: outcome.created, discarded: outcome.discarded })
      } else {
        this.failTask(task, result)
      }
    }
    this.finishPhase('chain')
  }

  private reconcile(): void {
    const { store } = this.deps
    const previous = store.previousCompletedScan(this.scan.workspaceId, this.scan.createdAt)
    markNewFindings(store, this.scan.id, previous ? store.scanFingerprints(previous.id) : undefined)
    const coverage = this.coverage()
    this.scan = store.updateScan(this.scan.id, { coverage, clearProgress: true })
    this.finishPhase('reconcile')
  }

  private complete(): void {
    const exhausted = this.budget.exhausted()
    if (exhausted && exhausted !== 'cancelled') {
      this.notice(
        'warn',
        `budget-${exhausted}`,
        `The ${exhausted === 'calls' ? 'model-request' : exhausted === 'tokens' ? 'token' : 'time'} budget was used up; some review work was skipped.`,
      )
    }
    this.scan = this.deps.store.updateScan(this.scan.id, {
      status: 'completed',
      phase: 'done',
      finishedAt: this.iso(),
      usage: this.budget.usage(),
    })
    this.event('info', 'run-complete', 'Scan completed')
  }

  private handleStop(error: unknown): void {
    const { store } = this.deps
    // Work that was running goes back to the queue so a resume picks it up again.
    for (const task of store.listTasks(this.scan.id, ['running'])) {
      store.updateTask(task.id, { status: 'pending' })
    }
    const request = this.stopRequest
    if (request === 'cancel') {
      for (const task of store.listTasks(this.scan.id, ['pending'])) {
        store.updateTask(task.id, { status: 'skipped', finishedAt: this.iso() })
      }
      this.scan = store.updateScan(this.scan.id, {
        status: 'cancelled',
        finishedAt: this.iso(),
        usage: this.budget.usage(),
      })
      this.event('info', 'run-cancelled', 'Scan cancelled')
      return
    }
    if (request === 'pause' || request === 'shutdown') {
      this.scan = store.updateScan(this.scan.id, {
        status: request === 'pause' ? 'paused' : 'interrupted',
        usage: this.budget.usage(),
      })
      this.event('info', `run-${request}`, request === 'pause' ? 'Scan paused' : 'Scan interrupted because DSH stopped')
      return
    }
    // The message reaches the browser (scan summary, activity log): never include an absolute Host path.
    const message = this.mask(error instanceof Error ? error.message : String(error))
    this.deps.logger.error('dsh-security: scan failed', error)
    this.scan = store.updateScan(this.scan.id, {
      status: 'failed',
      finishedAt: this.iso(),
      usage: this.budget.usage(),
      error: { code: 'scan-failed', message: firstLine(message) },
    })
    this.event('error', 'run-failed', firstLine(message))
  }

  // -------------------------------------------------------------------------
  // Task runners
  // -------------------------------------------------------------------------

  private async runHunter(task: TaskRecord, route: ModelRef): Promise<void> {
    const { privacy } = this.analysis
    const endpointIds = new Set(task.input.endpointIds ?? [])
    const endpoints = this.analysis.endpoints.filter(e => endpointIds.has(e.id) && privacy.endpointVisible(e))
    const wanted = new Set(task.input.signalFingerprints ?? [])
    const signals: TaskSignal[] = this.analysis.signals
      .filter(s => wanted.has(signalFingerprint(s)))
      .map((signal, index) => ({ id: `S${index + 1}`, signal }))
    // Withheld hits keep their id (path and rule only), but the hunter cannot rule on what it cannot read.
    const signalIds = new Map(
      signals
        .filter(s => isReportableSignal(s.signal) && !privacy.isWithheld(s.signal.location.path))
        .map(s => [s.id, signalFingerprint(s.signal)] as const),
    )
    const targets = new Set(task.input.targetPaths.filter(path => !privacy.isWithheld(path)))
    const assessed = new Set(signalIds.values())
    const known = this.deps.store
      .listFindings(this.scan.id)
      .filter(f => f.location && targets.has(f.location.path) && !assessed.has(f.fingerprint))
      .map(f => `${privacy.scrub(f.title)} (${f.location?.path}:${f.location?.startLine})`)
    const { result, ctx } = await this.runAgent<HunterOutput>(task, route, {
      system: hunterSystem(this.language()),
      task: hunterTask({
        kind: task.kind,
        focus: task.input.focus,
        targetPaths: [...targets],
        endpoints,
        signals: signals.map(({ id, signal }) => ({ id, signal: privacy.signal(signal) })),
        ...(task.input.hypothesis ? { hypothesis: task.input.hypothesis } : {}),
        ...(this.scan.threatModel ? { threatModelSummary: this.scan.threatModel.summary } : {}),
        known,
        frameworks: this.analysis.inventory.frameworks,
      }),
      submit: hunterSubmitTool(this.analysis.quoteSource),
      maxTurns: this.scan.budget.maxTurnsPerWorker,
    })
    if (result.status !== 'submitted' || !result.output) {
      this.failTask(task, result)
      return
    }
    const reviewThreshold = this.scan.settings.scan.reviewThreshold
    const outcome = recordHunterOutput(
      this.deps.store,
      {
        ...ctx,
        signalIds,
        willReview: severity =>
          this.scan.mode !== 'quick' &&
          this.route('skeptic') !== undefined &&
          severityAtLeastFor(this.scan.mode, severity, reviewThreshold),
      },
      result.output,
    )
    this.discarded += outcome.discarded
    if (outcome.discarded > 0) {
      this.event(
        'warn',
        'evidence-discarded',
        `${task.title}: ${outcome.discarded} finding(s) dropped because none of their code quotes matched the source.`,
      )
    }
    this.completeTask(task, {
      created: outcome.created,
      merged: outcome.merged,
      discarded: outcome.discarded,
      assessed: outcome.assessed,
      disputed: outcome.disputed,
    })
  }

  private async runSkeptic(task: TaskRecord, route: ModelRef): Promise<void> {
    const finding = task.input.findingId ? this.deps.store.getFinding(this.scan.id, task.input.findingId) : undefined
    if (finding?.verification !== 'potential') {
      this.deps.store.updateTask(task.id, { status: 'skipped', finishedAt: this.iso() })
      return
    }
    const { privacy } = this.analysis
    if (!privacy.reviewable(finding)) {
      // Planned before the withheld check existed (resumed scan): a reviewer could not see any evidence.
      this.deps.store.updateTask(task.id, {
        status: 'skipped',
        finishedAt: this.iso(),
        error: { code: 'withheld', message: 'The evidence is in files withheld by the privacy settings.' },
      })
      return
    }
    const { result, ctx } = await this.runAgent<SkepticOutput>(task, route, {
      system: skepticSystem(this.language()),
      task: skepticTask(privacy.finding(finding), {
        requestLocalization: this.language() !== 'en' && finding.source !== 'ai',
      }),
      submit: skepticSubmitTool(this.analysis.quoteSource),
      maxTurns: Math.min(this.scan.budget.maxTurnsPerWorker, MAX_SHORT_ROLE_TURNS),
    })
    if (result.status !== 'submitted' || !result.output) {
      this.failTask(task, result)
      return
    }
    const updated = applySkepticOutput(this.deps.store, finding, result.output, ctx)
    this.completeTask(task, { verdict: updated.review?.verdict ?? 'inconclusive' })
  }

  private async runPool(tasks: readonly TaskRecord[], run: (task: TaskRecord) => Promise<void>): Promise<void> {
    const queue = tasks.filter(t => t.status === 'pending' || t.status === 'running')
    const total = tasks.length
    let done = tasks.length - queue.length
    let next = 0
    this.progress(done, total)
    const workers = Math.max(1, Math.min(this.scan.settings.scan.parallelWorkers, this.deps.config.maxParallelWorkers))
    let halted = false
    const loop = async (): Promise<void> => {
      try {
        while (next < queue.length && !halted) {
          this.checkStopped()
          this.checkConsent()
          if (this.budget.exhausted()) return
          const task = queue[next++]
          if (!task) return
          await run(task)
          this.checkStopped()
          done++
          this.progress(done, total)
          this.persistUsage()
        }
      } catch (error) {
        halted = true
        throw error
      }
    }
    // Wait for every worker before propagating a stop or failure, so none keeps writing after the run has ended.
    const results = await Promise.allSettled(Array.from({ length: workers }, loop))
    const failure = results.find(result => result.status === 'rejected')
    if (failure) throw failure.reason
    this.checkStopped()
    // Budget ran out: what is left will not run in this scan.
    for (const task of queue.slice(next)) {
      const current = this.deps.store.getTask(task.id)
      if (current && (current.status === 'pending' || current.status === 'running')) {
        this.deps.store.updateTask(task.id, {
          status: 'skipped',
          finishedAt: this.iso(),
          error: { code: 'budget', message: 'Skipped because the scan budget was used up.' },
        })
      }
    }
  }

  private async runAgent<T>(
    task: TaskRecord,
    route: ModelRef,
    spec: {
      system: string
      task: string
      submit: WorkerTool<unknown, T>
      maxTurns: number
    },
  ): Promise<AgentOutcome<T>> {
    const llm = this.deps.llm()
    if (!llm) throw new Error('The DSH model registry is not available.')
    this.checkConsent(true)
    const { store } = this.deps
    const started = this.iso()
    store.updateTask(task.id, { status: 'running', attempts: task.attempts + 1, startedAt: started })
    const run: AgentRunRecord = {
      id: newId(),
      scanId: this.scan.id,
      taskId: task.id,
      role: task.role,
      title: task.title,
      provider: route.provider,
      model: route.model,
      status: 'running',
      turns: 0,
      toolCalls: 0,
      llmCalls: 0,
      inputTokens: 0,
      outputTokens: 0,
      startedAt: started,
      filesRead: [],
    }
    store.insertAgentRun(run)
    const filesRead = new Set<string>()
    const view: WorkerView = {
      id: run.id,
      role: task.role,
      title: task.title,
      model: `${route.provider}/${route.model}`,
      state: 'running',
      turns: 0,
      toolCalls: 0,
      startedAt: started,
    }
    this.deps.live.set(this.scan.id, view)
    this.event('info', 'worker-start', `${roleLabel(task.role)} started: ${task.title}`, {
      runId: run.id,
      role: task.role,
    })
    let turns = 0
    let toolCalls = 0
    const tools: WorkerTool<unknown, T>[] = [
      ...createWorkspaceTools(
        this.analysis.view(path => filesRead.add(path)),
        {
          includeTests: this.scan.settings.scan.includeTests,
        },
      ),
      spec.submit,
    ]
    const outcome = await runWorker<T>({
      id: run.id,
      role: task.role,
      llm,
      route: {
        provider: route.provider,
        model: route.model,
        ...(route.reasoningEffort ? { reasoningEffort: route.reasoningEffort } : {}),
        ...(route.maxOutputTokens ? { maxOutputTokens: route.maxOutputTokens } : {}),
      },
      system: spec.system,
      // Backstop over the whole message: no known secret value or absolute root, whatever the builder included.
      task: this.analysis.privacy.scrub(spec.task),
      tools,
      maxTurns: spec.maxTurns,
      budget: this.budget,
      signal: this.aiSignal,
      idleTimeoutMs: this.deps.config.llmIdleTimeoutMs,
      onEvent: event => {
        if (event.type === 'request' && event.attempt === 1) turns = event.turn
        if (event.type === 'tool') toolCalls++
        if (event.type === 'retry') {
          this.event('debug', 'worker-retry', `${task.title}: retrying after ${event.code} in ${event.delayMs} ms`)
        }
        this.deps.live.set(this.scan.id, { ...view, turns, toolCalls })
      },
    })
    // Cut off by the scan deadline: the work was not done because the time budget ran out.
    const result: WorkerResult<T> =
      outcome.status === 'cancelled' && this.deadlineReached && !this.signal.aborted && !this.consentRevoked
        ? { ...outcome, status: 'budget_exhausted', stopReason: 'time' }
        : outcome
    this.budget.addToolCalls(result.toolCalls)
    const finished = this.iso()
    store.updateAgentRun(run.id, {
      status: result.status,
      turns: result.turns,
      toolCalls: result.toolCalls,
      llmCalls: result.usage.llmCalls,
      inputTokens: result.usage.inputTokens,
      outputTokens: result.usage.outputTokens,
      finishedAt: finished,
      filesRead: [...filesRead].sort(),
      ...(result.stopReason ? { stopReason: result.stopReason } : {}),
      ...(result.error ? { error: { code: result.error.code, message: result.error.message } } : {}),
    })
    if (this.scan.settings.storage.keepTranscripts) store.saveTranscript(run.id, result.transcript)
    this.deps.live.set(this.scan.id, {
      ...view,
      turns: result.turns,
      toolCalls: result.toolCalls,
      state: result.status === 'submitted' ? 'done' : result.status === 'cancelled' ? 'cancelled' : 'failed',
    })
    this.event(
      result.status === 'submitted' ? 'info' : 'warn',
      'worker-end',
      `${roleLabel(task.role)} ${result.status === 'submitted' ? 'finished' : `stopped (${result.status}${result.stopReason ? `: ${result.stopReason}` : ''})`}: ${task.title}`,
      { runId: run.id, status: result.status, turns: result.turns },
    )
    if (result.status === 'blocked_by_provider' && !this.blockedNotified) {
      this.blockedNotified = true
      this.notice(
        'warn',
        'blocked-by-provider',
        `The model provider refused some review requests (${result.error?.code ?? 'policy'}). They were recorded as not reviewed; no other model was tried.`,
      )
    }
    if (result.status === 'cancelled') {
      this.checkStopped()
      this.checkConsent()
    }
    return {
      result,
      ctx: {
        scanId: this.scan.id,
        taskId: task.id,
        agentRunId: run.id,
        model: `${route.provider}/${route.model}`,
        now: () => this.iso(),
      },
    }
  }

  // -------------------------------------------------------------------------
  // Helpers
  // -------------------------------------------------------------------------

  private ensure(planned: PlannedTask): TaskRecord {
    return this.deps.store.ensureTask({
      id: newId(),
      scanId: this.scan.id,
      key: planned.key,
      kind: planned.kind,
      role: planned.role,
      title: planned.title,
      status: 'pending',
      priority: planned.priority,
      input: planned.input,
      attempts: 0,
      createdAt: this.iso(),
    })
  }

  private completeTask(task: TaskRecord, outcome: Readonly<Record<string, string | number | boolean>>): void {
    this.deps.store.updateTask(task.id, { status: 'done', finishedAt: this.iso(), outcome })
  }

  private failTask(task: TaskRecord, result: WorkerResult<unknown>): void {
    this.checkStopped()
    const budgetStop = result.status === 'budget_exhausted'
    this.deps.store.updateTask(task.id, {
      status: budgetStop ? 'skipped' : 'failed',
      finishedAt: this.iso(),
      error: {
        code: result.error?.code ?? result.status,
        message: result.error?.message ?? (result.stopReason ? `stopped: ${result.stopReason}` : result.status),
      },
    })
  }

  private route(role: RoleName): ModelRef | undefined {
    return this.deps.llm() ? this.scan.models[role] : undefined
  }

  private aiEnabled(): boolean {
    return this.route('hunter') !== undefined
  }

  private language(): 'en' | 'ja' | 'zh' {
    return this.scan.language ?? 'en'
  }

  /** In-scope endpoints a model may be told about (route text from withheld files is withheld too). */
  private modelEndpoints() {
    return this.inScopeEndpoints().filter(e => this.analysis.privacy.endpointVisible(e))
  }

  private inScopeEndpoints() {
    const includeTests = this.scan.settings.scan.includeTests
    return this.analysis.endpoints.filter(
      e => includeTests || this.analysis.snapshot.files.get(endpointPath(e))?.isTest !== true,
    )
  }

  private coverage(): Coverage {
    const { store } = this.deps
    const tasks = store.listTasks(this.scan.id)
    const runs = store.listAgentRuns(this.scan.id)
    const reviewedEndpoints = new Set<string>()
    for (const task of tasks) {
      if (task.status === 'done') for (const id of task.input.endpointIds ?? []) reviewedEndpoints.add(id)
    }
    const readByAi = new Set(runs.flatMap(r => r.filesRead))
    const discarded = tasks.reduce((n, t) => n + numberOf(t.outcome?.discarded), 0)
    const skipped = tasks.filter(t => t.status === 'skipped').length
    const failed = tasks.filter(t => t.status === 'failed').length
    const endpoints = this.inScopeEndpoints()
    const gaps: string[] = []
    if (!this.aiEnabled())
      gaps.push('AI review was not used; logic flaws such as broken authorization are not covered.')
    if (skipped > 0) gaps.push(`${skipped} review task(s) did not run (budget or task limit).`)
    if (failed > 0) gaps.push(`${failed} review task(s) failed; see the activity log.`)
    if (this.consentRevoked) gaps.push('AI review stopped early because sending code to models was turned off.')
    if (this.analysis.snapshot.truncated)
      gaps.push('Some files were not analyzed because the workspace exceeded the size limits.')
    const unreviewed = endpoints.length - endpoints.filter(e => reviewedEndpoints.has(e.id)).length
    if (this.aiEnabled() && unreviewed > 0)
      gaps.push(`${unreviewed} of ${endpoints.length} detected endpoints were not reviewed by AI.`)
    if (endpoints.length === 0) {
      gaps.push(
        'No HTTP endpoints were detected; the attack surface may use a framework this version does not recognize.',
      )
    }
    for (const analyzer of this.maskedAnalyzers()) {
      if (!analyzer.available && analyzer.source !== 'disabled')
        gaps.push(`${analyzer.id} unavailable: ${analyzer.reason ?? 'unknown'}`)
    }
    return {
      files: {
        total: this.analysis.snapshot.files.size,
        analyzed: [...this.analysis.snapshot.files.values()].filter(f => !f.isGenerated).length,
        readByAi: readByAi.size,
        excluded: this.analysis.snapshot.excluded.length,
      },
      endpoints: { total: endpoints.length, reviewed: endpoints.filter(e => reviewedEndpoints.has(e.id)).length },
      tasks: {
        planned: tasks.length,
        completed: tasks.filter(t => t.status === 'done').length,
        failed,
        skipped,
      },
      analyzers: this.maskedAnalyzers(),
      discardedUnverifiable: this.discarded > discarded ? this.discarded : discarded,
      gaps,
    }
  }

  private phase(phase: ScanPhase): void {
    if (this.scan.phase === phase && this.scan.phases.find(p => p.phase === phase)?.state === 'running') return
    const phases = this.scan.phases.map(p => (p.phase === phase ? { ...p, state: 'running' as const } : p))
    this.scan = this.deps.store.updateScan(this.scan.id, { phase, phases, clearProgress: true })
    this.event('info', 'phase', `Phase: ${phase}`, { phase })
  }

  private finishPhase(...names: ScanPhase[]): void {
    const set = new Set(names)
    const phases = this.scan.phases.map(p =>
      set.has(p.phase) && p.state !== 'skipped' ? { ...p, state: 'done' as const } : p,
    )
    this.scan = this.deps.store.updateScan(this.scan.id, { phases })
  }

  private skipPhases(...names: ScanPhase[]): void {
    const set = new Set(names)
    const phases = this.scan.phases.map(p => (set.has(p.phase) ? { ...p, state: 'skipped' as const } : p))
    this.scan = this.deps.store.updateScan(this.scan.id, { phases })
  }

  private progress(done: number, total: number): void {
    this.scan = this.deps.store.updateScan(this.scan.id, { progress: { done, total, unit: 'tasks' } })
  }

  private persistUsage(): void {
    if (!this.budget) return
    try {
      this.scan = this.deps.store.updateScan(this.scan.id, { usage: this.budget.usage() })
    } catch (error) {
      this.deps.logger.warn('dsh-security: could not persist usage', error)
    }
  }

  private checkStopped(): void {
    if (this.signal.aborted) throw new Stopped(this.stopRequest ?? 'cancel')
  }

  private event(
    level: 'debug' | 'info' | 'warn' | 'error',
    type: string,
    message: string,
    data?: Record<string, unknown>,
  ) {
    this.deps.store.appendEvent(this.scan.id, level, type, this.mask(message), data)
  }

  /**
   * Replace absolute Host paths (project root, data, temp and home directories) in text that is
   * recorded for the browser: tool stderr and spawn errors quote them.
   */
  private mask(text: string): string {
    const root = this.analysis?.snapshot.root
    const key = root ?? ''
    if (this.masker?.key !== key) {
      this.masker = {
        key,
        mask: createPathMasker({
          workspaceRoots: [this.scan.workspaceRoot, root],
          dataDir: this.deps.dataDir,
          tmp: tmpdir(),
          home: homedir(),
        }),
      }
    }
    return this.masker.mask(text)
  }

  private maskedAnalyzers(): AnalyzerStatus[] {
    return this.analysis.analyzers.map(a => (a.reason === undefined ? a : { ...a, reason: this.mask(a.reason) }))
  }

  private notice(level: 'info' | 'warn' | 'error', key: string, text: string): void {
    this.event(level, 'notice', text, { key })
  }

  private iso(): string {
    return this.deps.now().toISOString()
  }
}

/** Phase list for a new scan in `mode`. */
export function initialPhases(mode: ScanRecord['mode'], aiEnabled: boolean): ScanRecord['phases'] {
  const skipped = new Set<ScanPhase>()
  if (!aiEnabled) for (const p of ['threat-model', 'hunt', 'review', 'chain'] as const) skipped.add(p)
  if (mode === 'quick') for (const p of ['threat-model', 'review', 'chain'] as const) skipped.add(p)
  if (mode === 'deep') skipped.add('chain')
  return SCAN_PHASES.filter(p => p !== 'done').map(phase => ({
    phase,
    state: skipped.has(phase) ? ('skipped' as const) : ('pending' as const),
  }))
}

function severityAtLeastFor(
  mode: ScanRecord['mode'],
  severity: FindingRecord['severity'],
  threshold: FindingRecord['severity'],
): boolean {
  const order = ['critical', 'high', 'medium', 'low', 'info']
  const effective = mode === 'research' ? 'low' : threshold
  return order.indexOf(severity) <= order.indexOf(effective)
}

function roleLabel(role: RoleName): string {
  return role === 'planner'
    ? 'Planner'
    : role === 'hunter'
      ? 'Hunter'
      : role === 'skeptic'
        ? 'Reviewer'
        : 'Chain researcher'
}

function firstLine(text: string): string {
  return (text.split('\n')[0] ?? '').slice(0, 500)
}

function numberOf(value: string | number | boolean | undefined): number {
  return typeof value === 'number' && Number.isFinite(value) ? value : 0
}
