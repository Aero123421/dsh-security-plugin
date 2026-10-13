/**
 * The Host-side application service: one handler per RPC method, projecting
 * durable records into wire DTOs. Handlers never return absolute paths or
 * raw secrets; finding text and snippets are already redacted at write time.
 */

import { homedir } from 'node:os'
import type {
  AnalyzerStatus,
  Bootstrap,
  EvidenceView,
  FindingDetail,
  FindingFilter,
  FindingSummary,
  ProviderOption,
  ScanDetail,
  ScanEstimate,
  ScanEvent,
  ScanNotice,
  ScanSummary,
  ToolkitEntry,
  WorkspaceSummary,
} from '../shared/contracts.ts'
import { CONTRACT_VERSION } from '../shared/contracts.ts'
import { closureOf, formatCodeRef, isActiveScanStatus, type TriageState } from '../shared/domain.ts'
import type { AstGrepHandle } from './analysis/astgrep.ts'
import { buildInventory } from './analysis/inventory.ts'
import { extractRoutes } from './analysis/routes/index.ts'
import { ToolkitError, type Toolkit } from './analysis/toolkit.ts'
import { type Config, operatorLimits } from './config.ts'
import type { EvidenceRecord, FindingRecord, ScanRecord } from './core/model.ts'
import type { LlmPort, LoggerPort, WorkspaceRegistryPort } from './dsh/ports.ts'
import { renderReport } from './report/index.ts'
import { RpcError } from './rpc/errors.ts'
import type { RpcHandlers } from './rpc/server.ts'
import { snapshotWorkspace } from './scan/analysis.ts'
import type { ScanController } from './scan/controller.ts'
import { endpointPath, planHuntTasks } from './scan/planning.ts'
import { buildFixPrompt } from './fix-prompt.ts'
import type { SettingsService } from './settings.ts'
import type { SecurityStore } from './store/types.ts'

export interface ServiceDeps {
  readonly store: SecurityStore
  readonly settings: SettingsService
  readonly controller: ScanController
  readonly toolkit: Toolkit | undefined
  readonly config: Config
  readonly llm: () => LlmPort | undefined
  readonly workspaces: () => WorkspaceRegistryPort | undefined
  readonly astGrep: () => Promise<AstGrepHandle | undefined>
  readonly logger: LoggerPort
  readonly pluginVersion: string
  readonly now: () => Date
}

const ESTIMATE_TOKENS_PER_TASK = { min: 15_000, max: 90_000 } as const
const MAX_MODELS_PER_PROVIDER = 100
const MODEL_INFO_TIMEOUT_MS = 5_000

export function createHandlers(deps: ServiceDeps): RpcHandlers {
  const { store, settings, controller } = deps

  const requireScan = (scanId: string): ScanRecord => {
    const scan = store.getScan(scanId)
    if (!scan) throw new RpcError('security/not-found', 'Scan not found.', { scanId })
    return scan
  }

  const requireFinding = (scan: ScanRecord, findingId: string): FindingRecord => {
    const finding = store.getFinding(scan.id, findingId)
    if (!finding) throw new RpcError('security/not-found', 'Finding not found.', { findingId })
    return finding
  }

  const summary = (scan: ScanRecord): ScanSummary => {
    const { counts, confirmed } = store.countOpenFindings(scan.id, scan.workspaceId)
    return {
      id: scan.id,
      workspaceId: scan.workspaceId,
      workspaceTitle: scan.workspaceTitle,
      mode: scan.mode,
      status: scan.status,
      phase: scan.phase,
      createdAt: scan.createdAt,
      ...(scan.startedAt ? { startedAt: scan.startedAt } : {}),
      ...(scan.finishedAt ? { finishedAt: scan.finishedAt } : {}),
      counts,
      confirmed,
      ...(scan.error ? { error: scan.error } : {}),
      ...(scan.commit ? { commit: scan.commit } : {}),
    }
  }

  const detail = (scan: ScanRecord): ScanDetail => {
    const live = controller.liveWorkers(scan.id)
    const workers =
      live.length > 0
        ? live
        : store
            .listAgentRuns(scan.id)
            .slice(-30)
            .map(run => ({
              id: run.id,
              role: run.role,
              title: run.title,
              model: `${run.provider}/${run.model}`,
              state:
                run.status === 'running'
                  ? ('running' as const)
                  : run.status === 'submitted'
                    ? ('done' as const)
                    : run.status === 'cancelled'
                      ? ('cancelled' as const)
                      : ('failed' as const),
              turns: run.turns,
              toolCalls: run.toolCalls,
              startedAt: run.startedAt,
            }))
    return {
      summary: summary(scan),
      phases: scan.phases,
      ...(scan.progress ? { progress: scan.progress } : {}),
      usage: scan.usage,
      budget: {
        maxLlmCalls: scan.budget.maxLlmCalls,
        maxTokens: scan.budget.maxTokens,
        maxMinutes: scan.budget.maxMinutes,
      },
      workers: workers.sort((a, b) => (a.startedAt < b.startedAt ? 1 : -1)).slice(0, 30),
      ...(scan.coverage ? { coverage: scan.coverage } : {}),
      notices: notices(store, scan.id),
      models: scan.models,
      ...(scan.threatModel
        ? {
            threatModel: {
              summary: scan.threatModel.summary,
              assets: scan.threatModel.assets,
              actors: scan.threatModel.actors,
              trustBoundaries: scan.threatModel.trustBoundaries,
            },
          }
        : {}),
    }
  }

  const findingSummaries = (scan: ScanRecord): FindingSummary[] => {
    const findings = store.listFindings(scan.id)
    const triage = store.getTriage(
      scan.workspaceId,
      findings.map(f => f.fingerprint),
    )
    return findings.map(f => toSummary(f, triage.get(f.fingerprint)?.state ?? 'open'))
  }

  const findingDetail = (scan: ScanRecord, finding: FindingRecord): FindingDetail => {
    const triage = store.getTriage(scan.workspaceId, [finding.fingerprint]).get(finding.fingerprint)
    const evidence = store.getEvidence(scan.id, finding.supportEvidenceIds).map(toEvidenceView)
    const counter = store.getEvidence(scan.id, finding.counterEvidenceIds).map(toEvidenceView)
    return {
      ...toSummary(finding, triage?.state ?? 'open'),
      impact: finding.impact,
      preconditions: finding.preconditions,
      attackPath: finding.attackPath.map(step => ({
        order: step.order,
        description: step.description,
        ...(step.location ? { location: step.location } : {}),
        ...(step.snippet ? { snippet: step.snippet } : step.quote ? { snippet: step.quote } : {}),
        quoteCheck: step.quoteCheck,
      })),
      recommendation: finding.recommendation,
      evidence,
      counterevidence: counter,
      ...(finding.review
        ? {
            review: {
              verdict: finding.review.verdict,
              reasoning: finding.review.reasoning,
              model: finding.review.model,
            },
          }
        : {}),
      limitations: finding.limitations,
      references: finding.references,
      ...(triage?.note ? { triageNote: triage.note } : {}),
      createdBy: finding.createdBy,
    }
  }

  return {
    async getBootstrap(_payload, call) {
      const current = settings.get()
      const llm = deps.llm()
      const astGrep = await deps.astGrep()
      const analyzers: AnalyzerStatus[] = [
        { id: 'secrets', available: true, source: 'builtin' },
        { id: 'sast', available: true, source: 'builtin' },
        { id: 'routes', available: true, source: 'builtin' },
        { id: 'dependencies', available: true, source: 'builtin' },
        current.settings.privacy.allowDependencyLookup
          ? { id: 'osv', available: true, source: 'builtin' }
          : { id: 'osv', available: false, source: 'disabled', reason: 'dependency lookup is turned off' },
        astGrep
          ? { id: 'ast-grep', available: true, source: 'builtin' }
          : {
              id: 'ast-grep',
              available: false,
              source: 'builtin',
              reason: 'native module unavailable; using the built-in parser',
            },
      ]
      const bootstrap: Bootstrap = {
        pluginVersion: deps.pluginVersion,
        contractVersion: CONTRACT_VERSION,
        settings: current.settings,
        settingsRevision: current.revision,
        loopback: call.loopback,
        canEditHighRiskSettings: settings.canEditHighRisk(call.loopback),
        capabilities: {
          llm: (llm?.listProviders().length ?? 0) > 0,
          workspaces: deps.workspaces() !== undefined,
          analyzers,
        },
        limits: operatorLimits(deps.config),
      }
      return bootstrap
    },

    async listWorkspaces() {
      const registry = deps.workspaces()
      if (!registry) return []
      return registry.list().map((workspace): WorkspaceSummary => {
        const last = store.listScans({ workspaceId: workspace.id, limit: 1 })[0]
        return {
          id: workspace.id,
          title: workspace.title,
          displayPath: displayPath(workspace.path),
          ...(last ? { lastScan: summary(last) } : {}),
        }
      })
    },

    async listModels(_payload, call) {
      const llm = deps.llm()
      if (!llm) return []
      const providers = llm.listProviders()
      return await Promise.all(
        providers.map(async (provider): Promise<ProviderOption> => {
          try {
            const models = (await llm.listModels(provider.id)).slice(0, MAX_MODELS_PER_PROVIDER)
            const detailed = await Promise.all(
              models.map(async model => {
                const info = await withTimeout(
                  llm.resolveModelInfo(provider.id, model.id, call.signal),
                  MODEL_INFO_TIMEOUT_MS,
                ).catch(() => undefined)
                return {
                  id: model.id,
                  name: model.name,
                  ...(model.description ? { description: model.description } : {}),
                  ...(info?.context ? { contextWindow: info.context.contextWindow } : {}),
                  ...(info?.reasoning
                    ? {
                        reasoningEfforts: info.reasoning.efforts.map(e => ({ id: e.id, name: e.name })),
                        ...(info.reasoning.defaultEffort ? { defaultEffort: info.reasoning.defaultEffort } : {}),
                      }
                    : {}),
                }
              }),
            )
            return { id: provider.id, name: provider.name, models: detailed }
          } catch (error) {
            deps.logger.warn(`dsh-security: listing models of ${provider.id} failed`, error)
            return {
              id: provider.id,
              name: provider.name,
              models: [],
              error: 'Could not list models for this provider.',
            }
          }
        }),
      )
    },

    async updateSettings(payload, call) {
      return settings.update(payload.patch, payload.expectedRevision, call.loopback)
    },

    async estimateScan(payload, call) {
      const registry = deps.workspaces()
      const workspace = registry?.get(payload.workspaceId)
      if (!workspace) throw new RpcError('security/not-found', 'That project is no longer registered in DSH.', {})
      const { settings: current } = settings.get()
      const snapshot = await snapshotWorkspace(workspace.path, current, deps.config, call.signal).catch(error => {
        deps.logger.warn('dsh-security: estimate failed', error)
        throw new RpcError('security/workspace-unavailable', 'The project folder cannot be read.', {})
      })
      const inventory = buildInventory(snapshot)
      const astGrep = await deps.astGrep()
      const { endpoints } = await extractRoutes(snapshot, { ...(astGrep ? { astGrep } : {}), signal: call.signal })
      const includeTests = current.scan.includeTests
      const inScope = endpoints.filter(e => includeTests || snapshot.files.get(endpointPath(e))?.isTest !== true)
      const budget = current.budgets[payload.mode]
      const plan = planHuntTasks({
        mode: payload.mode,
        snapshot,
        endpoints: inScope,
        signals: [],
        hypotheses: [],
        includeTests,
        maxTasks: budget.maxTasks,
      })
      // Planner, reviews, and signal-driven tasks are not known before the scan; estimate generously.
      const extra = payload.mode === 'quick' ? 2 : payload.mode === 'deep' ? 8 : 20
      const tasks = Math.min(budget.maxTasks, plan.tasks.length + extra)
      const estimate: ScanEstimate = {
        files: snapshot.files.size,
        bytes: snapshot.totalBytes,
        excluded: snapshot.excluded.length,
        languages: inventory.languages.slice(0, 10).map(l => ({ language: l.language, files: l.files })),
        frameworks: inventory.frameworks,
        endpoints: inScope.length,
        plannedTasks: tasks,
        tokens: {
          min: Math.min(budget.maxTokens, tasks * ESTIMATE_TOKENS_PER_TASK.min),
          max: Math.min(budget.maxTokens, tasks * ESTIMATE_TOKENS_PER_TASK.max * (payload.mode === 'quick' ? 1 : 1.6)),
        },
        truncated: snapshot.truncated,
      }
      return estimate
    },

    async createScan(payload) {
      const scan = await controller.create(payload)
      return { scanId: scan.id }
    },

    async listScans(payload) {
      return store
        .listScans({
          ...(payload.workspaceId ? { workspaceId: payload.workspaceId } : {}),
          limit: Math.min(payload.limit ?? 50, 500),
        })
        .map(summary)
    },

    async getScan(payload) {
      return detail(requireScan(payload.scanId))
    },

    async pauseScan(payload) {
      return summary(controller.pause(requireScan(payload.scanId).id))
    },

    async resumeScan(payload) {
      return summary(controller.resume(requireScan(payload.scanId).id))
    },

    async cancelScan(payload) {
      return summary(controller.cancel(requireScan(payload.scanId).id))
    },

    async deleteScan(payload) {
      requireScan(payload.scanId)
      return { deleted: await controller.remove(payload.scanId) }
    },

    async listFindings(payload) {
      const scan = requireScan(payload.scanId)
      return applyFilter(findingSummaries(scan), payload.filter)
    },

    async getFinding(payload) {
      const scan = requireScan(payload.scanId)
      return findingDetail(scan, requireFinding(scan, payload.findingId))
    },

    async setTriage(payload) {
      const scan = requireScan(payload.scanId)
      const finding = requireFinding(scan, payload.findingId)
      const record = store.setTriage(scan.workspaceId, finding.fingerprint, payload.triage, payload.note)
      return toSummary(finding, record.state)
    },

    async getFixPrompt(payload) {
      const scan = requireScan(payload.scanId)
      const finding = requireFinding(scan, payload.findingId)
      return { prompt: buildFixPrompt(findingDetail(scan, finding), scan.language ?? 'en') }
    },

    async exportReport(payload) {
      const scan = requireScan(payload.scanId)
      if (isActiveScanStatus(scan.status) && scan.status !== 'paused' && scan.status !== 'interrupted') {
        throw new RpcError('security/invalid-state', 'Wait until the scan has finished before exporting.', {})
      }
      const findings = store.listFindings(scan.id).map(f => findingDetail(scan, f))
      return renderReport(
        {
          scan: detail(scan),
          findings,
          workspaceTitle: scan.workspaceTitle,
          generatedAt: deps.now().toISOString(),
          pluginVersion: deps.pluginVersion,
          language: scan.language === 'ja' ? 'ja' : 'en',
        },
        payload.format,
      )
    },

    async listEvents(payload) {
      requireScan(payload.scanId)
      return store
        .listEvents(payload.scanId, payload.afterSeq ?? 0, Math.min(payload.limit ?? 200, 1000))
        .filter(event => event.level !== 'debug')
        .map(
          (event): ScanEvent => ({
            seq: event.seq,
            at: event.at,
            level: event.level,
            type: event.type,
            message: event.message,
          }),
        )
    },

    async listToolkit() {
      return deps.toolkit ? await deps.toolkit.status() : []
    },

    async installTool(payload, call) {
      if (!deps.toolkit) throw new RpcError('security/toolkit-unavailable', 'The toolkit is not available.', {})
      if (!deps.config.allowManagedToolkit) {
        throw new RpcError('security/toolkit-unavailable', 'Managed downloads are disabled by the operator.', {})
      }
      if (!call.loopback && !settings.canEditHighRisk(false)) {
        throw new RpcError(
          'security/forbidden-remote',
          'Analyzers can only be installed from the machine running DSH.',
          {},
        )
      }
      try {
        return await deps.toolkit.install(payload.toolId, { signal: call.signal })
      } catch (error) {
        if (error instanceof ToolkitError) {
          throw new RpcError('security/toolkit-unavailable', error.message, { reason: error.code })
        }
        throw error
      }
    },
  }
}

// ---------------------------------------------------------------------------
// Projections
// ---------------------------------------------------------------------------

function toSummary(finding: FindingRecord, triage: TriageState): FindingSummary {
  return {
    id: finding.id,
    scanId: finding.scanId,
    fingerprint: finding.fingerprint,
    title: finding.title,
    category: finding.category,
    severity: finding.severity,
    verification: finding.verification,
    closure: closureOf(finding.verification),
    source: finding.source,
    ...(finding.cwe ? { cwe: finding.cwe } : {}),
    ...(finding.ruleId ? { ruleId: finding.ruleId } : {}),
    ...(finding.location ? { location: finding.location } : {}),
    summary: finding.summary,
    triage,
    isNew: finding.isNew,
  }
}

function toEvidenceView(evidence: EvidenceRecord): EvidenceView {
  return {
    id: evidence.id,
    kind: evidence.kind,
    trust: evidence.trust,
    claim: evidence.claim,
    ...(evidence.location ? { location: evidence.location } : {}),
    ...(evidence.snippet ? { snippet: evidence.snippet } : evidence.quote ? { snippet: evidence.quote } : {}),
    quoteCheck: evidence.quoteCheck,
    originRole: evidence.origin,
  }
}

function applyFilter(findings: FindingSummary[], filter: FindingFilter | undefined): FindingSummary[] {
  if (!filter) return findings
  const text = filter.text?.trim().toLowerCase()
  return findings.filter(
    f =>
      (!filter.severities?.length || filter.severities.includes(f.severity)) &&
      (!filter.closures?.length || filter.closures.includes(f.closure)) &&
      (!filter.sources?.length || filter.sources.includes(f.source)) &&
      (!filter.triage?.length || filter.triage.includes(f.triage)) &&
      (!text ||
        f.title.toLowerCase().includes(text) ||
        f.summary.toLowerCase().includes(text) ||
        (f.location ? formatCodeRef(f.location).toLowerCase().includes(text) : false) ||
        (f.cwe?.toLowerCase().includes(text) ?? false)),
  )
}

function notices(store: SecurityStore, scanId: string): ScanNotice[] {
  const out: ScanNotice[] = []
  let after = 0
  // Notices are rare; page through the log once to collect them.
  for (let page = 0; page < 20; page++) {
    const events = store.listEvents(scanId, after, 1000)
    if (events.length === 0) break
    for (const event of events) {
      if (event.type !== 'notice' || event.level === 'debug') continue
      const key = typeof event.data?.key === 'string' ? event.data.key : 'notice'
      out.push({ level: event.level, key, text: event.message, at: event.at })
    }
    after = events[events.length - 1]?.seq ?? after
    if (events.length < 1000) break
  }
  // The same notice can repeat across resumes; keep the latest of each key.
  const latest = new Map<string, ScanNotice>()
  for (const notice of out) latest.set(notice.key, notice)
  return [...latest.values()]
}

function displayPath(path: string): string {
  const home = homedir()
  if (home && (path === home || path.startsWith(`${home}/`) || path.startsWith(`${home}\\`))) {
    return `~${path.slice(home.length)}`
  }
  return path
}

async function withTimeout<T>(promise: Promise<T>, ms: number): Promise<T> {
  let timer: NodeJS.Timeout | undefined
  try {
    return await Promise.race([
      promise,
      new Promise<T>((_, reject) => {
        timer = setTimeout(() => reject(new Error('timeout')), ms)
      }),
    ])
  } finally {
    if (timer) clearTimeout(timer)
  }
}

export type { ToolkitEntry }
