/**
 * Deterministic task planning: turns the attack surface (endpoints), rule
 * hits, sensitive files, planner hypotheses, and a bounded source sweep into
 * ranked AI review tasks with stable keys, so re-planning after a resume yields the
 * same tasks.
 */

import { createHash } from 'node:crypto'
import {
  type FindingCategory,
  type ScanMode,
  type Severity,
  severityAtLeast,
  severityRank,
} from '../../shared/domain.ts'
import { resolveTargetPath, type TargetIndex } from '../agents/tools/paths.ts'
import { MUTATING_METHODS } from '../analysis/routes/signals.ts'
import type { Endpoint, Signal, Snapshot, SnapshotFile } from '../analysis/types.ts'
import type { FindingRecord, TaskInput, TaskKind } from '../core/model.ts'
import type { RoleName } from '../../shared/domain.ts'
import { signalFingerprint } from './findings.ts'
import { hasVisibleEvidence } from './privacy.ts'

export interface PlannedTask {
  readonly key: string
  readonly kind: TaskKind
  readonly role: RoleName
  readonly title: string
  readonly priority: number
  readonly input: TaskInput
}

export interface Hypothesis {
  readonly title: string
  readonly category: FindingCategory
  readonly targetPaths: readonly string[]
  readonly rationale: string
}

export interface HuntPlanInput {
  readonly mode: ScanMode
  readonly snapshot: Snapshot
  readonly endpoints: readonly Endpoint[]
  readonly signals: readonly Signal[]
  readonly hypotheses: readonly Hypothesis[]
  readonly includeTests: boolean
  readonly maxTasks: number
  /**
   * Hunt tasks the budget is expected to pay for. Low-priority sweeps only
   * fill the plan up to this (and `maxTasks`); other families are planned
   * up to `maxTasks` and ranked, so the budget runs out on the least
   * important ones. Default: `maxTasks`.
   */
  readonly budgetTasks?: number
  /**
   * The planner's priority targets (files or `METHOD /route` entry points),
   * most important first. Tasks covering one rank higher.
   */
  readonly priorities?: readonly string[]
  /**
   * Paths that must never be shown to a model. No task is planned for work
   * whose only material is in such files, and they are left out of target
   * lists (a worker cannot read them anyway).
   */
  readonly isWithheld?: (path: string) => boolean
}

const ENDPOINTS_PER_TASK = 8
const SIGNALS_PER_TASK = 12
const MAX_SENSITIVE_FILE_TASKS = 6
const SWEEP_FILES_PER_TASK = 4
/** Untrusted input reaching an interpreter, the network, the file system or HTML: worth checking in any file. */
const INPUT_FOCUS: readonly FindingCategory[] = ['injection', 'command-execution', 'ssrf', 'path-traversal', 'xss']
const SENSITIVE_NAME =
  /(?:^|[/_.-])(auth|authn|authz|login|logout|session|sessions|permission|permissions|policy|policies|guard|guards|acl|rbac|role|roles|middleware|tenant|tenants|account|accounts|admin|token|tokens|jwt|oauth|password|billing|payment|payments|invite|invites|upload|uploads|config|configuration|settings|cookie|cookies|security|constants|env)(?:[/_.-]|$)/i
const SOURCE_LANGUAGES = new Set([
  'javascript',
  'typescript',
  'python',
  'go',
  'java',
  'kotlin',
  'ruby',
  'php',
  'csharp',
  'rust',
])

/** Hunt tasks for one scan, best first, cut at `maxTasks`. */
export function planHuntTasks(input: HuntPlanInput): { readonly tasks: PlannedTask[]; readonly overflow: number } {
  const withheld = input.isWithheld ?? (() => false)
  const visible = (path: string) => !withheld(path)
  const inScope = (path: string) =>
    visible(path) && (input.includeTests || input.snapshot.files.get(path)?.isTest !== true)
  const steering = input.signals.filter(
    s => (s.kind === 'vulnerability' || s.kind === 'sink') && inScope(s.location.path),
  )
  const endpoints = input.endpoints.filter(e => visible(e.declaredAt.path))
  const candidates: PlannedTask[] =
    input.mode === 'quick'
      ? [
          ...planTriage(steering),
          ...planQuickEndpoints(
            endpoints.filter(e => inScope(endpointPath(e))),
            steering,
          ),
        ]
      : [
          ...planEndpoints(
            endpoints.filter(e => inScope(endpointPath(e))),
            steering,
          ),
          ...planSignals(steering, endpoints),
          ...(input.hypotheses.length > 0
            ? planHypotheses(
                resolveHypotheses(input.hypotheses, targetIndex(input.snapshot, inScope), visible, inScope),
                steering,
              )
            : []),
        ]
  if (input.mode !== 'quick') {
    const targeted = new Set(candidates.flatMap(task => task.input.targetPaths))
    candidates.push(...planSensitiveFiles(input.snapshot, targeted, inScope))
    boostPriorities(candidates, input.priorities ?? [], input.snapshot, endpoints, inScope)
  }
  // Quick stays within its configured task/request budgets: triage first,
  // then only the riskiest endpoint groups that fit. No hypotheses or sweep.
  const ranked = candidates.sort((a, b) => b.priority - a.priority || (a.key < b.key ? -1 : a.key > b.key ? 1 : 0))
  const tasks = ranked.slice(0, input.maxTasks)
  let overflow = Math.max(0, ranked.length - input.maxTasks)
  if (input.mode !== 'quick') {
    const targeted = new Set(candidates.flatMap(task => task.input.targetPaths))
    const room = Math.min(input.maxTasks, Math.max(0, Math.floor(input.budgetTasks ?? input.maxTasks)))
    const sweep = planSweep(input.snapshot, targeted, inScope, Math.max(0, room - tasks.length))
    // Append only: sweep work must never displace an existing task family.
    tasks.push(...sweep.tasks)
    overflow += sweep.overflow
  }
  return { tasks, overflow }
}

/** Findings that deserve an independent review in this mode, most severe first. */
export function planReviewTasks(
  findings: readonly FindingRecord[],
  mode: ScanMode,
  threshold: Severity,
  max: number,
  isWithheld: (path: string) => boolean = () => false,
): PlannedTask[] {
  if (mode === 'quick') return []
  const effective: Severity = mode === 'research' ? 'low' : threshold
  return findings
    .filter(
      f =>
        f.verification === 'potential' &&
        (f.source === 'ai' || f.source === 'sast' || f.source === 'external') &&
        severityAtLeast(f.severity, effective) &&
        // A reviewer who can see none of the evidence cannot judge it; the finding keeps its deterministic verification.
        hasVisibleEvidence(f, isWithheld),
    )
    .sort((a, b) => severityRank(a.severity) - severityRank(b.severity) || (a.title < b.title ? -1 : 1))
    .slice(0, max)
    .map(f => ({
      key: `review:${f.id}`,
      kind: 'review' as const,
      role: 'skeptic' as const,
      title: `Review: ${f.title}`,
      priority: 100 - severityRank(f.severity) * 10,
      input: {
        targetPaths: f.location && !isWithheld(f.location.path) ? [f.location.path] : [],
        findingId: f.id,
        focus: [f.category],
      },
    }))
}

// ---------------------------------------------------------------------------
// Task families
// ---------------------------------------------------------------------------

function planTriage(signals: readonly Signal[]): PlannedTask[] {
  const relevant = signals.filter(s => s.kind === 'vulnerability' && severityAtLeast(s.severity, 'medium'))
  return groupByPath(relevant, s => s.location.path).flatMap(([path, group]) =>
    chunk(sortSignals(group), SIGNALS_PER_TASK).map((part, index) => ({
      key: `triage:${path}#${index}`,
      kind: 'triage-signals' as const,
      role: 'hunter' as const,
      title: `Verify ${part.length} rule hit${part.length === 1 ? '' : 's'} in ${path}`,
      priority: 50 + weight(part),
      input: {
        targetPaths: [path],
        signalFingerprints: part.map(signalFingerprint),
        focus: categoriesOf(part),
      },
    })),
  )
}

function planQuickEndpoints(endpoints: readonly Endpoint[], signals: readonly Signal[]): PlannedTask[] {
  const risky = new Set(
    endpoints.filter(e => e.authHints.length === 0 && MUTATING_METHODS.has(e.method)).map(e => e.id),
  )
  const riskCount = (task: PlannedTask) => task.input.endpointIds?.filter(id => risky.has(id)).length ?? 0
  const tasks = planEndpoints(endpoints, signals, false).sort(
    (a, b) => riskCount(b) - riskCount(a) || b.priority - a.priority || (a.key < b.key ? -1 : a.key > b.key ? 1 : 0),
  )
  // Keep every endpoint below triage (priority >= 50), including in the worker queue.
  return tasks.map((task, index) => ({ ...task, priority: 49 - index / (tasks.length + 1) }))
}

function planEndpoints(endpoints: readonly Endpoint[], signals: readonly Signal[], spillSignals = true): PlannedTask[] {
  return groupByPath(endpoints, endpointPath).flatMap(([path, group]) => {
    const sorted = [...group].sort((a, b) => a.declaredAt.startLine - b.declaredAt.startLine)
    const fileSignals = signals.filter(s => s.location.path === path)
    const attached = new Set(sortSignals(fileSignals).slice(0, SIGNALS_PER_TASK))
    // Rule hits beyond what the first endpoint task carries get signal tasks of their own, so none goes unassessed
    // (Quick triages rule hits separately).
    const spilled = spillSignals
      ? sortSignals(fileSignals.filter(s => s.kind === 'vulnerability' && !attached.has(s)))
      : []
    const spill = chunk(spilled, SIGNALS_PER_TASK).map((part, index) => ({
      key: `signals:${path}#${index}`,
      kind: 'hunt-signals' as const,
      role: 'hunter' as const,
      title: `Trace ${part.length} more risky operation${part.length === 1 ? '' : 's'} in ${path}`,
      priority: 40 + weight(part),
      input: { targetPaths: [path], signalFingerprints: part.map(signalFingerprint), focus: categoriesOf(part) },
    }))
    return [
      ...spill,
      ...chunk(sorted, ENDPOINTS_PER_TASK).map((part, index) => {
        const unguarded = part.filter(e => e.authHints.length === 0).length
        const mutating = part.filter(e => MUTATING_METHODS.has(e.method)).length
        const params = part.reduce((n, e) => n + e.params.length, 0)
        // Groups are keyed by the handler file; also start from the file that declares (mounts) the route.
        const declarationPaths = part.flatMap(e => (e.declaredAt.path !== path ? [e.declaredAt.path] : []))
        return {
          key: `endpoints:${path}#${index}`,
          kind: 'hunt-endpoints' as const,
          role: 'hunter' as const,
          title: `Review ${part.length} endpoint${part.length === 1 ? '' : 's'} in ${path}`,
          priority: 50 + unguarded * 4 + mutating * 3 + Math.min(params, 6) * 2 + weight(fileSignals),
          input: {
            targetPaths: unique([path, ...declarationPaths]),
            endpointIds: part.map(e => e.id),
            ...(index === 0 && fileSignals.length > 0
              ? { signalFingerprints: sortSignals(fileSignals).slice(0, SIGNALS_PER_TASK).map(signalFingerprint) }
              : {}),
            // Rule hits in the route file count too, not only those in the handler file.
            focus: unique<FindingCategory>([
              'authz',
              'authn',
              ...INPUT_FOCUS,
              'business-logic',
              ...categoriesOf(
                signals.filter(s => s.location.path === path || declarationPaths.includes(s.location.path)),
              ),
            ]),
          },
        }
      }),
    ]
  })
}

function planSignals(signals: readonly Signal[], endpoints: readonly Endpoint[]): PlannedTask[] {
  const endpointFiles = new Set(endpoints.map(endpointPath))
  const remaining = signals.filter(s => !endpointFiles.has(s.location.path))
  return groupByPath(remaining, s => s.location.path).flatMap(([path, group]) =>
    chunk(sortSignals(group), SIGNALS_PER_TASK).map((part, index) => ({
      key: `signals:${path}#${index}`,
      kind: 'hunt-signals' as const,
      role: 'hunter' as const,
      title: `Trace ${part.length} risky operation${part.length === 1 ? '' : 's'} in ${path}`,
      priority: 40 + weight(part),
      input: {
        targetPaths: [path],
        signalFingerprints: part.map(signalFingerprint),
        focus: categoriesOf(part),
      },
    })),
  )
}

/** A hypothesis with its targets resolved to in-scope snapshot files, and the paths its task key is built from. */
interface ResolvedHypothesis {
  readonly hypothesis: Hypothesis
  readonly keyPaths: readonly string[]
  readonly targets: readonly string[]
}

/**
 * Map planner targets onto snapshot files (`resolveTargetPath`). A hypothesis
 * whose targets resolve only to withheld or out-of-scope files is dropped
 * (no task targets them); one whose targets cannot be resolved at all is
 * kept without targets, so its hunter starts by searching instead of the
 * task being skipped as stale.
 */
function resolveHypotheses(
  hypotheses: readonly Hypothesis[],
  index: TargetIndex,
  visible: (path: string) => boolean,
  inScope: (path: string) => boolean,
): ResolvedHypothesis[] {
  return hypotheses.flatMap(hypothesis => {
    const resolved = unique(hypothesis.targetPaths.flatMap(target => resolveTargetPath(target, index).paths))
    const targets = resolved.filter(inScope)
    if (resolved.length > 0 && targets.length === 0) return []
    // The key keeps its original basis so tasks of a resumed scan keep their identity.
    return [{ hypothesis, keyPaths: hypothesis.targetPaths.filter(visible), targets }]
  })
}

function planHypotheses(hypotheses: readonly ResolvedHypothesis[], signals: readonly Signal[]): PlannedTask[] {
  return hypotheses.map(({ hypothesis: h, keyPaths, targets }, index) => {
    const targetPaths = unique(targets).slice(0, 6)
    // Rule hits in the hypothesis's files are part of the same question: the hunter gives them verdicts too.
    const overlapping = sortSignals(
      signals.filter(s => s.kind === 'vulnerability' && targetPaths.includes(s.location.path)),
    ).slice(0, SIGNALS_PER_TASK)
    return {
      key: `hypothesis:${shortHash(`${h.title}\u0000${keyPaths.join('\u0000')}`)}`,
      kind: 'hunt-hypothesis' as const,
      role: 'hunter' as const,
      title: h.title,
      // Planner order expresses its own ranking.
      priority: 70 - Math.min(index, 20),
      input: {
        targetPaths,
        ...(overlapping.length > 0 ? { signalFingerprints: overlapping.map(signalFingerprint) } : {}),
        focus: [h.category],
        hypothesis: `${h.title}\n${h.rationale}`,
      },
    }
  })
}

/** Priority added to an endpoint, signal or file task that covers one of the planner's priorities. */
const PLANNER_PRIORITY_BOOST = 6

/**
 * Rank up tasks covering what the planner named as deserving the closest
 * review: a priority resolving to a file the task targets, or naming the
 * route of one of its endpoints (`POST /orders/:id`). Hypothesis tasks
 * already carry the planner's ranking. Mutates `tasks`.
 */
function boostPriorities(
  tasks: PlannedTask[],
  priorities: readonly string[],
  snapshot: Snapshot,
  endpoints: readonly Endpoint[],
  inScope: (path: string) => boolean,
): void {
  if (priorities.length === 0) return
  const index = targetIndex(snapshot, inScope)
  const files = new Set(priorities.flatMap(target => resolveTargetPath(target, index, 50).paths))
  const routes = new Set(
    endpoints
      .filter(e => priorities.some(target => target.includes(`${e.method} ${e.route}`) || target.trim() === e.route))
      .map(e => e.id),
  )
  for (const [i, task] of tasks.entries()) {
    if (task.kind === 'hunt-hypothesis') continue
    const covers =
      task.input.targetPaths.some(path => files.has(path)) || (task.input.endpointIds ?? []).some(id => routes.has(id))
    if (covers) tasks[i] = { ...task, priority: task.priority + PLANNER_PRIORITY_BOOST }
  }
}

/**
 * What planner targets resolve against: every snapshot path, with directories
 * expanding to their in-scope source files (production files, sensitive
 * names and larger files first) and, when given, symbol names to the files
 * defining them.
 */
export function targetIndex(
  snapshot: Snapshot,
  inScope: (path: string) => boolean,
  findSymbol?: (name: string) => readonly string[],
): TargetIndex {
  let candidates: string[] | undefined
  const paths = new Set(snapshot.files.keys())
  return {
    paths,
    get candidates() {
      candidates ??= [...snapshot.files.values()]
        .filter(f => SOURCE_LANGUAGES.has(f.language) && !f.isGenerated && inScope(f.path))
        .sort(preferForReview)
        .map(f => f.path)
      return candidates
    },
    ...(findSymbol ? { findSymbol } : {}),
  }
}

/** Production files first, then sensitive names, then larger files. */
function preferForReview(a: SnapshotFile, b: SnapshotFile): number {
  return (
    Number(a.isTest) - Number(b.isTest) ||
    Number(SENSITIVE_NAME.test(b.path)) - Number(SENSITIVE_NAME.test(a.path)) ||
    b.size - a.size ||
    (a.path < b.path ? -1 : a.path > b.path ? 1 : 0)
  )
}

function planSensitiveFiles(
  snapshot: Snapshot,
  targeted: ReadonlySet<string>,
  inScope: (path: string) => boolean,
): PlannedTask[] {
  const files = [...snapshot.files.values()].filter(
    f =>
      SOURCE_LANGUAGES.has(f.language) &&
      !f.isGenerated &&
      inScope(f.path) &&
      !targeted.has(f.path) &&
      SENSITIVE_NAME.test(f.path),
  )
  return files
    .sort((a, b) => b.size - a.size || (a.path < b.path ? -1 : 1))
    .slice(0, MAX_SENSITIVE_FILE_TASKS)
    .map(f => ({
      key: `file:${f.path}`,
      kind: 'hunt-file' as const,
      role: 'hunter' as const,
      title: `Review security-sensitive logic in ${f.path}`,
      priority: 45,
      input: { targetPaths: [f.path], focus: ['authn', 'authz', 'business-logic', 'crypto', ...INPUT_FOCUS] },
    }))
}

function planSweep(
  snapshot: Snapshot,
  targeted: ReadonlySet<string>,
  inScope: (path: string) => boolean,
  remaining: number,
): { tasks: PlannedTask[]; overflow: number } {
  const files = [...snapshot.files.values()]
    .filter(f => SOURCE_LANGUAGES.has(f.language) && !f.isGenerated && inScope(f.path) && !targeted.has(f.path))
    // Even with includeTests, spare sweep capacity goes to production first.
    .sort(preferForReview)
  const groups = chunk(files, SWEEP_FILES_PER_TASK)
  return {
    tasks: groups.slice(0, remaining).map((part, index) => ({
      key: `sweep:${shortHash(part.map(f => f.path).join('\u0000'))}`,
      kind: 'hunt-file',
      role: 'hunter',
      title: `Sweep ${part.length} otherwise-untargeted source file${part.length === 1 ? '' : 's'}`,
      // Preserve file ranking in the persisted worker queue too; all sweeps stay below other hunt families.
      priority: 10 - index / (groups.length + 1),
      input: {
        targetPaths: part.map(f => f.path),
        focus: ['authn', 'authz', ...INPUT_FOCUS, 'business-logic', 'crypto', 'misconfiguration', 'data-exposure'],
      },
    })),
    overflow: Math.max(0, groups.length - remaining),
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

export function endpointPath(endpoint: Endpoint): string {
  return endpoint.handler?.path ?? endpoint.declaredAt.path
}

function weight(signals: readonly Signal[]): number {
  return signals.reduce((sum, s) => sum + (5 - severityRank(s.severity)) * (s.kind === 'vulnerability' ? 2 : 1), 0)
}

function sortSignals(signals: readonly Signal[]): Signal[] {
  return [...signals].sort(
    (a, b) =>
      severityRank(a.severity) - severityRank(b.severity) ||
      (a.kind === b.kind ? 0 : a.kind === 'vulnerability' ? -1 : 1) ||
      a.location.startLine - b.location.startLine,
  )
}

function categoriesOf(signals: readonly Signal[]): FindingCategory[] {
  return unique(signals.map(s => s.category))
}

function groupByPath<T>(items: readonly T[], pathOf: (item: T) => string): [string, T[]][] {
  const groups = new Map<string, T[]>()
  for (const item of items) {
    const path = pathOf(item)
    const list = groups.get(path)
    if (list) list.push(item)
    else groups.set(path, [item])
  }
  return [...groups.entries()].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
}

function chunk<T>(items: readonly T[], size: number): T[][] {
  const out: T[][] = []
  for (let i = 0; i < items.length; i += size) out.push(items.slice(i, i + size))
  return out
}

function unique<T>(items: readonly T[]): T[] {
  return [...new Set(items)]
}

function shortHash(text: string): string {
  return createHash('sha256').update(text).digest('hex').slice(0, 16)
}
