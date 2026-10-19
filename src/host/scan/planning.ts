/**
 * Hunt task planning: turns the review plan (coverage units from
 * reconnaissance) into hunter tasks, then fills what the plan left out from
 * the deterministic analysis, in any language: every rule hit still gets a
 * verdict, endpoints in no unit get endpoint tasks, and in-scope source files
 * in no unit get low-priority sweeps as far as the task and budget room
 * allows. Keys are stable, so re-planning after a resume yields the same
 * tasks.
 */

import { createHash } from 'node:crypto'
import {
  type FindingCategory,
  type RoleName,
  type ScanMode,
  type Severity,
  severityAtLeast,
  severityRank,
} from '../../shared/domain.ts'
import type { TargetIndex } from '../agents/tools/paths.ts'
import { MUTATING_METHODS } from '../analysis/routes/signals.ts'
import { identifierWords } from '../analysis/sast/helpers.ts'
import { SAST_RULES } from '../analysis/sast/index.ts'
import type { Endpoint, Signal, Snapshot, SnapshotFile } from '../analysis/types.ts'
import type { FindingRecord, PlanUnitRecord, TaskInput, TaskKind } from '../core/model.ts'
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

export interface HuntPlanInput {
  readonly mode: ScanMode
  readonly snapshot: Snapshot
  readonly endpoints: readonly Endpoint[]
  readonly signals: readonly Signal[]
  /** Validated coverage units of the review plan, most important first (none without reconnaissance). */
  readonly units: readonly PlanUnitRecord[]
  /** Files and directories reconnaissance left out of the sweep (vendored, generated, docs, fixtures). */
  readonly excluded?: readonly string[]
  /** Files other tasks already target (critic units of a resumed scan); the sweep leaves them out. */
  readonly targeted?: ReadonlySet<string>
  readonly includeTests: boolean
  /** Hunt tasks this plan may hold (task slots kept for later critic waves already subtracted). */
  readonly maxTasks: number
  /**
   * Hunt tasks the budget is expected to pay for. Low-priority sweeps only
   * fill the plan up to this (and `maxTasks`); other families are planned
   * up to `maxTasks` and ranked, so the budget runs out on the least
   * important ones. Default: `maxTasks`.
   */
  readonly budgetTasks?: number
  /**
   * Paths that must never be shown to a model. No task is planned for work
   * whose only material is in such files, and they are left out of target
   * lists (a worker cannot read them anyway).
   */
  readonly isWithheld?: (path: string) => boolean
}

export interface HuntPlan {
  /** Tasks to run, best first. */
  readonly tasks: PlannedTask[]
  /** Tasks beyond `maxTasks`: recorded as not run (`task-limit`) so the coverage ledger shows them. */
  readonly cut: PlannedTask[]
  /** Planned work that does not run: cut tasks plus sweep groups beyond the room. */
  readonly overflow: number
  /** In-scope source files no task targets after the sweep, best first. */
  readonly unassigned: readonly string[]
  /** What limited the sweep: the task slots or the hunt budget. */
  readonly unassignedReason: 'task-limit' | 'budget'
}

const ENDPOINTS_PER_TASK = 8
const SIGNALS_PER_TASK = 12
/** Endpoints a unit task attaches from its files; the rest get endpoint tasks of their own. */
const ENDPOINTS_PER_UNIT = 20
/** Sinks (steering, not verdicts) shown in a unit task. */
const SINKS_PER_UNIT = 6
const SWEEP_FILES_PER_TASK = 4
/** Untrusted input reaching an interpreter, the network, the file system or HTML: worth checking in any file. */
const INPUT_FOCUS: readonly FindingCategory[] = ['injection', 'command-execution', 'ssrf', 'path-traversal', 'xss']
/** What a sweep looks for. */
export const SWEEP_FOCUS: readonly FindingCategory[] = [
  'authn',
  'authz',
  ...INPUT_FOCUS,
  'business-logic',
  'crypto',
  'misconfiguration',
  'data-exposure',
]
/** Words for code that enforces security: authentication, authorization, secrets, crypto, uploads. */
const MECHANISM_WORDS: ReadonlySet<string> = new Set([
  'auth',
  'authn',
  'authz',
  'authenticate',
  'authentication',
  'authorize',
  'authorization',
  'login',
  'logout',
  'signin',
  'signup',
  'session',
  'sessions',
  'token',
  'tokens',
  'jwt',
  'oauth',
  'oidc',
  'saml',
  'sso',
  'password',
  'passwords',
  'permission',
  'permissions',
  'policy',
  'policies',
  'guard',
  'guards',
  'acl',
  'rbac',
  'role',
  'roles',
  'scope',
  'scopes',
  'impersonate',
  'impersonation',
  'crypto',
  'cipher',
  'encrypt',
  'encryption',
  'secret',
  'secrets',
  'security',
  'csrf',
  'xsrf',
  'signature',
  'signing',
  'otp',
  'mfa',
  'totp',
  'upload',
  'uploads',
])
/** Configuration words: the file (or its directory) holds settings and secrets. */
const CONFIG_WORDS: ReadonlySet<string> = new Set([
  'config',
  'configuration',
  'settings',
  'env',
  'constants',
  'cookie',
  'cookies',
  'cors',
])
/** Domain words: sensitive data, but in a data-layer file usually plain CRUD. */
const DOMAIN_WORDS: ReadonlySet<string> = new Set([
  'tenant',
  'tenants',
  'account',
  'accounts',
  'admin',
  'billing',
  'payment',
  'payments',
  'invite',
  'invites',
  'middleware',
])
/** Directories of data-layer and routing files. */
const LAYER_DIR =
  /(?:^|\/)(?:repositories|repository|repos|services|service|controllers|controller|models|model|entities|entity|dtos?|schemas|routes|handlers)\//
/** Languages whose files count as source code for units, sweeps and the unassigned-file count. */
export const SOURCE_LANGUAGES: ReadonlySet<string> = new Set([
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

/** Base priority of a unit task by the planner's priority (Deep/Research; Quick ranks units below triage). */
const UNIT_PRIORITY = { critical: 90, high: 80, medium: 70, low: 55 } as const

/**
 * Hunt tasks for one scan, best first, cut at `maxTasks`. Quick puts rule-hit
 * triage first, then the plan's units, then endpoints no unit covers; Deep
 * and Research rank units by the planner's priority, and endpoint and
 * rule-hit tasks for what the units leave out by risk. Sweeps of unassigned
 * source files are appended in every mode, only within the room left by
 * `maxTasks` and `budgetTasks`.
 */
export function planHuntTasks(input: HuntPlanInput): HuntPlan {
  const withheld = input.isWithheld ?? (() => false)
  const visible = (path: string) => !withheld(path)
  const inScope = (path: string) =>
    visible(path) && (input.includeTests || input.snapshot.files.get(path)?.isTest !== true)
  const steering = input.signals.filter(
    s => (s.kind === 'vulnerability' || s.kind === 'sink') && inScope(s.location.path),
  )
  const endpoints = input.endpoints.filter(e => visible(e.declaredAt.path) && inScope(endpointPath(e)))
  const claimed = new Set<Signal>()
  const quick = input.mode === 'quick'
  const candidates: PlannedTask[] = []
  if (quick) {
    // Quick verifies the riskiest rule hits first, whatever the plan says.
    const triage = steering.filter(triageWorthy)
    for (const signal of triage) claimed.add(signal)
    candidates.push(...planTriage(triage))
  }
  const units = unitTasks(input.units, input.mode, steering, endpoints, claimed)
  candidates.push(...units.tasks)
  const remaining = endpoints.filter(e => !units.endpoints.has(e.id))
  const endpointTasks = planEndpoints(remaining, steering, claimed)
  candidates.push(...(quick ? belowUnits(endpointTasks, remaining) : endpointTasks))
  if (!quick) {
    // Every reportable hit no unit or endpoint task took gets a verdict; sinks steer where no task looks yet.
    const covered = new Set(candidates.flatMap(task => task.input.targetPaths))
    candidates.push(
      ...planSignals(
        steering.filter(s => (s.kind === 'vulnerability' ? !claimed.has(s) : !covered.has(s.location.path))),
      ),
    )
  }
  const ranked = candidates.sort((a, b) => b.priority - a.priority || (a.key < b.key ? -1 : a.key > b.key ? 1 : 0))
  const slots = Math.max(0, Math.floor(input.maxTasks))
  const tasks = ranked.slice(0, slots)
  const cut = ranked.slice(slots)
  const targeted = new Set([...(input.targeted ?? []), ...ranked.flatMap(task => task.input.targetPaths)])
  const budgetRoom = Math.max(0, Math.floor(input.budgetTasks ?? slots))
  const room = Math.min(slots, budgetRoom)
  const excluded = input.excluded ?? []
  const files = sweepCandidates(input.snapshot, path => inScope(path) && !isExcludedPath(path, excluded), targeted)
  const sweep = planSweep(files, Math.max(0, room - tasks.length))
  // Append only: sweep work must never displace an existing task family.
  tasks.push(...sweep.tasks)
  return {
    tasks,
    cut,
    overflow: cut.length + sweep.overflow,
    unassigned: sweep.unassigned,
    unassignedReason: budgetRoom < slots ? 'budget' : 'task-limit',
  }
}

/**
 * One `hunt-unit` task per unit, ranked by the unit's priority, then its
 * place in the plan. Each unit takes the reportable rule hits in its files
 * that no earlier task claimed (up to 12, so the hunter gives them
 * verdicts), up to 6 sinks there as steering, and the endpoints whose handler
 * or route file it targets (up to 20). Mutates `claimed`.
 */
export function unitTasks(
  units: readonly PlanUnitRecord[],
  mode: ScanMode,
  signals: readonly Signal[],
  endpoints: readonly Endpoint[],
  claimed: Set<Signal>,
): { readonly tasks: PlannedTask[]; readonly endpoints: ReadonlySet<string> } {
  const taken = new Set<string>()
  const order = units
    .map((unit, index) => ({ unit, index }))
    .sort((a, b) => severityRank(a.unit.priority) - severityRank(b.unit.priority) || a.index - b.index)
  const tasks = order.map(({ unit }, rank): PlannedTask => {
    const files = new Set(unit.targetPaths)
    const reportable = sortSignals(
      signals.filter(s => s.kind === 'vulnerability' && files.has(s.location.path) && !claimed.has(s)),
    ).slice(0, SIGNALS_PER_TASK)
    for (const signal of reportable) claimed.add(signal)
    const sinks = sortSignals(
      signals.filter(s => s.kind === 'sink' && files.has(s.location.path) && !claimed.has(s)),
    ).slice(0, SINKS_PER_UNIT)
    const own = endpoints
      .filter(e => !taken.has(e.id) && (files.has(endpointPath(e)) || files.has(e.declaredAt.path)))
      .slice(0, ENDPOINTS_PER_UNIT)
    for (const endpoint of own) taken.add(endpoint.id)
    const attached = [...reportable, ...sinks]
    const base = mode === 'quick' ? 48 : UNIT_PRIORITY[unit.priority]
    return {
      key: unit.id,
      kind: 'hunt-unit',
      role: 'hunter',
      title: unit.title,
      priority: base - rank / (order.length + 1),
      input: {
        targetPaths: unit.targetPaths,
        focus: unique<FindingCategory>([...unit.focus, ...categoriesOf(reportable)]),
        unitId: unit.id,
        origin: unit.origin,
        ...(unit.component ? { component: unit.component } : {}),
        ...(unit.surface ? { surface: unit.surface } : {}),
        rationale: unit.rationale,
        ...(unit.hypothesis ? { hypothesis: unit.hypothesis } : {}),
        ...(own.length > 0 ? { endpointIds: own.map(e => e.id) } : {}),
        ...(attached.length > 0 ? { signalFingerprints: attached.map(signalFingerprint) } : {}),
      },
    }
  })
  return { tasks, endpoints: taken }
}

/** Whether `path` is one of `excluded` or lies below one of them. */
export function isExcludedPath(path: string, excluded: readonly string[]): boolean {
  return excluded.some(entry => path === entry || path.startsWith(`${entry}/`))
}

/** In-scope, hand-written source files nobody targets yet, best first. */
export function sweepCandidates(
  snapshot: Snapshot,
  inScope: (path: string) => boolean,
  targeted: ReadonlySet<string>,
): SnapshotFile[] {
  return (
    [...snapshot.files.values()]
      .filter(f => SOURCE_LANGUAGES.has(f.language) && !f.isGenerated && inScope(f.path) && !targeted.has(f.path))
      // Even with includeTests, spare sweep capacity goes to production first.
      .sort(preferForReview)
  )
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
// Task families for what the plan leaves out
// ---------------------------------------------------------------------------

/** Base severity of each built-in rule, to tell the sinks of high/critical rules apart. */
const RULE_SEVERITY: ReadonlyMap<string, Severity> = new Map(SAST_RULES.map(rule => [rule.id, rule.severity]))

/**
 * Rule hits Quick mode verifies: medium-or-worse vulnerabilities, and medium-or-worse sinks of high/critical
 * rules (dynamic SQL, shell commands, code evaluation, unsafe deserialization), which in layered code are
 * often the only trace of an injection two calls away from the request.
 */
function triageWorthy(signal: Signal): boolean {
  if (signal.kind === 'vulnerability') return severityAtLeast(signal.severity, 'medium')
  if (signal.kind !== 'sink' || !severityAtLeast(signal.severity, 'medium')) return false
  const base = RULE_SEVERITY.get(signal.ruleId)
  return base !== undefined && severityAtLeast(base, 'high')
}

function planTriage(signals: readonly Signal[]): PlannedTask[] {
  return groupByPath(signals, s => s.location.path).flatMap(([path, group]) =>
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
        origin: 'gap' as const,
      },
    })),
  )
}

/** Quick: endpoint tasks below the plan's units, unguarded mutating endpoints first. */
function belowUnits(tasks: readonly PlannedTask[], endpoints: readonly Endpoint[]): PlannedTask[] {
  const risky = new Set(
    endpoints.filter(e => e.authHints.length === 0 && MUTATING_METHODS.has(e.method)).map(e => e.id),
  )
  const riskCount = (task: PlannedTask) => task.input.endpointIds?.filter(id => risky.has(id)).length ?? 0
  const sorted = [...tasks].sort(
    (a, b) => riskCount(b) - riskCount(a) || b.priority - a.priority || (a.key < b.key ? -1 : a.key > b.key ? 1 : 0),
  )
  // Below triage (>= 50) and units (47-48), also in the worker queue.
  return sorted.map((task, index) => ({ ...task, priority: 46 - index / (sorted.length + 1) }))
}

/**
 * Endpoints grouped by handler file, 8 per task. The first task of a file
 * takes that file's rule hits no other task claimed (up to 12; mutates
 * `claimed` for the reportable ones).
 */
function planEndpoints(
  endpoints: readonly Endpoint[],
  signals: readonly Signal[],
  claimed: Set<Signal>,
): PlannedTask[] {
  return groupByPath(endpoints, endpointPath).flatMap(([path, group]) => {
    const sorted = [...group].sort((a, b) => a.declaredAt.startLine - b.declaredAt.startLine)
    const fileSignals = signals.filter(s => s.location.path === path)
    const attached = sortSignals(fileSignals.filter(s => !claimed.has(s))).slice(0, SIGNALS_PER_TASK)
    for (const signal of attached) if (signal.kind === 'vulnerability') claimed.add(signal)
    return chunk(sorted, ENDPOINTS_PER_TASK).map((part, index) => {
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
          ...(index === 0 && attached.length > 0 ? { signalFingerprints: attached.map(signalFingerprint) } : {}),
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
          origin: 'gap' as const,
          surface: surfaceOf(part),
        },
      }
    })
  })
}

/** `GET /a, POST /b (+3 more)` for a group of endpoints. */
function surfaceOf(endpoints: readonly Endpoint[]): string {
  const shown = endpoints.slice(0, 3).map(e => `${e.method} ${e.route}`)
  const more = endpoints.length - shown.length
  const text = `${shown.join(', ')}${more > 0 ? ` (+${more} more)` : ''}`
  return text.length <= 200 ? text : `${text.slice(0, 199)}…`
}

function planSignals(signals: readonly Signal[]): PlannedTask[] {
  return groupByPath(signals, s => s.location.path).flatMap(([path, group]) =>
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
        origin: 'gap' as const,
      },
    })),
  )
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

/** Production files first, then names that say what the code enforces (most telling first), then larger files. */
export function preferForReview(a: SnapshotFile, b: SnapshotFile): number {
  return (
    Number(a.isTest) - Number(b.isTest) ||
    sensitivity(b.path) - sensitivity(a.path) ||
    b.size - a.size ||
    (a.path < b.path ? -1 : a.path > b.path ? 1 : 0)
  )
}

function planSweep(
  files: readonly SnapshotFile[],
  remaining: number,
): { tasks: PlannedTask[]; overflow: number; unassigned: string[] } {
  const groups = chunk(files, SWEEP_FILES_PER_TASK)
  return {
    tasks: groups.slice(0, remaining).map((part, index) => ({
      key: `sweep:${shortHash(part.map(f => f.path).join('\u0000'))}`,
      kind: 'hunt-file',
      role: 'hunter',
      title: `Sweep ${part.length} otherwise-untargeted source file${part.length === 1 ? '' : 's'}`,
      // Preserve file ranking in the persisted worker queue too; all sweeps stay below other hunt families.
      priority: 10 - index / (groups.length + 1),
      input: { targetPaths: part.map(f => f.path), focus: SWEEP_FOCUS, origin: 'gap' },
    })),
    overflow: Math.max(0, groups.length - remaining),
    unassigned: groups.slice(remaining).flatMap(part => part.map(f => f.path)),
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * How strongly a path's words point to security logic, 0 (none) to 3. File-name words count most
 * (`requireAuth.ts`, `tenantScope.ts`, `crypto.ts`: 3; `upload.ts`, `settings.py`: 2-3); a data-layer file named
 * after a domain entity (`repositories/payment.repository.ts`) and directory-only matches
 * (`middleware/rateLimit.ts`) count 1, except configuration directories (`config/index.ts`: 2).
 */
function sensitivity(path: string): number {
  const segments = path.split('/')
  const base = (segments.pop() ?? '').replace(/\.[^.]+$/, '')
  const tier = (word: string): number =>
    MECHANISM_WORDS.has(word) ? 3 : CONFIG_WORDS.has(word) || DOMAIN_WORDS.has(word) ? 2 : 0
  const words = identifierWords(base)
  let score = Math.max(0, ...words.map(tier))
  if (score === 2 && LAYER_DIR.test(path) && !words.some(w => CONFIG_WORDS.has(w))) score = 1
  for (const word of segments.flatMap(segment => identifierWords(segment))) {
    score = Math.max(score, CONFIG_WORDS.has(word) ? 2 : tier(word) > 0 ? 1 : 0)
  }
  return score
}

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

export function shortHash(text: string): string {
  return createHash('sha256').update(text).digest('hex').slice(0, 16)
}
