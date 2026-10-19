/**
 * Coverage units: the review plan that reconnaissance and the coverage critic
 * propose, validated against the snapshot, and the coverage ledger that
 * reports what became of every unit (and of the Host's gap-filling tasks).
 */

import type { CoverageUnit, Diagnostic } from '../../shared/contracts.ts'
import type { FindingCategory, ScanMode } from '../../shared/domain.ts'
import type { TargetResolution } from '../agents/tools/paths.ts'
import type { Endpoint, SnapshotFile } from '../analysis/types.ts'
import { cleanModelPath } from '../evidence/normalize.ts'
import type {
  EvidenceRecord,
  ExcludedReason,
  FindingRecord,
  PlanUnitRecord,
  TaskKind,
  TaskRecord,
  UnitPriority,
} from '../core/model.ts'
import { shortHash } from './planning.ts'

/** Task kinds a hunter works on; each becomes one ledger unit. Older kinds stay for stored scans. */
export const HUNT_TASK_KINDS: ReadonlySet<TaskKind> = new Set<TaskKind>([
  'triage-signals',
  'hunt-unit',
  'hunt-endpoints',
  'hunt-signals',
  'hunt-file',
  'hunt-hypothesis',
])

/** Most coverage units reconnaissance may plan per mode (also bounded by the mode's task limit). */
export const RECON_UNITS: Readonly<Record<ScanMode, number>> = { quick: 8, deep: 40, research: 80 }
/** Coverage-critic passes per mode. */
export const CRITIC_PASSES: Readonly<Record<ScanMode, number>> = { quick: 0, deep: 1, research: 2 }
/** Most new units one critic pass may add. */
export const CRITIC_UNITS: Readonly<Record<ScanMode, number>> = { quick: 0, deep: 8, research: 16 }
/** Target files one unit may start from. */
export const MAX_UNIT_FILES = 8

/** One unit as a model submits it (after schema validation). */
export interface RawUnit {
  readonly title: string
  readonly component?: string | undefined
  readonly surface?: string | undefined
  readonly focus: readonly FindingCategory[]
  readonly target_paths: readonly string[]
  readonly priority: UnitPriority
  readonly rationale: string
  readonly hypothesis?: string | undefined
}

export interface UnitResolveOptions {
  /** Maps a model-written target onto snapshot files that a model may see (withheld files removed). */
  readonly resolve: (target: string) => TargetResolution
  /** Whether a resolved file is in this scan's scope (tests per `includeTests`). */
  readonly inScope: (path: string) => boolean
  /** Most units kept; later ones are dropped. */
  readonly limit: number
  readonly origin: 'recon' | 'critic'
  /** Unit ids that already exist (an earlier plan or wave); duplicates of them are dropped. */
  readonly existing?: ReadonlySet<string>
  /** Applied to every model-written text field (redaction backstop). */
  readonly scrub?: (text: string) => string
}

export interface UnitResolution {
  /** Validated, deduplicated units in submission order. */
  readonly units: PlanUnitRecord[]
  /** Units none of whose targets names a snapshot file, with close paths, for one request to correct them. */
  readonly unresolved: readonly {
    readonly index: number
    readonly title: string
    readonly targets: readonly { readonly target: string; readonly suggestions: readonly string[] }[]
  }[]
  /** Units dropped: beyond the limit, duplicates, unresolved, or only out-of-scope files. */
  readonly dropped: number
}

/** Stable id of a unit: its sorted target files and focus. */
export function unitId(targetPaths: readonly string[], focus: readonly FindingCategory[]): string {
  return `unit:${shortHash(`${[...targetPaths].sort().join('\u0000')}\u0001${[...new Set(focus)].sort().join(',')}`)}`
}

/**
 * Validate model-proposed units: resolve each target (exact path, directory,
 * near match, or symbol), keep in-scope files (at most 8 per unit), drop
 * units whose targets do not resolve or resolve only to out-of-scope files,
 * and drop duplicates (same files and focus, also against `existing`). At
 * most `limit` units are kept, in submission order.
 */
export function resolveUnits(raw: readonly RawUnit[], options: UnitResolveOptions): UnitResolution {
  const scrub = options.scrub ?? ((text: string) => text)
  const seen = new Set(options.existing ?? [])
  const units: PlanUnitRecord[] = []
  const unresolved: {
    index: number
    title: string
    targets: { target: string; suggestions: readonly string[] }[]
  }[] = []
  let dropped = 0
  raw.forEach((unit, index) => {
    if (units.length >= options.limit) {
      dropped++
      return
    }
    const resolutions = unit.target_paths.map(target => ({ target, ...options.resolve(target) }))
    const resolved = [...new Set(resolutions.flatMap(r => r.paths))]
    if (resolved.length === 0) {
      unresolved.push({
        index,
        title: unit.title,
        targets: resolutions.map(r => ({ target: r.target, suggestions: r.suggestions })),
      })
      dropped++
      return
    }
    const targetPaths = resolved.filter(options.inScope).slice(0, MAX_UNIT_FILES)
    const focus = [...new Set(unit.focus)]
    if (targetPaths.length === 0 || focus.length === 0) {
      dropped++
      return
    }
    const id = unitId(targetPaths, focus)
    if (seen.has(id)) {
      dropped++
      return
    }
    seen.add(id)
    const component = optionalText(unit.component, 120, scrub)
    const surface = optionalText(unit.surface, 200, scrub)
    const hypothesis = optionalText(unit.hypothesis, 800, scrub)
    units.push({
      id,
      title: clip(scrub(unit.title), 200),
      ...(component ? { component } : {}),
      ...(surface ? { surface } : {}),
      focus,
      targetPaths,
      priority: unit.priority,
      rationale: clip(scrub(unit.rationale), 800),
      ...(hypothesis ? { hypothesis } : {}),
      origin: options.origin,
    })
  })
  return { units, unresolved, dropped }
}

/** Retry text for units whose targets name no file (sent back once). */
export function describeUnresolved(unresolved: UnitResolution['unresolved'], tool: string): string | undefined {
  if (unresolved.length === 0) return undefined
  const lines = unresolved.flatMap(unit =>
    unit.targets.map(
      ({ target, suggestions }) =>
        `- unit ${unit.index + 1} ("${clip(unit.title, 80)}"): ${JSON.stringify(clip(target, 120))} is not a file in this repository${suggestions.length > 0 ? `; did you mean ${suggestions.join(', ')}?` : '.'}`,
    ),
  )
  return `Some units name no file that exists in this repository:\n${lines.join('\n')}\nUse workspace-relative paths as list_files shows them; a directory stands for its files and a function or class name for the file that defines it. Call ${tool} again with corrected target_paths for these units (resend the whole submission). Units whose files still cannot be found are dropped.`
}

/** What a planner's reason text claims; the Host still has to see it in the files. */
const EXCLUSION_REASONS: readonly [RegExp, ExcludedReason][] = [
  [/vendor|third[\s_-]?party|bundled|upstream/i, 'vendored'],
  [/generat|compiled|minif|build output|\bdist\b/i, 'generated'],
  [/fixture|sample|example|mock|test data/i, 'fixtures'],
  [/\bdoc(?:s|umentation)?\b/i, 'docs'],
]

const VENDOR_DIR =
  /(?:^|\/)(?:vendor|vendors|vendored|third[_-]?party|external|deps|node_modules|bower_components|Pods)(?:\/|$)/i
/** Directories and file names that code generators use. */
const GENERATED_PATH =
  /(?:^|\/)(?:generated|__generated__|gen|autogen)\/|\.(?:pb|pb\.gw|g|gen|generated|min)\.[^/.]+$|_pb2(?:_grpc)?\.py$/i
const DOCS_DIR = /(?:^|\/)(?:docs?|documentation)\//i
const DOC_FILE = /\.(?:md|mdx|markdown|rst|adoc|txt)$/i
/** Fixture and example directories (not test directories: whether tests are reviewed is the user's setting). */
const FIXTURE_DIR =
  /(?:^|\/)(?:fixtures|__fixtures__|testdata|test[_-]data|examples?|samples?|__mocks__|mocks|stubs)\//i

/** Exclusion reasons the Host can see in a file's path or content itself. */
function hostExclusionReasons(file: SnapshotFile): Set<ExcludedReason> {
  const reasons = new Set<ExcludedReason>()
  if (VENDOR_DIR.test(file.path)) reasons.add('vendored')
  if (file.isGenerated || GENERATED_PATH.test(file.path)) reasons.add('generated')
  if (DOCS_DIR.test(file.path) || DOC_FILE.test(file.path) || file.language === 'markdown') reasons.add('docs')
  if (FIXTURE_DIR.test(file.path)) reasons.add('fixtures')
  return reasons
}

export interface ExclusionContext {
  /** Snapshot files a model may see. */
  readonly files: readonly SnapshotFile[]
  /** Files with detected endpoints or rule hits: never excluded. */
  readonly protectedPaths: ReadonlySet<string>
}

/**
 * The planner's exclusions the Host can corroborate. The reason text must
 * claim vendored, generated, docs or fixtures, and every snapshot file under
 * the path must carry such a marker itself: a vendor or third-party
 * directory, generated content or a generator's directory or file name, a
 * documentation directory or file type, or a fixture/example directory. A
 * path holding a detected endpoint or rule hit is never excluded, nor is the
 * workspace root. The stored reason is the claimed one when every file bears
 * it out, otherwise the Host's most common one. At most 50 are kept.
 */
export function validExclusions(
  raw: readonly { readonly path: string; readonly reason: string }[],
  context: ExclusionContext,
): { readonly path: string; readonly reason: ExcludedReason }[] {
  const out = new Map<string, ExcludedReason>()
  for (const entry of raw) {
    const claimed = EXCLUSION_REASONS.find(([pattern]) => pattern.test(entry.reason))?.[1]
    const path = cleanModelPath(entry.path)?.replace(/\/+$/, '')
    if (!claimed || !path || path === '.' || out.has(path)) continue
    const under = context.files.filter(file => file.path === path || file.path.startsWith(`${path}/`))
    if (under.length === 0 || under.some(file => context.protectedPaths.has(file.path))) continue
    const reasons = under.map(hostExclusionReasons)
    if (reasons.some(set => set.size === 0)) continue
    out.set(path, reasons.every(set => set.has(claimed)) ? claimed : mostCommon(reasons))
  }
  return [...out.entries()].slice(0, 50).map(([path, reason]) => ({ path, reason }))
}

function mostCommon(reasons: readonly ReadonlySet<ExcludedReason>[]): ExcludedReason {
  const counts = new Map<ExcludedReason, number>()
  for (const set of reasons) for (const reason of set) counts.set(reason, (counts.get(reason) ?? 0) + 1)
  return [...counts.entries()].sort((a, b) => b[1] - a[1])[0]?.[0] ?? 'generated'
}

/**
 * A bounded directory overview for reconnaissance: one row per directory
 * (as deep as fits in `maxRows`) with its file count, main languages and
 * test/generated/vendored markers.
 */
export function directoryTree(files: readonly SnapshotFile[], maxRows = 60): string[] {
  const dirOf = (path: string, depth: number) => {
    const parts = path.split('/').slice(0, -1)
    return parts.length === 0 ? '.' : parts.slice(0, depth).join('/')
  }
  let depth = 4
  let groups = groupFiles(files, path => dirOf(path, depth))
  while (groups.size > maxRows && depth > 1) {
    depth--
    groups = groupFiles(files, path => dirOf(path, depth))
  }
  const byPath = (a: [string, SnapshotFile[]], b: [string, SnapshotFile[]]) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0)
  const rows = [...groups.entries()].sort(byPath)
  // Too many even one level deep: the largest directories, in path order.
  const shown =
    rows.length > maxRows
      ? rows
          .toSorted((a, b) => b[1].length - a[1].length || byPath(a, b))
          .slice(0, maxRows)
          .sort(byPath)
      : rows
  const lines = shown.map(([dir, group]) => {
    const languages = new Map<string, number>()
    for (const file of group) languages.set(file.language, (languages.get(file.language) ?? 0) + 1)
    const top = [...languages.entries()]
      .sort((a, b) => b[1] - a[1] || (a[0] < b[0] ? -1 : 1))
      .slice(0, 3)
      .map(([language, count]) => `${language} ${count}`)
    const markers = [
      group.filter(f => f.isTest).length * 2 >= group.length ? 'tests' : '',
      group.filter(f => f.isGenerated).length * 2 >= group.length ? 'generated' : '',
      VENDOR_DIR.test(`${dir}/`) ? 'vendored?' : '',
    ].filter(Boolean)
    return `${dir === '.' ? '(root)' : `${dir}/`}  ${group.length} file${group.length === 1 ? '' : 's'} (${top.join(', ')})${markers.length > 0 ? ` [${markers.join(', ')}]` : ''}`
  })
  if (rows.length > shown.length) lines.push(`… ${rows.length - shown.length} smaller directories not shown`)
  return lines
}

function groupFiles(files: readonly SnapshotFile[], key: (path: string) => string): Map<string, SnapshotFile[]> {
  const groups = new Map<string, SnapshotFile[]>()
  for (const file of files) {
    const k = key(file.path)
    const list = groups.get(k)
    if (list) list.push(file)
    else groups.set(k, [file])
  }
  return groups
}

// ---------------------------------------------------------------------------
// Coverage ledger
// ---------------------------------------------------------------------------

/** Ledger reason codes (`CoverageUnit.reason.code`) with their English fallback texts. */
export const UNIT_REASONS = {
  budget: 'Not examined: the scan budget ran out.',
  'task-limit': 'Not examined: beyond the task limit for this mode.',
  failed: 'Not examined: the review did not finish; see the activity log.',
  'consent-revoked': 'Not examined: sending code to models was turned off.',
  'provider-rejected': 'Not examined: the model provider rejected the request.',
  'no-tools': 'Not examined: the model answered without calling tools.',
  'stale-target': 'Not examined: its files or endpoints no longer exist.',
  'needs-runtime': 'The reviewer could not decide from the source alone; it depends on runtime or deployment.',
  partial: 'The reviewer ran out of turns before finishing this part.',
} as const

export type UnitReasonCode = keyof typeof UNIT_REASONS

/** A hunter's verdict on how completely it examined its unit. */
export type CoverageVerdict = 'complete' | 'partial' | 'needs-runtime'

export interface LedgerInput {
  readonly tasks: readonly TaskRecord[]
  readonly findings: readonly FindingRecord[]
  readonly evidence: readonly EvidenceRecord[]
  readonly endpoints: ReadonlyMap<string, Endpoint>
  /** In-scope source files no hunt task targets, and why. */
  readonly unassigned: {
    readonly paths: readonly string[]
    readonly reason: 'task-limit' | 'budget' | 'consent-revoked'
  }
}

/**
 * The coverage ledger: one unit per hunt task (plan, critic and gap-filling
 * tasks alike), plus one `not-run` unit for the source files no task
 * included. A finished task with at least one non-refuted finding backed by
 * its evidence is `finding`; finished with a `needs-runtime` or `partial`
 * verdict, `blocked`; otherwise finished, `covered`. Anything else is
 * `not-run` with a reason from the task's error code (a task still queued
 * counts as stopped by the budget).
 */
export function coverageLedger(input: LedgerInput): CoverageUnit[] {
  const taskOfEvidence = new Map<string, string>()
  for (const evidence of input.evidence) {
    if (evidence.taskId && evidence.origin === 'hunter') taskOfEvidence.set(evidence.id, evidence.taskId)
  }
  const findingsPerTask = new Map<string, number>()
  for (const finding of input.findings) {
    if (finding.verification === 'refuted') continue
    const tasks = new Set(finding.supportEvidenceIds.flatMap(id => taskOfEvidence.get(id) ?? []))
    for (const task of tasks) findingsPerTask.set(task, (findingsPerTask.get(task) ?? 0) + 1)
  }
  // Ids stay unique: a unit re-planned under a new key (endpoints added on resume) is listed by its task key.
  const ids = new Set<string>()
  const units: CoverageUnit[] = input.tasks
    .filter(task => HUNT_TASK_KINDS.has(task.kind))
    .map(task => {
      const findings = findingsPerTask.get(task.id) ?? 0
      const surface = task.input.surface ?? surfaceOf(task.input.endpointIds ?? [], input.endpoints)
      const id = task.input.unitId !== undefined && !ids.has(task.input.unitId) ? task.input.unitId : task.key
      ids.add(id)
      const base = {
        id,
        title: task.title,
        ...(task.input.component ? { component: task.input.component } : {}),
        ...(surface ? { surface } : {}),
        focus: task.input.focus,
        paths: task.input.targetPaths.slice(0, MAX_UNIT_FILES),
        findings,
        origin: task.input.origin ?? (task.kind === 'hunt-hypothesis' ? ('recon' as const) : ('gap' as const)),
        kind: unitKind(task),
      }
      if (task.status === 'done') {
        if (findings > 0) return { ...base, status: 'finding' as const }
        const verdict = task.outcome?.coverage
        if (verdict === 'needs-runtime' || verdict === 'partial') {
          const note = task.outcome?.coverageNote
          return {
            ...base,
            status: 'blocked' as const,
            reason: reason(verdict, typeof note === 'string' && note !== '' ? { note } : undefined),
          }
        }
        return { ...base, status: 'covered' as const }
      }
      return { ...base, status: 'not-run' as const, reason: reason(reasonOf(task)) }
    })
  const { paths } = input.unassigned
  if (paths.length > 0) {
    units.push({
      id: 'unassigned',
      title: `${paths.length} source file${paths.length === 1 ? '' : 's'} not assigned to any review unit`,
      focus: [],
      paths: paths.slice(0, 20),
      status: 'not-run',
      findings: 0,
      reason: reason(input.unassigned.reason, { count: paths.length }),
      origin: 'gap',
    })
  }
  return units
}

/** What produced a hunt task's unit (see `CoverageUnit.kind`). */
function unitKind(task: TaskRecord): NonNullable<CoverageUnit['kind']> {
  switch (task.kind) {
    case 'hunt-unit':
      return 'plan'
    case 'hunt-endpoints':
      return 'endpoints'
    case 'hunt-signals':
      return 'signals'
    case 'triage-signals':
      return 'triage'
    case 'hunt-file':
      return task.key.startsWith('sweep:') ? 'sweep' : 'file'
    default:
      return 'legacy'
  }
}

function reasonOf(task: TaskRecord): UnitReasonCode {
  // Still queued when the ledger is made: hunting stopped before it started, which only the budget does.
  if ((task.status === 'pending' || task.status === 'running') && task.error === undefined) return 'budget'
  switch (task.error?.code) {
    case 'budget':
    case 'budget_exhausted':
      return 'budget'
    case 'task-limit':
      return 'task-limit'
    case 'consent-revoked':
      return 'consent-revoked'
    case 'provider-route-rejected':
    case 'blocked_by_provider':
      return 'provider-rejected'
    case 'provider-route-no-tools':
      return 'no-tools'
    case 'stale-target':
      return 'stale-target'
    default:
      return 'failed'
  }
}

function reason(code: UnitReasonCode, params?: Diagnostic['params']): Diagnostic {
  return { code, fallback: UNIT_REASONS[code], ...(params ? { params } : {}) }
}

function surfaceOf(ids: readonly string[], endpoints: ReadonlyMap<string, Endpoint>): string | undefined {
  const known = ids.flatMap(id => endpoints.get(id) ?? [])
  if (known.length === 0) return undefined
  const shown = known.slice(0, 3).map(e => `${e.method} ${e.route}`)
  const more = known.length - shown.length
  return clip(`${shown.join(', ')}${more > 0 ? ` (+${more} more)` : ''}`, 200)
}

function optionalText(text: string | undefined, max: number, scrub: (text: string) => string): string | undefined {
  const value = text?.trim()
  return value ? clip(scrub(value), max) : undefined
}

function clip(text: string, max: number): string {
  const single = text.replace(/\s+/g, ' ').trim()
  return single.length <= max ? single : `${single.slice(0, max - 1)}…`
}
