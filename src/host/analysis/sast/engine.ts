/**
 * Built-in SAST driver: walks the snapshot, builds a code model per file
 * (native AST when available, tokens otherwise), runs the language rules, and
 * turns their hits into deduplicated, redacted analyzer signals.
 *
 * Signal kinds:
 * - `vulnerability`: user input visibly reaches the sink in the same
 *   function or expression (confidence high when the source is written
 *   inside the sink call, medium when it arrives through a local alias or a
 *   route parameter).
 * - `sink`: a dangerous API receives a dynamic value of unknown origin. These
 *   carry lower severity and only steer the AI review.
 */

import { createHash } from 'node:crypto'
import type { Severity } from '../../../shared/domain.ts'
import type { AstGrepHandle } from '../astgrep.ts'
import { redactText } from '../secrets.ts'
import { type AnalyzerRun, type Signal, type Snapshot, type SnapshotFile, yieldToEventLoop } from '../types.ts'
import { CONFIG_RULES, configRules, isConfigFile } from './config.ts'
import { djangoScalarParams } from './django.ts'
import { JS_RULES, jsRules, templateRules } from './js.ts'
import { lineOf, lineStarts } from './lexer.ts'
import type { FileModel, Span } from './model.ts'
import { modelFor, modelKind } from './models.ts'
import { PY_RULES, pyRules, pyTemplateRules } from './python.ts'
import type { Confidence, FileContext, Hit, RuleMeta } from './rule.ts'

const YIELD_EVERY = 25
const SNIPPET_MAX_LINES = 5
const SNIPPET_MAX_CHARS = 400
const FINGERPRINT_MAX_CHARS = 240
const TEXT_SCAN_MAX_CHARS = 2 * 1024 * 1024

/**
 * Every built-in rule, one entry per rule id (the first definition wins when
 * several matchers share an id, e.g. reflected and DOM XSS), sorted by id.
 */
export const SAST_RULES: readonly RuleMeta[] = [
  ...new Map([...JS_RULES, ...PY_RULES, ...CONFIG_RULES].reverse().map(rule => [rule.id, rule])).values(),
].sort((a, b) => compare(a.id, b.id))

const SEVERITY_ORDER: Readonly<Record<Severity, number>> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }
const CONFIDENCE_ORDER: Readonly<Record<Confidence, number>> = { high: 0, medium: 1, low: 2 }

/**
 * Run the built-in SAST rules over a snapshot. Generated files are skipped;
 * test files are scanned with severity capped at `low` and confidence `low`.
 * Throws the signal's reason when `signal` is aborted.
 */
export async function runSast(
  snapshot: Snapshot,
  options: { readonly astGrep?: AstGrepHandle; readonly signal?: AbortSignal } = {},
): Promise<AnalyzerRun> {
  const started = performance.now()
  const { astGrep, signal } = options
  const warnings: string[] = []
  const byKey = new Map<string, Signal>()
  let index = 0
  signal?.throwIfAborted()
  const scalarParams = djangoScalarParams(snapshot, astGrep)
  for (const file of snapshot.files.values()) {
    if (++index % YIELD_EVERY === 0) {
      await yieldToEventLoop()
      signal?.throwIfAborted()
    }
    if (file.isGenerated || file.content.length > TEXT_SCAN_MAX_CHARS) continue
    try {
      for (const sig of scanFile(file, astGrep, scalarParams.get(file.path))) {
        const key = `${sig.ruleId}\0${sig.location.path}\0${sig.location.startLine}`
        const prev = byKey.get(key)
        if (!prev || isStronger(sig, prev)) byKey.set(key, sig)
      }
    } catch (error) {
      warnings.push(
        `sast: ${file.path}: ${redactText(error instanceof Error ? error.message : String(error)).slice(0, 200)}`,
      )
    }
  }
  signal?.throwIfAborted()
  const signals = [...byKey.values()].sort(
    (a, b) =>
      compare(a.location.path, b.location.path) ||
      a.location.startLine - b.location.startLine ||
      compare(a.ruleId, b.ruleId),
  )
  return {
    status: { id: 'sast', available: true, source: 'builtin' },
    signals: distinguishOccurrences(signals),
    durationMs: Math.round(performance.now() - started),
    warnings,
  }
}

/**
 * Distinguish identical expressions after matcher deduplication, in file order.
 * Single occurrences retain their existing line-independent fingerprint.
 * Adding/removing identical sinks can renumber occurrences (or return one to
 * its singleton identity): triage is deliberately not shared across those
 * identities, since doing so could hide a different, still-vulnerable sink.
 */
function distinguishOccurrences(signals: readonly Signal[]): Signal[] {
  const groups = new Map<string, Signal[]>()
  for (const signal of signals) {
    const key = JSON.stringify(signal.fingerprintParts)
    const group = groups.get(key) ?? []
    group.push(signal)
    groups.set(key, group)
  }
  const discriminated = new Map<Signal, Signal>()
  for (const group of groups.values()) {
    if (group.length < 2) continue
    group.forEach((signal, index) => {
      discriminated.set(signal, {
        ...signal,
        fingerprintParts: [...signal.fingerprintParts, `occurrence:${index + 1}`],
      })
    })
  }
  return signals.map(signal => discriminated.get(signal) ?? signal)
}

/**
 * Scan one file and return its (not yet deduplicated) signals. `scalarParams` lists view parameters other
 * files constrain to numbers (see `djangoScalarParams`).
 */
export function scanFile(
  file: SnapshotFile,
  astGrep: AstGrepHandle | undefined,
  scalarParams?: FileContext['scalarParams'],
): Signal[] {
  const hits: Hit[] = []
  const ctx: FileContext = { file, report: hit => hits.push(hit), ...(scalarParams ? { scalarParams } : {}) }
  let model: FileModel | undefined
  const kind = modelKind(file)
  if (kind) {
    model = modelFor(file, astGrep)
    if (model?.lang === 'js') jsRules(model, ctx)
    else if (model?.lang === 'py') pyRules(model, ctx)
  }
  if (kind !== 'js' && kind !== 'py') {
    templateRules(ctx)
    pyTemplateRules(ctx)
  }
  if (isConfigFile(file)) configRules(ctx)
  if (hits.length === 0) return []
  const starts = lineStarts(file.content)
  return hits.map(hit => toSignal(file, starts, hit, model?.mode ?? 'text'))
}

function toSignal(file: SnapshotFile, starts: readonly number[], hit: Hit, mode: string): Signal {
  const { rule } = hit
  const content = file.content
  const startLine = lineOf(starts, hit.span.start)
  const endLine = Math.max(startLine, lineOf(starts, Math.max(hit.span.start, hit.span.end - 1)))
  const lastLine = Math.min(endLine, startLine + SNIPPET_MAX_LINES - 1)
  const from = starts[startLine - 1] ?? 0
  const to = lastLine < starts.length ? starts[lastLine]! - 1 : content.length
  const masks = (hit.mask ?? []).filter(m => m.end > m.start)
  const snippetRaw = maskText(content, from, Math.max(from, to), masks).replace(/\r(?=\n|$)/g, '')
  const snippet = clip(redactText(snippetRaw), SNIPPET_MAX_CHARS)
  const expr = redactText(maskText(content, hit.span.start, hit.span.end, masks))
    .replace(/\s+/g, ' ')
    .trim()
  const normalized =
    expr.length <= FINGERPRINT_MAX_CHARS
      ? expr
      : `${expr.slice(0, 200)}#${createHash('sha256').update(expr).digest('hex').slice(0, 16)}`

  let severity: Severity = hit.severity ?? (hit.kind === 'vulnerability' ? rule.severity : (rule.sinkSeverity ?? 'low'))
  let confidence: Confidence = hit.confidence
  if (file.isTest) {
    if (SEVERITY_ORDER[severity] < SEVERITY_ORDER.low) severity = 'low'
    confidence = 'low'
  }
  const parts: string[] = [hit.kind === 'sink' ? (rule.sinkMessage ?? rule.message) : rule.message]
  if (hit.taint) parts.push(`Here the value comes from \`${hit.taint.source}\`.`)
  if (hit.note) parts.push(hit.note)
  if (file.isTest)
    parts.push('This file looks like a test, fixture or example, so the code may never run in production.')
  const column = hit.span.start - from + 1
  return {
    analyzer: 'sast',
    ruleId: rule.id,
    kind: hit.kind,
    title: hit.kind === 'sink' ? (rule.sinkTitle ?? `Review: ${rule.title}`) : rule.title,
    category: rule.category,
    severity,
    confidence,
    cwe: rule.cwe,
    location: { path: file.path, startLine, endLine },
    snippet,
    message: redactText(parts.join(' ')),
    recommendation: rule.recommendation,
    fingerprintParts: [rule.id, file.path, normalized],
    references: rule.references,
    metadata: {
      column,
      mode,
      ...(rule.cwe === 'CWE-798' && masks.length === 1
        ? { secretStart: masks[0]!.start, secretEnd: masks[0]!.end }
        : {}),
      ...(hit.taint ? { source: redactText(hit.taint.source) } : {}),
      ...hit.metadata,
    },
  }
}

/** Text of `[start, end)` with masked spans replaced by `***`. */
function maskText(content: string, start: number, end: number, masks: readonly Span[]): string {
  let out = ''
  let cursor = start
  for (const m of [...masks].sort((a, b) => a.start - b.start)) {
    if (m.end <= cursor || m.start >= end) continue
    out += content.slice(cursor, Math.max(cursor, m.start)) + '***'
    cursor = Math.min(end, m.end)
  }
  return out + content.slice(cursor, end)
}

function clip(text: string, max: number): string {
  return text.length <= max ? text : `${text.slice(0, max - 1)}…`
}

function isStronger(a: Signal, b: Signal): boolean {
  if (a.kind !== b.kind) return a.kind === 'vulnerability'
  if (a.severity !== b.severity) return SEVERITY_ORDER[a.severity] < SEVERITY_ORDER[b.severity]
  if (a.confidence !== b.confidence) return CONFIDENCE_ORDER[a.confidence] < CONFIDENCE_ORDER[b.confidence]
  return a.location.endLine - a.location.startLine < b.location.endLine - b.location.startLine
}

function compare(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0
}
