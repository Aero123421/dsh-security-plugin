import { expect } from 'vitest'
import { type AstGrepHandle, loadAstGrep } from '../../../src/host/analysis/astgrep.ts'
import { runSast } from '../../../src/host/analysis/sast/engine.ts'
import type { Signal } from '../../../src/host/analysis/types.ts'
import { snapshotOf } from './helpers.ts'

/** The native engine when this platform has it; tests fall back to token mode otherwise. */
export const astGrep: AstGrepHandle | undefined = await loadAstGrep()

type Modes = readonly (readonly [string, AstGrepHandle | undefined])[]

/**
 * Analysis modes for JavaScript/TypeScript cases. `fallback` passes
 * `undefined` explicitly; `ast` uses the native engine (skipped when
 * unavailable).
 */
export const MODES: Modes = astGrep
  ? [
      ['fallback', undefined],
      ['ast', astGrep],
    ]
  : [['fallback', undefined]]

/**
 * Analysis modes for Python cases: `ast` only when the shipped grammar
 * loaded (otherwise a handle would silently use the indentation fallback
 * for `.py` files).
 */
export const PY_MODES: Modes = astGrep?.supportsPython
  ? [
      ['fallback', undefined],
      ['ast', astGrep],
    ]
  : [['fallback', undefined]]

/** Run SAST over in-memory files and return its signals. */
export async function sast(files: Record<string, string>, handle: AstGrepHandle | undefined): Promise<Signal[]> {
  const run = await runSast(snapshotOf(files), { astGrep: handle })
  expect(run.warnings).toEqual([])
  return [...run.signals]
}

/** Signals of one rule. */
export function ofRule(signals: readonly Signal[], ruleId: string): Signal[] {
  return signals.filter(s => s.ruleId === ruleId)
}

/** Compact `line kind` summaries for one rule, for readable assertions. */
export function hits(signals: readonly Signal[], ruleId: string): string[] {
  return ofRule(signals, ruleId).map(s => `${s.location.startLine} ${s.kind}`)
}

/**
 * Expected `line kind` summaries from inline markers: a line ending in a
 * `VULN` comment (`// VULN` or `# VULN`) expects a `vulnerability`, `SINK` a
 * `sink`; unmarked lines must not be reported for the rule.
 */
export function expectedHits(code: string): string[] {
  return code.split('\n').flatMap((line, i) => {
    const m = /(?:\/\/|#|<!--|\{#) (VULN|SINK)\b/.exec(line)
    return m ? [`${i + 1} ${m[1] === 'VULN' ? 'vulnerability' : 'sink'}`] : []
  })
}
