/** Built-in SAST analyzer: rule engine, language rule sets and shared taint heuristics. */

export { runSast, SAST_RULES, scanFile } from './engine.ts'
export type { RuleMeta } from './rule.ts'
