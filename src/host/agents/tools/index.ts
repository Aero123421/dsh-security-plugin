/**
 * Read-only tools that let AI workers navigate the frozen snapshot.
 */

export { compileGlob, expandBraces, type GlobMatcher, MAX_GLOB_LENGTH, matchGlob, normalizeGlob } from './glob.ts'
export { isUnder, levenshtein, normalizeDir, suggestPaths } from './paths.ts'
export { compileLineMatcher, type LineMatcher, MAX_PATTERN_LENGTH } from './search.ts'
export {
  createWorkspaceTools,
  MAX_SEARCH_SCAN_BYTES,
  WORKSPACE_TOOL_NAMES,
  type WorkspaceToolOptions,
  type WorkspaceView,
  workspaceQuoteSource,
} from './workspace.ts'
