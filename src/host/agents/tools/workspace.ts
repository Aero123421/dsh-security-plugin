/**
 * Read-only workspace tools for AI workers.
 *
 * Workers navigate a frozen, in-memory snapshot exclusively through these
 * tools: there is no filesystem, network, or shell access behind them. Every
 * excerpt is redacted with the scan's {@link Redactor} (plus the stateless
 * backstop), the absolute snapshot root is masked, and credential files
 * (built-in sensitive paths plus user `withheldGlobs`) are never shown. File
 * content is treated purely as data; nothing in it is ever interpreted.
 */

import { z } from 'zod'
import type { AstGrepHandle } from '../../analysis/astgrep.ts'
import { findSymbol, outlineFile } from '../../analysis/outline.ts'
import { isSensitivePath, type Redactor, redactText } from '../../analysis/secrets.ts'
import type { Endpoint, Snapshot, SnapshotFile } from '../../analysis/types.ts'
import { isEndpointVisible, yieldToEventLoop } from '../../analysis/types.ts'
import { normalizePath } from '../../evidence/normalize.ts'
import { type QuoteSource, snapshotQuoteSource } from '../../evidence/quote.ts'
import { clipText, countLines, maskRoot, numberLines, stripCr } from '../../evidence/text.ts'
import { defineTool, type ToolResult, type WorkerTool } from '../runtime/tool.ts'
import { compileGlob, type GlobMatcher, normalizeGlob } from './glob.ts'
import { isUnder, normalizeDir, suggestPaths } from './paths.ts'
import { compileLineMatcher, DEFAULT_REGEX_TIME_BUDGET_MS, MAX_PATTERN_LENGTH } from './search.ts'

/** What the workspace tools can see. */
export interface WorkspaceView {
  readonly snapshot: Snapshot
  readonly redactor: Redactor
  /** Extra gitignore-style globs for files that must never be shown (on top of the built-in credential files). */
  readonly withheldGlobs: readonly string[]
  readonly endpoints: readonly Endpoint[]
  readonly astGrep?: AstGrepHandle
  /** Per-worker log of files actually read (for coverage); `read_file` reports each path it shows. */
  readonly onRead?: (path: string) => void
}

/** Limits for {@link createWorkspaceTools}. */
export interface WorkspaceToolOptions {
  /** Show test, fixture, and example files without being asked. Default false. */
  readonly includeTests?: boolean
  /** Most lines one `read_file` call returns. Default 400. */
  readonly maxReadLines?: number
  /** Default and maximum number of `search_code` results. Default 50. */
  readonly maxSearchResults?: number
  /** Total regex execution time per `search_code` call. Default 2000 ms. */
  readonly regexTimeBudgetMs?: number
  /** File bytes one `search_code` call may scan. Default {@link MAX_SEARCH_SCAN_BYTES} (50 MB). */
  readonly maxSearchScanBytes?: number
}

/** Tool names created by {@link createWorkspaceTools}, in order. */
export const WORKSPACE_TOOL_NAMES = [
  'list_files',
  'read_file',
  'search_code',
  'find_symbol',
  'file_outline',
  'list_endpoints',
] as const

/** Default cap on file bytes one `search_code` call scans. */
export const MAX_SEARCH_SCAN_BYTES = 50 * 1024 * 1024

const DEFAULT_LIST_LIMIT = 200
const MAX_LIST_LIMIT = 500
const DEFAULT_READ_LINES = 400
const DEFAULT_SEARCH_RESULTS = 50
const DEFAULT_ENDPOINT_LIMIT = 100
const MAX_ENDPOINT_LIMIT = 500
const MAX_SYMBOL_RESULTS = 30
const MAX_OUTPUT_CHARS = 20_000
const MAX_READ_LINE_CHARS = 2_000
const MAX_SEARCH_LINE_CHARS = 200
const MAX_NAME_CHARS = 200
const SEARCH_BATCH_CHARS = 1024 * 1024
const SEARCH_BATCH_FILES = 64
const MAX_SUGGESTIONS = 5
const MAX_ENDPOINT_LABEL_CHARS = 80

/** Glob or directory text that explicitly asks for test, fixture, or example files. */
const TEST_TARGET =
  /(?:^|[^a-z])(?:tests?|specs?|__tests__|__mocks__|mocks?|e2e|fixtures?|__fixtures__|testdata|examples?|conftest)(?:[^a-z]|$)/i
const IDENTIFIER_PATH = /^[\p{L}_$][\p{L}\p{N}_$]*(?:\.[\p{L}_$][\p{L}\p{N}_$]*)*$/u

const INVALID_PATH =
  'Invalid path. Use a workspace-relative path such as "src/app.ts"; absolute paths, "..", and NUL characters are not allowed.'
const INVALID_DIR =
  'Invalid directory. Use a workspace-relative directory such as "src/routes"; absolute paths, "..", and NUL characters are not allowed.'
const INVALID_GLOB =
  'Invalid glob. Use a workspace-relative pattern such as "src/**/*.ts" (at most 300 characters); absolute paths, "..", and NUL characters are not allowed.'

/**
 * Create the read-only, non-terminal workspace tools for one worker:
 * `list_files`, `read_file`, `search_code`, `find_symbol`, `file_outline`
 * and `list_endpoints`. Outputs are compact, deterministic plain text with
 * secrets redacted and the snapshot root masked.
 */
export function createWorkspaceTools(
  view: WorkspaceView,
  options: WorkspaceToolOptions = {},
): WorkerTool<unknown, never>[] {
  const ws = new Workspace(view, options)
  const tools = [
    listFilesTool(ws),
    readFileTool(ws),
    searchCodeTool(ws),
    findSymbolTool(ws),
    fileOutlineTool(ws),
    listEndpointsTool(ws),
  ]
  return tools as WorkerTool<unknown, never>[]
}

/**
 * A {@link QuoteSource} that sees exactly what the workspace tools show:
 * the same redaction, root masking, and withheld files. Use it to verify
 * quotes cited by workers that used these tools.
 */
export function workspaceQuoteSource(
  view: Pick<WorkspaceView, 'snapshot' | 'redactor' | 'withheldGlobs'>,
): QuoteSource {
  const { snapshot, redactor } = view
  const masked = {
    redactFile: (path: string, content: string) =>
      maskRoot(redactor.redactFile(path, content), snapshot.workspaceRoot ?? snapshot.root),
  }
  return snapshotQuoteSource(snapshot, masked, view.withheldGlobs)
}

// ---------------------------------------------------------------------------
// Shared state
// ---------------------------------------------------------------------------

/**
 * Redacted content shared by every tool set over the same redactor and
 * snapshot. `null` means redaction changed nothing, so the snapshot content
 * itself is served and no copy is kept.
 */
const redactedCache = new WeakMap<Redactor, WeakMap<Snapshot, Map<string, string | null>>>()
const lineCountCache = new WeakMap<SnapshotFile, number>()

class Workspace {
  readonly snapshot: Snapshot
  readonly includeTests: boolean
  readonly maxReadLines: number
  readonly maxSearchResults: number
  readonly regexTimeBudgetMs: number
  readonly maxSearchScanBytes: number
  readonly #view: WorkspaceView
  readonly #withheld = new Map<string, boolean>()
  readonly #redacted: Map<string, string | null>
  #sortedPaths: readonly string[] | undefined
  #excluded: ReadonlyMap<string, string> | undefined

  constructor(view: WorkspaceView, options: WorkspaceToolOptions) {
    this.#view = view
    this.snapshot = view.snapshot
    this.includeTests = options.includeTests === true
    this.maxReadLines = positiveInt(options.maxReadLines, DEFAULT_READ_LINES)
    this.maxSearchResults = positiveInt(options.maxSearchResults, DEFAULT_SEARCH_RESULTS)
    this.regexTimeBudgetMs = positiveInt(options.regexTimeBudgetMs, DEFAULT_REGEX_TIME_BUDGET_MS)
    this.maxSearchScanBytes = positiveInt(options.maxSearchScanBytes, MAX_SEARCH_SCAN_BYTES)
    let bySnapshot = redactedCache.get(view.redactor)
    if (!bySnapshot) {
      bySnapshot = new WeakMap()
      redactedCache.set(view.redactor, bySnapshot)
    }
    let cache = bySnapshot.get(view.snapshot)
    if (!cache) {
      cache = new Map()
      bySnapshot.set(view.snapshot, cache)
    }
    this.#redacted = cache
  }

  get astGrep(): AstGrepHandle | undefined {
    return this.#view.astGrep
  }

  get endpoints(): readonly Endpoint[] {
    return this.#view.endpoints
  }

  /** Every snapshot path in code-unit order. */
  sortedPaths(): readonly string[] {
    this.#sortedPaths ??= [...this.snapshot.files.keys()].sort(compareStrings)
    return this.#sortedPaths
  }

  isWithheld(path: string): boolean {
    let withheld = this.#withheld.get(path)
    if (withheld === undefined) {
      withheld = isSensitivePath(path, this.#view.withheldGlobs)
      this.#withheld.set(path, withheld)
    }
    return withheld
  }

  /** Redacted, root-masked content: exactly what a model may see. */
  redacted(file: SnapshotFile): string {
    const cached = this.#redacted.get(file.path)
    if (cached !== undefined) return cached ?? file.content
    const text = maskRoot(
      this.#view.redactor.redactFile(file.path, file.content),
      this.snapshot.workspaceRoot ?? this.snapshot.root,
    )
    this.#redacted.set(file.path, text === file.content ? null : text)
    return text
  }

  lineCount(file: SnapshotFile): number {
    let count = lineCountCache.get(file)
    if (count === undefined) {
      count = countLines(file.content)
      lineCountCache.set(file, count)
    }
    return count
  }

  /** Final pass over every tool output: stateless redaction where needed and root masking. */
  finish(text: string, isError = false, redact = false): ToolResult {
    const safe = maskRoot(redact ? redactText(text) : text, this.snapshot.workspaceRoot ?? this.snapshot.root)
    return isError ? { text: safe, isError: true } : { text: safe }
  }

  error(text: string): ToolResult {
    return this.finish(text, true, true)
  }

  markRead(path: string): void {
    try {
      this.#view.onRead?.(path)
    } catch {
      // Coverage bookkeeping must never break a tool call.
    }
  }

  /** Error result for a path that is not a readable snapshot file, with suggestions. */
  unknownPath(path: string): ToolResult {
    const excluded = this.excludedReason(path)
    if (excluded) {
      return this.error(
        `${path} is not part of the analyzed snapshot (excluded: ${excluded}), so it cannot be read. ` +
          'Reason about it from the code that uses it.',
      )
    }
    const prefix = `${path}/`
    if (this.sortedPaths().some(p => p.startsWith(prefix))) {
      return this.error(`${path} is a directory. Use list_files with under="${path}" to see its files.`)
    }
    const suggestions = suggestPaths(path, this.sortedPaths(), MAX_SUGGESTIONS)
    const hint =
      suggestions.length > 0
        ? `Did you mean:\n${suggestions.map(s => `  ${s}${this.isWithheld(s) ? '  [withheld]' : ''}`).join('\n')}`
        : 'Use list_files or search_code to find the right path.'
    return this.error(`File not found in the snapshot: ${path}\n${hint}`)
  }

  withheldError(path: string): ToolResult {
    return this.error(
      `${path} is withheld: this file may contain credentials and is never shown; ` +
        'reason about it from its usage instead (for example, search_code for where its settings are read).',
    )
  }

  private excludedReason(path: string): string | undefined {
    this.#excluded ??= new Map(this.snapshot.excluded.map(entry => [entry.path, entry.reason]))
    return this.#excluded.get(path)
  }
}

// ---------------------------------------------------------------------------
// list_files
// ---------------------------------------------------------------------------

function listFilesTool(ws: Workspace) {
  return defineTool({
    name: 'list_files',
    description:
      'List files in the repository snapshot, sorted by path, as "path  (language, N lines)". Filter with a glob ' +
      '(e.g. "**/*.py", "src/{routes,api}/**") and/or a directory (under). Files marked [withheld] may hold ' +
      'credentials and cannot be read. Test, fixture, and example files are hidden unless glob or under targets them ' +
      '(e.g. under="tests" or glob="**/*.test.ts").',
    input: z.object({
      glob: z
        .string()
        .optional()
        .describe(
          'Glob over workspace-relative paths. Supports *, **, ?, {a,b}. A pattern without "/" matches file names at any depth.',
        ),
      under: z.string().optional().describe('Only list files below this workspace-relative directory, e.g. "src/api".'),
      limit: z
        .number()
        .int()
        .positive()
        .optional()
        .describe(`Maximum files to list (default ${DEFAULT_LIST_LIMIT}, at most ${MAX_LIST_LIMIT}).`),
    }),
    execute: async ({ glob, under, limit }) => {
      const dir = under === undefined ? '' : normalizeDir(under)
      if (dir === undefined) return ws.error(INVALID_DIR)
      let matcher: GlobMatcher | undefined
      if (glob !== undefined && glob.trim() !== '') {
        const compiled = compileGlobSafe(glob)
        if (!compiled.ok) return ws.error(compiled.error)
        matcher = compiled.matcher
      }
      const showTests = ws.includeTests || targetsTests(glob) || targetsTests(dir)
      const max = Math.min(limit ?? DEFAULT_LIST_LIMIT, MAX_LIST_LIMIT)

      const matched: SnapshotFile[] = []
      let hiddenTests = 0
      for (const path of ws.sortedPaths()) {
        if (!isUnder(path, dir)) continue
        if (matcher && !matcher(path) && !(dir !== '' && path !== dir && matcher(path.slice(dir.length + 1)))) {
          continue
        }
        const file = ws.snapshot.files.get(path)
        if (!file) continue
        if (file.isTest && !showTests) {
          hiddenTests++
          continue
        }
        matched.push(file)
      }

      const lines: string[] = []
      let chars = 0
      for (const file of matched) {
        if (lines.length >= max || chars > MAX_OUTPUT_CHARS) break
        const line = ws.isWithheld(file.path)
          ? `${file.path}  [withheld]`
          : `${file.path}  (${file.language}, ${ws.lineCount(file)} lines${file.isGenerated ? ', generated' : ''})`
        lines.push(line)
        chars += line.length + 1
      }

      const out: string[] = []
      const scope = describeScope(glob, dir)
      if (matched.length === 0) {
        out.push(`No files match${scope}.`)
        if (hiddenTests === 0) out.push('Check the glob syntax, or call list_files without filters to see the layout.')
      } else {
        out.push(`${matched.length} file${matched.length === 1 ? '' : 's'}${scope}:`)
        out.push(...lines)
        const rest = matched.length - lines.length
        if (rest > 0) {
          out.push(`… ${rest} more not shown; raise limit (max ${MAX_LIST_LIMIT}) or narrow with glob/under.`)
        }
      }
      if (hiddenTests > 0) {
        out.push(
          `(${hiddenTests} test/fixture/example file${hiddenTests === 1 ? '' : 's'} hidden; set under or glob to a test location to list ${hiddenTests === 1 ? 'it' : 'them'}.)`,
        )
      }
      return ws.finish(out.join('\n'))
    },
  })
}

// ---------------------------------------------------------------------------
// read_file
// ---------------------------------------------------------------------------

function readFileTool(ws: Workspace) {
  return defineTool({
    name: 'read_file',
    description:
      `Read a file from the repository snapshot with line numbers ("  12| code"). Returns at most ${ws.maxReadLines} ` +
      'lines per call; use start_line/end_line to read a range or to continue. Secrets appear as [REDACTED:rule]. ' +
      'Withheld credential files cannot be read. When quoting evidence, copy the code text without the line-number prefix.',
    input: z.object({
      path: z.string().describe('Workspace-relative file path, e.g. "src/routes/users.ts".'),
      start_line: z.number().int().positive().optional().describe('First line to show (1-based). Default 1.'),
      end_line: z
        .number()
        .int()
        .positive()
        .optional()
        .describe(`Last line to show (inclusive). Default: start_line + ${ws.maxReadLines - 1} or end of file.`),
    }),
    execute: async ({ path: rawPath, start_line: startLine, end_line: endLine }) => {
      const path = normalizePath(rawPath)
      if (path === undefined) return ws.error(INVALID_PATH)
      if (ws.isWithheld(path)) return ws.withheldError(path)
      const file = ws.snapshot.files.get(path)
      if (!file) return ws.unknownPath(path)

      const text = ws.redacted(file)
      const lines = text === '' ? [] : text.split('\n')
      if (lines.length > 1 && lines.at(-1) === '') lines.pop()
      const total = lines.length
      if (total === 0) {
        ws.markRead(path)
        return ws.finish(`${path} (empty file)`)
      }
      const start = startLine ?? 1
      if (start > total) {
        return ws.error(`start_line ${start} is past the end of ${path}, which has ${total} lines.`)
      }
      if (endLine !== undefined && endLine < start) {
        return ws.error(`end_line ${endLine} is before start_line ${start}.`)
      }
      const wantedEnd = Math.min(endLine ?? total, total)
      let end = Math.min(wantedEnd, start + ws.maxReadLines - 1)
      // Keep the whole result within the worker's tool-output budget.
      let chars = 0
      for (let line = start; line <= end; line++) {
        chars += Math.min((lines[line - 1] ?? '').length, MAX_READ_LINE_CHARS) + 10
        if (chars > MAX_OUTPUT_CHARS && line > start) {
          end = line - 1
          break
        }
      }

      const body = numberLines(lines.slice(start - 1, end), start, MAX_READ_LINE_CHARS)
      const parts = [`${path} (lines ${start}-${end} of ${total})`, body]
      if (end < wantedEnd) {
        const rest = wantedEnd - end
        const scope = endLine === undefined ? '' : ' in the requested range'
        parts.push(
          `[${rest} more line${rest === 1 ? '' : 's'}${scope}; call read_file with start_line=${end + 1} to continue.]`,
        )
      }
      ws.markRead(path)
      return ws.finish(parts.join('\n'))
    },
  })
}

// ---------------------------------------------------------------------------
// search_code
// ---------------------------------------------------------------------------

function searchCodeTool(ws: Workspace) {
  return defineTool({
    name: 'search_code',
    description:
      'Search file contents line by line and return matching lines as "path:line: text" (sorted by path, line text ' +
      `clipped to ${MAX_SEARCH_LINE_CHARS} chars). By default the pattern is a literal, case-insensitive substring; ` +
      'set regex=true for a JavaScript regular expression (matched against one line at a time, no multiline). ' +
      'Withheld credential files are skipped; test files are skipped unless path_glob targets them.',
    input: z.object({
      pattern: z
        .string()
        .min(1)
        .describe(`Text or regular expression to find (at most ${MAX_PATTERN_LENGTH} characters, single line).`),
      regex: z.boolean().optional().describe('Treat pattern as a regular expression. Default false (literal).'),
      case_sensitive: z.boolean().optional().describe('Match case exactly. Default false.'),
      path_glob: z
        .string()
        .optional()
        .describe('Only search files whose workspace-relative path matches this glob, e.g. "src/**/*.ts" or "*.py".'),
      max_results: z
        .number()
        .int()
        .positive()
        .optional()
        .describe(`Maximum matching lines to return (default and maximum ${ws.maxSearchResults}).`),
    }),
    execute: async (args, ctx) => {
      const compiled = compileLineMatcher(args.pattern, {
        regex: args.regex === true,
        caseSensitive: args.case_sensitive === true,
        timeBudgetMs: ws.regexTimeBudgetMs,
      })
      if (!compiled.ok) return ws.error(compiled.error)
      const { matcher } = compiled
      let glob: GlobMatcher | undefined
      if (args.path_glob !== undefined && args.path_glob.trim() !== '') {
        const g = compileGlobSafe(args.path_glob)
        if (!g.ok) return ws.error(g.error)
        glob = g.matcher
      }
      const showTests = ws.includeTests || targetsTests(args.path_glob)
      const limit = Math.min(args.max_results ?? ws.maxSearchResults, ws.maxSearchResults)

      const results: string[] = []
      let more = false
      let withheld = 0
      let hiddenTests = 0
      let scannedFiles = 0
      let scannedBytes = 0
      let byteCapHit = false
      let timedOut = false
      let batch: { path: string; text: string }[] = []
      let batchChars = 0

      const flush = async (): Promise<void> => {
        if (batch.length === 0) return
        const current = batch
        batch = []
        batchChars = 0
        const outcome = matcher.scan(
          current.map(entry => entry.text),
          limit + 1 - results.length,
        )
        if (outcome.timedOut) timedOut = true
        const split = new Map<number, string[]>()
        for (const hit of outcome.hits) {
          if (results.length >= limit) {
            more = true
            break
          }
          const entry = current[hit.text]
          if (!entry) continue
          let lines = split.get(hit.text)
          if (!lines) {
            lines = entry.text.split('\n')
            split.set(hit.text, lines)
          }
          const line = stripCr(lines[hit.line] ?? '')
          results.push(`${entry.path}:${hit.line + 1}: ${clipAround(line, hit.column, MAX_SEARCH_LINE_CHARS)}`)
        }
        await yieldToEventLoop()
        ctx.signal.throwIfAborted()
      }

      for (const path of ws.sortedPaths()) {
        if (more || timedOut || results.length > limit) break
        ctx.signal.throwIfAborted()
        if (glob && !glob(path)) continue
        const file = ws.snapshot.files.get(path)
        if (!file) continue
        if (ws.isWithheld(path)) {
          withheld++
          continue
        }
        if (file.isTest && !showTests) {
          hiddenTests++
          continue
        }
        if (scannedBytes + file.size > ws.maxSearchScanBytes) {
          byteCapHit = true
          break
        }
        scannedBytes += file.size
        scannedFiles++
        const text = ws.redacted(file)
        batch.push({ path, text })
        batchChars += text.length
        if (batchChars >= SEARCH_BATCH_CHARS || batch.length >= SEARCH_BATCH_FILES) await flush()
      }
      if (!more && !timedOut) await flush()

      const what = `${matcher.kind === 'regex' ? 'regex' : 'text'} ${JSON.stringify(args.pattern)}`
      const out: string[] = []
      if (results.length === 0) {
        out.push(`No matches for ${what} in ${scannedFiles} file${scannedFiles === 1 ? '' : 's'}.`)
      } else {
        out.push(`${results.length}${more ? '+' : ''} match${results.length === 1 && !more ? '' : 'es'} for ${what}:`)
        out.push(...results)
      }
      if (more) {
        out.push(`[More matches exist beyond ${limit}; narrow with path_glob or a more specific pattern.]`)
      }
      if (timedOut) {
        out.push(
          '[Search stopped early: the regular expression took too long (it may backtrack heavily). ' +
            `${results.length > 0 ? 'Only the matches found before it stopped are listed; ' : ''}` +
            'results are incomplete. Simplify the pattern or use a literal search.]',
        )
      }
      if (byteCapHit) {
        out.push(
          `[Search stopped after ${scannedFiles} file${scannedFiles === 1 ? '' : 's'} (${formatBytes(scannedBytes)}): ` +
            `the per-call scan limit is ${formatBytes(ws.maxSearchScanBytes)}. Results are incomplete; narrow with path_glob.]`,
        )
      }
      if (withheld > 0) out.push(`(${withheld} withheld file${withheld === 1 ? '' : 's'} not searched.)`)
      if (hiddenTests > 0) {
        out.push(
          `(${hiddenTests} test/fixture/example file${hiddenTests === 1 ? '' : 's'} not searched; set path_glob to a test location to include them.)`,
        )
      }
      return ws.finish(out.join('\n'))
    },
  })
}

// ---------------------------------------------------------------------------
// find_symbol
// ---------------------------------------------------------------------------

function findSymbolTool(ws: Workspace) {
  return defineTool({
    name: 'find_symbol',
    description:
      'Find where a function, class, method, or top-level variable is defined (JavaScript/TypeScript and Python). ' +
      'Returns "path:start-end kind" for each definition; never call sites (use search_code for those). ' +
      'Use "Class.method" to find one method of a class.',
    input: z.object({
      name: z.string().min(1).describe('Identifier to look up, e.g. "createUser" or "UserService.create".'),
    }),
    execute: async ({ name: rawName }) => {
      const name = rawName.trim()
      if (name.length > MAX_NAME_CHARS || !IDENTIFIER_PATH.test(name)) {
        return ws.error('find_symbol expects an identifier such as "handleLogin" or "UserService.create".')
      }
      const found = findSymbol(ws.snapshot, name, {
        ...(ws.astGrep ? { astGrep: ws.astGrep } : {}),
        limit: MAX_SYMBOL_RESULTS * 4,
      })
      let hiddenTests = 0
      const visible = found.filter(def => {
        if (ws.isWithheld(def.path)) return false
        if (!ws.includeTests && ws.snapshot.files.get(def.path)?.isTest === true) {
          hiddenTests++
          return false
        }
        return true
      })
      visible.sort(
        (a, b) => compareStrings(a.path, b.path) || a.startLine - b.startLine || compareStrings(a.kind, b.kind),
      )
      const shown = visible.slice(0, MAX_SYMBOL_RESULTS)
      const out: string[] = []
      if (shown.length === 0) {
        out.push(`No definitions named "${name}" found.`)
        if (hiddenTests === 0) {
          out.push(
            'It may be defined in a language without outline support, imported from a dependency, or created dynamically; try search_code.',
          )
        }
      } else {
        out.push(`${shown.length} definition${shown.length === 1 ? '' : 's'} of "${name}":`)
        for (const def of shown) out.push(`${def.path}:${def.startLine}-${def.endLine} ${def.kind}`)
        if (visible.length > shown.length) out.push(`… ${visible.length - shown.length} more not shown.`)
      }
      if (hiddenTests > 0) {
        out.push(`(${hiddenTests} definition${hiddenTests === 1 ? '' : 's'} in test files not shown.)`)
      }
      return ws.finish(out.join('\n'), false, true)
    },
  })
}

// ---------------------------------------------------------------------------
// file_outline
// ---------------------------------------------------------------------------

function fileOutlineTool(ws: Workspace) {
  return defineTool({
    name: 'file_outline',
    description:
      'Summarize one JavaScript/TypeScript or Python file without reading it: its imports (line, module, names) and ' +
      'its functions, classes, methods, and top-level variables with line ranges. Use it to decide which lines to read.',
    input: z.object({
      path: z.string().describe('Workspace-relative file path, e.g. "src/services/auth.ts".'),
    }),
    execute: async ({ path: rawPath }) => {
      const path = normalizePath(rawPath)
      if (path === undefined) return ws.error(INVALID_PATH)
      if (ws.isWithheld(path)) return ws.withheldError(path)
      const file = ws.snapshot.files.get(path)
      if (!file) return ws.unknownPath(path)

      const outline = outlineFile(file, ws.astGrep)
      const header = `${path} (${file.language}, ${ws.lineCount(file)} lines)`
      if (outline.imports.length === 0 && outline.symbols.length === 0) {
        return ws.finish(
          `${header}\nNo imports or symbols found (outlines cover JavaScript/TypeScript and Python). Use read_file instead.`,
          false,
          true,
        )
      }
      const out = [header]
      out.push(outline.imports.length === 0 ? 'imports: none' : 'imports:')
      for (const imp of outline.imports) {
        const names = imp.names.length > 0 ? `  [${imp.names.join(', ')}]` : ''
        out.push(`  ${imp.line}: ${imp.source}${names}`)
      }
      out.push(outline.symbols.length === 0 ? 'symbols: none' : 'symbols:')
      for (const symbol of outline.symbols) {
        const range =
          symbol.startLine === symbol.endLine ? `${symbol.startLine}` : `${symbol.startLine}-${symbol.endLine}`
        out.push(`  ${range} ${symbol.kind} ${symbol.name}${symbol.exported ? ' (exported)' : ''}`)
      }
      return ws.finish(clipOutput(out), false, true)
    },
  })
}

// ---------------------------------------------------------------------------
// list_endpoints
// ---------------------------------------------------------------------------

function listEndpointsTool(ws: Workspace) {
  return defineTool({
    name: 'list_endpoints',
    description:
      'List HTTP endpoints detected by static route extraction as "METHOD route  path:line  middleware=[…] auth=[…]". ' +
      'auth lists middleware or decorators whose names suggest authentication or authorization (a hint, not proof). ' +
      'Filter by the directory of the declaring file (under) or by HTTP method.',
    input: z.object({
      under: z
        .string()
        .optional()
        .describe('Only endpoints declared in files below this workspace-relative directory, e.g. "src/admin".'),
      method: z
        .string()
        .optional()
        .describe('HTTP method such as "POST". Endpoints accepting ANY method are included.'),
      limit: z
        .number()
        .int()
        .positive()
        .optional()
        .describe(`Maximum endpoints to list (default ${DEFAULT_ENDPOINT_LIMIT}, at most ${MAX_ENDPOINT_LIMIT}).`),
    }),
    execute: async ({ under, method, limit }) => {
      const dir = under === undefined ? '' : normalizeDir(under)
      if (dir === undefined) {
        return ws.error(`${INVALID_DIR} Note: under filters by source directory, not by URL path.`)
      }
      const wantedMethod = method?.trim().toUpperCase()
      const max = Math.min(limit ?? DEFAULT_ENDPOINT_LIMIT, MAX_ENDPOINT_LIMIT)
      const all = ws.endpoints.filter(endpoint => isEndpointVisible(endpoint, path => ws.isWithheld(path)))
      if (all.length === 0) {
        return ws.finish(
          'No endpoints were detected. Route extraction covers common JavaScript/TypeScript and Python frameworks ' +
            '(Express, Fastify, Koa, Hono, NestJS, Next.js, Flask, FastAPI, Django). Search manually with search_code, ' +
            'e.g. for "router.", "app.get", "@app.route", "urlpatterns", or "@Controller".',
        )
      }
      const matched = all
        .filter(endpoint => isUnder(endpoint.declaredAt.path, dir))
        .filter(
          endpoint =>
            !wantedMethod || endpoint.method.toUpperCase() === wantedMethod || endpoint.method.toUpperCase() === 'ANY',
        )
        .sort(
          (a, b) =>
            compareStrings(a.route, b.route) ||
            compareStrings(a.method, b.method) ||
            compareStrings(a.declaredAt.path, b.declaredAt.path) ||
            a.declaredAt.startLine - b.declaredAt.startLine,
        )
      if (matched.length === 0) {
        return ws.finish(
          `No endpoints match the filters (${all.length} endpoint${all.length === 1 ? '' : 's'} detected in total).`,
        )
      }
      const out = [`${matched.length} endpoint${matched.length === 1 ? '' : 's'}:`]
      for (const endpoint of matched.slice(0, max)) out.push(formatEndpoint(endpoint))
      if (matched.length > max)
        out.push(`… ${matched.length - max} more not shown; raise limit or filter with under/method.`)
      return ws.finish(clipOutput(out), false, true)
    },
  })
}

function formatEndpoint(endpoint: Endpoint): string {
  const at = endpoint.declaredAt
  const list = (items: readonly string[]): string =>
    `[${items.map(item => clipText(item.replace(/\s+/g, ' '), MAX_ENDPOINT_LABEL_CHARS)).join(', ')}]`
  let line =
    `${endpoint.method} ${endpoint.route}  ${at.path}:${at.startLine}` +
    `  middleware=${list(endpoint.middleware)} auth=${list(endpoint.authHints)}`
  const handler = endpoint.handler
  if (handler && (handler.path !== at.path || handler.startLine !== at.startLine || handler.endLine !== at.endLine)) {
    line += `  handler=${handler.path}:${handler.startLine}-${handler.endLine}`
  }
  return line
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function compileGlobSafe(
  glob: string,
): { readonly ok: true; readonly matcher: GlobMatcher } | { readonly ok: false; readonly error: string } {
  const normalized = normalizeGlob(glob)
  if (normalized === undefined) return { ok: false, error: INVALID_GLOB }
  try {
    return { ok: true, matcher: compileGlob(normalized) }
  } catch {
    return { ok: false, error: 'The glob has too many {a,b} alternatives; simplify it.' }
  }
}

/** Whether a glob or directory filter explicitly targets test, fixture, or example files. */
function targetsTests(filter: string | undefined): boolean {
  return filter !== undefined && filter !== '' && TEST_TARGET.test(filter)
}

function describeScope(glob: string | undefined, dir: string): string {
  const parts: string[] = []
  if (dir !== '') parts.push(`under ${dir}/`)
  if (glob !== undefined && glob.trim() !== '') parts.push(`matching ${JSON.stringify(glob.trim())}`)
  return parts.length === 0 ? '' : ` ${parts.join(' ')}`
}

/**
 * Clip a matching line to at most `max` characters of source, keeping the
 * match in view: leading indentation is dropped, and long lines are cut to a
 * window around `column` marked with `…`.
 */
export function clipAround(line: string, column: number, max: number): string {
  const indent = line.length - line.trimStart().length
  const text = line.trim()
  if (text.length <= max) return text
  const at = Math.max(0, column - indent)
  const start = Math.max(0, Math.min(at - Math.floor(max / 4), text.length - max))
  const body = text.slice(start, start + max)
  return (start > 0 ? '…' : '') + body + (start + max < text.length ? '…' : '')
}

/** Join output lines, cutting at {@link MAX_OUTPUT_CHARS} with a note. */
function clipOutput(lines: readonly string[]): string {
  const out: string[] = []
  let chars = 0
  for (const [index, line] of lines.entries()) {
    if (chars + line.length > MAX_OUTPUT_CHARS) {
      out.push(`… output cut: ${lines.length - index} more lines not shown.`)
      break
    }
    out.push(line)
    chars += line.length + 1
  }
  return out.join('\n')
}

function formatBytes(bytes: number): string {
  if (bytes >= 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MB`
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${bytes} B`
}

function compareStrings(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0
}

function positiveInt(value: number | undefined, fallback: number): number {
  return typeof value === 'number' && Number.isFinite(value) && value >= 1 ? Math.floor(value) : fallback
}
