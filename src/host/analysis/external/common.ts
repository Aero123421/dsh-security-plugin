/**
 * Pieces shared by the external analyzer runners: tool handles, result
 * builders, report-path normalization, and redacted snippet extraction.
 */

import { open } from 'node:fs/promises'
import { isAbsolute, relative, sep } from 'node:path'
import type { AnalyzerId, AnalyzerStatus } from '../../../shared/contracts.ts'
import { type Redactor, redactText } from '../secrets.ts'
import type { AnalyzerRun, Signal, Snapshot } from '../types.ts'

/** A resolved external executable. */
export interface ToolHandle {
  /** Absolute path to the executable. */
  readonly path: string
  readonly source: 'managed' | 'path'
  readonly version?: string
}

/** Options every external runner accepts. */
export interface ExternalRunOptions {
  /** Resolved executable; `undefined` yields an "unavailable" run. */
  readonly tool: ToolHandle | undefined
  /** Absolute canonical workspace root (normally `snapshot.root`). */
  readonly root: string
  /**
   * When given, results are limited to files in the snapshot (ignored,
   * vendored, and excluded files are dropped) and snippets come from the
   * snapshot text, redacted with `redactor` when provided.
   */
  readonly snapshot?: Snapshot
  readonly redactor?: Redactor
  /** Default 10 minutes. */
  readonly timeoutMs?: number
  readonly signal?: AbortSignal
  /** Cap per output stream. Default 64 MiB. */
  readonly maxOutputBytes?: number
}

export const DEFAULT_EXTERNAL_TIMEOUT_MS = 10 * 60_000
export const DEFAULT_MAX_OUTPUT_BYTES = 64 * 1024 * 1024
const MAX_SNIPPET_LINES = 6
const MAX_SNIPPET_CHARS = 1200

/** Analyzer run for a tool that could not be used at all. */
export function unavailableRun(
  id: AnalyzerId,
  reason: string,
  started: number,
  warnings: string[] = [],
  reasonCode = 'unavailable',
): AnalyzerRun {
  return {
    status: { id, available: false, source: 'disabled', reason, reasonCode },
    signals: [],
    durationMs: Date.now() - started,
    warnings,
  }
}

/** Analyzer run for a tool that was found but failed (timeout, crash, unreadable output). */
export function failedRun(
  id: AnalyzerId,
  tool: ToolHandle,
  reason: string,
  started: number,
  warnings: string[] = [],
): AnalyzerRun {
  return {
    status: statusOf(id, tool, false, reason),
    signals: [],
    durationMs: Date.now() - started,
    warnings: [...warnings, reason],
  }
}

/** Analyzer run that completed. */
export function completedRun(
  id: AnalyzerId,
  tool: ToolHandle,
  signals: Signal[],
  started: number,
  warnings: string[],
): AnalyzerRun {
  return { status: statusOf(id, tool, true), signals, durationMs: Date.now() - started, warnings }
}

function statusOf(id: AnalyzerId, tool: ToolHandle, available: boolean, reason?: string): AnalyzerStatus {
  return {
    id,
    available,
    source: tool.source,
    ...(tool.version ? { version: tool.version } : {}),
    ...(reason ? { reason, reasonCode: 'failed' } : {}),
  }
}

/**
 * Convert a path reported by a tool into a workspace-relative POSIX path.
 * Returns `undefined` for anything outside the root.
 */
export function toWorkspacePath(root: string, reported: string, pathPrefix?: string): string | undefined {
  if (reported === '') return undefined
  const native = reported.replace(/[\\/]/g, sep)
  const rel = isAbsolute(native) ? relative(root, native) : native.replace(/^(?:\.[\\/])+/, '')
  if (rel === '' || isAbsolute(rel)) return undefined
  const posix = rel.split(sep).join('/')
  if (posix.split('/').some(segment => segment === '..' || segment === '')) return undefined
  return pathPrefix ? `${pathPrefix}/${posix}` : posix
}

/** Read a tool-written report file with a size cap. */
export async function readReport(path: string, maxBytes: number): Promise<string> {
  const fh = await open(path, 'r')
  try {
    const st = await fh.stat()
    if (!st.isFile()) throw new Error('report is not a regular file')
    if (st.size > maxBytes) throw new Error(`report exceeds ${maxBytes} bytes`)
    const buffer = Buffer.alloc(st.size)
    const { bytesRead } = await fh.read(buffer, 0, st.size, 0)
    return buffer.subarray(0, bytesRead).toString('utf8')
  } finally {
    await fh.close()
  }
}

/**
 * Snippet for a reported range: snapshot text (redacted through `redactor`
 * when available) or the tool's own excerpt, always through `redactText`.
 */
export function snippetFor(
  options: Pick<ExternalRunOptions, 'snapshot' | 'redactor'>,
  path: string,
  startLine: number,
  endLine: number,
  fallback: string,
  cache: Map<string, readonly string[]>,
): string {
  const file = options.snapshot?.files.get(path)
  let text = fallback
  if (file) {
    let lines = cache.get(path)
    if (!lines) {
      const content = options.redactor ? options.redactor.redactFile(path, file.content) : file.content
      lines = content.split('\n')
      cache.set(path, lines)
    }
    const from = Math.max(1, startLine)
    const to = Math.min(Math.max(from, endLine), from + MAX_SNIPPET_LINES - 1)
    text = lines
      .slice(from - 1, to)
      .map(line => line.replace(/\r$/, ''))
      .join('\n')
  }
  const redacted = redactText(text)
  return redacted.length > MAX_SNIPPET_CHARS ? `${redacted.slice(0, MAX_SNIPPET_CHARS - 1)}…` : redacted
}

/** Collapse whitespace so fingerprints survive reformatting. */
export function normalizeForFingerprint(text: string): string {
  return text.replace(/\s+/g, ' ').trim()
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

export function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error)
}

/** First non-empty stderr line, trimmed, for user-facing failure reasons. */
export function firstLine(text: string, max = 300): string {
  const line =
    text
      .split(/\r?\n/)
      .map(l => l.trim())
      .find(l => l !== '') ?? ''
  return line.length > max ? `${line.slice(0, max - 1)}…` : line
}

/** Compare dotted numeric versions; non-numeric parts compare as 0. */
export function compareVersions(a: string, b: string): number {
  const pa = a.split(/[.-]/).map(part => Number.parseInt(part, 10) || 0)
  const pb = b.split(/[.-]/).map(part => Number.parseInt(part, 10) || 0)
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const diff = (pa[i] ?? 0) - (pb[i] ?? 0)
    if (diff !== 0) return diff
  }
  return 0
}
