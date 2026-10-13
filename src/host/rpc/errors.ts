/**
 * RPC failure mapping. Only `RpcError` messages and zod issue paths reach the
 * browser; everything else becomes a generic `security/internal` failure and
 * the real error is logged on the Host. Failures never echo request input,
 * stack traces, or absolute paths.
 */

import { z } from 'zod'
import type { ErrorCode, RpcFailure } from '../../shared/contracts.ts'
import type { LoggerPort } from '../dsh/ports.ts'
import { maskDeep, type PathMasker } from '../paths.ts'

/** A failure the handler means to show the browser, with a stable code. */
export class RpcError extends Error {
  readonly code: ErrorCode
  readonly details: Readonly<Record<string, unknown>>

  constructor(code: ErrorCode, message: string, details: Record<string, unknown> = {}) {
    super(message)
    this.name = 'RpcError'
    this.code = code
    this.details = details
  }

  /** The wire shape of this error. */
  toFailure(): RpcFailure {
    return { code: this.code, message: this.message, details: { ...this.details } }
  }
}

/** One validation issue as sent to the browser: where and what, never the input. */
export interface RpcIssue {
  readonly path: string
  readonly message: string
}

const MAX_ISSUES = 20
const MAX_ISSUE_MESSAGE = 200
const MAX_PATH_SEGMENTS = 16
const MAX_SEGMENT_LENGTH = 64
const GENERIC_INTERNAL_MESSAGE = 'An internal error occurred. Check the DSH Host log for details.'

/** Render a zod issue path as `a.b[0].c`, bounded so hostile keys cannot bloat the reply. */
function formatIssuePath(path: readonly PropertyKey[]): string {
  let out = ''
  for (const segment of path.slice(0, MAX_PATH_SEGMENTS)) {
    if (typeof segment === 'number') {
      out += `[${segment}]`
      continue
    }
    const text = typeof segment === 'symbol' ? (segment.description ?? 'symbol') : segment
    const safe = text.replace(/[^\w$-]/g, '_').slice(0, MAX_SEGMENT_LENGTH)
    out += out === '' ? safe : `.${safe}`
  }
  if (path.length > MAX_PATH_SEGMENTS) out += '…'
  return out === '' ? '(root)' : out
}

/**
 * Build a browser-safe issue list. zod's default messages describe expected
 * types and bounds, but `unrecognized_keys` messages quote the attacker's key
 * names, so those are rewritten to name only how many keys were refused.
 */
export function issuesOf(error: z.core.$ZodError): RpcIssue[] {
  return error.issues.slice(0, MAX_ISSUES).map(issue => {
    const message =
      issue.code === 'unrecognized_keys'
        ? `Unrecognized key${issue.keys.length === 1 ? '' : 's'} (${issue.keys.length})`
        : issue.message.slice(0, MAX_ISSUE_MESSAGE)
    return { path: formatIssuePath(issue.path), message }
  })
}

/** A `security/bad-request` failure built from a zod error. */
export function badRequestFromZod(error: z.core.$ZodError, message = 'The request is invalid.'): RpcFailure {
  const issues = issuesOf(error)
  const more = error.issues.length - issues.length
  return { code: 'security/bad-request', message, details: more > 0 ? { issues, truncated: more } : { issues } }
}

/**
 * Map anything a handler threw to a wire failure.
 * - `RpcError` passes through, with absolute Host paths in its message and
 *   string details replaced by `maskPaths` when given.
 * - Any zod error (classic or core) becomes `security/bad-request` with
 *   `details.issues`.
 * - Anything else becomes `security/internal` with a generic message; the
 *   real error is logged at `error`.
 */
export function toRpcFailure(error: unknown, logger: LoggerPort, maskPaths?: PathMasker): RpcFailure {
  if (error instanceof RpcError) {
    const failure = error.toFailure()
    if (!maskPaths) return failure
    return { code: failure.code, message: maskPaths(failure.message), details: maskDeep(failure.details, maskPaths) }
  }
  if (error instanceof z.core.$ZodError) return badRequestFromZod(error)
  logger.error('dsh-security: internal RPC failure', error)
  return { code: 'security/internal', message: GENERIC_INTERNAL_MESSAGE, details: {} }
}
