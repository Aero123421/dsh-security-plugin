/**
 * Exact DSH Connection Fetch routes for every RPC method.
 *
 * DSH applies its Host/Origin trust fence and browser authentication before a
 * route runs. Each route then speaks the standard Connection unary envelope:
 *
 *   POST /api/dsh-security/<method>
 *   content-type: application/json
 *   { "type": "client-request", "rpcId": "…", "method": "dsh-security/<method>", "payload": … }
 *
 * and answers HTTP 200 with
 *
 *   { "type": "server-response", "rpcId": "…", "result": { "ok": true, "value": … } | { "ok": false, "error": … } }
 *
 * Transport problems that cannot be correlated to an `rpcId` answer with a
 * plain HTTP status instead (405, 413, 415, 400).
 */

import type { RpcFailure, RpcMethodName, RpcRequest, RpcResponse, RpcResult } from '../../shared/contracts.ts'
import { RPC_METHOD_NAMES, RPC_NAMESPACE } from '../../shared/contracts.ts'
import type { ConnectionFetchRoute, ConnectionPort, LoggerPort } from '../dsh/ports.ts'
import type { PathMasker } from '../paths.ts'
import { badRequestFromZod, toRpcFailure } from './errors.ts'
import { isLoopbackRequest } from './loopback.ts'
import { requestSchemaFor } from './schemas.ts'

/** Per-call facts a handler may use (e.g. loopback gating for high-risk settings). */
export interface RpcCallContext {
  readonly request: Request
  /** Whether the page is on the Host's own machine (see `isLoopbackRequest`). */
  readonly loopback: boolean
  /** Aborted when the browser goes away. */
  readonly signal: AbortSignal
}

/** One implementation per RPC method; payloads arrive already validated. */
export type RpcHandlers = {
  readonly [M in RpcMethodName]: (payload: RpcRequest<M>, call: RpcCallContext) => Promise<RpcResponse<M>>
}

export interface RpcServerOptions {
  readonly logger: LoggerPort
  /** Largest accepted request body in bytes; default {@link DEFAULT_MAX_BODY_BYTES}. */
  readonly maxBodyBytes?: number
  /** Replaces absolute Host paths in `RpcError` messages and details before they are sent. */
  readonly maskPaths?: PathMasker
}

/** Default request body cap: 1 MiB. */
export const DEFAULT_MAX_BODY_BYTES = 1024 * 1024
/** Longest accepted correlation id. */
export const MAX_RPC_ID_LENGTH = 128

const JSON_CONTENT_TYPE = 'application/json'
const RPC_ID_RE = /^[^\u0000-\u001f\u007f]+$/
const BASE_HEADERS = {
  'cache-control': 'no-store',
  'x-content-type-options': 'nosniff',
} as const

/** The exact Fetch path for one method. */
export function rpcRoutePath(method: RpcMethodName): string {
  return `/api/${RPC_NAMESPACE}/${method}`
}

/** The envelope `method` value for one method. */
export function rpcEndpoint(method: RpcMethodName): string {
  return `${RPC_NAMESPACE}/${method}`
}

// ---------------------------------------------------------------------------
// Responses
// ---------------------------------------------------------------------------

function plainResponse(status: number, text: string, extraHeaders: Record<string, string> = {}): Response {
  return new Response(text, {
    status,
    headers: { ...BASE_HEADERS, 'content-type': 'text/plain; charset=utf-8', ...extraHeaders },
  })
}

function envelopeResponse(rpcId: string, result: RpcResult<unknown>): Response {
  const body = JSON.stringify({ type: 'server-response', rpcId, result })
  return new Response(body, {
    status: 200,
    headers: { ...BASE_HEADERS, 'content-type': `${JSON_CONTENT_TYPE}; charset=utf-8` },
  })
}

function failureResponse(rpcId: string, error: RpcFailure): Response {
  return envelopeResponse(rpcId, { ok: false, error })
}

// ---------------------------------------------------------------------------
// Request reading
// ---------------------------------------------------------------------------

type BodyRead = { readonly ok: true; readonly bytes: Uint8Array } | { readonly ok: false; readonly status: 400 | 413 }

/** Read the body, refusing it as soon as it exceeds `limit` bytes. */
async function readBody(request: Request, limit: number): Promise<BodyRead> {
  const declared = request.headers.get('content-length')
  if (declared !== null) {
    const length = Number(declared.trim())
    if (!Number.isFinite(length) || length < 0) return { ok: false, status: 400 }
    if (length > limit) return { ok: false, status: 413 }
  }
  if (request.body === null) return { ok: true, bytes: new Uint8Array() }
  const reader = request.body.getReader()
  const chunks: Uint8Array[] = []
  let received = 0
  try {
    for (;;) {
      const { done, value } = await reader.read()
      if (done) break
      received += value.byteLength
      if (received > limit) {
        await reader.cancel().catch(() => undefined)
        return { ok: false, status: 413 }
      }
      chunks.push(value)
    }
  } catch {
    return { ok: false, status: 400 }
  } finally {
    reader.releaseLock()
  }
  const bytes = new Uint8Array(received)
  let offset = 0
  for (const chunk of chunks) {
    bytes.set(chunk, offset)
    offset += chunk.byteLength
  }
  return { ok: true, bytes }
}

function isJsonContentType(value: string | null): boolean {
  return value?.split(';', 1)[0]?.trim().toLowerCase() === JSON_CONTENT_TYPE
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

/** The correlation id when it is present and well formed. */
function readableRpcId(body: unknown): string | undefined {
  if (!isRecord(body)) return undefined
  const rpcId = body.rpcId
  if (typeof rpcId !== 'string' || rpcId.length > MAX_RPC_ID_LENGTH || !RPC_ID_RE.test(rpcId)) return undefined
  return rpcId
}

function envelopeIssue(path: string, message: string): RpcFailure {
  return {
    code: 'security/bad-request',
    message: 'The request envelope is invalid.',
    details: { issues: [{ path, message }] },
  }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/**
 * The Fetch handler for one method: transport checks, envelope and payload
 * validation, dispatch, and failure mapping. Exported for tests.
 */
export function createMethodHandler<M extends RpcMethodName>(
  method: M,
  handler: RpcHandlers[M],
  options: RpcServerOptions,
): (request: Request) => Promise<Response> {
  const limit = options.maxBodyBytes ?? DEFAULT_MAX_BODY_BYTES
  const endpoint = rpcEndpoint(method)
  const schema = requestSchemaFor(method)
  const { logger } = options

  return async request => {
    if (request.method !== 'POST') return plainResponse(405, 'method not allowed', { allow: 'POST' })
    if (!isJsonContentType(request.headers.get('content-type'))) {
      return plainResponse(415, 'content type must be application/json')
    }

    const read = await readBody(request, limit)
    if (!read.ok) return plainResponse(read.status, read.status === 413 ? 'request body too large' : 'bad request')

    let body: unknown
    try {
      body = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(read.bytes))
    } catch {
      return plainResponse(400, 'body is not JSON')
    }

    const rpcId = readableRpcId(body)
    if (rpcId === undefined || !isRecord(body)) return plainResponse(400, 'invalid client-request envelope')
    if (body.type !== 'client-request') {
      return failureResponse(rpcId, envelopeIssue('type', 'Expected "client-request"'))
    }
    if (body.method !== endpoint) {
      return failureResponse(rpcId, envelopeIssue('method', `Expected "${endpoint}"`))
    }

    // `JSON.stringify` drops an `undefined` payload, so a missing payload
    // means "no arguments"; methods with required fields still reject it.
    const parsed = schema.safeParse(body.payload === undefined ? {} : body.payload)
    if (!parsed.success) return failureResponse(rpcId, badRequestFromZod(parsed.error))

    const call: RpcCallContext = { request, loopback: isLoopbackRequest(request), signal: request.signal }
    let result: RpcResult<unknown>
    try {
      result = { ok: true, value: await handler(parsed.data, call) }
    } catch (error) {
      const failure = toRpcFailure(error, logger, options.maskPaths)
      logger.warn(`dsh-security: RPC ${method} failed (${failure.code})`)
      result = { ok: false, error: failure }
    }

    try {
      return envelopeResponse(rpcId, result)
    } catch (error) {
      // The handler returned something JSON cannot carry (BigInt, cycles).
      const failure = toRpcFailure(error, logger)
      logger.warn(`dsh-security: RPC ${method} returned an unserializable value`)
      return failureResponse(rpcId, failure)
    }
  }
}

function routeFor<M extends RpcMethodName>(
  method: M,
  handlers: RpcHandlers,
  options: RpcServerOptions,
): ConnectionFetchRoute {
  const handler: RpcHandlers[M] = handlers[method]
  return {
    path: rpcRoutePath(method),
    methods: ['POST'],
    requestBody: 'buffered',
    fetch: createMethodHandler(method, handler, options),
  }
}

/**
 * Registers one exact route per method; returns a disposer that unregisters
 * all of them. If any registration throws, the routes already registered are
 * removed before the error propagates.
 */
export function registerRpcRoutes(
  connection: ConnectionPort,
  handlers: RpcHandlers,
  options: RpcServerOptions,
): () => Promise<void> {
  const disposers: (() => Promise<void>)[] = []
  const disposeAll = async (): Promise<void> => {
    const pending = disposers.splice(0).reverse()
    const results = await Promise.allSettled(pending.map(dispose => dispose()))
    const failed = results.find(result => result.status === 'rejected')
    if (failed !== undefined) throw failed.reason
  }

  try {
    for (const method of RPC_METHOD_NAMES)
      disposers.push(connection.fetch.register(routeFor(method, handlers, options)))
  } catch (error) {
    void disposeAll().catch(cleanupError => {
      options.logger.warn('dsh-security: failed to roll back RPC routes', cleanupError)
    })
    throw error
  }

  return disposeAll
}
