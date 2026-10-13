import type { RpcMethodName } from '../../../src/shared/contracts.ts'
import { RPC_METHOD_NAMES } from '../../../src/shared/contracts.ts'
import type { ConnectionFetchRoute, ConnectionPort, LoggerPort } from '../../../src/host/dsh/ports.ts'
import type { RpcHandlers } from '../../../src/host/rpc/server.ts'

export interface LogEntry {
  readonly level: 'debug' | 'info' | 'warn' | 'error'
  readonly args: readonly unknown[]
}

/** A logger that records every call. */
export function recordingLogger(): LoggerPort & { readonly entries: LogEntry[] } {
  const entries: LogEntry[] = []
  return {
    entries,
    debug: (...args) => entries.push({ level: 'debug', args }),
    info: (...args) => entries.push({ level: 'info', args }),
    warn: (...args) => entries.push({ level: 'warn', args }),
    error: (...args) => entries.push({ level: 'error', args }),
  }
}

/** A ConnectionPort that keeps routes in a map and enforces exact-path uniqueness like DSH. */
export function fakeConnection(): ConnectionPort & {
  readonly routes: Map<string, ConnectionFetchRoute>
  readonly disposed: string[]
  failOn?: string
} {
  const routes = new Map<string, ConnectionFetchRoute>()
  const disposed: string[] = []
  const port = {
    routes,
    disposed,
    failOn: undefined as string | undefined,
    fetch: {
      register(route: ConnectionFetchRoute): () => Promise<void> {
        if (route.path === port.failOn) throw new Error(`refused ${route.path}`)
        if (routes.has(route.path)) throw new Error(`duplicate ${route.path}`)
        routes.set(route.path, route)
        return async () => {
          routes.delete(route.path)
          disposed.push(route.path)
        }
      },
    },
  }
  return port
}

/** Handlers that reject every call; tests override the ones they exercise. */
export function stubHandlers(overrides: Partial<RpcHandlers> = {}): RpcHandlers {
  const entries = RPC_METHOD_NAMES.map(method => [
    method,
    async () => {
      throw new Error(`unexpected call to ${method}`)
    },
  ])
  return { ...(Object.fromEntries(entries) as RpcHandlers), ...overrides }
}

export interface EnvelopeInit {
  readonly method?: string
  readonly rpcId?: unknown
  readonly type?: unknown
  readonly payload?: unknown
  readonly omitPayload?: boolean
}

/** Build a `client-request` body for one method. */
export function envelope(method: RpcMethodName, init: EnvelopeInit = {}): Record<string, unknown> {
  const body: Record<string, unknown> = {
    type: init.type ?? 'client-request',
    rpcId: init.rpcId ?? 'rpc-1',
    method: init.method ?? `dsh-security/${method}`,
  }
  if (init.omitPayload !== true) body.payload = 'payload' in init ? init.payload : {}
  return body
}

export interface RequestInit2 {
  readonly url?: string
  readonly method?: string
  readonly headers?: Record<string, string>
  readonly body?: string | ReadableStream<Uint8Array>
}

/** Build a Request for an RPC route. */
export function rpcRequest(method: RpcMethodName, body: unknown, init: RequestInit2 = {}): Request {
  const httpMethod = init.method ?? 'POST'
  const raw = init.body ?? (typeof body === 'string' ? body : JSON.stringify(body))
  const hasBody = httpMethod !== 'GET' && httpMethod !== 'HEAD'
  return new Request(init.url ?? `http://dsh.internal/api/dsh-security/${method}`, {
    method: httpMethod,
    headers: { 'content-type': 'application/json', host: 'localhost:3080', ...init.headers },
    ...(hasBody ? { body: raw, duplex: 'half' } : {}),
  } as RequestInit)
}

export interface ServerResponseBody {
  readonly type: string
  readonly rpcId: string
  readonly result:
    | { readonly ok: true; readonly value: unknown }
    | {
        readonly ok: false
        readonly error: { readonly code: string; readonly message: string; readonly details: Record<string, unknown> }
      }
}

/** Parse a 200 envelope response. */
export async function readEnvelope(response: Response): Promise<ServerResponseBody> {
  if (response.status !== 200) throw new Error(`expected 200, got ${response.status}`)
  return (await response.json()) as ServerResponseBody
}

/** The failure from an envelope, or throw. */
export function failureOf(body: ServerResponseBody): {
  code: string
  message: string
  details: Record<string, unknown>
} {
  if (body.result.ok) throw new Error('expected a failure result')
  return body.result.error
}
