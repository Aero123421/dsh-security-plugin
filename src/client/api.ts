/**
 * Typed wrapper over DSH's Connection RPC. Every Host method is reached as
 * `/api` + `dsh-security/<method>`. Transport throws (non-2xx, network) and
 * malformed envelopes become ordinary `RpcResult` failures so callers only
 * ever branch on `ok`.
 */

import {
  RPC_NAMESPACE,
  type RpcFailure,
  type RpcMethodName,
  type RpcRequest,
  type RpcResponse,
  type RpcResult,
} from '../shared/contracts.ts'
import type { DshRpc } from './dsh.ts'

/** Client-only failure codes (never produced by the Host). */
export const TRANSPORT_ERROR = 'security/transport'
export const ABORTED_ERROR = 'security/aborted'

export const RPC_CHANNEL = '/api'

export interface SecurityApi {
  call<M extends RpcMethodName>(
    method: M,
    payload: RpcRequest<M>,
    signal?: AbortSignal,
  ): Promise<RpcResult<RpcResponse<M>>>
}

export function failure(code: string, message: string, details: Record<string, unknown> = {}): RpcFailure {
  return { code, message, details }
}

export function createApi(rpc: DshRpc): SecurityApi {
  return {
    async call<M extends RpcMethodName>(
      method: M,
      payload: RpcRequest<M>,
      signal?: AbortSignal,
    ): Promise<RpcResult<RpcResponse<M>>> {
      let raw: unknown
      try {
        raw = await rpc.call(RPC_CHANNEL, `${RPC_NAMESPACE}/${method}`, payload, signal)
      } catch (error) {
        if (signal?.aborted || isAbortError(error)) {
          return { ok: false, error: failure(ABORTED_ERROR, 'The request was cancelled.') }
        }
        return { ok: false, error: failure(TRANSPORT_ERROR, messageOf(error), { method }) }
      }
      return normalize<RpcResponse<M>>(raw, method)
    },
  }
}

function normalize<T>(raw: unknown, method: string): RpcResult<T> {
  if (typeof raw !== 'object' || raw === null || !('ok' in raw)) {
    return { ok: false, error: failure(TRANSPORT_ERROR, 'Malformed response from DSH.', { method }) }
  }
  const envelope = raw as { ok: unknown; value?: unknown; error?: unknown }
  if (envelope.ok === true) return { ok: true, value: envelope.value as T }
  const error = (typeof envelope.error === 'object' && envelope.error !== null ? envelope.error : {}) as {
    code?: unknown
    message?: unknown
    details?: unknown
  }
  return {
    ok: false,
    error: failure(
      typeof error.code === 'string' && error.code ? error.code : 'security/internal',
      typeof error.message === 'string' ? error.message : '',
      typeof error.details === 'object' && error.details !== null ? (error.details as Record<string, unknown>) : {},
    ),
  }
}

function isAbortError(error: unknown): boolean {
  return typeof error === 'object' && error !== null && (error as { name?: unknown }).name === 'AbortError'
}

function messageOf(error: unknown): string {
  if (error instanceof Error && error.message) return error.message
  if (typeof error === 'string' && error) return error
  return 'Could not reach DSH.'
}
