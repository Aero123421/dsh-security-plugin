import { describe, expect, it, vi } from 'vitest'
import { ABORTED_ERROR, createApi, RPC_CHANNEL, TRANSPORT_ERROR } from '../../src/client/api.ts'
import type { DshRpc } from '../../src/client/dsh.ts'
import { RPC_NAMESPACE } from '../../src/shared/contracts.ts'

function rpcReturning(impl: DshRpc['call']): DshRpc & { call: ReturnType<typeof vi.fn> } {
  return { call: vi.fn(impl) }
}

describe('createApi', () => {
  it('calls the namespaced endpoint on the /api channel with the payload and signal', async () => {
    const rpc = rpcReturning(async () => ({ ok: true, value: { scanId: 's1' } }))
    const api = createApi(rpc)
    const signal = new AbortController().signal
    const result = await api.call('createScan', { workspaceId: 'w', mode: 'quick' }, signal)
    expect(rpc.call).toHaveBeenCalledWith(
      RPC_CHANNEL,
      `${RPC_NAMESPACE}/createScan`,
      { workspaceId: 'w', mode: 'quick' },
      signal,
    )
    expect(RPC_CHANNEL).toBe('/api')
    expect(result).toEqual({ ok: true, value: { scanId: 's1' } })
  })

  it('passes Host failures through with code, message and details', async () => {
    const rpc = rpcReturning(async () => ({
      ok: false,
      error: { code: 'security/busy', message: 'Another scan is running', details: { queued: true } },
    }))
    const result = await createApi(rpc).call('getBootstrap', {})
    expect(result).toEqual({
      ok: false,
      error: { code: 'security/busy', message: 'Another scan is running', details: { queued: true } },
    })
  })

  it('fills in missing failure fields', async () => {
    const rpc = rpcReturning(async () => ({ ok: false, error: {} as never }))
    const result = await createApi(rpc).call('getBootstrap', {})
    expect(result).toEqual({ ok: false, error: { code: 'security/internal', message: '', details: {} } })
  })

  it('converts a thrown transport error (HTTP status ≠ 2xx) into security/transport', async () => {
    const rpc = rpcReturning(async () => {
      throw new Error('HTTP 502 Bad Gateway')
    })
    const result = await createApi(rpc).call('listWorkspaces', {})
    expect(result.ok).toBe(false)
    if (result.ok) return
    expect(result.error.code).toBe(TRANSPORT_ERROR)
    expect(result.error.code).toBe('security/transport')
    expect(result.error.message).toBe('HTTP 502 Bad Gateway')
    expect(result.error.details).toEqual({ method: 'listWorkspaces' })
  })

  it('converts non-Error throws too', async () => {
    const rpc = rpcReturning(async () => {
      throw 'boom'
    })
    const result = await createApi(rpc).call('listWorkspaces', {})
    expect(result).toMatchObject({ ok: false, error: { code: TRANSPORT_ERROR, message: 'boom' } })
  })

  it('maps a malformed envelope to security/transport', async () => {
    const rpc = rpcReturning(async () => 'nonsense' as never)
    const result = await createApi(rpc).call('listWorkspaces', {})
    expect(result).toMatchObject({ ok: false, error: { code: TRANSPORT_ERROR } })
  })

  it('maps an abort to security/aborted, not a transport failure', async () => {
    const abort = new AbortController()
    const rpc = rpcReturning(async () => {
      abort.abort()
      throw new DOMException('aborted', 'AbortError')
    })
    const result = await createApi(rpc).call('getScan', { scanId: 'x' }, abort.signal)
    expect(result).toMatchObject({ ok: false, error: { code: ABORTED_ERROR } })
  })
})
