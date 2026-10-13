import { describe, expect, it } from 'vitest'
import { RPC_METHOD_NAMES } from '../../../src/shared/contracts.ts'
import { RpcError } from '../../../src/host/rpc/errors.ts'
import type { RpcCallContext } from '../../../src/host/rpc/server.ts'
import { createMethodHandler, registerRpcRoutes, rpcRoutePath } from '../../../src/host/rpc/server.ts'
import {
  envelope,
  failureOf,
  fakeConnection,
  readEnvelope,
  recordingLogger,
  rpcRequest,
  stubHandlers,
} from './helpers.ts'

describe('createMethodHandler: happy path', () => {
  it('validates, dispatches, and wraps the value in a server-response envelope', async () => {
    const logger = recordingLogger()
    const calls: { payload: unknown; call: RpcCallContext }[] = []
    const handler = createMethodHandler(
      'getScan',
      async (payload, call) => {
        calls.push({ payload, call })
        return { scanId: payload.scanId } as never
      },
      { logger },
    )
    const request = rpcRequest('getScan', envelope('getScan', { rpcId: 'abc-123', payload: { scanId: 'scan_1' } }))
    const response = await handler(request)

    expect(response.status).toBe(200)
    expect(response.headers.get('cache-control')).toBe('no-store')
    expect(response.headers.get('content-type')).toMatch(/^application\/json/)
    expect(await response.json()).toEqual({
      type: 'server-response',
      rpcId: 'abc-123',
      result: { ok: true, value: { scanId: 'scan_1' } },
    })
    expect(calls).toHaveLength(1)
    expect(calls[0]!.payload).toEqual({ scanId: 'scan_1' })
    expect(calls[0]!.call.loopback).toBe(true)
    expect(calls[0]!.call.signal).toBe(calls[0]!.call.request.signal)
    expect(logger.entries).toEqual([])
  })

  it('passes the request abort signal through to the handler', async () => {
    const controller = new AbortController()
    let seen: AbortSignal | undefined
    const handler = createMethodHandler(
      'listWorkspaces',
      async (_payload, call) => {
        seen = call.signal
        return []
      },
      { logger: recordingLogger() },
    )
    const request = new Request(rpcRequest('listWorkspaces', envelope('listWorkspaces')), {
      signal: controller.signal,
    })
    await handler(request)
    expect(seen).toBeDefined()
    controller.abort()
    expect(seen!.aborted).toBe(true)
  })

  it('accepts a missing payload as {} for methods without arguments', async () => {
    const handler = createMethodHandler('getBootstrap', async payload => ({ echoed: payload }) as never, {
      logger: recordingLogger(),
    })
    const body = await readEnvelope(
      await handler(rpcRequest('getBootstrap', envelope('getBootstrap', { omitPayload: true }))),
    )
    expect(body.result).toEqual({ ok: true, value: { echoed: {} } })
  })

  it('treats a missing payload as {} and still rejects it for methods with required fields', async () => {
    const handler = createMethodHandler('getScan', async () => ({}) as never, { logger: recordingLogger() })
    const body = await readEnvelope(await handler(rpcRequest('getScan', envelope('getScan', { omitPayload: true }))))
    const failure = failureOf(body)
    expect(failure.code).toBe('security/bad-request')
    expect(failure.details.issues).toEqual([{ path: 'scanId', message: expect.any(String) }])
  })

  it('accepts content-type with parameters', async () => {
    const handler = createMethodHandler('listToolkit', async () => [], { logger: recordingLogger() })
    const response = await handler(
      rpcRequest('listToolkit', envelope('listToolkit'), {
        headers: { 'content-type': 'Application/JSON; charset=utf-8' },
      }),
    )
    expect((await readEnvelope(response)).result).toEqual({ ok: true, value: [] })
  })

  it('marks requests through a non-loopback Host as remote', async () => {
    let loopback: boolean | undefined
    const handler = createMethodHandler(
      'listModels',
      async (_payload, call) => {
        loopback = call.loopback
        return []
      },
      { logger: recordingLogger() },
    )
    await handler(rpcRequest('listModels', envelope('listModels'), { headers: { host: '192.168.1.10:3080' } }))
    expect(loopback).toBe(false)
  })
})

describe('createMethodHandler: transport failures', () => {
  const ok = () => createMethodHandler('listToolkit', async () => [], { logger: recordingLogger(), maxBodyBytes: 256 })

  it('answers 405 to non-POST methods', async () => {
    for (const method of ['GET', 'HEAD', 'PUT']) {
      const response = await ok()(rpcRequest('listToolkit', envelope('listToolkit'), { method }))
      expect(response.status).toBe(405)
      expect(response.headers.get('allow')).toBe('POST')
      expect(response.headers.get('cache-control')).toBe('no-store')
    }
  })

  it('answers 415 to non-JSON content types', async () => {
    for (const type of [
      'text/plain',
      'application/x-www-form-urlencoded',
      'multipart/form-data',
      'application/jsonx',
    ]) {
      const response = await ok()(
        rpcRequest('listToolkit', envelope('listToolkit'), { headers: { 'content-type': type } }),
      )
      expect(response.status).toBe(415)
    }
    const missing = new Request('http://dsh.internal/api/dsh-security/listToolkit', { method: 'POST', body: '{}' })
    missing.headers.delete('content-type')
    expect((await ok()(missing)).status).toBe(415)
  })

  it('answers 413 when content-length exceeds maxBodyBytes', async () => {
    const big = JSON.stringify(envelope('listToolkit', { rpcId: 'x'.repeat(300) }))
    const response = await ok()(
      rpcRequest('listToolkit', big, { headers: { 'content-length': String(new TextEncoder().encode(big).length) } }),
    )
    expect(response.status).toBe(413)
  })

  it('answers 413 when the streamed body exceeds maxBodyBytes without a content-length', async () => {
    const chunk = new TextEncoder().encode('x'.repeat(100))
    let pulls = 0
    const stream = new ReadableStream<Uint8Array>({
      pull(controller) {
        pulls++
        if (pulls > 50) controller.close()
        else controller.enqueue(chunk)
      },
    })
    const request = rpcRequest('listToolkit', undefined, { body: stream })
    expect(request.headers.get('content-length')).toBeNull()
    const response = await ok()(request)
    expect(response.status).toBe(413)
    expect(pulls).toBeLessThan(10)
  })

  it('answers 413 when the actual body is larger than a lying content-length', async () => {
    const body = JSON.stringify(envelope('listToolkit', { rpcId: 'y'.repeat(400) }))
    const encoder = new TextEncoder()
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(encoder.encode(body))
        controller.close()
      },
    })
    const request = rpcRequest('listToolkit', undefined, { body: stream, headers: { 'content-length': '10' } })
    expect((await ok()(request)).status).toBe(413)
  })

  it('answers 400 to a malformed content-length', async () => {
    const response = await ok()(
      rpcRequest('listToolkit', envelope('listToolkit'), { headers: { 'content-length': 'abc' } }),
    )
    expect(response.status).toBe(400)
  })

  it('answers 400 to invalid JSON and invalid UTF-8', async () => {
    expect((await ok()(rpcRequest('listToolkit', '{not json'))).status).toBe(400)
    expect((await ok()(rpcRequest('listToolkit', ''))).status).toBe(400)
    const bad = new Uint8Array([0x7b, 0x22, 0xff, 0x22, 0x7d])
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(bad)
        controller.close()
      },
    })
    expect((await ok()(rpcRequest('listToolkit', undefined, { body: stream }))).status).toBe(400)
  })

  it('answers 400 when no usable rpcId can be read', async () => {
    const cases: unknown[] = [
      [],
      'string',
      null,
      42,
      { type: 'client-request', method: 'dsh-security/listToolkit', payload: {} },
      { type: 'client-request', rpcId: 7, method: 'dsh-security/listToolkit', payload: {} },
      { type: 'client-request', rpcId: '', method: 'dsh-security/listToolkit', payload: {} },
      { type: 'client-request', rpcId: 'a\nb', method: 'dsh-security/listToolkit', payload: {} },
    ]
    const handler = createMethodHandler('listToolkit', async () => [], { logger: recordingLogger() })
    for (const body of cases) {
      const response = await handler(rpcRequest('listToolkit', JSON.stringify(body)))
      expect(response.status, JSON.stringify(body)).toBe(400)
    }
  })

  it('answers 400 to an rpcId longer than 128 characters', async () => {
    const handler = createMethodHandler('listToolkit', async () => [], { logger: recordingLogger() })
    expect((await handler(rpcRequest('listToolkit', envelope('listToolkit', { rpcId: 'r'.repeat(129) })))).status).toBe(
      400,
    )
    const atLimit = await handler(rpcRequest('listToolkit', envelope('listToolkit', { rpcId: 'r'.repeat(128) })))
    expect((await readEnvelope(atLimit)).rpcId).toBe('r'.repeat(128))
  })
})

describe('createMethodHandler: envelope failures', () => {
  const handler = createMethodHandler('listToolkit', async () => [], { logger: recordingLogger() })

  it('answers a 200 bad-request envelope for a wrong type when the rpcId is readable', async () => {
    const body = await readEnvelope(
      await handler(rpcRequest('listToolkit', envelope('listToolkit', { type: 'server-response' }))),
    )
    expect(body.type).toBe('server-response')
    expect(body.rpcId).toBe('rpc-1')
    const failure = failureOf(body)
    expect(failure.code).toBe('security/bad-request')
    expect(failure.details.issues).toEqual([{ path: 'type', message: expect.any(String) }])
  })

  it('rejects a method that does not match the route', async () => {
    for (const method of ['dsh-security/getScan', 'listToolkit', 'other/listToolkit', 'dsh-security/listToolkit/x']) {
      const body = await readEnvelope(await handler(rpcRequest('listToolkit', envelope('listToolkit', { method }))))
      const failure = failureOf(body)
      expect(failure.code).toBe('security/bad-request')
      expect(failure.details.issues).toEqual([{ path: 'method', message: 'Expected "dsh-security/listToolkit"' }])
    }
  })

  it('rejects a payload with unknown keys without echoing them', async () => {
    const body = await readEnvelope(
      await handler(rpcRequest('listToolkit', envelope('listToolkit', { payload: { '<script>secret': 1 } }))),
    )
    const failure = failureOf(body)
    expect(failure.code).toBe('security/bad-request')
    expect(JSON.stringify(failure)).not.toContain('secret')
  })

  it('rejects a non-object payload', async () => {
    for (const payload of [null, [], 'x', 3]) {
      const body = await readEnvelope(await handler(rpcRequest('listToolkit', envelope('listToolkit', { payload }))))
      expect(failureOf(body).code).toBe('security/bad-request')
    }
  })
})

describe('createMethodHandler: handler failures', () => {
  it('passes RpcError through and logs a warning naming the method', async () => {
    const logger = recordingLogger()
    const handler = createMethodHandler(
      'getScan',
      async () => {
        throw new RpcError('security/not-found', 'Scan not found.', { scanId: 'scan_1' })
      },
      { logger },
    )
    const body = await readEnvelope(
      await handler(rpcRequest('getScan', envelope('getScan', { payload: { scanId: 'scan_1' } }))),
    )
    expect(failureOf(body)).toEqual({
      code: 'security/not-found',
      message: 'Scan not found.',
      details: { scanId: 'scan_1' },
    })
    const warns = logger.entries.filter(entry => entry.level === 'warn')
    expect(warns).toHaveLength(1)
    expect(String(warns[0]!.args[0])).toContain('getScan')
  })

  it('does not leak internal error messages, stacks, or paths', async () => {
    const logger = recordingLogger()
    const secret = new Error('ENOENT: open /home/alice/.ssh/id_rsa')
    const handler = createMethodHandler(
      'listWorkspaces',
      async () => {
        throw secret
      },
      { logger },
    )
    const response = await handler(rpcRequest('listWorkspaces', envelope('listWorkspaces')))
    const text = await response.clone().text()
    expect(text).not.toContain('/home/alice')
    expect(text).not.toContain('ENOENT')
    expect(text).not.toContain('at ')
    const failure = failureOf(await readEnvelope(response))
    expect(failure.code).toBe('security/internal')
    expect(failure.details).toEqual({})
    expect(logger.entries.some(entry => entry.level === 'error' && entry.args.includes(secret))).toBe(true)
    expect(
      logger.entries.some(entry => entry.level === 'warn' && String(entry.args[0]).includes('listWorkspaces')),
    ).toBe(true)
  })

  it('maps a thrown non-Error value to security/internal', async () => {
    const handler = createMethodHandler(
      'listWorkspaces',
      async () => {
        throw 'boom /etc/passwd'
      },
      { logger: recordingLogger() },
    )
    const response = await handler(rpcRequest('listWorkspaces', envelope('listWorkspaces')))
    const text = await response.clone().text()
    expect(text).not.toContain('passwd')
    expect(failureOf(await readEnvelope(response)).code).toBe('security/internal')
  })

  it('maps an unserializable handler value to security/internal', async () => {
    const handler = createMethodHandler('listWorkspaces', async () => [{ id: 1n }] as never, {
      logger: recordingLogger(),
    })
    const failure = failureOf(
      await readEnvelope(await handler(rpcRequest('listWorkspaces', envelope('listWorkspaces')))),
    )
    expect(failure.code).toBe('security/internal')
  })
})

describe('registerRpcRoutes', () => {
  it('registers one exact POST route per method and disposes them all', async () => {
    const connection = fakeConnection()
    const dispose = registerRpcRoutes(connection, stubHandlers(), { logger: recordingLogger() })
    expect([...connection.routes.keys()].sort()).toEqual(RPC_METHOD_NAMES.map(rpcRoutePath).sort())
    for (const route of connection.routes.values()) {
      expect(route.path).toMatch(/^\/api\/dsh-security\/[A-Za-z]+$/)
      expect(route.methods).toEqual(['POST'])
      expect(route.requestBody).toBe('buffered')
    }
    await dispose()
    expect(connection.routes.size).toBe(0)
    expect(connection.disposed).toHaveLength(RPC_METHOD_NAMES.length)
    await dispose()
    expect(connection.disposed).toHaveLength(RPC_METHOD_NAMES.length)
  })

  it('routes each path to its own handler', async () => {
    const connection = fakeConnection()
    registerRpcRoutes(
      connection,
      stubHandlers({
        listScans: async payload => [{ id: `limit-${payload.limit}` }] as never,
        deleteScan: async payload => ({ deleted: payload.scanId === 's1' }),
      }),
      { logger: recordingLogger() },
    )
    const list = connection.routes.get('/api/dsh-security/listScans')!
    const listBody = await readEnvelope(
      await list.fetch(rpcRequest('listScans', envelope('listScans', { payload: { limit: 5 } }))),
    )
    expect(listBody.result).toEqual({ ok: true, value: [{ id: 'limit-5' }] })

    const del = connection.routes.get('/api/dsh-security/deleteScan')!
    const delBody = await readEnvelope(
      await del.fetch(rpcRequest('deleteScan', envelope('deleteScan', { payload: { scanId: 's1' } }))),
    )
    expect(delBody.result).toEqual({ ok: true, value: { deleted: true } })
  })

  it('rolls back earlier registrations when one fails', async () => {
    const connection = fakeConnection()
    connection.failOn = '/api/dsh-security/getScan'
    expect(() => registerRpcRoutes(connection, stubHandlers(), { logger: recordingLogger() })).toThrow(/refused/)
    await new Promise(resolve => setTimeout(resolve, 0))
    expect(connection.routes.size).toBe(0)
  })
})
