import { describe, expect, it } from 'vitest'
import { isLoopbackHostname, isLoopbackRequest } from '../../../src/host/rpc/loopback.ts'

function request(url: string, headers: Record<string, string> = {}): Request {
  return new Request(url, { method: 'POST', headers })
}

describe('isLoopbackRequest', () => {
  const viaBridge = 'http://dsh.internal/api/dsh-security/getBootstrap'

  it.each([
    ['localhost:3080', true],
    ['localhost', true],
    ['LOCALHOST:3080', true],
    ['app.localhost:3080', true],
    ['127.0.0.1', true],
    ['127.0.0.1:3080', true],
    ['127.10.20.30:8080', true],
    ['[::1]:3080', true],
    ['[::1]', true],
    ['[0:0:0:0:0:0:0:1]:3080', true],
    ['192.168.1.10', false],
    ['192.168.1.10:3080', false],
    ['10.0.0.5:3080', false],
    ['example.com', false],
    ['localhost.example.com', false],
    ['127.0.0.1.nip.io', false],
    ['128.0.0.1', false],
    ['127.0.0.256', false],
    ['[::2]:3080', false],
    ['[fe80::1]', false],
    ['0.0.0.0:3080', false],
    ['', false],
    ['localhost:abc', false],
  ])('host header %j → %s', (host, expected) => {
    expect(isLoopbackRequest(request(viaBridge, { host }))).toBe(expected)
  })

  it('ignores X-Forwarded-Host and Forwarded from a reverse proxy', () => {
    const proxied = request(viaBridge, {
      host: 'security.example.com',
      'x-forwarded-host': 'localhost:3080',
      'x-forwarded-for': '127.0.0.1',
      forwarded: 'for=127.0.0.1;host=localhost',
    })
    expect(isLoopbackRequest(proxied)).toBe(false)
  })

  it('does not trust a loopback X-Forwarded-Host when Host is a LAN address', () => {
    expect(isLoopbackRequest(request(viaBridge, { host: '192.168.1.10:3080', 'x-forwarded-host': '127.0.0.1' }))).toBe(
      false,
    )
  })

  it('falls back to the URL hostname without a host header', () => {
    expect(isLoopbackRequest(request('http://localhost:3080/api/x'))).toBe(true)
    expect(isLoopbackRequest(request('http://[::1]:3080/api/x'))).toBe(true)
    expect(isLoopbackRequest(request('https://127.0.0.1/api/x'))).toBe(true)
    expect(isLoopbackRequest(request('http://192.168.1.10:3080/api/x'))).toBe(false)
    expect(isLoopbackRequest(request('https://example.com/api/x'))).toBe(false)
  })

  it('treats non-HTTP carriers (DSH Desktop in-process) as loopback', () => {
    expect(isLoopbackRequest(request('app://dsh/api/dsh-security/getBootstrap'))).toBe(true)
    expect(isLoopbackRequest(request('app://dsh/api/dsh-security/getBootstrap', { host: 'example.com' }))).toBe(true)
  })
})

describe('isLoopbackHostname', () => {
  it('handles brackets, trailing dots, and case', () => {
    expect(isLoopbackHostname('[::1]')).toBe(true)
    expect(isLoopbackHostname('::1')).toBe(true)
    expect(isLoopbackHostname('localhost.')).toBe(true)
    expect(isLoopbackHostname('Dev.LocalHost')).toBe(true)
    expect(isLoopbackHostname('::')).toBe(false)
    expect(isLoopbackHostname('1::1')).toBe(false)
  })
})
