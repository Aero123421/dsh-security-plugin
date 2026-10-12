import { describe, expect, it } from 'vitest'
import { cvss3BaseScore, osvSeverity, queryOsv, severityFromScore } from '../../../src/host/analysis/osv.ts'
import type { Dependency } from '../../../src/host/analysis/types.ts'

const ENDPOINT = 'https://osv.test'

function dep(overrides: Partial<Dependency> & Pick<Dependency, 'name' | 'version'>): Dependency {
  return {
    ecosystem: 'npm',
    exact: true,
    manifest: 'package-lock.json',
    line: 10,
    direct: true,
    dev: false,
    ...overrides,
  }
}

interface Recorded {
  method: string
  url: string
  body: unknown
}

/** A fake fetch routing by URL; records every request. */
function fakeFetch(
  handler: (req: Recorded) => { status?: number; json?: unknown } | Promise<{ status?: number; json?: unknown }>,
): { fetch: typeof fetch; requests: Recorded[] } {
  const requests: Recorded[] = []
  const impl = async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const url = String(input)
    const body = typeof init?.body === 'string' ? JSON.parse(init.body) : undefined
    const req = { method: init?.method ?? 'GET', url, body }
    requests.push(req)
    const { status = 200, json } = await handler(req)
    return new Response(JSON.stringify(json ?? {}), { status, headers: { 'content-type': 'application/json' } })
  }
  return { fetch: impl as typeof fetch, requests }
}

const LODASH_VULN = {
  id: 'GHSA-35jh-r3h4-6jhm',
  summary: 'Command Injection in lodash',
  aliases: ['CVE-2021-23337'],
  database_specific: { severity: 'HIGH', cwe_ids: ['CWE-77', 'CWE-94'] },
  severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H' }],
  affected: [
    {
      package: { ecosystem: 'npm', name: 'lodash' },
      ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '4.17.21' }] }],
    },
    {
      package: { ecosystem: 'npm', name: 'lodash-es' },
      ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '4.17.99' }] }],
    },
  ],
  references: [
    { type: 'WEB', url: 'https://example.com/web' },
    { type: 'ADVISORY', url: 'https://nvd.nist.gov/vuln/detail/CVE-2021-23337' },
    { type: 'PACKAGE', url: 'javascript:alert(1)' },
  ],
}

describe('queryOsv', () => {
  it('queries exact versions in batches, fetches details, and maps signals', async () => {
    const { fetch, requests } = fakeFetch(req => {
      if (req.url === `${ENDPOINT}/v1/querybatch`) {
        const queries = (req.body as { queries: { package: { name: string } }[] }).queries
        return {
          json: {
            results: queries.map(q => (q.package.name === 'lodash' ? { vulns: [{ id: LODASH_VULN.id }] } : {})),
          },
        }
      }
      if (req.url === `${ENDPOINT}/v1/vulns/${LODASH_VULN.id}`) return { json: LODASH_VULN }
      return { status: 404 }
    })
    const deps = [
      dep({ name: 'lodash', version: '4.17.20' }),
      dep({ name: 'lodash', version: '4.17.20', manifest: 'apps/web/package-lock.json', line: 4 }),
      dep({ name: 'express', version: '4.18.2' }),
      dep({ name: 'chalk', version: '^5.0.0', exact: false, manifest: 'package.json' }),
      dep({ name: 'Flask', version: '2.0.0', ecosystem: 'PyPI', manifest: 'requirements.txt' }),
    ]
    const result = await queryOsv(deps, { endpoint: `${ENDPOINT}/`, fetch, batchSize: 2 })

    expect(result.warnings).toEqual([])
    expect(result.queried).toBe(3)
    const batches = requests.filter(r => r.url.endsWith('/querybatch'))
    expect(batches).toHaveLength(2)
    expect(batches[0]!.body).toEqual({
      queries: [
        { package: { name: 'lodash', ecosystem: 'npm' }, version: '4.17.20' },
        { package: { name: 'express', ecosystem: 'npm' }, version: '4.18.2' },
      ],
    })
    // Only names, versions, and ecosystems leave the machine.
    expect(JSON.stringify(batches)).not.toMatch(/package-lock|requirements|manifest/)
    expect(requests.filter(r => r.url.includes('/v1/vulns/'))).toHaveLength(1)

    expect(result.signals).toHaveLength(1)
    const signal = result.signals[0]!
    expect(signal).toMatchObject({
      analyzer: 'osv',
      kind: 'dependency',
      category: 'dependency',
      ruleId: 'GHSA-35jh-r3h4-6jhm',
      severity: 'high',
      cwe: 'CWE-77',
      location: { path: 'package-lock.json', startLine: 10, endLine: 10 },
      snippet: 'lodash@4.17.20',
      fingerprintParts: ['osv', 'GHSA-35jh-r3h4-6jhm', 'npm', 'lodash', '4.17.20'],
    })
    expect(signal.title).toContain('GHSA-35jh-r3h4-6jhm')
    expect(signal.recommendation).toContain('4.17.21')
    expect(signal.recommendation).not.toContain('4.17.99')
    expect(signal.message).toMatch(/not analyzed/)
    expect(signal.message).toContain('apps/web/package-lock.json')
    expect(signal.references![0]).toBe('https://osv.dev/vulnerability/GHSA-35jh-r3h4-6jhm')
    expect(signal.references).toContain('https://nvd.nist.gov/vuln/detail/CVE-2021-23337')
    expect(signal.references!.some(url => url.startsWith('javascript:'))).toBe(false)
    expect(signal.references!.length).toBeLessThanOrEqual(5)
    expect(signal.metadata).toMatchObject({ alias: 'GHSA-35jh-r3h4-6jhm', cvssScore: 7.2 })
  })

  it('follows next_page_token for a single entry', async () => {
    const { fetch, requests } = fakeFetch(req => {
      if (req.url.endsWith('/querybatch')) {
        const query = (req.body as { queries: { page_token?: string }[] }).queries[0]!
        if (query.page_token === 'p2') return { json: { results: [{ vulns: [{ id: 'OSV-2' }] }] } }
        return { json: { results: [{ vulns: [{ id: 'OSV-1' }], next_page_token: 'p2' }] } }
      }
      const id = req.url.split('/').pop()!
      return { json: { id, summary: `vuln ${id}` } }
    })
    const result = await queryOsv([dep({ name: 'pkg', version: '1.0.0' })], { endpoint: ENDPOINT, fetch })
    expect(result.signals.map(s => s.ruleId)).toEqual(['OSV-1', 'OSV-2'])
    const follow = requests.filter(r => r.url.endsWith('/querybatch'))[1]!
    expect(follow.body).toEqual({
      queries: [{ package: { name: 'pkg', ecosystem: 'npm' }, version: '1.0.0', page_token: 'p2' }],
    })
    // No CVSS or label: defaults to medium.
    expect(result.signals[0]!.severity).toBe('medium')
  })

  it('keeps partial results and warns on failures', async () => {
    const { fetch } = fakeFetch(req => {
      if (req.url.endsWith('/querybatch')) {
        const name = (req.body as { queries: { package: { name: string } }[] }).queries[0]!.package.name
        if (name === 'bad') return { status: 503 }
        return { json: { results: [{ vulns: [{ id: 'GHSA-aaaa-bbbb-cccc' }] }] } }
      }
      return { status: 500 }
    })
    const result = await queryOsv([dep({ name: 'good', version: '1.0.0' }), dep({ name: 'bad', version: '1.0.0' })], {
      endpoint: ENDPOINT,
      fetch,
      batchSize: 1,
    })
    expect(result.queried).toBe(1)
    expect(result.signals.map(s => s.ruleId)).toEqual(['GHSA-aaaa-bbbb-cccc'])
    expect(result.warnings).toEqual([
      'OSV batch query failed with HTTP 503',
      'OSV details for GHSA-aaaa-bbbb-cccc failed with HTTP 500',
    ])
  })

  it('treats network errors and timeouts as warnings', async () => {
    const throwing = (async () => {
      throw new TypeError('fetch failed')
    }) as unknown as typeof fetch
    const failed = await queryOsv([dep({ name: 'a', version: '1.0.0' })], { endpoint: ENDPOINT, fetch: throwing })
    expect(failed.signals).toEqual([])
    expect(failed.warnings).toEqual(['OSV batch query failed: fetch failed'])

    const hanging = ((_: unknown, init?: RequestInit) =>
      new Promise((_resolve, reject) => {
        init?.signal?.addEventListener('abort', () => reject(init.signal?.reason))
      })) as unknown as typeof fetch
    const slow = await queryOsv([dep({ name: 'a', version: '1.0.0' })], {
      endpoint: ENDPOINT,
      fetch: hanging,
      timeoutMs: 20,
    })
    expect(slow.warnings).toEqual(['OSV batch query failed: timed out'])
  })

  it('rejects when the caller aborts', async () => {
    const controller = new AbortController()
    const { fetch } = fakeFetch(() => {
      controller.abort(new Error('scan cancelled'))
      return { json: { results: [{}] } }
    })
    await expect(
      queryOsv([dep({ name: 'a', version: '1.0.0' }), dep({ name: 'b', version: '1.0.0' })], {
        endpoint: ENDPOINT,
        fetch,
        batchSize: 1,
        signal: controller.signal,
      }),
    ).rejects.toThrow('scan cancelled')
  })

  it('caps detail fetches at 300 and warns', async () => {
    const ids = Array.from({ length: 305 }, (_, i) => `OSV-2024-${i}`)
    const { fetch, requests } = fakeFetch(req => {
      if (req.url.endsWith('/querybatch')) return { json: { results: [{ vulns: ids.map(id => ({ id })) }] } }
      return { json: { id: req.url.split('/').pop() } }
    })
    const result = await queryOsv([dep({ name: 'a', version: '1.0.0' })], { endpoint: ENDPOINT, fetch })
    expect(requests.filter(r => r.url.includes('/v1/vulns/'))).toHaveLength(300)
    expect(result.warnings).toEqual([expect.stringMatching(/first 300/)])
    // Advisories without details are still reported.
    expect(result.signals).toHaveLength(305)
  })

  it('strips the v prefix from Go versions and ignores mismatched result counts', async () => {
    const { fetch, requests } = fakeFetch(() => ({ json: { results: [] } }))
    const result = await queryOsv([dep({ ecosystem: 'Go', name: 'golang.org/x/net', version: 'v0.17.0' })], {
      endpoint: ENDPOINT,
      fetch,
    })
    expect((requests[0]!.body as { queries: { version: string }[] }).queries[0]!.version).toBe('0.17.0')
    expect(result.queried).toBe(0)
    expect(result.warnings[0]).toMatch(/0 results for 1 queries/)
  })

  it('skips withdrawn advisories', async () => {
    const { fetch } = fakeFetch(req =>
      req.url.endsWith('/querybatch')
        ? { json: { results: [{ vulns: [{ id: 'GHSA-xxxx-yyyy-zzzz' }] }] } }
        : { json: { id: 'GHSA-xxxx-yyyy-zzzz', withdrawn: '2024-01-01T00:00:00Z' } },
    )
    const result = await queryOsv([dep({ name: 'a', version: '1.0.0' })], { endpoint: ENDPOINT, fetch })
    expect(result.signals).toEqual([])
  })
})

describe('CVSS v3 base score', () => {
  it.each([
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 9.8],
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N', 6.1],
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H', 10],
    ['CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N', 5.5],
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H', 7.5],
    ['CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H', 9.9],
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N', 0],
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:P/RL:O', 9.8],
  ])('%s → %s', (vector, score) => {
    expect(cvss3BaseScore(vector)).toBe(score)
  })

  it.each([
    'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N',
    'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H',
    'CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/A:L',
    'AV:N/AC:L/Au:N/C:P/I:P/A:P',
    'not a vector',
  ])('rejects %s', vector => {
    expect(cvss3BaseScore(vector)).toBeUndefined()
  })

  it('maps scores and labels to severities', () => {
    expect(severityFromScore(9.0)).toBe('critical')
    expect(severityFromScore(7.0)).toBe('high')
    expect(severityFromScore(4.0)).toBe('medium')
    expect(severityFromScore(0.1)).toBe('low')
    expect(severityFromScore(0)).toBe('info')
    expect(osvSeverity({ id: 'X', database_specific: { severity: 'MODERATE' } }).severity).toBe('medium')
    expect(osvSeverity({ id: 'X', severity: [{ type: 'CVSS_V3', score: '9.1' }] })).toEqual({
      severity: 'critical',
      score: 9.1,
    })
    expect(
      osvSeverity({ id: 'X', severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H' }] }),
    ).toEqual({ severity: 'high', score: 7.5 })
    expect(osvSeverity({ id: 'X' })).toEqual({ severity: 'medium' })
  })
})
