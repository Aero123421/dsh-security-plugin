import { describe, expect, it } from 'vitest'
import { isLinkableReference } from '../../src/client/views/FindingDetail.tsx'

describe('isLinkableReference', () => {
  it('links well-known advisory and weakness databases over https', () => {
    expect(isLinkableReference('https://cwe.mitre.org/data/definitions/89.html')).toBe(true)
    expect(isLinkableReference('https://osv.dev/vulnerability/GHSA-xxxx-yyyy-zzzz')).toBe(true)
    expect(isLinkableReference('https://github.com/advisories/GHSA-xxxx-yyyy-zzzz')).toBe(true)
    expect(isLinkableReference('https://cheatsheetseries.owasp.org/cheatsheets/XSS.html')).toBe(true)
  })

  it('shows anything else as text', () => {
    for (const value of [
      'javascript:alert(1)',
      'http://cwe.mitre.org/data/definitions/89.html',
      'https://cwe.mitre.org.evil.example/x',
      'https://evil.example/cwe-89',
      'https://github.com/attacker/repo',
      'https://user:pass@osv.dev/x',
      'https://osv.dev:8443/x',
      'CWE-89',
      '',
    ]) {
      expect(isLinkableReference(value), value).toBe(false)
    }
  })
})
