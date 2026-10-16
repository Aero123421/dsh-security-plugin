import { describe, expect, it } from 'vitest'
import {
  certaintyCounts,
  DEFAULT_FINDINGS_FILTER,
  filterFindings,
  isDefaultFilter,
  toggleIn,
  topOpenFindings,
} from '../../src/client/findings.ts'
import { SEVERITIES } from '../../src/shared/domain.ts'
import { makeFinding } from './helpers.tsx'

const findings = [
  makeFinding({
    id: 'a',
    severity: 'medium',
    title: 'Weak hash',
    closure: 'open_proof_gap',
    verification: 'potential',
    source: 'sast',
  }),
  makeFinding({ id: 'b', severity: 'critical', title: 'RCE via eval', isNew: true }),
  makeFinding({ id: 'c', severity: 'high', title: 'Refuted XSS', closure: 'ruled_out', verification: 'refuted' }),
  makeFinding({ id: 'd', severity: 'low', title: 'Accepted thing', triage: 'accepted_risk' }),
  makeFinding({ id: 'e', severity: 'high', title: 'False alarm', triage: 'false_positive' }),
  makeFinding({ id: 'f', severity: 'high', title: 'Already fixed', triage: 'fixed' }),
  makeFinding({
    id: 'g',
    severity: 'info',
    title: 'Leaked key',
    source: 'secret',
    location: { path: 'config/prod.env.example', startLine: 1, endLine: 1 },
  }),
]

const ids = (list: { id: string }[]) => list.map(f => f.id)

describe('filterFindings', () => {
  it('hides ruled-out and triaged-away findings by default, most severe first', () => {
    expect(ids(filterFindings(findings, DEFAULT_FINDINGS_FILTER))).toEqual(['b', 'a', 'g'])
  })

  it('shows ruled-out findings when that closure is toggled on', () => {
    const filter = {
      ...DEFAULT_FINDINGS_FILTER,
      closures: toggleIn(DEFAULT_FINDINGS_FILTER.closures, 'ruled_out', [
        'confirmed',
        'open_proof_gap',
        'ruled_out',
      ] as const),
    }
    expect(ids(filterFindings(findings, filter))).toEqual(['b', 'c', 'a', 'g'])
  })

  it('shows triaged findings only when their triage state is toggled on', () => {
    const filter = { ...DEFAULT_FINDINGS_FILTER, triage: ['open', 'false_positive', 'fixed', 'accepted_risk'] as const }
    expect(ids(filterFindings(findings, filter))).toEqual(['b', 'f', 'e', 'a', 'd', 'g'])
  })

  it('filters by severity and source', () => {
    expect(ids(filterFindings(findings, { ...DEFAULT_FINDINGS_FILTER, severities: ['medium'] }))).toEqual(['a'])
    expect(ids(filterFindings(findings, { ...DEFAULT_FINDINGS_FILTER, source: 'secret' }))).toEqual(['g'])
  })

  it('searches title, summary and path, all words must match', () => {
    expect(ids(filterFindings(findings, { ...DEFAULT_FINDINGS_FILTER, text: 'EVAL' }))).toEqual(['b'])
    expect(ids(filterFindings(findings, { ...DEFAULT_FINDINGS_FILTER, text: 'prod.env' }))).toEqual(['g'])
    expect(ids(filterFindings(findings, { ...DEFAULT_FINDINGS_FILTER, text: 'leaked prod' }))).toEqual(['g'])
    expect(ids(filterFindings(findings, { ...DEFAULT_FINDINGS_FILTER, text: 'leaked nope' }))).toEqual([])
  })

  it('does not mutate the input', () => {
    const copy = [...findings]
    filterFindings(findings, DEFAULT_FINDINGS_FILTER)
    expect(findings).toEqual(copy)
  })
})

describe('helpers', () => {
  it('toggleIn keeps canonical order', () => {
    expect(toggleIn(['high', 'critical'], 'medium', SEVERITIES)).toEqual(['critical', 'high', 'medium'])
    expect(toggleIn(['critical', 'high'], 'critical', SEVERITIES)).toEqual(['high'])
  })

  it('isDefaultFilter detects changes', () => {
    expect(isDefaultFilter(DEFAULT_FINDINGS_FILTER)).toBe(true)
    expect(isDefaultFilter({ ...DEFAULT_FINDINGS_FILTER, text: ' x ' })).toBe(false)
    expect(isDefaultFilter({ ...DEFAULT_FINDINGS_FILTER, severities: ['high'] })).toBe(false)
  })

  it('certaintyCounts and topOpenFindings summarize a scan', () => {
    expect(certaintyCounts(findings)).toEqual({ confirmed: 5, open_proof_gap: 1, ruled_out: 1, isNew: 1 })
    expect(ids(topOpenFindings(findings, 2))).toEqual(['b', 'a'])
  })
})

it('precomputes lowercase search fields once per immutable findings array', () => {
  let reads = 0
  const finding = makeFinding()
  Object.defineProperty(finding, 'summary', {
    get: () => {
      reads++
      return 'Unique SUMMARY'
    },
  })
  const list = [finding]
  expect(filterFindings(list, { ...DEFAULT_FINDINGS_FILTER, text: 'unique' })).toHaveLength(1)
  expect(filterFindings(list, { ...DEFAULT_FINDINGS_FILTER, text: 'SUMMARY users.ts' })).toHaveLength(1)
  expect(reads).toBe(1)
  expect(filterFindings([...list], { ...DEFAULT_FINDINGS_FILTER, text: 'unique' })).toHaveLength(1)
  expect(reads).toBe(2)
})
