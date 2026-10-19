import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { isVerifiedCode, verifyCitation, type VerifiedCitation } from '../../../src/host/agents/roles/common.ts'
import type { HunterFinding } from '../../../src/host/agents/roles/hunter.ts'
import type { SkepticOutput } from '../../../src/host/agents/roles/skeptic.ts'
import { runSast } from '../../../src/host/analysis/sast/engine.ts'
import { Redactor } from '../../../src/host/analysis/secrets.ts'
import { snapshotQuoteSource } from '../../../src/host/evidence/quote.ts'
import {
  applySkepticOutput,
  markNewFindings,
  recordChains,
  recordHunterOutput,
  recordSignalFindings,
  signalFingerprint,
} from '../../../src/host/scan/findings.ts'
import { createHandlers } from '../../../src/host/service.ts'
import { openSecurityStore } from '../../../src/host/store/sqlite.ts'
import type { SecurityStore } from '../../../src/host/store/types.ts'
import { snapshotOf } from '../analysis/helpers.ts'
import { findingRecord, insertScan } from './factories.ts'
import { createHarness, registryOf } from './helpers.ts'

const now = () => '2026-10-16T00:00:00.000Z'
const ctx = {
  scanId: 'scan-1',
  taskId: 'task',
  agentRunId: 'run',
  model: 'test',
  now,
  signalIds: new Map<string, string>(),
  willReview: () => false,
}
function citation(text: string, quote = text, path = 'src/app.ts', line = 1): VerifiedCitation {
  const source = snapshotQuoteSource(snapshotOf({ [path]: text }), new Redactor([]))
  return verifyCitation(source, {
    description: 'Evidence',
    path,
    start_line: line,
    end_line: line + quote.split('\n').length - 1,
    quote,
  })
}
function hunter(attackPath: readonly VerifiedCitation[]): HunterFinding {
  return {
    title: 'IDOR',
    category: 'authz',
    cwe: 'CWE-639',
    severity: 'high',
    summary: 'Missing ownership.',
    impact: 'Reads private data.',
    preconditions: [],
    attackPath: [...attackPath],
    defenses: [],
    recommendation: 'Check ownership.',
    references: [],
  }
}
const output = (findings: HunterFinding[]) => ({ findings, assessments: [] })
const review = (overrides: Partial<SkepticOutput> = {}): SkepticOutput => ({
  verdict: 'confirmed',
  reasoning: 'Reviewed.',
  supporting: [],
  counterevidence: [],
  missingInformation: [],
  ...overrides,
})
let store: SecurityStore
beforeEach(() => {
  store = openSecurityStore(':memory:', { now: () => new Date(now()) })
  insertScan(store)
})
afterEach(() => store.close())

describe('B2 evidence classification', () => {
  it('blocks a defensive comment padded with adjacent sink code, but keeps a code-led guard citation', () => {
    const mixed = citation('// Input is sanitized and authorization is enforced by the trusted gateway.\nrun(input)')
    expect(isVerifiedCode(mixed)).toBe(false)
    const guard = citation('// owner check\nif (order.owner !== req.user.id) return res.status(403).end()')
    expect(isVerifiedCode(guard)).toBe(true)
    const finding = findingRecord()
    store.insertFinding(finding)
    expect(
      applySkepticOutput(store, finding, review({ verdict: 'refuted', counterevidence: [mixed] }), ctx).verification,
    ).toBe('inconclusive')
  })

  it.each([
    [
      'src/app.ts',
      'const claim = "Input is sanitized upstream by the trusted gateway"',
      'Input is sanitized upstream by the trusted gateway',
    ],
    [
      'src/app.py',
      'claim = """Input is sanitized upstream by the trusted gateway"""',
      'Input is sanitized upstream by the trusted gateway',
    ],
    [
      'src/app.ts',
      'const claim = `Input is sanitized upstream by the trusted gateway`',
      'Input is sanitized upstream by the trusted gateway',
    ],
  ])('rejects literal-interior prose in %s while accepting surrounding code', (path, text, quote) => {
    expect(isVerifiedCode(citation(text, quote, path))).toBe(false)
    expect(isVerifiedCode(citation('if (x === "admin") reject()', undefined, path))).toBe(true)
  })

  it.each([
    ['rs', '/* outer /* inner */ Input is sanitized upstream */'],
    ['swift', '/* outer /* inner */ Input is sanitized upstream */'],
    ['kt', '/* outer /* inner */ Input is sanitized upstream */'],
    ['scala', '/* outer /* inner */ Input is sanitized upstream */'],
    ['hs', '{- outer {- inner -} Input is sanitized upstream -}'],
  ])('keeps text after an inner block close non-code in %s', (ext, text) => {
    expect(isVerifiedCode(citation(`${text}\nrun(input)`, 'Input is sanitized upstream', `src/app.${ext}`))).toBe(false)
    expect(isVerifiedCode(citation(`${text}\nrun(input)`, 'run(input)', `src/app.${ext}`, 2))).toBe(true)
  })

  it.each(['// fabricated vulnerability in the repository', '})'])(
    'does not create a quick-mode finding from %s alone',
    text => {
      expect(recordHunterOutput(store, ctx, output([hunter([citation(text)])]))).toMatchObject({
        created: 0,
        discarded: 1,
      })
      expect(store.listFindings(ctx.scanId)).toEqual([])
    },
  )

  it('selects a real code key step and persists the supporting comment classification', () => {
    const code = citation('run(input)')
    const comment = citation('// narrative only', undefined, 'src/notes.ts')
    recordHunterOutput(store, ctx, output([hunter([code, comment])]))
    const [finding] = store.listFindings(ctx.scanId)
    expect(finding?.location?.path).toBe('src/app.ts')
    expect(finding?.attackPath[1]).toMatchObject({ commentOnly: true })
  })

  it.each(['// fabricated vulnerability', '})'])(
    'does not upgrade non-code attack paths or reviewer support to strong evidence: %s',
    text => {
      const comment = citation(text)
      const finding = findingRecord({ attackPath: [{ order: 1, ...comment }] })
      store.insertFinding(finding)
      expect(applySkepticOutput(store, finding, review({ supporting: [comment] }), ctx).verification).toBe(
        'inconclusive',
      )
    },
  )

  it('does not create a chain from comment-only steps even with two valid parts', () => {
    const a = findingRecord({ id: 'a', fingerprint: 'a' })
    const b = findingRecord({ id: 'b', fingerprint: 'b' })
    store.insertFinding(a)
    store.insertFinding(b)
    const finding = hunter([citation('// fabricated attack chain')])
    expect(
      recordChains(
        store,
        [{ ...finding, findingIds: ['F1', 'F2'] }],
        new Map([
          ['F1', a],
          ['F2', b],
        ]),
        ctx,
      ),
    ).toEqual({ created: 0, discarded: 1 })
    expect(store.listFindings(ctx.scanId)).toHaveLength(2)
  })
})

describe('B2 finding identities', () => {
  it('normalizes accepted numbered quotes in storage and keeps fingerprint, triage and isNew after line shifts', () => {
    const first = citation('run(input)', '1| run(input)')
    recordHunterOutput(store, ctx, output([hunter([first])]))
    const before = store.listFindings(ctx.scanId)[0]!
    store.setTriage('/work/shop', before.fingerprint, 'accepted_risk', undefined)
    insertScan(store, { id: 'scan-2' })
    const shifted = citation('\n\n\n\nrun(input)', '5| run(input)', 'src/app.ts', 500)
    expect(shifted).toMatchObject({ quoteCheck: 'relocated', location: { startLine: 5 } })
    recordHunterOutput(store, { ...ctx, scanId: 'scan-2' }, output([hunter([shifted])]))
    markNewFindings(store, 'scan-2', new Set([before.fingerprint]))
    const after = store.listFindings('scan-2')[0]!
    expect(after.fingerprint).toBe(before.fingerprint)
    expect(after.isNew).toBe(false)
    expect(store.getTriage('/work/shop', [after.fingerprint]).get(after.fingerprint)?.state).toBe('accepted_risk')
    expect(first.quote).toBe('run(input)')
    expect(shifted.quote).toBe('run(input)')
  })

  it('keeps distinct adjacent IDORs three lines apart but deduplicates a repeated issue', () => {
    const text = 'orders.find(req.params.id)\n\n\nusers.find(req.params.id)'
    const a = hunter([citation(text, 'orders.find(req.params.id)')])
    const b = hunter([citation(text, 'users.find(req.params.id)', 'src/app.ts', 4)])
    expect(recordHunterOutput(store, ctx, output([a, b, a]))).toMatchObject({ created: 2, merged: 1 })
    expect(store.listFindings(ctx.scanId)).toHaveLength(2)
  })

  it('stores two identical SAST sinks and keeps the remaining sink open after fixing one', async () => {
    const text = 'function a(req) { eval(req.query.code) }\nfunction b(req) { eval(req.query.code) }'
    const signals = (await runSast(snapshotOf({ 'src/app.js': text }))).signals.filter(s => s.kind === 'vulnerability')
    expect(signals).toHaveLength(2)
    expect(new Set(signals.map(signalFingerprint)).size).toBe(2)
    expect(recordSignalFindings(store, ctx.scanId, signals, now).created).toBe(2)
    const first = store.listFindings(ctx.scanId).find(f => f.location?.startLine === 1)!
    store.setTriage('/work/shop', first.fingerprint, 'accepted_risk', undefined)
    expect(Object.values(store.countOpenFindings(ctx.scanId, '/work/shop').counts).reduce((a, b) => a + b, 0)).toBe(1)
    insertScan(store, { id: 'scan-2' })
    const remaining = (await runSast(snapshotOf({ 'src/app.js': 'function b(req) { eval(req.query.code) }' }))).signals
    recordSignalFindings(store, 'scan-2', remaining, now)
    expect(Object.values(store.countOpenFindings('scan-2', '/work/shop').counts).reduce((a, b) => a + b, 0)).toBe(1)
    const shifted = (await runSast(snapshotOf({ 'src/app.js': '\n\nfunction b(req) { eval(req.query.code) }' })))
      .signals
    expect(shifted.map(signalFingerprint)).toEqual(remaining.map(signalFingerprint))
  })
})

describe('B2 triage through merge flips', () => {
  it.each([false, true])(
    'preserves triage when the merged status flips in both directions (merged first=%s)',
    async mergedFirst => {
      const h = createHarness({ store, workspaces: [{ id: 'ws-1', path: '/work/shop', title: 'Shop' }] })
      const handlers = createHandlers({
        ...h,
        toolkit: undefined,
        llm: () => undefined,
        workspaces: () => registryOf([{ id: 'ws-1', path: '/work/shop', title: 'Shop' }]),
        astGrep: async () => undefined,
        pluginVersion: 'test',
        now: () => new Date(),
      })
      const call = { request: new Request('http://localhost/'), loopback: true, signal: new AbortController().signal }
      const make = (id: string, scanId: string, merged: boolean) =>
        findingRecord({
          id,
          scanId,
          fingerprint: merged ? 'sast-fp' : 'ai-fp',
          mergedFingerprints: merged ? ['ai-fp'] : [],
        })
      const before = make('before', 'scan-1', mergedFirst)
      store.insertFinding(before)
      await handlers.setTriage(
        { scanId: 'scan-1', findingId: 'before', triage: 'accepted_risk', note: 'Reviewed' },
        call,
      )
      insertScan(store, { id: 'scan-2' })
      const after = make('after', 'scan-2', !mergedFirst)
      store.insertFinding(after)
      expect((await handlers.listFindings({ scanId: 'scan-2' }, call))[0]?.triage).toBe('accepted_risk')
      expect((await handlers.getFinding({ scanId: 'scan-2', findingId: 'after' }, call)).triageNote).toBe('Reviewed')
      expect(Object.values(store.countOpenFindings('scan-2', '/work/shop').counts).reduce((a, b) => a + b, 0)).toBe(0)
      await handlers.setTriage({ scanId: 'scan-2', findingId: 'after', triage: 'open' }, call)
      expect((await handlers.getFinding({ scanId: 'scan-1', findingId: 'before' }, call)).triage).toBe('open')
      expect(store.countOpenFindings('scan-1', '/work/shop').counts.high).toBe(1)
      await h.controller.dispose()
    },
  )
})
