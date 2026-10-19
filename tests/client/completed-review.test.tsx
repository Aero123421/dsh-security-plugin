import { act } from 'react'
import { afterEach, describe, expect, it } from 'vitest'
import { createController, type SecurityController } from '../../src/client/controller.ts'
import { analyzerReasonText, diagnosticText, getTranslator } from '../../src/client/i18n.ts'
import { SecurityPage } from '../../src/client/views/SecurityPage.tsx'
import type { Coverage, ScanDetail } from '../../src/shared/contracts.ts'
import { reviewOutcome } from '../../src/shared/review.ts'
import {
  byText,
  click,
  fail,
  fakeApi,
  flush,
  makeBootstrap,
  makeDetail,
  makeFinding,
  makeSettings,
  mount,
  ok,
  type Mounted,
} from './helpers.tsx'

const models = { hunter: { provider: 'test', model: 'reviewer' } }
function coverage(completed: number, planned: number, failed = 0, skipped = 0): Coverage {
  return {
    files: { total: 20, analyzed: 20, readByAi: completed ? 2 : 0, excluded: 0 },
    endpoints: { total: 2, reviewed: 0 },
    tasks: { completed, planned, failed, skipped },
    analyzers: [],
    discardedUnverifiable: 0,
    gaps: [],
  }
}

let controller: SecurityController | undefined
let mounted: Mounted | undefined
afterEach(() => {
  mounted?.unmount()
  controller?.dispose()
  mounted = undefined
  controller = undefined
  document.body.innerHTML = ''
})

async function render(detail: ScanDetail, lang: 'en' | 'ja' = 'en') {
  const api = fakeApi({
    getBootstrap: () => ok(makeBootstrap({ settings: makeSettings({ ui: { language: lang } }) })),
    listWorkspaces: () => ok([{ id: 'ws-1', title: 'Demo', displayPath: '~/demo' }]),
    listScans: () => ok([detail.summary]),
    listModels: () => ok([]),
    listToolkit: () => ok([]),
    getScan: () => ok(detail),
    listFindings: () => ok([makeFinding({ source: 'ai', verification: 'potential', closure: 'open_proof_gap' })]),
    listEvents: () =>
      ok([
        {
          seq: 1,
          at: detail.summary.createdAt,
          level: 'error',
          type: 'worker-end',
          message: 'Provider refused this request.',
        },
      ]),
  })
  controller = createController({ api, storage: null, host: {}, dshLocale: lang })
  mounted = mount(<SecurityPage controller={controller} />)
  await flush(15)
  return { api, container: mounted.container }
}

function diagnosticsOf(root: ParentNode): HTMLDetailsElement {
  const found = [...root.querySelectorAll('details')].find(
    e => e.querySelector(':scope > summary')?.textContent === 'Usage and activity',
  )
  if (!found) throw new Error('no usage and activity disclosure')
  return found
}

describe('review completion is separate from process completion', () => {
  it.each([
    ['not-run', coverage(0, 0)],
    ['failed', coverage(0, 4, 4)],
    ['partial', coverage(2, 15, 1, 12)],
    ['complete', coverage(4, 4)],
  ] as const)('classifies %s without claiming safety', (state, value) => {
    expect(reviewOutcome({ models, coverage: value })).toEqual({
      state,
      completed: value.tasks.completed,
      planned: value.tasks.planned,
    })
  })

  it('does not count tasks whose targets no longer exist as missing review', () => {
    const stale: Coverage = {
      ...coverage(4, 6, 0, 2),
      gapDetails: [{ code: 'stale-tasks', params: { count: 2 }, fallback: '2 obsolete review task(s) were skipped' }],
    }
    expect(reviewOutcome({ models, coverage: stale })).toEqual({ state: 'complete', completed: 4, planned: 4 })
    // Work skipped for other reasons (budget, task limits) still leaves the review incomplete.
    const mixed: Coverage = { ...stale, tasks: { completed: 4, planned: 7, failed: 0, skipped: 3 } }
    expect(reviewOutcome({ models, coverage: mixed })).toEqual({ state: 'partial', completed: 4, planned: 5 })
  })

  it('distinguishes built-in only from legacy unknown AI coverage', () => {
    expect(reviewOutcome({ models: {} }).state).toBe('builtin')
    expect(reviewOutcome({ models }).state).toBe('unknown')
  })

  it.each([
    ['not-run', coverage(0, 0), 'No AI review tasks were scheduled'],
    ['failed', coverage(0, 5, 5), 'AI review failed: 0 of 5 tasks completed'],
    ['partial', coverage(2, 15, 1, 12), 'AI review incomplete: 2 of 15 tasks completed'],
  ] as const)('puts %s coverage and retained diagnostics on completed results', async (_state, value, label) => {
    const detail = makeDetail(
      {},
      {
        models,
        coverage: value,
        notices: [{ key: 'budget-tokens', level: 'warn', text: 'Token budget exhausted.', at: '2026-10-01T10:00:00Z' }],
      },
    )
    const { container, api } = await render(detail)
    const card = container.querySelector('.dshsec-results')!
    const reviewLine = card.querySelector('.dshsec-review-line')!
    expect(reviewLine.textContent).toContain(label)
    expect(card.textContent).toContain('token budget ran out')
    expect(card.textContent).toContain('Some findings due a second opinion were not reviewed')
    const diagnostics = diagnosticsOf(card)
    await click(diagnostics.querySelector('summary')!)
    expect(diagnostics.textContent).toContain('AI requests')
    expect(diagnostics.textContent).toContain('Reviewers')
    // The Host's sentence names what ended and why.
    expect(diagnostics.querySelector('.dshsec-feed-msg')?.textContent).toBe('Provider refused this request.')
    expect(api.callsOf('listEvents')).toHaveLength(1)
    // How complete the review was is read before the findings; what was covered comes after them.
    const list = card.querySelector('.dshsec-flist')!
    const coverageEl = card.querySelector('.dshsec-coverage')!
    expect(reviewLine.compareDocumentPosition(list) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
    expect(list.compareDocumentPosition(coverageEl) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
  })

  it('does not infer all findings reviewed from one completed skeptic', async () => {
    const detail = makeDetail(
      {},
      {
        models,
        coverage: coverage(2, 3, 0, 1),
        workers: [
          {
            id: 'worker-1',
            role: 'skeptic',
            title: 'Verify finding A',
            model: 'reviewer',
            state: 'done',
            turns: 1,
            toolCalls: 0,
            startedAt: '2026-10-01T10:00:00Z',
          },
        ],
      },
    )
    const { api, container } = await render(detail)
    expect(container.textContent).toContain('Some findings due a second opinion were not reviewed')
    api.handlers.listFindings = () => ok([makeFinding({ independentlyReviewed: true })])
    await act(async () => {
      await controller!.loadFindings('scan-1', true)
    })
    await flush()
    expect(container.textContent).not.toContain('Some findings due a second opinion were not reviewed')
  })

  it('localizes structured diagnostics and preserves technical details in Japanese', async () => {
    const value = coverage(0, 3, 3)
    const detail = makeDetail(
      {},
      {
        models,
        coverage: {
          ...value,
          gaps: ['3 review tasks failed'],
          gapDetails: [{ code: 'failed-tasks', params: { count: 3 }, fallback: '3 review tasks failed' }],
          analyzers: [
            {
              id: 'ast-grep',
              available: false,
              source: 'builtin',
              reasonCode: 'native-unavailable',
              reason: 'native unavailable',
            },
          ],
        },
      },
    )
    const { container } = await render(detail, 'ja')
    expect(container.querySelector('.dshsec-review-line')?.textContent).toContain('AI レビューが失敗しました')
    expect(container.textContent).toContain('3件の作業が失敗しました')
    expect(container.textContent).toContain('この環境ではネイティブモジュールを利用できません')
    expect(container.querySelector('.dshsec-coverage details')?.textContent).toContain('native unavailable')
    // A localized label leads; the Host's English sentence follows as detail.
    const line = container.querySelector('.dshsec-feed-msg')!
    expect(line.firstChild?.textContent).toBe('AI の作業が終了しました。')
    expect(line.querySelector('.dshsec-feed-detail')?.textContent).toBe('Provider refused this request.')
  })

  it('offers a retry for failed completed-event retrieval without hiding results', async () => {
    const { api, container } = await render(makeDetail({}, { models, coverage: coverage(1, 1) }))
    api.handlers.listEvents = () => fail('security/transport')
    await act(async () => {
      await controller!.loadScanEvents('scan-1', true)
    })
    await flush()
    const diagnostics = diagnosticsOf(container)
    expect(diagnostics.textContent).toContain('Couldn’t reach DSH')
    expect(container.querySelector('.dshsec-review-line')?.textContent).toBe('AI review completed (1 tasks).')
    api.handlers.listEvents = () => ok([])
    await click(byText(diagnostics, 'button', 'Retry'))
    await flush()
    expect(diagnostics.textContent).not.toContain('Couldn’t reach DSH')
  })

  it('offers a budget top-up on a partial scan and continues it in place', async () => {
    const detail = makeDetail(
      {},
      {
        models,
        coverage: coverage(2, 15, 1, 12),
        usage: { llmCalls: 10, inputTokens: 2_900_000, outputTokens: 50_000, toolCalls: 20, elapsedMs: 60_000 },
        notices: [{ key: 'budget-tokens', level: 'warn', text: 'Token budget exhausted.', at: '2026-10-01T10:00:00Z' }],
      },
    )
    const { api, container } = await render(detail)
    expect(container.textContent).toContain('Add budget')
    api.handlers.extendScanBudget = () => ok({ ...detail.summary, status: 'queued' as const, phase: 'hunt' as const })
    await click(byText(container, 'button', '+100%'))
    await flush()
    // Tokens are the binding dimension (98% used); calls and minutes stay untouched.
    expect(api.callsOf('extendScanBudget')).toEqual([{ scanId: 'scan-1', addTokens: 3_000_000 }])
  })

  it('does not offer a budget top-up when the scheduled review completed', async () => {
    const { container } = await render(makeDetail({}, { models, coverage: coverage(4, 4) }))
    expect(container.textContent).not.toContain('Add budget')
  })

  it('does not offer a budget top-up when no budget limit stopped the scan', async () => {
    // Skipped tasks can be obsolete targets or a failed provider; more budget would not run them.
    const { container } = await render(makeDetail({}, { models, coverage: coverage(2, 15, 1, 12) }))
    expect(container.querySelector('.dshsec-review-line')?.textContent).toContain('AI review incomplete')
    expect(container.textContent).not.toContain('Add budget')
  })

  it('shows findings counts as plain report rows, not dashboard widgets', async () => {
    const { container } = await render(makeDetail({}, { models, coverage: coverage(4, 4) }))
    const items = [...container.querySelectorAll('.dshsec-sevsum-item')]
    expect(items).toHaveLength(5)
    expect(items.find(r => r.textContent?.includes('High'))?.textContent).toContain('1')
    // Certainty is one line of counts under the severities, not explanation columns.
    expect(container.querySelector('.dshsec-sevsum .dshsec-meta')?.textContent).toContain('need proof')
    expect(container.querySelector('.dshsec-summary-panel, .dshsec-distbar, .dshsec-ledger, .dshsec-tile')).toBeNull()
  })

  it('groups legacy gap text under a single disclosure', async () => {
    const value = { ...coverage(1, 1), gaps: ['legacy gap one', 'legacy gap two'] }
    const { container } = await render(makeDetail({}, { models, coverage: value }))
    const coverageEl = container.querySelector('.dshsec-coverage')!
    const disclosures = [...coverageEl.querySelectorAll('details')]
    expect(disclosures).toHaveLength(1)
    expect(disclosures[0]!.querySelector('summary')?.textContent).toContain('older scan')
    await click(disclosures[0]!.querySelector('summary')!)
    expect(disclosures[0]!.textContent).toContain('legacy gap one')
    expect(disclosures[0]!.textContent).toContain('legacy gap two')
  })

  it('keeps unknown and legacy diagnostic text out of localized primary copy', () => {
    const tr = getTranslator('ja')
    expect(diagnosticText(tr, { code: 'future-code', fallback: 'raw english' })).not.toContain('raw english')
    expect(
      analyzerReasonText(tr, { id: 'sast', available: false, source: 'builtin', reason: 'raw english' }),
    ).not.toContain('raw english')
  })
})
