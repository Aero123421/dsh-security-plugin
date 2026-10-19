import { afterEach, describe, expect, it } from 'vitest'
import { createController, type SecurityController } from '../../src/client/controller.ts'
import { DICTIONARIES } from '../../src/client/i18n.ts'
import { SecurityPage } from '../../src/client/views/SecurityPage.tsx'
import type { Coverage, CoverageUnit, ScanDetail } from '../../src/shared/contracts.ts'
import {
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

function unit(id: string, status: CoverageUnit['status'], overrides: Partial<CoverageUnit> = {}): CoverageUnit {
  return {
    id,
    title: `Part ${id}`,
    focus: ['injection'],
    paths: [`src/${id}.ts`],
    status,
    findings: status === 'finding' ? 1 : 0,
    origin: 'recon',
    ...overrides,
  }
}

function coverage(extra: Partial<Coverage> = {}): Coverage {
  return {
    files: { total: 40, analyzed: 40, readByAi: 12, excluded: 0 },
    endpoints: { total: 4, reviewed: 4 },
    tasks: { planned: 6, completed: 6, failed: 0, skipped: 0 },
    analyzers: [],
    discardedUnverifiable: 0,
    gaps: [],
    ...extra,
  }
}

/** 2 not examined, 1 undecided, 2 with findings, 7 examined. */
function ledger(): CoverageUnit[] {
  return [
    ...Array.from({ length: 7 }, (_, i) => unit(`ok${i}`, 'covered')),
    unit('f1', 'finding', { findings: 2, surface: 'POST /api/orders/:id' }),
    unit('f2', 'finding', { paths: ['src/a.ts', 'src/b.ts', 'src/c.ts'] }),
    unit('b1', 'blocked', {
      reason: { code: 'needs-runtime', fallback: 'Needs a running system to decide.' },
      origin: 'critic',
    }),
    unit('n1', 'not-run', { reason: { code: 'budget', fallback: 'Token budget exhausted.' }, origin: 'gap' }),
    unit('n2', 'not-run', { reason: { code: 'brand-new-code', fallback: 'Raw English from a newer Host.' } }),
  ]
}

let controller: SecurityController | undefined
let mounted: Mounted | undefined
function cleanup() {
  mounted?.unmount()
  controller?.dispose()
  mounted = undefined
  controller = undefined
  document.body.innerHTML = ''
}
afterEach(cleanup)

async function render(value: Coverage, lang: 'en' | 'ja' | 'zh' = 'en') {
  cleanup()
  const detail: ScanDetail = makeDetail({}, { models, coverage: value })
  const api = fakeApi({
    getBootstrap: () => ok(makeBootstrap({ settings: makeSettings({ ui: { language: lang } }) })),
    listWorkspaces: () => ok([{ id: 'ws-1', title: 'Demo', displayPath: '~/demo' }]),
    listScans: () => ok([detail.summary]),
    listModels: () => ok([]),
    listToolkit: () => ok([]),
    getScan: () => ok(detail),
    listFindings: () => ok([makeFinding()]),
    listEvents: () => ok([]),
  })
  controller = createController({ api, storage: null, host: {}, dshLocale: lang })
  mounted = mount(<SecurityPage controller={controller} />)
  await flush(15)
  const section = mounted.container.querySelector<HTMLElement>('.dshsec-coverage')
  if (!section) throw new Error('no coverage section')
  return section
}

function rowOf(section: HTMLElement, label: string): HTMLElement | undefined {
  return [...section.querySelectorAll<HTMLElement>('.dshsec-kv-row')].find(
    row => row.querySelector('dt')?.textContent === label,
  )
}

const titles = (root: ParentNode) => [...root.querySelectorAll('.dshsec-unit-title')].map(el => el.textContent)

describe('coverage ledger', () => {
  it('summarizes the parts on one line, leaving out empty counts', async () => {
    const section = await render(coverage({ units: ledger() }))
    expect(rowOf(section, 'Review plan')?.querySelector('dd')?.textContent).toBe(
      '12 parts: 7 examined, 2 with findings, 1 undecided, 2 not examined',
    )
    const small = await render(coverage({ units: [unit('a', 'covered')] }))
    expect(rowOf(small, 'Review plan')?.querySelector('dd')?.textContent).toBe('1 part: 1 examined')
  })

  it('lists not examined parts first, then undecided, findings and examined', async () => {
    const section = await render(coverage({ units: ledger() }))
    expect([...section.querySelectorAll('.dshsec-unit-group > .dshsec-h4')].map(h => h.textContent)).toEqual([
      'Not examined · 2',
      'Undecided · 1',
      'With findings · 2',
      'Examined, nothing to report · 7',
    ])
    expect(titles(section)).toEqual([
      'Part n1',
      'Part n2',
      'Part b1',
      'Part f1',
      'Part f2',
      ...Array.from({ length: 7 }, (_, i) => `Part ok${i}`),
    ])
  })

  it('shows unexamined and undecided parts in full and collapses the rest behind one disclosure', async () => {
    const section = await render(coverage({ units: ledger() }))
    const disclosure = section.querySelector<HTMLDetailsElement>('.dshsec-units > details.dshsec-disclosure')!
    expect(disclosure.open).toBe(false)
    expect(disclosure.querySelector(':scope > summary')?.textContent).toBe('Show 9 more parts')
    // Everything that was not examined sits outside the disclosure.
    expect(titles(disclosure)).toHaveLength(9)
    const outside = [...section.querySelectorAll('section.dshsec-units > .dshsec-unit-group .dshsec-unit-title')]
    expect(outside.map(el => el.textContent)).toEqual(['Part n1', 'Part n2', 'Part b1'])
    // The summary is a native, keyboard-operable control.
    expect(disclosure.querySelector(':scope > summary')?.tagName).toBe('SUMMARY')
  })

  it('does not collapse a short list', async () => {
    const section = await render(
      coverage({ units: [unit('n', 'not-run'), unit('f', 'finding'), unit('a', 'covered'), unit('b', 'covered')] }),
    )
    expect(section.querySelector('.dshsec-units details')).toBeNull()
    expect(titles(section)).toEqual(['Part n', 'Part f', 'Part a', 'Part b'])
  })

  it('shows surface, first path, extra paths, finding count, reasons and origin notes', async () => {
    const section = await render(coverage({ units: ledger() }))
    const meta = (id: string) =>
      [...section.querySelectorAll('.dshsec-unit')]
        .find(li => li.querySelector('.dshsec-unit-title')?.textContent === `Part ${id}`)!
        .querySelector('.dshsec-unit-meta')!
    expect(meta('f1').textContent).toBe('POST /api/orders/:idsrc/f1.ts2 findings')
    expect(meta('f2').textContent).toBe('src/a.ts (+2 more)1 finding')
    expect(meta('b1').textContent).toContain('The source code alone was not enough to decide.')
    expect(meta('b1').textContent).toContain('added by gap check')
    expect(meta('n1').textContent).toContain('The scan budget ran out before this was reviewed.')
    expect(meta('n1').textContent).toContain('added by the Host')
    // Examined parts say nothing about reasons or origin when there is none.
    expect(meta('ok0').textContent).toBe('src/ok0.ts')
  })

  it('keeps the Host sentence in a tooltip and shows a generic localized sentence for unknown codes', async () => {
    const section = await render(coverage({ units: ledger() }))
    const reason = [...section.querySelectorAll<HTMLElement>('.dshsec-unit-meta span[title]')].map(el => [
      el.textContent,
      el.title,
    ])
    expect(reason).toContainEqual(['The reason cannot be shown in this version.', 'Raw English from a newer Host.'])
    expect(section.textContent).not.toContain('Raw English from a newer Host.')
    expect(section.textContent).not.toContain('Needs a running system to decide.')
  })

  it('localizes the plan, groups and reasons in Japanese without raw English', async () => {
    const section = await render(coverage({ units: ledger() }), 'ja')
    expect(rowOf(section, '調査計画')?.querySelector('dd')?.textContent).toBe(
      '調査対象 12 件：確認済み 7、指摘あり 2、判断保留 1、未確認 2',
    )
    expect([...section.querySelectorAll('.dshsec-unit-group > .dshsec-h4')].map(h => h.textContent)).toEqual([
      '未確認 · 2',
      '判断保留 · 1',
      '指摘あり · 2',
      '確認済み（指摘なし） · 7',
    ])
    expect(section.textContent).toContain('予算を使い切ったため、確認できませんでした。')
    expect(section.textContent).toContain('ソースコードだけでは判断できませんでした。')
    expect(section.textContent).toContain('この版では理由を表示できません。')
    expect(section.textContent).toContain('ホストが追加')
    expect(section.textContent).toContain('抜け漏れの確認で追加')
    expect(section.textContent).toContain('ほか 9 件を表示')
    expect(section.textContent).toContain('src/a.ts （ほか 2 件）')
    expect(section.textContent).not.toMatch(/Needs a running|Token budget|Raw English/)
  })

  it('adds a row for source files that were in no review part', async () => {
    const section = await render(coverage({ units: ledger(), unassignedFiles: 3 }))
    expect(rowOf(section, 'Unassigned files')?.querySelector('dd')?.textContent).toBe(
      '3 source files were in no review part',
    )
    const one = await render(coverage({ units: ledger(), unassignedFiles: 1 }))
    expect(rowOf(one, 'Unassigned files')?.querySelector('dd')?.textContent).toBe('1 source file was in no review part')
    const none = await render(coverage({ units: ledger(), unassignedFiles: 0 }))
    expect(rowOf(none, 'Unassigned files')).toBeUndefined()
  })

  it('renders exactly as before when the scan has no ledger', async () => {
    const plain = await render(coverage())
    const html = plain.innerHTML
    expect(plain.querySelector('.dshsec-units')).toBeNull()
    expect(rowOf(plain, 'Review plan')).toBeUndefined()
    expect(rowOf(plain, 'Unassigned files')).toBeUndefined()
    // An empty ledger adds nothing either.
    const empty = await render(coverage({ units: [] }))
    expect(empty.innerHTML).toBe(html)
  })

  it('ignores units with a status this client does not know', async () => {
    const odd = { ...unit('x', 'covered'), status: 'sideways' } as unknown as CoverageUnit
    const section = await render(coverage({ units: [odd, unit('n', 'not-run')] }))
    expect(titles(section)).toEqual(['Part n'])
    expect(rowOf(section, 'Review plan')?.querySelector('dd')?.textContent).toBe('1 part: 1 not examined')
  })
})

describe('coverage ledger strings', () => {
  it('has a localized sentence for every reason code the Host can send', () => {
    const codes = [
      'budget',
      'task-limit',
      'failed',
      'consent-revoked',
      'provider-rejected',
      'no-tools',
      'stale-target',
      'needs-runtime',
      'partial',
    ]
    for (const lang of ['en', 'ja', 'zh'] as const) {
      for (const code of codes) {
        expect(Object.hasOwn(DICTIONARIES[lang], `coverage.reason.${code}`), `${lang}:${code}`).toBe(true)
      }
    }
  })
})
