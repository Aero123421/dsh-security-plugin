import { describe, expect, it } from 'vitest'
import type { Coverage } from '../../../src/shared/contracts.ts'
import { renderMarkdown } from '../../../src/host/report/markdown.ts'
import { codeSpan, fencedCode, inline, paragraphs } from '../../../src/host/report/markdown-escape.ts'
import { finding, reportInput, scanDetail } from './fixtures.ts'

/** Index of each needle in order; fails if any is missing or out of order. */
function expectInOrder(text: string, needles: readonly string[]): void {
  let from = 0
  for (const needle of needles) {
    const index = text.indexOf(needle, from)
    expect(index, `missing or out of order: ${needle}`).toBeGreaterThanOrEqual(0)
    from = index + needle.length
  }
}

/** Lines that are (un-indented) fences, i.e. open or close a code block at top level or in a list. */
function fenceBalance(markdown: string): void {
  let open: string | undefined
  for (const line of markdown.split('\n')) {
    const match = /^\s*(`{3,})/.exec(line)
    if (match === null) continue
    const fence = match[1]!
    if (open === undefined) open = fence
    else if (fence.length >= open.length && line.trim() === fence) open = undefined
  }
  expect(open, 'unterminated code fence').toBeUndefined()
}

describe('renderMarkdown structure', () => {
  it('emits sections in order', () => {
    const md = renderMarkdown(reportInput())
    expectInOrder(md, [
      '# DSH Security report: Acme API',
      '## Scan',
      '## How to read this report',
      '## Summary',
      'No findings is not proof of safety.',
      '## Coverage',
      'Known gaps',
      '## Threat model',
      '## Findings',
      '### Confirmed (1)',
      '#### SQL injection in user search',
      '### Needs proof (3)',
      '#### Hard-coded API key',
      '#### Missing authorization on export',
      '#### Verbose errors',
      '### Ruled out (1)',
      '<details>',
      '#### Refuted XSS',
      '</details>',
    ])
    expect(md.endsWith('\n')).toBe(true)
    fenceBalance(md)
  })

  it('sorts within a group by severity, then verification strength', () => {
    const input = reportInput({
      findings: [
        finding({ title: 'Low one', severity: 'low' }),
        finding({ title: 'Critical potential', severity: 'critical', verification: 'potential' }),
        finding({ title: 'Critical inconclusive', severity: 'critical', verification: 'inconclusive' }),
        finding({ title: 'Medium one', severity: 'medium' }),
      ],
    })
    expectInOrder(renderMarkdown(input), ['Critical potential', 'Critical inconclusive', 'Medium one', 'Low one'])
  })

  it('renders scan metadata, models by role, and usage', () => {
    const md = renderMarkdown(reportInput())
    expect(md).toContain('| Mode | Deep |')
    expect(md).toContain('| Status | Completed |')
    expect(md).toContain('`0123456789abcdef0123456789abcdef01234567` (uncommitted changes)')
    expect(md).toContain('| Model (planner) | `deepseek/deepseek-reasoner (high)` |')
    expect(md).toContain('| Model (skeptic) | `other/judge-1` |')
    expect(md).toContain('123 model calls · 1,234,567 input tokens · 89,012 output tokens · 456 tool calls · 41m 25s')
    expect(md).not.toContain('Last phase')
  })

  it('shows the phase and error for a failed scan', () => {
    const scan = scanDetail({
      status: 'failed',
      phase: 'hunt',
      error: { code: 'security/no-model', message: 'No model' },
    })
    const md = renderMarkdown(reportInput({ scan }))
    expect(md).toContain('| Status | Failed |')
    expect(md).toContain('| Last phase | `hunt` |')
    expect(md).toContain('| Error | `security/no-model` No model |')
  })

  it('renders every finding field', () => {
    const md = renderMarkdown(reportInput())
    const section = md.slice(md.indexOf('#### SQL injection in user search'), md.indexOf('### Needs proof'))
    expectInOrder(section, [
      '| Severity | **Critical** |',
      '| Verification | Strong static evidence |',
      '| CWE | CWE-89 (<https://cwe.mitre.org/data/definitions/89.html>) |',
      '| Location | `src/db/users.ts:10-12` |',
      '| Triage | Open |',
      '| New since previous scan | yes |',
      '**Summary**',
      '**Impact**',
      '**Preconditions**',
      '**Attack path**',
      '1. Request handler reads \\`req.query.name\\`.',
      '`src/routes/users.ts:4` · ✓ quote verified',
      '```typescript',
      '2. The value is concatenated into SQL.',
      '⚠ quote not found in the source',
      '3. The database returns all rows.',
      '**Evidence**',
      '**Independent review**: Inconclusive (model: judge-1)',
      '**Limitations**',
      '**Recommendation**',
      '**References**',
      '- <https://owasp.org/Top10/A03_2021-Injection/>',
      '- javascript:alert(1)',
    ])
    expect(section).not.toContain('<javascript:')
  })

  it('renders triage notes and analyzer provenance', () => {
    const md = renderMarkdown(reportInput())
    expect(md).toContain('**Triage note (Accepted risk)**\n\nInternal-only endpoint behind VPN')
    expect(md).toContain('reported by analyzer (secrets)')
    expect(md).toContain('rule `secrets/generic-api-key`')
    expect(md).toContain('Triage: Open 3 · Accepted risk 1 · False positive 1.')
    expect(md).toContain('1 finding is new since the previous scan.')
  })

  it('renders the summary table with a totals row', () => {
    const md = renderMarkdown(reportInput())
    expect(md).toContain('| Severity | Confirmed | Needs proof | Ruled out | Total |')
    expect(md).toContain('| Critical | 1 | 0 | 0 | 1 |')
    expect(md).toContain('| High | 0 | 2 | 1 | 3 |')
    expect(md).toContain('| **Total** | **1** | **3** | **1** | **5** |')
  })

  it('explains severity vs verification for beginners', () => {
    const md = renderMarkdown(reportInput())
    const guide = md.slice(md.indexOf('## How to read this report'), md.indexOf('## Summary'))
    expect(guide).toContain('**Severity**')
    expect(guide).toContain('**Verification**')
    for (const level of ['Proven (dynamic)', 'Strong static evidence', 'Potential', 'Inconclusive', 'Refuted']) {
      expect(guide).toContain(`**${level}**`)
    }
    expect(guide).toContain('✓')
    expect(guide).toContain('⚠')
  })

  it('leads the zero-findings note with "none reported" when nothing is actionable', () => {
    const md = renderMarkdown(reportInput({ findings: [] }))
    expect(md).toContain(
      '> [!IMPORTANT]\n> **No findings is not proof of safety.** This scan reported no confirmed or unproven findings.',
    )
    expect(md).toContain('### Confirmed (0)\n\nNone.')
    expect(md).toContain('### Ruled out (0)\n\nNone.')
    expect(md).not.toContain('<details>')
  })

  it('handles a scan without coverage, models, or threat model', () => {
    const scan = scanDetail(
      { status: 'cancelled' },
      { coverage: undefined, models: {}, threatModel: undefined, notices: [] },
    )
    const md = renderMarkdown(reportInput({ scan }))
    expect(md).toContain('Coverage was not recorded for this scan')
    expect(md).toContain('no model was used')
    expect(md).not.toContain('## Threat model')
  })
})

describe('renderMarkdown in Japanese', () => {
  it('uses Japanese headings and labels', () => {
    const md = renderMarkdown(reportInput({ language: 'ja' }))
    expectInOrder(md, [
      '# DSH Security レポート: Acme API',
      '## スキャン情報',
      '## このレポートの読み方',
      '## 集計',
      '検出事項がゼロでも、安全とは限りません。',
      '## カバレッジ',
      '## 脅威モデル',
      '## 検出事項',
      '### 確認済み（1 件）',
      '### 要検証（3 件）',
      '### 除外（1 件）',
    ])
    expect(md).toContain('| 重大度 | **重大** |')
    expect(md).toContain('| 検証度 | 強い静的証拠あり |')
    expect(md).toContain('✓ 引用を確認済み')
    expect(md).toContain('| モード | ディープ |')
    expect(md).toContain('41分25秒')
    expect(md).not.toContain('How to read')
  })
})

describe('renderMarkdown in Simplified Chinese', () => {
  it('uses Chinese headings and labels', () => {
    const md = renderMarkdown(reportInput({ language: 'zh' }))
    expectInOrder(md, [
      '# DSH Security 报告: Acme API',
      '## 扫描信息',
      '## 如何阅读本报告',
      '## 汇总',
      '没有发现问题，并不代表就是安全的。',
      '## 覆盖范围',
      '## 威胁模型',
      '## 发现的问题',
      '### 已通过代码确认（1 个）',
      '### 需要确认（3 个）',
      '### 已排除（1 个）',
    ])
    expect(md).toContain('| 严重程度 | **严重** |')
    expect(md).toContain('| 确认程度 | 强有力的静态证据 |')
    expect(md).toContain('✓ 引用已核实')
    expect(md).toContain('| 模式 | 深入 |')
    expect(md).toContain('41 分 25 秒')
    for (const english of ['How to read', 'Needs proof', 'Ruled out', 'Known gaps', 'Attack path', 'quote verified']) {
      expect(md).not.toContain(english)
    }
    fenceBalance(md)
  })
})

describe('renderMarkdown language parity', () => {
  const languages = ['en', 'ja', 'zh'] as const
  const render = (language: (typeof languages)[number]) => renderMarkdown(reportInput({ language }))
  const shape = (md: string) => ({
    headings: md.split('\n').flatMap(line => {
      const match = /^(#{1,6}) /.exec(line)
      return match ? [match[1]!.length] : []
    }),
    tableRows: md.split('\n').filter(line => line.startsWith('|')).length,
    details: md.split('<details>').length - 1,
    fences: md.split('\n').filter(line => /^\s*`{3,}/.test(line)).length,
  })

  it('renders the same sections, tables, and findings in every language', () => {
    const en = shape(render('en'))
    expect(en.headings.filter(level => level === 4)).toHaveLength(5)
    for (const language of ['ja', 'zh'] as const) expect(shape(render(language)), language).toEqual(en)
  })

  it('leaves no label key or missing value in any language', () => {
    for (const language of languages) {
      const md = render(language)
      for (const key of [
        'open_proof_gap',
        'ruled_out',
        'strong_static_evidence',
        'proven_dynamic',
        'accepted_risk',
        'false_positive',
        'undefined',
        'null',
        '[object Object]',
        'NaN',
      ]) {
        expect(md, `${language}: ${key}`).not.toContain(key)
      }
    }
  })
})

describe('Markdown escaping of untrusted text', () => {
  it('chooses a fence longer than any backtick run in a snippet', () => {
    const snippet = 'const md = `\n```\n# not a heading\n````\n`'
    const input = reportInput({
      findings: [
        finding({
          attackPath: [
            {
              order: 1,
              description: 'Step',
              location: { path: 'a.md', startLine: 1, endLine: 5 },
              snippet,
              quoteCheck: 'match',
            },
          ],
        }),
      ],
    })
    const md = renderMarkdown(input)
    expect(md).toContain('   `````\n')
    expect(md).toContain('   ```\n   # not a heading\n   ````\n')
    expect(md).not.toMatch(/^# not a heading/m)
    fenceBalance(md)
    expect(fencedCode('a ``` b', '')).toBe('````\na ``` b\n````')
    expect(fencedCode('plain')).toBe('```\nplain\n```')
  })

  it('neutralizes HTML in titles, summaries, and paths', () => {
    const md = renderMarkdown(
      reportInput({
        workspaceTitle: '<img src=x onerror=alert(1)>',
        findings: [
          finding({
            title: '<script>alert("t")</script> & co',
            summary: '<iframe src="https://evil"></iframe>\n</details>',
            location: { path: 'src/<b>x</b>.ts', startLine: 1, endLine: 1 },
            verification: 'refuted',
          }),
        ],
      }),
    )
    // Code spans render their content literally, so only text outside them can carry HTML.
    const outsideCode = md.replace(/(`+)[^`]*?\1/g, '')
    expect(outsideCode).not.toMatch(/<(script|img|iframe|b)\b/i)
    expect(md).toContain('| Location | `src/<b>x</b>.ts:1` |')
    expect(md).toContain('#### &lt;script&gt;alert("t")&lt;/script&gt; & co')
    expect(md).toContain('&lt;img src=x onerror=alert(1)&gt;')
    // The only details tags are the renderer's own wrapper.
    expect(md.match(/<\/?details>/g)).toEqual(['<details>', '</details>'])
    expect(md).toContain('&lt;/details&gt;')
  })

  it('keeps headings, tables, and lists intact against hostile text', () => {
    const md = renderMarkdown(
      reportInput({
        findings: [
          finding({
            title: 'Pipe | in title\n## Injected heading',
            summary: '# Fake heading\n- fake item\n1. fake ordered\n    indented code?\n| a | b |',
            cwe: 'CWE-89 | injected',
            ruleId: 'rule`with`ticks|pipe',
            limitations: ['line one\n# heading'],
          }),
        ],
      }),
    )
    expect(md).not.toMatch(/^## Injected heading/m)
    expect(md).not.toMatch(/^# Fake heading/m)
    expect(md).not.toMatch(/^- fake item/m)
    expect(md).not.toMatch(/^1\. fake ordered/m)
    expect(md).not.toMatch(/^ {4}indented/m)
    expect(md).toContain('#### Pipe \\| in title \\#\\# Injected heading')
    expect(md).toContain('\\# Fake heading\n\\- fake item\n1\\. fake ordered\nindented code?\n\\| a \\| b \\|')
    // Table rows keep their column count.
    const cweRow = md.split('\n').find(line => line.startsWith('| CWE |'))!
    expect(cweRow.replace(/\\\|/g, '').split('|').length).toBe(4)
    const sourceRow = md.split('\n').find(line => line.startsWith('| Source |'))!
    expect(sourceRow.replace(/\\\|/g, '').split('|').length).toBe(4)
    expect(sourceRow).toContain('``rule`with`ticks\\|pipe``')
  })

  it('makes bidi controls visible and strips other control characters', () => {
    expect(inline('a‮b\u0007c')).toBe('a⟨U+202E⟩bc')
  })

  it('escapes inline markers but keeps identifiers readable', () => {
    expect(inline('user_id *bold* [link](x) `code` ~~s~~ $x')).toBe(
      'user_id \\*bold\\* \\[link\\](x) \\`code\\` \\~\\~s\\~\\~ \\$x',
    )
    expect(inline('_emphasis_')).toBe('\\_emphasis\\_')
    expect(inline('+ item')).toBe('\\+ item')
    expect(inline('&amp; &#60; & plain')).toBe('&amp;amp; &amp;\\#60; & plain')
    expect(paragraphs('a\n\n\n\nb\n')).toBe('a\n\nb')
    expect(codeSpan('`x`')).toBe('`` `x` ``')
    expect(codeSpan('a|b', true)).toBe('`a\\|b`')
    expect(codeSpan('   ')).toBe('')
  })
})

describe('renderMarkdown coverage ledger', () => {
  const base = scanDetail().coverage!
  const ledger: Coverage = {
    ...base,
    unassignedFiles: 3,
    units: [
      {
        id: 'u1',
        title: 'Order API',
        surface: 'GET /orders/:id',
        focus: ['authz'],
        paths: ['src/orders.ts'],
        status: 'finding',
        findings: 2,
        origin: 'recon',
      },
      {
        id: 'u2',
        title: 'Webhooks',
        focus: ['ssrf'],
        paths: ['src/hooks.go', 'src/client.go', 'src/retry.go'],
        status: 'blocked',
        findings: 0,
        reason: { code: 'needs-runtime', params: { note: 'Depends on the egress proxy.' }, fallback: 'x' },
        origin: 'critic',
      },
      {
        id: 'unassigned',
        title: '3 source files not assigned to any review unit',
        focus: [],
        paths: ['a.php', 'b.php', 'c.php'],
        status: 'not-run',
        findings: 0,
        reason: { code: 'budget', params: { count: 3 }, fallback: 'x' },
        origin: 'gap',
      },
    ],
  }

  it('lists what was and was not examined, unexamined first', () => {
    const md = renderMarkdown(reportInput({ scan: scanDetail({}, { coverage: ledger }) }))
    expect(md).toContain('**Review units**')
    expect(md).toContain('0 examined without findings · 1 with findings · 1 undecided · 1 not examined')
    expectInOrder(md, [
      '| Not examined | Source files in no review unit (3) · added by the Host | a.php, b.php, … | The scan budget ran out. |',
      '| Undecided | Webhooks · added by gap check | src/hooks.go, src/client.go, … | Depends on runtime or deployment the source does not show. Depends on the egress proxy. |',
      '| With findings (2) | Order API · review plan | GET /orders/:id |   |',
    ])
  })

  it('is localized, and absent without a ledger', () => {
    const md = renderMarkdown(reportInput({ scan: scanDetail({}, { coverage: ledger }), language: 'ja' }))
    expect(md).toContain('**調査対象**')
    expect(md).toContain('| 未確認 | どの調査対象にも入らなかったソースファイル (3) · ホストが追加 |')
    expect(md).toContain('| 指摘あり (2) | Order API · 調査計画 |')
    expect(renderMarkdown(reportInput())).not.toContain('Review units')
  })

  it('uses the UI wording for statuses and origins in every language', () => {
    const ja = renderMarkdown(reportInput({ scan: scanDetail({}, { coverage: ledger }), language: 'ja' }))
    expect(ja).toContain('指摘なしで確認 0 · 指摘あり 1 · 判断保留 1 · 未確認 1')
    expect(ja).toContain('Webhooks · 抜け漏れの確認で追加')
    expect(ja).not.toContain('検出あり')
    expect(ja).not.toContain('アナライザーから追加')
    const zh = renderMarkdown(reportInput({ scan: scanDetail({}, { coverage: ledger }), language: 'zh' }))
    expect(zh).toContain('| 有发现 (2) | Order API · 审查计划 |')
    expect(zh).toContain('Webhooks · 由缺口检查补充')
    expect(zh).toContain('· 由 Host 补充 |')
  })

  describe('titles of units the Host made', () => {
    const hostUnit = (id: string, kind: NonNullable<Coverage['units']>[number]['kind'], paths: string[]) => ({
      id,
      title: `Host English title ${id}`,
      focus: [],
      paths,
      status: 'covered' as const,
      findings: 0,
      origin: 'gap' as const,
      kind,
    })
    const hosted: Coverage = {
      ...base,
      units: [
        hostUnit('h1', 'endpoints', ['src/a.ts']),
        hostUnit('h2', 'signals', ['src/b.ts']),
        hostUnit('h3', 'triage', ['src/c.ts', 'src/d.ts']),
        hostUnit('h4', 'sweep', ['src/e.ts', 'src/f.ts', 'src/g.ts']),
        hostUnit('h5', 'file', ['src/h.ts']),
        hostUnit('h6', 'legacy', ['src/i.ts']),
        hostUnit('h7', 'endpoints', []),
        { ...hostUnit('p1', 'plan', ['src/j.ts']), title: 'Billing flow', origin: 'recon' as const },
        { ...hostUnit('p2', 'endpoints', ['src/k.ts']), title: 'Critic part', origin: 'critic' as const },
      ],
    }
    const render = (language: 'en' | 'ja' | 'zh') =>
      renderMarkdown(reportInput({ scan: scanDetail({}, { coverage: hosted }), language }))

    it.each([
      [
        'en',
        [
          'Endpoints in src/a.ts · added by the Host',
          'Rule hits in src/b.ts · added by the Host',
          'Triage of rule hits · added by the Host',
          'Files no part covered (3) · added by the Host',
          'File src/h.ts · added by the Host',
        ],
      ],
      [
        'ja',
        [
          'src/a.ts のエンドポイント · ホストが追加',
          'src/b.ts のルール検出 · ホストが追加',
          'ルール検出の確認 · ホストが追加',
          'どの調査対象にも入らなかったファイル（3 件） · ホストが追加',
          'src/h.ts · ホストが追加',
        ],
      ],
      [
        'zh',
        [
          'src/a.ts 中的接口 · 由 Host 补充',
          'src/b.ts 中的规则命中 · 由 Host 补充',
          '规则命中的核实 · 由 Host 补充',
          '未纳入任何审查部分的文件（3 个） · 由 Host 补充',
          '文件 src/h.ts · 由 Host 补充',
        ],
      ],
    ] as const)('are rebuilt in %s from the unit kind', (language, titles) => {
      const md = render(language)
      for (const title of titles) expect(md).toContain(title)
      expect(md).not.toContain('Host English title h1')
      expect(md).not.toContain('Host English title h2')
      expect(md).not.toContain('Host English title h3')
      expect(md).not.toContain('Host English title h4')
      expect(md).not.toContain('Host English title h5')
    })

    it('keeps the stored title for legacy and path-less Host units, and for plan and critic units', () => {
      const md = render('ja')
      expect(md).toContain('Host English title h6 · ホストが追加')
      expect(md).toContain('Host English title h7 · ホストが追加')
      expect(md).toContain('Billing flow · 調査計画')
      expect(md).toContain('Critic part · 抜け漏れの確認で追加')
    })
  })
})
