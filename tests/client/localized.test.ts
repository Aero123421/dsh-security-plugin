import { describe, expect, it } from 'vitest'
import {
  findingImpact,
  findingRecommendation,
  findingSummary,
  findingTitle,
  workerTitle,
} from '../../src/client/localized.ts'
import { getTranslator } from '../../src/client/i18n.ts'
import {
  SECRET_RECOMMENDATION,
  secretBody,
  secretMessage,
  secretTitle,
  type SecretCopy,
} from '../../src/shared/secret-copy.ts'
import { reviewEndpointsTitle, reviewSensitiveTitle } from '../../src/shared/task-title.ts'

const en = getTranslator('en')
const ja = getTranslator('ja')

const copy: SecretCopy = {
  kind: 'secret',
  ruleId: 'github-token',
  description: 'GitHub token',
  preview: 'ghp_****…',
  inTest: false,
}

const legacy = {
  title: secretTitle(copy.description),
  summary: secretBody(copy.description, copy.preview),
  impact: secretMessage(copy),
  recommendation: SECRET_RECOMMENDATION,
  ruleId: 'github-token',
}

describe('localized secret findings', () => {
  it('keeps English and translates Japanese from stored arguments', () => {
    const finding = { ...legacy, copy }
    expect(findingTitle(en, finding)).toBe(legacy.title)
    expect(findingSummary(en, finding)).toBe(legacy.summary)
    expect(findingImpact(en, finding)).toBe(legacy.impact)
    expect(findingRecommendation(en, finding)).toBe(SECRET_RECOMMENDATION)
    expect(findingTitle(ja, finding)).toBe('ソースに直接書かれた秘密情報: GitHub トークン')
    expect(findingSummary(ja, finding)).toContain('GitHub トークン')
    expect(findingSummary(ja, finding)).toContain('ghp_****…')
    expect(findingSummary(ja, finding)).not.toContain('Hard-coded secret')
    expect(findingImpact(ja, finding)).toBe(findingSummary(ja, finding))
    expect(findingRecommendation(ja, finding)).toContain('ローテーション')
  })

  it('recovers a 0.4.1 row that has no copy field, including the test-file note', () => {
    const withTest = {
      ...legacy,
      impact: secretMessage({ ...copy, inTest: true }),
      summary: secretBody(copy.description, copy.preview),
    }
    expect(findingTitle(ja, withTest)).toContain('GitHub トークン')
    expect(findingImpact(ja, withTest)).toContain('テストまたはサンプル')
    expect(findingSummary(ja, withTest)).not.toContain('テストまたはサンプル')
  })

  it('shows the stored English when the rule id or the sentence cannot be recovered', () => {
    const custom = { title: 'Custom title', summary: 'Custom body', impact: 'Custom impact', recommendation: 'Do this' }
    expect(findingTitle(ja, custom)).toBe('Custom title')
    expect(findingSummary(ja, custom)).toBe('Custom body')
    expect(findingImpact(ja, custom)).toBe('Custom impact')
    expect(findingRecommendation(ja, custom)).toBe('Do this')
    const unknownRule = { ...legacy, ruleId: 'not-a-secret-rule' }
    expect(findingTitle(ja, unknownRule)).toBe(legacy.title)
  })

  it('keeps a rewritten title instead of translating a stale copy', () => {
    const rewritten = { ...legacy, copy, title: '【検証済み】別の説明' }
    expect(findingTitle(ja, rewritten)).toBe('【検証済み】別の説明')
    expect(findingSummary(ja, rewritten)).toBe(legacy.summary)
  })
})

describe('localized task titles', () => {
  it('translates the two Review titles and leaves other titles stored', () => {
    const one = { title: reviewEndpointsTitle(1, 'src/routes/auth.ts') }
    const many = {
      title: reviewEndpointsTitle(3, 'src/routes/admin.ts'),
      titleCopy: { kind: 'review-endpoints' as const, count: 3, path: 'src/routes/admin.ts' },
    }
    const file = { title: reviewSensitiveTitle('src/middleware/auth.ts') }
    expect(workerTitle(en, one)).toBe(one.title)
    expect(workerTitle(ja, one)).toBe('src/routes/auth.ts のエンドポイント 1 件を調べる')
    expect(workerTitle(ja, many)).toBe('src/routes/admin.ts のエンドポイント 3 件を調べる')
    expect(workerTitle(ja, file)).toBe('src/middleware/auth.ts の認証や権限に関わる処理を調べる')
    expect(workerTitle(ja, { title: 'Sweep 4 otherwise-untargeted source files' })).toBe(
      'Sweep 4 otherwise-untargeted source files',
    )
  })
})
