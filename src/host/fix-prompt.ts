/**
 * The draft handed to a normal DSH chat when the user clicks "Fix in chat".
 * Remediation is left to the user's coding agent, which edits code under
 * the user's own permissions; the security plugin itself stays read-only.
 */

import type { FindingDetail, ReportLanguage } from '../shared/contracts.ts'
import { formatCodeRef, isQuoteVerified } from '../shared/domain.ts'

const TEXT = {
  en: {
    intro: 'Please fix the following security issue found by DSH Security in this project.',
    title: 'Issue',
    where: 'Location',
    severity: 'Severity',
    status: 'Verification',
    summary: 'What is wrong',
    impact: 'Impact',
    path: 'Attack path (code checked against the source)',
    fix: 'Suggested fix',
    rules: `Requirements:
- Read the relevant code first and confirm the problem before changing anything.
- Make the smallest change that removes the vulnerability; do not weaken or remove other security checks.
- Add or update a test that fails before the fix and passes after it, if the project has tests.
- Explain what you changed and why, and mention anything you could not verify.`,
  },
  ja: {
    intro: 'DSH Security がこのプロジェクトで見つけた次のセキュリティ問題を修正してください。',
    title: '問題',
    where: '場所',
    severity: '重大度',
    status: '確実性',
    summary: '何が問題か',
    impact: '影響',
    path: '攻撃経路（ソースと照合済みのコード）',
    fix: '修正の方針',
    rules: `条件:
- 変更する前に関係するコードを読み、問題が実際にあることを確認してください。
- 脆弱性をなくす最小限の変更にし、他のセキュリティチェックを弱めたり削除したりしないでください。
- テストがあるプロジェクトなら、修正前に失敗し修正後に成功するテストを追加・更新してください。
- 何をなぜ変更したか、確認できなかった点があればそれも説明してください。`,
  },
  zh: {
    intro: '请修复 DSH Security 在本项目中发现的以下安全问题。',
    title: '问题',
    where: '位置',
    severity: '严重程度',
    status: '确认程度',
    summary: '问题描述',
    impact: '影响',
    path: '攻击路径（已与源码核对的代码）',
    fix: '修复建议',
    rules: `要求：
- 修改前先阅读相关代码并确认问题确实存在。
- 只做消除漏洞所需的最小修改，不要削弱或删除其他安全检查。
- 如果项目有测试，请添加或更新一个修复前失败、修复后通过的测试。
- 说明你修改了什么、为什么修改，以及无法确认的地方。`,
  },
} as const

export function buildFixPrompt(finding: FindingDetail, language: ReportLanguage): string {
  const t = TEXT[language]
  const lines: string[] = [t.intro, '', `## ${t.title}: ${finding.title}`]
  if (finding.location) lines.push(`- ${t.where}: ${formatCodeRef(finding.location)}`)
  lines.push(`- ${t.severity}: ${finding.severity}`, `- ${t.status}: ${finding.verification}`)
  if (finding.cwe) lines.push(`- CWE: ${finding.cwe}`)
  lines.push('', `### ${t.summary}`, finding.summary, '', `### ${t.impact}`, finding.impact)
  const steps = finding.attackPath.filter(step => isQuoteVerified(step.quoteCheck) && step.location)
  if (steps.length > 0) {
    lines.push('', `### ${t.path}`)
    for (const step of steps) {
      lines.push(`${step.order}. ${step.description} (${step.location ? formatCodeRef(step.location) : ''})`)
      if (step.snippet) lines.push(fence(step.snippet))
    }
  }
  if (finding.recommendation) lines.push('', `### ${t.fix}`, finding.recommendation)
  lines.push('', t.rules)
  return lines.join('\n')
}

function fence(code: string): string {
  const longest = Math.max(0, ...[...code.matchAll(/`+/g)].map(m => m[0].length))
  const marker = '`'.repeat(Math.max(3, longest + 1))
  return `${marker}\n${code}\n${marker}`
}
