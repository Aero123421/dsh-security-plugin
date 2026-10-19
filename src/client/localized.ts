/**
 * Display text for built-in secret findings and the two `Review … in <path>`
 * task titles. English stays the stored sentence. Other UI languages use the
 * client dictionary. Reports do not call this module.
 */

import type { FindingDetail, FindingSummary, WorkerView } from '../shared/contracts.ts'
import {
  displaySecretCopy,
  SECRET_RECOMMENDATION,
  secretBody,
  secretMessage,
  secretTitle,
  type SecretCopy,
} from '../shared/secret-copy.ts'
import {
  displayTaskTitle,
  reviewEndpointsTitle,
  reviewSensitiveTitle,
  type TaskTitleCopy,
} from '../shared/task-title.ts'
import type { Translator } from './i18n.ts'

type FindingText = Pick<FindingSummary, 'title' | 'summary' | 'ruleId'> & {
  readonly copy?: SecretCopy
  readonly impact?: string
  readonly recommendation?: string
}

export function findingTitle(tr: Translator, finding: FindingText): string {
  const copy = displaySecretCopy(finding)
  if (!copy) return finding.title
  return tr.lang === 'en' ? secretTitle(copy.description) : tr.t('secret.title', { kind: secretKind(tr, copy) })
}

export function findingSummary(tr: Translator, finding: FindingText): string {
  const copy = displaySecretCopy(finding)
  if (!copy) return finding.summary
  if (tr.lang === 'en') return secretBody(copy.description, copy.preview)
  return tr.t('secret.body', { kind: secretKind(tr, copy), preview: copy.preview })
}

export function findingImpact(tr: Translator, finding: FindingText & { readonly impact?: string }): string {
  const copy = displaySecretCopy(finding)
  const stored = finding.impact ?? ''
  if (!copy) return stored
  if (tr.lang === 'en') return secretMessage(copy)
  const body = tr.t('secret.body', { kind: secretKind(tr, copy), preview: copy.preview })
  return copy.inTest ? `${body} ${tr.t('secret.testNote')}` : body
}

export function findingRecommendation(tr: Translator, finding: FindingText): string {
  const copy = displaySecretCopy(finding)
  const stored = finding.recommendation ?? ''
  if (!copy) return stored
  return tr.lang === 'en' ? SECRET_RECOMMENDATION : tr.t('secret.recommendation')
}

export function workerTitle(tr: Translator, worker: Pick<WorkerView, 'title' | 'titleCopy'>): string {
  const copy = displayTaskTitle(worker)
  if (!copy) return worker.title
  if (tr.lang === 'en') {
    return copy.kind === 'review-endpoints'
      ? reviewEndpointsTitle(copy.count, copy.path)
      : reviewSensitiveTitle(copy.path)
  }
  return taskTitle(tr, copy)
}

function secretKind(tr: Translator, copy: SecretCopy): string {
  return tr.lookup(`secret.rule.${copy.ruleId}`) ?? copy.description
}

function taskTitle(tr: Translator, copy: TaskTitleCopy): string {
  if (copy.kind === 'review-sensitive') return tr.t('task.reviewSensitive', { path: copy.path })
  if (copy.count === 1) return tr.t('task.reviewEndpoints.one', { path: copy.path })
  return tr.t('task.reviewEndpoints.many', { count: copy.count, path: copy.path })
}

export function attackStepText(tr: Translator, finding: FindingDetail, description: string | undefined): string {
  if (typeof description !== 'string' || description.trim() === '') return ''
  if (description === finding.title) return findingTitle(tr, finding)
  return description
}
