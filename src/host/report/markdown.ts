/**
 * Human-readable Markdown report. Every piece of finding or scan text is
 * escaped through `markdown-escape.ts`; the only HTML emitted is the fixed
 * `<details>` wrapper around ruled-out findings, whose summary holds no
 * untrusted text.
 */

import type { AttackStepView, EvidenceView, FindingDetail } from '../../shared/contracts.ts'
import type { CodeRef, QuoteCheck } from '../../shared/domain.ts'
import { formatCodeRef, ROLE_NAMES, SEVERITIES, TRIAGE_STATES, VERIFICATIONS } from '../../shared/domain.ts'
import type { ReportInput } from './common.ts'
import { CLOSURE_ORDER, countFindings, cweNumber, cweUrl, groupByClosure, TOOL_NAME } from './common.ts'
import type { ReportLabels } from './i18n.ts'
import { labelsFor } from './i18n.ts'
import { codeSpan, fencedCode, inline, languageForPath, linkOrText, paragraphs, table } from './markdown-escape.ts'

/** Render the full Markdown report. */
export function renderMarkdown(input: ReportInput): string {
  const labels = labelsFor(input.language)
  const groups = groupByClosure(input.findings)
  const blocks: string[] = [
    `# ${inline(labels.title)}: ${inline(input.workspaceTitle)}`,
    `_${inline(labels.generated(input.generatedAt, `${TOOL_NAME} ${input.pluginVersion}`))}_`,
    section(labels.sections.scan, scanTable(input, labels)),
    section(labels.sections.howToRead, howToRead(labels)),
    section(labels.sections.summary, summary(input, labels)),
    section(labels.sections.coverage, coverage(input, labels)),
  ]
  const threat = threatModel(input, labels)
  if (threat !== undefined) blocks.push(section(labels.sections.threatModel, threat))

  const findingBlocks: string[] = [`## ${inline(labels.sections.findings)}`]
  for (const closure of CLOSURE_ORDER) {
    const findings = groups.get(closure) ?? []
    const heading = labels.groupHeading(closure, findings.length)
    const body =
      findings.length === 0
        ? inline(labels.noFindingsInGroup)
        : findings.map(finding => renderFinding(finding, labels)).join('\n\n')
    if (closure === 'ruled_out') {
      // Collapsed: a fixed, entity-escaped summary; Markdown body after a blank line.
      findingBlocks.push(
        `### ${inline(heading)}`,
        findings.length === 0
          ? body
          : `<details>\n<summary>${htmlText(labels.showRuledOut(findings.length))}</summary>\n\n${body}\n\n</details>`,
      )
    } else {
      findingBlocks.push(`### ${inline(heading)}`, body)
    }
  }
  blocks.push(findingBlocks.join('\n\n'))
  return `${blocks.join('\n\n')}\n`
}

function section(title: string, body: string): string {
  return `## ${inline(title)}\n\n${body}`
}

/** Text for an HTML context (the `<summary>` element). */
function htmlText(text: string): string {
  return text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')
}

function number(value: number, language: 'en' | 'ja'): string {
  return Number.isFinite(value) ? value.toLocaleString(language === 'ja' ? 'ja-JP' : 'en-US') : '—'
}

function elapsed(ms: number, labels: ReportLabels): string {
  const total = Math.max(0, Math.round(Number.isFinite(ms) ? ms / 1000 : 0))
  return labels.elapsed(Math.floor(total / 3600), Math.floor((total % 3600) / 60), total % 60)
}

// ---------------------------------------------------------------------------
// Scan metadata
// ---------------------------------------------------------------------------

function scanTable(input: ReportInput, labels: ReportLabels): string {
  const { scan, language } = input
  const s = scan.summary
  const f = labels.scanFields
  const missing = inline(labels.notRecorded)
  const rows: string[][] = [
    [f.workspace, inline(input.workspaceTitle)],
    [f.scanId, codeSpan(s.id, true)],
    [f.mode, inline(labels.modes[s.mode])],
    [f.status, inline(labels.statuses[s.status])],
  ]
  if (s.status !== 'completed') rows.push([f.phase, codeSpan(s.phase, true)])
  if (s.error !== undefined) rows.push([f.error, `${codeSpan(s.error.code, true)} ${inline(s.error.message)}`])
  rows.push([
    f.commit,
    s.commit === undefined
      ? missing
      : `${codeSpan(s.commit, true)}${s.dirty === true ? ` ${inline(labels.scanFields.dirty)}` : ''}`,
  ])
  rows.push([f.started, s.startedAt === undefined ? missing : inline(s.startedAt)])
  rows.push([f.finished, s.finishedAt === undefined ? missing : inline(s.finishedAt)])

  const modelRows = ROLE_NAMES.flatMap(role => {
    const ref = scan.models[role]
    if (ref === undefined) return []
    const effort = ref.reasoningEffort === undefined ? '' : ` (${ref.reasoningEffort})`
    return [[f.model(labels.roles[role]), codeSpan(`${ref.provider}/${ref.model}${effort}`, true)]]
  })
  rows.push(...(modelRows.length > 0 ? modelRows : [[f.model('—'), inline(labels.noModels)]]))

  const u = scan.usage
  rows.push([
    f.usage,
    inline(
      labels.usageLine(
        number(u.llmCalls, language),
        number(u.inputTokens, language),
        number(u.outputTokens, language),
        number(u.toolCalls, language),
        elapsed(u.elapsedMs, labels),
      ),
    ),
  ])
  rows.push([
    f.budget,
    inline(
      labels.budgetLine(
        number(scan.budget.maxLlmCalls, language),
        number(scan.budget.maxTokens, language),
        number(scan.budget.maxMinutes, language),
      ),
    ),
  ])
  return table(
    [inline(labels.field), inline(labels.value)],
    rows.map(([field, value]) => [inline(field ?? ''), value ?? '']),
  )
}

// ---------------------------------------------------------------------------
// Reading guide, summary, coverage
// ---------------------------------------------------------------------------

/** The reading guide is fixed, trusted text (it contains intentional bold markers). */
function howToRead(labels: ReportLabels): string {
  const h = labels.howToRead
  const levels = VERIFICATIONS.map(
    verification => `- **${labels.verifications[verification]}**: ${labels.verificationHelp[verification]}`,
  )
  return [
    h.intro,
    '',
    `- ${h.severity}`,
    `- ${h.verification}`,
    ...levels.map(line => `  ${line}`),
    '',
    h.groups,
    '',
    h.quoteCheck,
  ].join('\n')
}

function summary(input: ReportInput, labels: ReportLabels): string {
  const counts = countFindings(input.findings)
  const language = input.language
  const header = [
    inline(labels.summary.severity),
    ...CLOSURE_ORDER.map(c => inline(labels.closures[c])),
    inline(labels.summary.total),
  ]
  const rows = SEVERITIES.map(severity => [
    inline(labels.severities[severity]),
    ...CLOSURE_ORDER.map(closure => number(counts.matrix[severity][closure], language)),
    number(counts.bySeverity[severity], language),
  ])
  rows.push([
    `**${inline(labels.summary.total)}**`,
    ...CLOSURE_ORDER.map(closure => `**${number(counts.byClosure[closure], language)}**`),
    `**${number(counts.total, language)}**`,
  ])
  const blocks = [table(header, rows, [false, true, true, true, true])]

  const triageParts = TRIAGE_STATES.filter(state => counts.byTriage[state] > 0).map(
    state => `${labels.triage[state]} ${number(counts.byTriage[state], language)}`,
  )
  if (triageParts.length > 0) blocks.push(inline(labels.summary.triageLine(triageParts.join(' · '))))
  const fresh = input.findings.filter(finding => finding.isNew).length
  if (fresh > 0) blocks.push(inline(labels.summary.newLine(fresh)))

  // Prominent on every report; leads with "none reported" when the scan found nothing actionable.
  const actionable = counts.byClosure.confirmed + counts.byClosure.open_proof_gap
  const note = labels.zeroFindingsNote
  const lead = actionable === 0 ? `${note.noneReported} ` : ''
  blocks.push(`> [!IMPORTANT]\n> **${inline(note.heading)}** ${inline(lead + note.body)}`)
  return blocks.join('\n\n')
}

function coverage(input: ReportInput, labels: ReportLabels): string {
  const c = input.scan.coverage
  const l = labels.coverage
  const language = input.language
  const blocks: string[] = []
  if (c === undefined) {
    blocks.push(inline(l.missing))
  } else {
    const ratio = (part: number, whole: number) =>
      whole > 0 ? `${number(part, language)} / ${number(whole, language)}` : number(part, language)
    blocks.push(
      table(
        [inline(l.item), inline(l.count)],
        [
          [inline(l.filesAnalyzed), ratio(c.files.analyzed, c.files.total)],
          [inline(l.filesReadByAi), ratio(c.files.readByAi, c.files.total)],
          [inline(l.filesExcluded), number(c.files.excluded, language)],
          [inline(l.endpointsReviewed), ratio(c.endpoints.reviewed, c.endpoints.total)],
          [
            inline(l.tasks),
            inline(
              l.tasksLine(
                number(c.tasks.planned, language),
                number(c.tasks.completed, language),
                number(c.tasks.failed, language),
                number(c.tasks.skipped, language),
              ),
            ),
          ],
          [inline(l.discardedUnverifiable), number(c.discardedUnverifiable, language)],
        ],
        [false, true],
      ),
    )
    if (c.analyzers.length > 0) {
      const lines = c.analyzers.map(analyzer => {
        const version = analyzer.version === undefined ? '' : ` ${inline(analyzer.version)}`
        const state = analyzer.available ? l.available : l.unavailable
        const reason = analyzer.reason === undefined ? '' : `: ${inline(analyzer.reason)}`
        return `- ${codeSpan(analyzer.id)}${version} (${inline(analyzer.source)}): ${inline(state)}${reason}`
      })
      blocks.push(`**${inline(l.analyzers)}**\n\n${lines.join('\n')}`)
    }
    blocks.push(
      `**${inline(l.gaps)}**\n\n${c.gaps.length === 0 ? inline(l.noGaps) : c.gaps.map(gap => `- ${inline(gap)}`).join('\n')}`,
    )
  }
  const notices = input.scan.notices.filter(notice => notice.level !== 'info')
  if (notices.length > 0) {
    const lines = notices.map(notice => `- ${notice.level === 'error' ? '⚠' : '•'} ${inline(notice.text)}`)
    blocks.push(`**${inline(l.notices)}**\n\n${lines.join('\n')}`)
  }
  return blocks.join('\n\n')
}

function threatModel(input: ReportInput, labels: ReportLabels): string | undefined {
  const model = input.scan.threatModel
  if (model === undefined) return undefined
  const blocks: string[] = []
  const text = paragraphs(model.summary)
  if (text !== '') blocks.push(text)
  const lists: [string, readonly string[]][] = [
    [labels.threatModel.assets, model.assets],
    [labels.threatModel.actors, model.actors],
    [labels.threatModel.trustBoundaries, model.trustBoundaries],
  ]
  for (const [title, items] of lists) {
    if (items.length > 0) blocks.push(`**${inline(title)}**\n\n${items.map(item => `- ${inline(item)}`).join('\n')}`)
  }
  return blocks.join('\n\n')
}

// ---------------------------------------------------------------------------
// Findings
// ---------------------------------------------------------------------------

function location(ref: CodeRef | undefined, labels: ReportLabels, inTable = false): string {
  return ref === undefined ? inline(labels.finding.noLocation) : codeSpan(formatCodeRef(ref), inTable)
}

function quoteMark(check: QuoteCheck, labels: ReportLabels): string {
  return inline(labels.quoteChecks[check])
}

function cweCell(cwe: string | undefined, labels: ReportLabels): string {
  if (cwe === undefined) return inline(labels.finding.none)
  const id = cweNumber(cwe)
  const url = cweUrl(cwe)
  return id === undefined || url === undefined ? inline(cwe) : `CWE-${id} (<${url}>)`
}

function renderFinding(finding: FindingDetail, labels: ReportLabels): string {
  const f = labels.finding
  const blocks: string[] = [`#### ${inline(finding.title)}`]

  const source = [
    inline(labels.sources[finding.source]),
    `${inline(f.category)} ${codeSpan(finding.category, true)}`,
    ...(finding.ruleId === undefined ? [] : [`${inline(f.rule)} ${codeSpan(finding.ruleId, true)}`]),
    `${inline(f.reportedBy)} ${inline(createdBy(finding, labels))}`,
  ].join(' · ')
  const rows: string[][] = [
    [inline(f.severity), `**${inline(labels.severities[finding.severity])}**`],
    [inline(f.verification), inline(labels.verifications[finding.verification])],
    [inline(f.cwe), cweCell(finding.cwe, labels)],
    [inline(f.location), location(finding.location, labels, true)],
    [inline(f.source), source],
    [inline(f.triage), inline(labels.triage[finding.triage])],
  ]
  if (finding.isNew) rows.push([inline(f.isNew), inline(f.yes)])
  rows.push([
    inline(f.id),
    `${codeSpan(finding.id, true)} · ${inline(f.fingerprint)} ${codeSpan(finding.fingerprint, true)}`,
  ])
  blocks.push(table([inline(labels.field), inline(labels.value)], rows))

  pushProse(blocks, f.summary, finding.summary)
  pushProse(blocks, f.impact, finding.impact)
  pushList(blocks, f.preconditions, finding.preconditions)
  if (finding.attackPath.length > 0) {
    const steps = [...finding.attackPath].sort((a, b) => a.order - b.order)
    blocks.push(
      `**${inline(f.attackPath)}**\n\n${steps.map((step, index) => attackStep(step, index + 1, labels)).join('\n\n')}`,
    )
  }
  if (finding.evidence.length > 0) {
    blocks.push(`**${inline(f.evidence)}**\n\n${finding.evidence.map(item => evidenceItem(item, labels)).join('\n\n')}`)
  }
  if (finding.counterevidence.length > 0) {
    blocks.push(
      `**${inline(f.counterevidence)}**\n\n${finding.counterevidence.map(item => evidenceItem(item, labels)).join('\n\n')}`,
    )
  }
  if (finding.review !== undefined) {
    const verdict = `${inline(labels.reviewVerdicts[finding.review.verdict])} (${inline(f.reviewModel(finding.review.model))})`
    const reasoning = paragraphs(finding.review.reasoning)
    blocks.push(`**${inline(f.review)}**: ${verdict}${reasoning === '' ? '' : `\n\n${reasoning}`}`)
  }
  pushList(blocks, f.limitations, finding.limitations)
  pushProse(blocks, f.recommendation, finding.recommendation)
  if (finding.references.length > 0) {
    blocks.push(`**${inline(f.references)}**\n\n${finding.references.map(ref => `- ${linkOrText(ref)}`).join('\n')}`)
  }
  if (finding.triageNote !== undefined && finding.triageNote.trim() !== '') {
    pushProse(blocks, `${f.triageNote} (${labels.triage[finding.triage]})`, finding.triageNote)
  }
  return blocks.join('\n\n')
}

function createdBy(finding: FindingDetail, labels: ReportLabels): string {
  const by = finding.createdBy
  const role = labels.roles[by.role]
  const detail = by.analyzer ?? by.model
  return detail === undefined ? role : `${role} (${detail})`
}

function pushProse(blocks: string[], title: string, text: string): void {
  const body = paragraphs(text)
  if (body !== '') blocks.push(`**${inline(title)}**\n\n${body}`)
}

function pushList(blocks: string[], title: string, items: readonly string[]): void {
  const lines = items.map(item => inline(item)).filter(item => item !== '')
  if (lines.length > 0) blocks.push(`**${inline(title)}**\n\n${lines.map(line => `- ${line}`).join('\n')}`)
}

/** Indent every non-empty line so it stays inside a list item. */
function indentBlock(text: string, indent: string): string {
  return text
    .split('\n')
    .map(line => (line === '' ? '' : `${indent}${line}`))
    .join('\n')
}

function attackStep(step: AttackStepView, ordinal: number, labels: ReportLabels): string {
  const marker = `${ordinal}. `
  const indent = ' '.repeat(marker.length)
  const description = paragraphs(step.description) || inline(labels.finding.none)
  const lines = [`${marker}${indentBlock(description, indent).slice(indent.length)}`]
  const meta = [
    ...(step.location === undefined ? [] : [location(step.location, labels)]),
    ...(step.snippet === undefined && step.location === undefined ? [] : [quoteMark(step.quoteCheck, labels)]),
  ]
  if (meta.length > 0) lines.push('', `${indent}${meta.join(' · ')}`)
  if (step.snippet !== undefined && step.snippet.trim() !== '') {
    lines.push('', fencedCode(step.snippet, languageForPath(step.location?.path), indent))
  }
  return lines.join('\n')
}

function evidenceItem(item: EvidenceView, labels: ReportLabels): string {
  const indent = '  '
  const claim = paragraphs(item.claim) || inline(labels.finding.none)
  const origin = labels.roles[item.originRole]
  const meta = [
    ...(item.location === undefined ? [] : [location(item.location, labels)]),
    `${inline(origin)} · ${codeSpan(item.kind)} · ${codeSpan(item.trust)}`,
    ...(item.snippet === undefined && item.location === undefined ? [] : [quoteMark(item.quoteCheck, labels)]),
  ]
  const lines = [`- ${indentBlock(claim, indent).slice(indent.length)}`, '', `${indent}${meta.join(' · ')}`]
  if (item.snippet !== undefined && item.snippet.trim() !== '') {
    lines.push('', fencedCode(item.snippet, languageForPath(item.location?.path), indent))
  }
  return lines.join('\n')
}
