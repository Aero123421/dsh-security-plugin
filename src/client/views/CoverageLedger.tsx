import type { Coverage, CoverageUnit, CoverageUnitStatus } from '../../shared/contracts.ts'
import { asArray, formatNumber, isFiniteNumber } from '../format.ts'
import { coverageReasonText, type MessageKey, type Translator } from '../i18n.ts'

/** Units shown in full. Everything else sits behind one disclosure once it is longer than this. */
const INLINE_LIMIT = 5

const STATUS_ORDER: readonly CoverageUnitStatus[] = ['not-run', 'blocked', 'finding', 'covered']
const GROUP_LABEL: Readonly<Record<CoverageUnitStatus, MessageKey>> = {
  'not-run': 'coverage.units.notRun',
  blocked: 'coverage.units.blocked',
  finding: 'coverage.units.finding',
  covered: 'coverage.units.covered',
}
const PLAN_PART: Readonly<Record<CoverageUnitStatus, MessageKey>> = {
  'not-run': 'coverage.plan.notRun',
  blocked: 'coverage.plan.blocked',
  finding: 'coverage.plan.finding',
  covered: 'coverage.plan.examined',
}

/** Units the UI can place; a Host newer than this client may send statuses it does not know. */
export function ledgerUnits(coverage: Coverage): readonly CoverageUnit[] {
  return asArray(coverage.units).filter(
    unit => unit && typeof unit.title === 'string' && STATUS_ORDER.includes(unit.status),
  )
}

/** "34 parts: 25 examined, 3 with findings, 2 undecided, 4 not examined", leaving out empty parts. */
export function planSummary(tr: Translator, units: readonly CoverageUnit[]): string {
  const locale = tr.intlLocale
  const parts = [...STATUS_ORDER].reverse().flatMap(status => {
    const count = units.filter(unit => unit.status === status).length
    return count > 0 ? [tr.t(PLAN_PART[status], { count: formatNumber(count, locale) })] : []
  })
  const total =
    units.length === 1
      ? tr.t('coverage.plan.totalOne')
      : tr.t('coverage.plan.total', { count: formatNumber(units.length, locale) })
  return tr.t('coverage.plan.value', { total, parts: parts.join(tr.t('coverage.plan.separator')) })
}

export function unassignedText(tr: Translator, count: number): string {
  return count === 1
    ? tr.t('coverage.unassigned.valueOne')
    : tr.t('coverage.unassigned.value', { count: formatNumber(count, tr.intlLocale) })
}

/** Rows for "Review plan" and, when source files fell outside every part, "Unassigned files". */
export function LedgerRows(props: { readonly coverage: Coverage; readonly tr: Translator }) {
  const { coverage, tr } = props
  const units = ledgerUnits(coverage)
  const unassigned = isFiniteNumber(coverage.unassignedFiles) ? coverage.unassignedFiles : 0
  return (
    <>
      {units.length ? (
        <div className="dshsec-kv-row">
          <dt>{tr.t('coverage.plan')}</dt>
          <dd className="dshsec-num">{planSummary(tr, units)}</dd>
        </div>
      ) : null}
      {unassigned > 0 ? (
        <div className="dshsec-kv-row">
          <dt>{tr.t('coverage.unassigned')}</dt>
          <dd className="dshsec-num">{unassignedText(tr, unassigned)}</dd>
        </div>
      ) : null}
    </>
  )
}

/** What the AI review examined and what it did not: unexamined and undecided parts first, in full. */
export function LedgerList(props: { readonly coverage: Coverage; readonly tr: Translator }) {
  const { tr } = props
  const units = ledgerUnits(props.coverage)
  if (!units.length) return null
  const byStatus = (status: CoverageUnitStatus) => units.filter(unit => unit.status === status)
  const attention = STATUS_ORDER.slice(0, 2)
  const rest = STATUS_ORDER.slice(2)
  const restCount = rest.reduce((sum, status) => sum + byStatus(status).length, 0)
  const group = (status: CoverageUnitStatus) => (
    <LedgerGroup key={status} status={status} units={byStatus(status)} tr={tr} />
  )
  return (
    <section className="dshsec-units" aria-label={tr.t('coverage.units.label')}>
      {attention.map(group)}
      {restCount > INLINE_LIMIT ? (
        <details className="dshsec-disclosure">
          <summary>{tr.t('coverage.units.showRest', { count: formatNumber(restCount, tr.intlLocale) })}</summary>
          <div className="dshsec-units dshsec-units--rest">{rest.map(group)}</div>
        </details>
      ) : (
        rest.map(group)
      )}
    </section>
  )
}

function LedgerGroup(props: {
  readonly status: CoverageUnitStatus
  readonly units: readonly CoverageUnit[]
  readonly tr: Translator
}) {
  const { status, units, tr } = props
  if (!units.length) return null
  return (
    <div className="dshsec-unit-group">
      <h4 className="dshsec-h4">
        {tr.t(GROUP_LABEL[status])}
        <span className="dshsec-muted dshsec-num"> · {formatNumber(units.length, tr.intlLocale)}</span>
      </h4>
      <ul className="dshsec-unit-list">
        {units.map((unit, index) => (
          // biome-ignore lint/suspicious/noArrayIndexKey: unit ids come from the Host and are not guaranteed unique
          <LedgerUnit key={`${unit.id}:${index}`} unit={unit} tr={tr} />
        ))}
      </ul>
    </div>
  )
}

function LedgerUnit(props: { readonly unit: CoverageUnit; readonly tr: Translator }) {
  const { unit, tr } = props
  const paths = asArray(unit.paths).filter(path => typeof path === 'string' && path)
  const more = paths.length - 1
  const unexamined = unit.status === 'not-run' || unit.status === 'blocked'
  const findings = isFiniteNumber(unit.findings) ? unit.findings : 0
  return (
    <li className={`dshsec-unit is-${unit.status}`}>
      <span className="dshsec-unit-dot" aria-hidden="true" />
      <div className="dshsec-unit-body">
        <span className="dshsec-unit-title">{unit.title}</span>
        <span className="dshsec-unit-meta">
          {unit.surface ? <span>{unit.surface}</span> : null}
          {paths.length ? (
            <span>
              <span className="dshsec-mono">{paths[0]}</span>
              {more > 0 ? ` ${tr.t('coverage.unit.morePaths', { count: formatNumber(more, tr.intlLocale) })}` : null}
            </span>
          ) : null}
          {unit.status === 'finding' && findings > 0 ? (
            <span>
              {findings === 1
                ? tr.t('coverage.unit.findingsOne')
                : tr.t('coverage.unit.findings', { count: formatNumber(findings, tr.intlLocale) })}
            </span>
          ) : null}
          {unexamined && unit.reason ? (
            // The Host's English sentence stays a tooltip; the visible copy is always localized.
            <span title={unit.reason.fallback || undefined}>{coverageReasonText(tr, unit.reason)}</span>
          ) : null}
          {unit.origin === 'critic' ? <span>{tr.t('coverage.unit.originCritic')}</span> : null}
          {unit.origin === 'gap' ? <span>{tr.t('coverage.unit.originGap')}</span> : null}
        </span>
      </div>
    </li>
  )
}
