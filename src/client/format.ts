/**
 * Defensive formatters. Every function accepts possibly-missing data and
 * returns a display string, using an em dash for anything unknown, so a
 * surprising Host payload never crashes a view.
 */

export const DASH = '—'

export function isFiniteNumber(value: unknown): value is number {
  return typeof value === 'number' && Number.isFinite(value)
}

export function formatNumber(value: unknown, locale: string): string {
  if (!isFiniteNumber(value)) return DASH
  try {
    return new Intl.NumberFormat(locale).format(value)
  } catch {
    return String(value)
  }
}

/** Compact form for large token counts (1.2M, 120万). */
export function formatCompact(value: unknown, locale: string): string {
  if (!isFiniteNumber(value)) return DASH
  try {
    return new Intl.NumberFormat(locale, { notation: 'compact', maximumFractionDigits: 1 }).format(value)
  } catch {
    return String(value)
  }
}

export function parseDate(value: unknown): Date | undefined {
  if (typeof value !== 'string' && typeof value !== 'number') return undefined
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? undefined : date
}

export function formatDateTime(value: unknown, locale: string): string {
  const date = parseDate(value)
  if (!date) return DASH
  try {
    return new Intl.DateTimeFormat(locale, { dateStyle: 'medium', timeStyle: 'short' }).format(date)
  } catch {
    return date.toISOString()
  }
}

export function formatTime(value: unknown, locale: string): string {
  const date = parseDate(value)
  if (!date) return DASH
  try {
    return new Intl.DateTimeFormat(locale, { hour: '2-digit', minute: '2-digit', second: '2-digit' }).format(date)
  } catch {
    return date.toISOString().slice(11, 19)
  }
}

const RELATIVE_STEPS: readonly [Intl.RelativeTimeFormatUnit, number][] = [
  ['second', 60],
  ['minute', 60],
  ['hour', 24],
  ['day', 7],
  ['week', 4.345],
  ['month', 12],
  ['year', Number.POSITIVE_INFINITY],
]

export function formatRelative(value: unknown, locale: string, now: number = Date.now()): string {
  const date = parseDate(value)
  if (!date) return DASH
  let amount = (date.getTime() - now) / 1000
  if (Math.abs(amount) < 45) {
    try {
      return new Intl.RelativeTimeFormat(locale, { numeric: 'auto' }).format(0, 'second')
    } catch {
      return DASH
    }
  }
  for (const [unit, size] of RELATIVE_STEPS) {
    if (Math.abs(amount) < size) {
      try {
        return new Intl.RelativeTimeFormat(locale, { numeric: 'auto' }).format(Math.round(amount), unit)
      } catch {
        return formatDateTime(value, locale)
      }
    }
    amount /= size
  }
  return formatDateTime(value, locale)
}

/** `1 h 05 min`, `12 min`, `40 s`, localized through Intl unit formatting. */
export function formatDuration(ms: unknown, locale: string): string {
  if (!isFiniteNumber(ms) || ms < 0) return DASH
  const totalSeconds = Math.round(ms / 1000)
  const hours = Math.floor(totalSeconds / 3600)
  const minutes = Math.floor((totalSeconds % 3600) / 60)
  const seconds = totalSeconds % 60
  const unit = (amount: number, name: 'hour' | 'minute' | 'second'): string => {
    try {
      return new Intl.NumberFormat(locale, { style: 'unit', unit: name, unitDisplay: 'short' }).format(amount)
    } catch {
      return `${amount} ${name[0]}`
    }
  }
  if (hours > 0) return `${unit(hours, 'hour')} ${unit(minutes, 'minute')}`
  if (minutes > 0) return `${unit(minutes, 'minute')}`
  return unit(seconds, 'second')
}

export function formatMinutes(ms: unknown): number {
  return isFiniteNumber(ms) ? Math.max(0, Math.round(ms / 60_000)) : 0
}

export function shortSha(commit: unknown): string {
  return typeof commit === 'string' && commit ? commit.slice(0, 7) : DASH
}

export function text(value: unknown): string {
  if (typeof value === 'string') return value.trim() ? value : DASH
  if (isFiniteNumber(value)) return String(value)
  return DASH
}

/** Ratio in [0, 1]; 0 when either side is unusable. */
export function ratio(done: unknown, total: unknown): number {
  if (!isFiniteNumber(done) || !isFiniteNumber(total) || total <= 0) return 0
  return Math.min(1, Math.max(0, done / total))
}

export function asArray<T>(value: readonly T[] | undefined | null): readonly T[] {
  return Array.isArray(value) ? value : []
}
