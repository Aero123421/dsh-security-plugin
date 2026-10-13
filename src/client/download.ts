/** Browser file and clipboard helpers. */

import type { ReportFile } from '../shared/contracts.ts'

/** Keep only the basename of a Host-supplied filename and strip reserved characters. */
export function safeFilename(name: unknown, fallback = 'security-report.txt'): string {
  if (typeof name !== 'string') return fallback
  const base = name.split(/[\\/]/).pop() ?? ''
  const cleaned = base
    .replace(/[:*?"<>|\u0000-\u001f]+/g, '-')
    .replace(/^\.+/, '')
    .trim()
  return cleaned.slice(0, 180) || fallback
}

/**
 * Save a report through a temporary `<a download>`. The object URL is revoked
 * on the next task so the click has time to start the download.
 */
export function downloadFile(file: ReportFile, doc: Document = document): void {
  const mime = typeof file.mime === 'string' && file.mime ? file.mime : 'text/plain'
  const blob = new Blob([typeof file.content === 'string' ? file.content : ''], { type: `${mime};charset=utf-8` })
  const url = URL.createObjectURL(blob)
  const anchor = doc.createElement('a')
  anchor.href = url
  anchor.download = safeFilename(file.filename)
  anchor.rel = 'noopener'
  anchor.style.display = 'none'
  doc.body.append(anchor)
  try {
    anchor.click()
  } finally {
    anchor.remove()
    setTimeout(() => URL.revokeObjectURL(url), 0)
  }
}

/** Copy text with the async Clipboard API, falling back to a hidden textarea. */
export async function copyText(value: string, doc: Document = document): Promise<boolean> {
  const clipboard = typeof navigator !== 'undefined' ? navigator.clipboard : undefined
  if (clipboard && typeof clipboard.writeText === 'function') {
    try {
      await clipboard.writeText(value)
      return true
    } catch {
      // Permission denied or insecure context: fall through.
    }
  }
  const area = doc.createElement('textarea')
  area.value = value
  area.setAttribute('readonly', '')
  area.style.position = 'fixed'
  area.style.opacity = '0'
  area.style.pointerEvents = 'none'
  doc.body.append(area)
  const previous = doc.activeElement instanceof HTMLElement ? doc.activeElement : null
  try {
    area.select()
    return typeof doc.execCommand === 'function' ? doc.execCommand('copy') : false
  } catch {
    return false
  } finally {
    area.remove()
    previous?.focus()
  }
}
