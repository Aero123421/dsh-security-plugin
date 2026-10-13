/**
 * Stable identities for "the same issue" across scans. Line numbers are
 * deliberately excluded so an unrelated edit above the code does not make an
 * old finding look new or lose its triage.
 */

import { createHash } from 'node:crypto'

/** 32 hex chars of SHA-256 over the NUL-joined parts. */
export function fingerprintOf(parts: readonly string[]): string {
  return createHash('sha256').update(parts.join('\u0000')).digest('hex').slice(0, 32)
}

/** Whitespace-insensitive form used inside fingerprints. */
export function normalizeCode(text: string): string {
  return text.replace(/\s+/g, ' ').trim().slice(0, 400)
}

/** Digest of a snapshot's (path, sha256) list. */
export function snapshotDigest(files: Iterable<{ readonly path: string; readonly sha256: string }>): string {
  const hash = createHash('sha256')
  const sorted = [...files].sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0))
  for (const file of sorted) hash.update(`${file.path}\u0000${file.sha256}\n`)
  return hash.digest('hex')
}
