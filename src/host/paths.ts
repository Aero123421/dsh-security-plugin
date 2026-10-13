/**
 * Masking of absolute Host paths in text that reaches the browser (scan
 * errors, analyzer and toolkit failure reasons, warnings, event messages,
 * RPC error details). Tool stderr and spawn errors routinely quote the
 * project root, the plugin data directory or the user's home directory;
 * this is the one place that turns them into placeholders.
 *
 * Model-facing text uses `maskRoot` (`evidence/text.ts`) instead, which only
 * knows the snapshot root.
 */

import { realpathSync } from 'node:fs'

/** Placeholder for a project (workspace) root. */
export const PROJECT_PLACEHOLDER = '<project>'
/** Placeholder for the plugin data directory (database, managed toolkit). */
export const DATA_PLACEHOLDER = '<data>'
/** Placeholder for the system temp directory. */
export const TMP_PLACEHOLDER = '<tmp>'
/** Placeholder for the Host user's home directory. */
export const HOME_PLACEHOLDER = '~'

/** Absolute directories to mask; every field is optional. */
export interface HostPathMaskOptions {
  /** Project roots (as registered and as canonicalized), shown as `<project>`. */
  readonly workspaceRoots?: readonly (string | undefined)[]
  /** Plugin data directory, shown as `<data>`. */
  readonly dataDir?: string | undefined
  /** System temp directory, shown as `<tmp>`. */
  readonly tmp?: string | undefined
  /** Host user's home directory, shown as `~`. */
  readonly home?: string | undefined
}

/** Replaces absolute Host paths in browser-bound text. */
export type PathMasker = (text: string) => string

// A file-name character: a match must not start or end inside a longer name.
const NAME_CHAR = '[0-9A-Za-z_\\-\\u0080-\\uffff]'
const BEFORE = `(?<!${NAME_CHAR}|\\.)`
// A trailing `.` ends a sentence ("… in /home/u/app."), while `.git` continues a name.
const AFTER = `(?!${NAME_CHAR}|\\.${NAME_CHAR})`

interface Rule {
  readonly length: number
  readonly pattern: RegExp
  readonly placeholder: string
}

/**
 * Build a masker. Directories are replaced longest first (so a project under
 * the home directory becomes `<project>`, not `~/…`), in their `/` and `\`
 * spellings, case-insensitively for Windows-style paths (`C:\…`, `\\server\…`).
 * A match must sit on path boundaries: `/home/u` does not mask `/home/user2`
 * or `/srv/home/u`. Roots shorter than two characters (`/`, `C:`) are ignored.
 */
export function createPathMasker(options: HostPathMaskOptions): PathMasker {
  const rules: Rule[] = []
  const addOne = (dir: string, placeholder: string) => {
    const rule = ruleFor(dir, placeholder)
    if (rule && !rules.some(r => r.pattern.source === rule.pattern.source)) rules.push(rule)
  }
  // Tools often print canonical paths (macOS `/var/…` is `/private/var/…`), so mask both spellings.
  const add = (dir: string | undefined, placeholder: string) => {
    if (dir === undefined) return
    addOne(dir, placeholder)
    const real = canonical(dir)
    if (real !== undefined && real !== dir) addOne(real, placeholder)
  }
  for (const root of options.workspaceRoots ?? []) add(root, PROJECT_PLACEHOLDER)
  add(options.dataDir, DATA_PLACEHOLDER)
  add(options.tmp, TMP_PLACEHOLDER)
  add(options.home, HOME_PLACEHOLDER)
  rules.sort((a, b) => b.length - a.length)
  return text => {
    if (text === '' || rules.length === 0) return text
    let out = text
    for (const rule of rules) out = out.replace(rule.pattern, rule.placeholder)
    return out
  }
}

function canonical(dir: string): string | undefined {
  try {
    return realpathSync.native(dir)
  } catch {
    return undefined
  }
}

/** One-off form of {@link createPathMasker}. */
export function maskHostPaths(text: string, options: HostPathMaskOptions): string {
  return createPathMasker(options)(text)
}

/**
 * Apply `mask` to every string inside a JSON-like value (objects, arrays),
 * returning a copy. Non-plain objects are returned unchanged.
 */
export function maskDeep<T>(value: T, mask: PathMasker, depth = 0): T {
  if (typeof value === 'string') return mask(value) as T
  if (depth > 16 || value === null || typeof value !== 'object') return value
  if (Array.isArray(value)) return value.map(item => maskDeep(item, mask, depth + 1)) as T
  const proto = Object.getPrototypeOf(value)
  if (proto !== Object.prototype && proto !== null) return value
  const out: Record<string, unknown> = {}
  for (const [key, field] of Object.entries(value)) out[key] = maskDeep(field, mask, depth + 1)
  return out as T
}

/**
 * Home-relative form of an absolute path (`~/projects/app`) when it lies
 * under `home`; the path unchanged otherwise.
 */
export function homeRelative(path: string, home: string | undefined): string {
  const rule = home ? ruleFor(home, HOME_PLACEHOLDER) : undefined
  if (!rule) return path
  const anchored = new RegExp(`^${rule.pattern.source}`, rule.pattern.flags.replace('g', ''))
  const match = anchored.exec(path)
  return match ? `${HOME_PLACEHOLDER}${path.slice(match[0].length)}` : path
}

function ruleFor(dir: string, placeholder: string): Rule | undefined {
  const trimmed = dir.trim().replace(/[\\/]+$/, '')
  if (trimmed.length < 2 || /^[A-Za-z]:$/.test(trimmed)) return undefined
  const windows = /^[A-Za-z]:[\\/]/.test(trimmed) || /^[\\/]{2}[^\\/]/.test(trimmed)
  const leading = /^[\\/]*/.exec(trimmed)?.[0].length ?? 0
  const body =
    (leading > 0 ? `[\\\\/]{${leading}}` : '') +
    trimmed
      .slice(leading)
      .split(/[\\/]+/)
      .map(segment => segment.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'))
      .join('[\\\\/]+')
  return {
    length: trimmed.length,
    pattern: new RegExp(`${BEFORE}${body}${AFTER}`, windows ? 'gi' : 'g'),
    placeholder,
  }
}
