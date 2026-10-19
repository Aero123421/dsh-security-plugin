/**
 * Repairs for ordinary slips in model-written tool arguments, guided by the
 * tool's own zod schema, so one formatting mistake does not send a whole
 * submission back: `null` for an optional field, `"26"` for a line number,
 * `"High"` or `"idor"` for an enum value, one object where a list is
 * expected, `startLine` for `start_line`.
 *
 * The repairs only reshape values toward what the schema already accepts;
 * the schema still validates the result, so bounds, lengths and closed enums
 * hold exactly as before. Nothing here interprets meaning: a tool that needs
 * field-specific repairs (CWE ids, reference URLs) passes them as fixups.
 * {@link salvageArgs} is the last-chance variant used on a worker's final
 * request: it drops the list items that still fail instead of rejecting all.
 */

import type { z } from 'zod'

/** A repair for one schema node, applied before the generic rules for that node. */
export type Fixup = (value: unknown) => unknown

/** Options for {@link coerceArgs}. */
export interface CoerceOptions {
  /** Field-specific repairs keyed by the schema instance used in the tool's input. */
  readonly fixups?: ReadonlyMap<z.ZodType, Fixup>
  /**
   * Extra spellings of enum values, keyed by the normalized spelling
   * ({@link enumKey}). Each entry lists canonical values in order of
   * preference; the first one the enum at hand accepts wins.
   */
  readonly aliases?: Readonly<Record<string, readonly string[]>>
}

const MAX_DEPTH = 24

/**
 * Reshape `value` toward `schema`. Never throws; values it cannot repair are
 * returned unchanged for the schema to report. Rules:
 *
 * - `null` for an optional or defaulted field becomes `undefined`, so the
 *   default applies; `null` for a required list becomes `[]`.
 * - A non-list value where a list is expected becomes a one-item list; a
 *   string holding a JSON object or array is decoded where one is expected.
 * - Object keys spelled in camelCase (`startLine`) or with hyphens fill a
 *   missing snake_case key (`start_line`).
 * - Numeric strings (`"26"`, `"L26"`) become numbers, `"true"`/`"false"`
 *   become booleans, a list of strings where one string is expected is joined
 *   with newlines.
 * - Enum values match case-insensitively and ignoring `-`, `_` and spaces,
 *   then through `aliases`.
 */
export function coerceArgs(schema: z.ZodType, value: unknown, options: CoerceOptions = {}): unknown {
  return coerce(schema, value, options, 0)
}

/** Normalized spelling used to compare enum values: lower case without `-`, `_`, spaces and dots. */
export function enumKey(value: string): string {
  return value
    .trim()
    .toLowerCase()
    .replace(/[\s_.-]+/g, '')
}

interface Def {
  readonly type?: string
  readonly innerType?: z.ZodType
  readonly element?: z.ZodType
  readonly shape?: Record<string, z.ZodType>
  readonly entries?: Record<string, string | number>
}

function defOf(schema: z.ZodType): Def {
  return ((schema as unknown as { def?: Def }).def ?? {}) as Def
}

function coerce(schema: z.ZodType, input: unknown, options: CoerceOptions, depth: number): unknown {
  if (depth > MAX_DEPTH) return input
  const fixup = options.fixups?.get(schema)
  let value = input
  if (fixup) {
    try {
      value = fixup(value)
    } catch {
      value = input
    }
  }
  const def = defOf(schema)
  switch (def.type) {
    case 'optional':
    case 'default':
      if (value === null || value === undefined) return undefined
      return def.innerType ? coerce(def.innerType, value, options, depth + 1) : value
    case 'nullable':
      if (value === null) return null
      return def.innerType ? coerce(def.innerType, value, options, depth + 1) : value
    case 'object':
      return coerceObject(def, value, options, depth)
    case 'array':
      return coerceArray(def, value, options, depth)
    case 'string':
      return coerceString(value)
    case 'number':
      return coerceNumber(value)
    case 'boolean':
      return coerceBoolean(value)
    case 'enum':
      return coerceEnum(def, value, options)
    default:
      return value
  }
}

function coerceObject(def: Def, input: unknown, options: CoerceOptions, depth: number): unknown {
  const value = decodeJson(input, '{')
  if (typeof value !== 'object' || value === null || Array.isArray(value) || !def.shape) return value
  const source = value as Record<string, unknown>
  const out: Record<string, unknown> = { ...source }
  for (const [key, field] of Object.entries(def.shape)) {
    let current = source[key]
    if (current === undefined) {
      const alias = aliasKeys(key).find(name => source[name] !== undefined)
      if (alias !== undefined) {
        current = source[alias]
        delete out[alias]
      }
    }
    if (current === undefined) continue
    const repaired = coerce(field, current, options, depth + 1)
    if (repaired === undefined) delete out[key]
    else out[key] = repaired
  }
  return out
}

function coerceArray(def: Def, input: unknown, options: CoerceOptions, depth: number): unknown {
  if (input === null) return []
  let value = decodeJson(input, '[')
  if (value === undefined) return value
  if (!Array.isArray(value)) value = [value]
  const element = def.element
  if (!element) return value
  return (value as unknown[]).map(item => coerce(element, item, options, depth + 1))
}

function coerceString(value: unknown): unknown {
  if (Array.isArray(value) && value.length > 0 && value.every(item => typeof item === 'string')) {
    return value.join('\n')
  }
  return value
}

function coerceNumber(value: unknown): unknown {
  if (typeof value !== 'string') return value
  const line = /^\s*L?(\d{1,15})\s*$/i.exec(value)
  if (line?.[1]) return Number(line[1])
  if (/^\s*-?\d{1,15}(?:\.\d+)?\s*$/.test(value)) return Number(value)
  return value
}

function coerceBoolean(value: unknown): unknown {
  if (typeof value !== 'string') return value
  const text = value.trim().toLowerCase()
  if (text === 'true' || text === 'yes') return true
  if (text === 'false' || text === 'no') return false
  return value
}

function coerceEnum(def: Def, value: unknown, options: CoerceOptions): unknown {
  if (typeof value !== 'string' || !def.entries) return value
  const values = Object.values(def.entries).filter((entry): entry is string => typeof entry === 'string')
  if (values.includes(value)) return value
  const key = enumKey(value)
  const direct = values.find(candidate => enumKey(candidate) === key)
  if (direct !== undefined) return direct
  const aliased = options.aliases?.[key]?.find(candidate => values.includes(candidate))
  return aliased ?? value
}

/** A string holding JSON of the expected shape (`{` object, `[` array) is decoded; anything else is kept. */
function decodeJson(value: unknown, opener: '{' | '['): unknown {
  if (typeof value !== 'string') return value
  const text = value.trim()
  if (!text.startsWith(opener)) return value
  try {
    return JSON.parse(text) as unknown
  } catch {
    return value
  }
}

/** Other spellings of a snake_case key: `startLine`, `start-line`, `StartLine`. */
function aliasKeys(key: string): string[] {
  if (!key.includes('_')) return []
  const camel = key.replace(/_([a-z0-9])/g, (_, char: string) => char.toUpperCase())
  return [camel, key.replace(/_/g, '-'), camel.charAt(0).toUpperCase() + camel.slice(1)]
}

/** Outcome of {@link salvageArgs}. */
export type Salvage<A> =
  | { readonly ok: true; readonly value: A; readonly dropped: number }
  | { readonly ok: false; readonly issues: readonly z.core.$ZodIssue[] }

/**
 * Validate `value`, dropping list items that fail: for every issue, the
 * innermost list item on its path is removed, and a list over its maximum
 * length is cut, until the rest validates (at most `rounds` passes). Fails
 * when an issue concerns a field outside any list (nothing can be dropped).
 * `value` is not modified.
 */
export async function salvageArgs<A>(schema: z.ZodType<A>, value: unknown, rounds = 8): Promise<Salvage<A>> {
  const current: unknown = cloneJson(value)
  let dropped = 0
  let issues: readonly z.core.$ZodIssue[] = []
  for (let round = 0; round <= rounds; round++) {
    const parsed = await schema.safeParseAsync(current)
    if (parsed.success) return { ok: true, value: parsed.data, dropped }
    issues = parsed.error.issues
    if (round === rounds) break
    const removals = new Map<string, readonly PropertyKey[]>()
    const cuts: { readonly path: readonly PropertyKey[]; readonly maximum: number }[] = []
    for (const issue of issues) {
      const maximum = (issue as { maximum?: unknown }).maximum
      if (issue.code === 'too_big' && typeof maximum === 'number' && Array.isArray(at(current, issue.path))) {
        cuts.push({ path: issue.path, maximum })
        continue
      }
      let position = -1
      for (let i = issue.path.length - 1; i >= 0; i--) {
        if (typeof issue.path[i] === 'number') {
          position = i
          break
        }
      }
      if (position < 0) return { ok: false, issues }
      const item = issue.path.slice(0, position + 1)
      removals.set(pathKey(item), item)
    }
    // Invalid items go first; a list is cut to its maximum only once its remaining items are valid,
    // so the cut never keeps an invalid item in place of a valid one. Zod reports an over-long list
    // without checking its items, so those are checked against the item schema here.
    if (removals.size === 0) {
      for (const cut of cuts) {
        const list = at(current, cut.path)
        if (!Array.isArray(list)) continue
        const item = elementSchema(schema, cut.path)
        if (item) {
          const valid: unknown[] = []
          for (const entry of list) if ((await item.safeParseAsync(entry)).success) valid.push(entry)
          dropped += list.length - valid.length
          list.splice(0, list.length, ...valid)
        }
        if (list.length > cut.maximum) {
          dropped += list.length - cut.maximum
          list.length = cut.maximum
        }
      }
    }
    // Deepest first, then highest index first, so no removal shifts a later one; an item whose
    // enclosing item is removed anyway is left alone.
    const ordered = [...removals.values()].sort(
      (a, b) => b.length - a.length || (b.at(-1) as number) - (a.at(-1) as number),
    )
    for (const item of ordered) {
      const enclosed = item.some(
        (key, position) =>
          position < item.length - 1 && typeof key === 'number' && removals.has(pathKey(item.slice(0, position + 1))),
      )
      if (enclosed) continue
      const list = at(current, item.slice(0, -1))
      const index = item.at(-1) as number
      if (Array.isArray(list) && index < list.length) {
        list.splice(index, 1)
        dropped++
      }
    }
  }
  return { ok: false, issues }
}

function pathKey(path: readonly PropertyKey[]): string {
  return JSON.stringify(path.map(key => (typeof key === 'number' ? key : String(key))))
}

/** The item schema of the list at `path` within `schema`, unwrapping optional, default and nullable wrappers. */
function elementSchema(schema: z.ZodType, path: readonly PropertyKey[]): z.ZodType | undefined {
  let node: z.ZodType | undefined = schema
  const unwrap = (current: z.ZodType | undefined): z.ZodType | undefined => {
    let value = current
    for (let i = 0; value && i < MAX_DEPTH; i++) {
      const def = defOf(value)
      if (def.type !== 'optional' && def.type !== 'default' && def.type !== 'nullable') break
      value = def.innerType
    }
    return value
  }
  for (const key of path) {
    const current = unwrap(node)
    if (!current) return undefined
    const def = defOf(current)
    node = typeof key === 'number' ? def.element : def.shape?.[String(key)]
    if (!node) return undefined
  }
  const list = unwrap(node)
  return list ? defOf(list).element : undefined
}

function at(root: unknown, path: readonly PropertyKey[]): unknown {
  let node = root
  for (const key of path) {
    if (typeof node !== 'object' || node === null) return undefined
    node = (node as Record<PropertyKey, unknown>)[key]
  }
  return node
}

function cloneJson(value: unknown): unknown {
  try {
    return structuredClone(value)
  } catch {
    return value
  }
}
