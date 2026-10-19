/**
 * Optional native AST engine backed by `@ast-grep/napi` (tree-sitter).
 *
 * The package is an optional dependency with prebuilt binaries for a handful
 * of platforms, so every caller must cope with `undefined`: analyzers fall
 * back to their token/line based extractors with reduced precision. Python
 * uses the tree-sitter grammar shipped in `vendor/tree-sitter-python` when
 * this OS and CPU have a prebuild, registered as a dynamic language.
 *
 * Only the small structural surface below is used. The native objects are
 * typed locally so nothing from the optional package leaks into our types.
 */

import { closeSync, openSync, readSync, statSync } from 'node:fs'
import { PYTHON_DYNAMIC_LANGUAGE, vendoredPythonLibrary } from './python-grammar.ts'

/** 0-based position reported by ast-grep. `index` is a UTF-16 offset into the source string. */
export interface SgPos {
  readonly line: number
  readonly column: number
  readonly index: number
}

export interface SgRange {
  readonly start: SgPos
  readonly end: SgPos
}

/** A pattern string or a rule object such as `{ rule: { kind: 'call_expression' } }`. */
export type SgMatcher = string | { readonly rule: Readonly<Record<string, unknown>> }

/** Structural subset of ast-grep's `SgNode`. */
export interface SgNode {
  range(): SgRange
  text(): string
  kind(): string
  isNamed(): boolean
  isLeaf(): boolean
  field(name: string): SgNode | null
  parent(): SgNode | null
  children(): SgNode[]
  find(matcher: SgMatcher): SgNode | null
  findAll(matcher: SgMatcher): SgNode[]
  getMatch(name: string): SgNode | null
}

/** Structural subset of ast-grep's `SgRoot`. */
export interface SgRoot {
  root(): SgNode
}

/** Language identifiers accepted by {@link AstGrepHandle.parse}. */
export interface AstGrepLangs {
  readonly JavaScript: string
  readonly TypeScript: string
  readonly Tsx: string
  /** Present only when the shipped Python grammar was registered. */
  readonly Python?: string
}

/** A loaded ast-grep engine. */
export interface AstGrepHandle {
  readonly Lang: AstGrepLangs
  /** Whether `Lang.Python` can be parsed. */
  readonly supportsPython: boolean
  /** Parse source text. Throws on engine errors; prefer {@link parseSafely}. */
  parse(lang: string, source: string): SgRoot
}

/** Files larger than this (UTF-8 bytes) are never parsed natively. */
export const AST_MAX_SOURCE_BYTES = 512 * 1024

const NAPI_MODULE = '@ast-grep/napi'
const PYTHON_LANG = 'python'

let loading: Promise<AstGrepHandle | undefined> | undefined
/** Library registered as the `python` dynamic language in this process (registration is process-wide). */
let pythonLibrary: string | undefined

/**
 * Load the native engine once per process. Resolves to `undefined` when the
 * package is missing, has no binary for this platform, or `disabled` is set.
 * Never rejects.
 */
export async function loadAstGrep(options: { readonly disabled?: boolean } = {}): Promise<AstGrepHandle | undefined> {
  if (options.disabled) return undefined
  loading ??= importEngine()
  return loading
}

/**
 * Build a handle from an already imported `@ast-grep/napi` module namespace.
 * `python` is the dynamic-language registration (`libraryPath`, `extensions`,
 * `languageSymbol`, `expandoChar`). Exposed for tools and tests that supply
 * the grammar themselves; returns `undefined` when `napi` does not have the
 * expected shape.
 */
export function createAstGrepHandle(napi: unknown, python?: unknown): AstGrepHandle | undefined {
  const mod = moduleRecord(napi)
  if (!mod) return undefined
  const parseFn = mod.parse
  const lang = mod.Lang
  if (typeof parseFn !== 'function' || !isRecord(lang)) return undefined
  const js = typeof lang.JavaScript === 'string' ? lang.JavaScript : undefined
  const ts = typeof lang.TypeScript === 'string' ? lang.TypeScript : undefined
  const tsx = typeof lang.Tsx === 'string' ? lang.Tsx : undefined
  if (!js || !ts || !tsx) return undefined

  const parse = (language: string, source: string): SgRoot => {
    const root: unknown = Reflect.apply(parseFn, mod, [language, source])
    if (!isRecord(root) || typeof root.root !== 'function') throw new Error('ast-grep returned no tree')
    return root as unknown as SgRoot
  }

  let supportsPython = false
  if (python !== undefined && typeof mod.registerDynamicLanguage === 'function') {
    try {
      const reg = moduleRecord(python)
      // `libraryPath` is a lazy getter that throws when no prebuilt parser exists.
      const libraryPath = reg?.libraryPath
      // The native registrar aborts the whole process (an uncatchable Rust
      // panic) on a missing or invalid library, so check the file first and
      // register at most once per process. A later handle only claims Python
      // when it was given a valid grammar library too.
      if (reg && typeof libraryPath === 'string' && (libraryPath === pythonLibrary || isNativeLibrary(libraryPath))) {
        if (pythonLibrary === undefined) {
          Reflect.apply(mod.registerDynamicLanguage, mod, [
            {
              [PYTHON_LANG]: {
                libraryPath,
                extensions: Array.isArray(reg.extensions) ? reg.extensions : [...PYTHON_DYNAMIC_LANGUAGE.extensions],
                ...(typeof reg.languageSymbol === 'string' ? { languageSymbol: reg.languageSymbol } : {}),
                ...(typeof reg.expandoChar === 'string' ? { expandoChar: reg.expandoChar } : {}),
              },
            },
          ])
          pythonLibrary = libraryPath
        }
        parse(PYTHON_LANG, 'x = 1\n').root()
        supportsPython = true
      }
    } catch {
      supportsPython = false
    }
  }

  return {
    Lang: { JavaScript: js, TypeScript: ts, Tsx: tsx, ...(supportsPython ? { Python: PYTHON_LANG } : {}) },
    supportsPython,
    parse,
  }
}

/**
 * Parse `source`, returning `undefined` instead of throwing. Sources over
 * {@link AST_MAX_SOURCE_BYTES} are skipped so callers use their fallback.
 */
export function parseSafely(handle: AstGrepHandle | undefined, lang: string, source: string): SgNode | undefined {
  if (!handle) return undefined
  if (source.length > AST_MAX_SOURCE_BYTES) return undefined
  if (source.length * 3 > AST_MAX_SOURCE_BYTES && Buffer.byteLength(source, 'utf8') > AST_MAX_SOURCE_BYTES) {
    return undefined
  }
  try {
    return handle.parse(lang, source).root()
  } catch {
    return undefined
  }
}

/**
 * The ast-grep language for a workspace path, or `undefined` when the engine
 * cannot parse it (unknown extension, or Python without the grammar).
 */
export function astLangForPath(handle: AstGrepHandle | undefined, path: string): string | undefined {
  if (!handle) return undefined
  const ext = /\.([A-Za-z0-9]+)$/.exec(path)?.[1]?.toLowerCase()
  switch (ext) {
    case 'ts':
    case 'mts':
    case 'cts':
      return handle.Lang.TypeScript
    case 'tsx':
      return handle.Lang.Tsx
    case 'js':
    case 'jsx':
    case 'mjs':
    case 'cjs':
      return handle.Lang.JavaScript
    case 'py':
    case 'pyw':
    case 'pyi':
      return handle.Lang.Python
    default:
      return undefined
  }
}

const validKindCache = new Map<string, Map<string, boolean>>()

/**
 * Find all descendants of `node` whose kind is one of `kinds`, silently
 * ignoring kinds the grammar does not define (ast-grep rejects the whole rule
 * otherwise). Results are in document order.
 */
export function findAllKinds(node: SgNode, lang: string, kinds: readonly string[]): SgNode[] {
  const valid = kinds.filter(kind => isValidKind(node, lang, kind))
  if (valid.length === 0) return []
  try {
    return node.findAll({ rule: valid.length === 1 ? { kind: valid[0] } : { any: valid.map(kind => ({ kind })) } })
  } catch {
    return []
  }
}

function isValidKind(node: SgNode, lang: string, kind: string): boolean {
  let cache = validKindCache.get(lang)
  if (!cache) {
    cache = new Map()
    validKindCache.set(lang, cache)
  }
  const known = cache.get(kind)
  if (known !== undefined) return known
  let ok = true
  try {
    node.find({ rule: { kind } })
  } catch {
    ok = false
  }
  cache.set(kind, ok)
  return ok
}

async function importEngine(): Promise<AstGrepHandle | undefined> {
  let napi: unknown
  try {
    napi = await import(NAPI_MODULE)
  } catch {
    return undefined
  }
  const libraryPath = vendoredPythonLibrary()
  const python = libraryPath ? { libraryPath, ...PYTHON_DYNAMIC_LANGUAGE } : undefined
  try {
    return createAstGrepHandle(napi, python)
  } catch {
    return undefined
  }
}

/** A readable regular file that starts with an ELF, Mach-O or PE header. */
function isNativeLibrary(path: string): boolean {
  let fd: number | undefined
  try {
    if (!statSync(path).isFile()) return false
    fd = openSync(path, 'r')
    const head = Buffer.alloc(4)
    if (readSync(fd, head, 0, 4, 0) < 4) return false
    const magic = head.readUInt32BE(0)
    return (
      magic === 0x7f454c46 || // ELF
      magic === 0xcffaedfe || // Mach-O 64-bit (little-endian)
      magic === 0xcefaedfe || // Mach-O 32-bit (little-endian)
      magic === 0xcafebabe || // Mach-O universal
      head.readUInt16BE(0) === 0x4d5a // PE ("MZ")
    )
  } catch {
    return false
  } finally {
    if (fd !== undefined) closeSync(fd)
  }
}

/** ESM namespace of a CommonJS module: prefer named exports, fall back to `default`. */
function moduleRecord(value: unknown): Record<string, unknown> | undefined {
  if (!isRecord(value)) return undefined
  if (typeof value.parse === 'function' || typeof value.libraryPath === 'string') return value
  const def = value.default
  if (isRecord(def)) return def
  return value
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return (typeof value === 'object' || typeof value === 'function') && value !== null
}
