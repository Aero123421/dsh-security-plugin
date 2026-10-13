/**
 * Builds (and briefly caches) the code model of a snapshot file, choosing the
 * native AST when it is available and trustworthy for the file, and the token
 * fallback otherwise. Shared by SAST, route extraction and the outline.
 */

import { type AstGrepHandle, astLangForPath, findAllKinds, parseSafely } from '../astgrep.ts'
import type { SnapshotFile } from '../types.ts'
import { buildJsModel } from './js-facts.ts'
import type { FileModel } from './model.ts'
import { buildPyModel } from './py-facts.ts'

/** Files above this size are not modelled at all (minified bundles, data dumps). */
export const MODEL_MAX_CHARS = 2 * 1024 * 1024

const CACHE_SIZE = 48
const cache = new Map<string, FileModel>()

const JS_EXT = /\.(?:[cm]?[jt]sx?)$/i
const PY_EXT = /\.py[iw]?$/i
const EMBED_EXT = /\.(?:vue|svelte|html?)$/i

/** Model kind for a file: JavaScript/TypeScript, Python, or a markup file with embedded `<script>` blocks. */
export function modelKind(file: Pick<SnapshotFile, 'path' | 'language'>): 'js' | 'py' | 'embedded-js' | undefined {
  if (file.language === 'javascript' || file.language === 'typescript' || JS_EXT.test(file.path)) return 'js'
  if (file.language === 'python' || PY_EXT.test(file.path)) return 'py'
  if (file.language === 'vue' || file.language === 'svelte' || file.language === 'html' || EMBED_EXT.test(file.path)) {
    return 'embedded-js'
  }
  return undefined
}

/**
 * The code model for a JS/TS/Python file (or the scripts of a Vue/Svelte/HTML
 * file), or `undefined` for other files. `mode` is `ast` only when the native
 * engine parsed the file without large error regions.
 */
export function modelFor(file: SnapshotFile, astGrep: AstGrepHandle | undefined): FileModel | undefined {
  const kind = modelKind(file)
  if (!kind || file.content.length > MODEL_MAX_CHARS) return undefined
  const key = `${astGrep ? 'a' : 't'}:${file.path}:${file.sha256}`
  const hit = cache.get(key)
  if (hit) {
    cache.delete(key)
    cache.set(key, hit)
    return hit
  }
  const model = build(file, kind, astGrep)
  cache.set(key, model)
  if (cache.size > CACHE_SIZE) {
    const oldest = cache.keys().next().value
    if (oldest !== undefined) cache.delete(oldest)
  }
  return model
}

function build(file: SnapshotFile, kind: 'js' | 'py' | 'embedded-js', astGrep: AstGrepHandle | undefined): FileModel {
  if (kind === 'py') {
    const lang = astLangForPath(astGrep, file.path)
    const root = lang ? parseSafely(astGrep, lang, file.content) : undefined
    if (root && lang && !mostlyErrors(root, lang, file.content.length))
      return buildPyModel(file.path, file.content, root, lang)
    return buildPyModel(file.path, file.content)
  }
  if (kind === 'embedded-js') {
    // Blank everything outside <script> blocks; offsets and lines stay intact.
    const scripts = scriptOnly(file.content)
    const lang = scripts.typescript ? astGrep?.Lang.TypeScript : astGrep?.Lang.JavaScript
    const root = lang ? parseSafely(astGrep, lang, scripts.text) : undefined
    const model =
      root && lang && !mostlyErrors(root, lang, scripts.text.length)
        ? buildJsModel(file.path, scripts.text, root, lang)
        : buildJsModel(file.path, scripts.text)
    return { ...model, source: file.content }
  }
  const lang = astLangForPath(astGrep, file.path)
  const root = lang ? parseSafely(astGrep, lang, file.content) : undefined
  if (root && lang && !mostlyErrors(root, lang, file.content.length)) {
    try {
      return buildJsModel(file.path, file.content, root, lang)
    } catch {
      // fall back to tokens below
    }
  }
  return buildJsModel(file.path, file.content)
}

/** A tree whose ERROR nodes cover a large part of the file is worse than the token fallback. */
function mostlyErrors(root: import('../astgrep.ts').SgNode, lang: string, length: number): boolean {
  let covered = 0
  for (const node of findAllKinds(root, lang, ['ERROR'])) {
    const r = node.range()
    covered += r.end.index - r.start.index
    if (covered > Math.max(200, length * 0.2)) return true
  }
  return false
}

/** Replace non-script content with spaces (newlines kept) so offsets match the original file. */
function scriptOnly(content: string): { text: string; typescript: boolean } {
  const chars = content.replace(/[^\n\r]/g, ' ').split('')
  let typescript = false
  const re = /<script\b([^>]*)>([\s\S]*?)<\/script\s*>/gi
  for (const m of content.matchAll(re)) {
    const attrs = m[1] ?? ''
    if (/\btype\s*=\s*["']?(?!(?:module|text\/javascript|application\/javascript)\b)[\w/+-]+/i.test(attrs)) {
      if (!/\blang\s*=\s*["']?ts/i.test(attrs)) continue
    }
    if (/\bsrc\s*=/.test(attrs)) continue
    if (/\blang\s*=\s*["']?ts/i.test(attrs)) typescript = true
    const start = (m.index ?? 0) + m[0].indexOf('>') + 1
    const body = m[2] ?? ''
    for (let i = 0; i < body.length; i++) chars[start + i] = body[i]!
  }
  return { text: chars.join(''), typescript }
}

/** Drop cached models (tests). */
export function clearModelCache(): void {
  cache.clear()
}
