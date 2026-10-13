import { describe, expect, it } from 'vitest'
import {
  AST_MAX_SOURCE_BYTES,
  astLangForPath,
  createAstGrepHandle,
  findAllKinds,
  loadAstGrep,
  parseSafely,
} from '../../../src/host/analysis/astgrep.ts'
import { modelFor } from '../../../src/host/analysis/sast/models.ts'
import { fileOf } from './helpers.ts'
import { astGrep, hits, sast } from './sast-helpers.ts'

describe('loadAstGrep', () => {
  it('returns undefined when disabled and caches the loaded engine', async () => {
    expect(await loadAstGrep({ disabled: true })).toBeUndefined()
    const [a, b] = await Promise.all([loadAstGrep(), loadAstGrep()])
    expect(a).toBe(b)
    expect(await loadAstGrep()).toBe(a)
    expect(a === undefined).toBe(astGrep === undefined)
  })

  it('rejects modules that do not look like @ast-grep/napi', () => {
    expect(createAstGrepHandle(undefined)).toBeUndefined()
    expect(createAstGrepHandle({ parse: 'nope' })).toBeUndefined()
    expect(createAstGrepHandle({ parse: () => ({}), Lang: { JavaScript: 'js' } })).toBeUndefined()
  })

  it('treats a missing handle as "no AST" everywhere', () => {
    expect(parseSafely(undefined, 'TypeScript', 'const a = 1')).toBeUndefined()
    expect(astLangForPath(undefined, 'a.ts')).toBeUndefined()
  })
})

describe.runIf(astGrep)('native engine', () => {
  const handle = astGrep!

  it('maps paths to languages, and Python only with the optional grammar', () => {
    expect(astLangForPath(handle, 'a.ts')).toBe(handle.Lang.TypeScript)
    expect(astLangForPath(handle, 'a.tsx')).toBe(handle.Lang.Tsx)
    expect(astLangForPath(handle, 'a.cjs')).toBe(handle.Lang.JavaScript)
    expect(astLangForPath(handle, 'a.py')).toBe(handle.supportsPython ? handle.Lang.Python : undefined)
    expect(astLangForPath(handle, 'a.go')).toBeUndefined()
  })

  it('parses small sources and skips sources over 512 KB', () => {
    expect(parseSafely(handle, handle.Lang.TypeScript, 'const a: number = 1')?.kind()).toBe('program')
    const big = `${'// padding\n'.repeat(Math.ceil(AST_MAX_SOURCE_BYTES / 11) + 1)}const a = 1\n`
    expect(big.length).toBeGreaterThan(AST_MAX_SOURCE_BYTES)
    expect(parseSafely(handle, handle.Lang.TypeScript, big)).toBeUndefined()
    // Multi-byte text: few UTF-16 code units, more than 512 KB of UTF-8.
    const wide = `const s = '${'漢'.repeat(Math.ceil(AST_MAX_SOURCE_BYTES / 3) + 10)}'\n`
    expect(wide.length).toBeLessThan(AST_MAX_SOURCE_BYTES)
    expect(parseSafely(handle, handle.Lang.TypeScript, wide)).toBeUndefined()
  })

  it('never throws on unknown languages or kinds', () => {
    expect(parseSafely(handle, 'no-such-language', 'x')).toBeUndefined()
    const root = parseSafely(handle, handle.Lang.JavaScript, 'f(1); g(2)')!
    expect(findAllKinds(root, handle.Lang.JavaScript, ['call_expression', 'not_a_kind']).map(n => n.text())).toEqual([
      'f(1)',
      'g(2)',
    ])
    expect(findAllKinds(root, handle.Lang.JavaScript, ['not_a_kind'])).toEqual([])
  })

  it('falls back to tokens for large files and keeps finding issues', async () => {
    const pad = '// filler line to push the file over the native parser limit\n'.repeat(9000)
    const code = `${pad}const { exec } = require('child_process')\napp.get('/x', (req, res) => exec('ls ' + req.query.d))\n`
    expect(modelFor(fileOf('src/big.js', code), handle)?.mode).toBe('tokens')
    expect(modelFor(fileOf('src/small.js', 'exec(1)'), handle)?.mode).toBe('ast')
    expect(hits(await sast({ 'src/big.js': code }, handle), 'js.command-injection')).toEqual(['9002 vulnerability'])
  })
})
