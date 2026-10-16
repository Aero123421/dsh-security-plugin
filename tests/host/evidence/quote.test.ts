import { createHash } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import { Redactor, scanSecrets } from '../../../src/host/analysis/secrets.ts'
import {
  checkStaleness,
  excerpt,
  type QuoteSource,
  SNIPPET_MAX_CHARS,
  snapshotQuoteSource,
  verifyQuote,
} from '../../../src/host/evidence/quote.ts'
import { snapshotOf } from '../analysis/helpers.ts'

// Assembled at runtime so this file never contains a contiguous token.
const j = (...parts: string[]): string => parts.join('')
const TOKEN = j('ghp', '_', 'aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA5')

const sha = (text: string): string => createHash('sha256').update(text).digest('hex')

/** A QuoteSource over `path → content` with an optional redaction function and withheld set. */
function sourceOf(
  files: Record<string, string>,
  options: { redact?: (path: string, content: string) => string; withheld?: readonly string[] } = {},
): QuoteSource & { redactCalls: number } {
  const source = {
    redactCalls: 0,
    file: (path: string) => {
      const content = files[path]
      return content === undefined ? undefined : { content, sha256: sha(content) }
    },
    redact: (path: string, content: string) => {
      source.redactCalls++
      return options.redact ? options.redact(path, content) : content
    },
    isWithheld: (path: string) => (options.withheld ?? []).includes(path),
  }
  return source
}

const APP = [
  "import express from 'express'", // 1
  "import { db } from './db'", // 2
  '', // 3
  'const app = express()', // 4
  '', // 5
  "app.get('/users/:id', async (req, res) => {", // 6
  '  const user = await db.query(', // 7
  "    'SELECT * FROM users WHERE id = ' + req.params.id,", // 8
  '  )', // 9
  '  res.json(user)', // 10
  '})', // 11
  '', // 12
  "app.get('/health', (req, res) => res.send('ok'))", // 13
  '', // 14
  'export default app', // 15
].join('\n')

describe('verifyQuote: match', () => {
  const source = sourceOf({ 'src/app.ts': `${APP}\n` })

  it('matches a quote at the cited lines and returns the cited location with a snippet', () => {
    const result = verifyQuote(source, {
      path: 'src/app.ts',
      startLine: 8,
      endLine: 8,
      quote: "'SELECT * FROM users WHERE id = ' + req.params.id",
    })
    expect(result.check).toBe('match')
    expect(result.location).toEqual({ path: 'src/app.ts', startLine: 8, endLine: 8 })
    expect(result.snippet).toBe("    'SELECT * FROM users WHERE id = ' + req.params.id,")
    expect(result.reason).toBeUndefined()
  })

  it('accepts a quote within the slack window around the cited range', () => {
    const cited = { path: 'src/app.ts', startLine: 10, endLine: 10, quote: 'const user = await db.query(' }
    expect(verifyQuote(source, cited).check).toBe('match') // line 7 is within 3 lines of 10
    expect(verifyQuote(source, cited, { slackLines: 0 }).check).toBe('relocated')
  })

  it('matches a multi-line quote regardless of indentation and wrapping', () => {
    const quote = "const user = await db.query(\n'SELECT * FROM users WHERE id = ' +\n      req.params.id,\n)"
    const result = verifyQuote(source, { path: 'src/app.ts', startLine: 7, endLine: 9, quote })
    expect(result.check).toBe('match')
    expect(result.location).toEqual({ path: 'src/app.ts', startLine: 7, endLine: 9 })
    expect(result.snippet?.split('\n')).toHaveLength(3)
  })

  it('is indentation-insensitive with tabs and CRLF line endings', () => {
    const crlf = sourceOf({ 'a.py': 'def f(x):\r\n\tif x:\r\n\t\treturn eval(x)\r\n\treturn None\r\n' })
    const result = verifyQuote(crlf, { path: 'a.py', startLine: 2, endLine: 3, quote: 'if x:   return eval(x)' })
    expect(result.check).toBe('match')
    expect(result.snippet).toBe('\tif x:\n\t\treturn eval(x)')
  })

  it('normalizes the cited path', () => {
    const result = verifyQuote(source, {
      path: './src//app.ts',
      startLine: 15,
      endLine: 15,
      quote: 'export default app',
    })
    expect(result.check).toBe('match')
    expect(result.location?.path).toBe('src/app.ts')
    expect(
      verifyQuote(source, { path: 'src\\app.ts', startLine: 15, endLine: 15, quote: 'export default app' }).check,
    ).toBe('match')
  })

  it('accepts quotes copied with read_file line-number prefixes', () => {
    const quote = "   7|   const user = await db.query(\n   8|     'SELECT * FROM users WHERE id = ' + req.params.id,"
    const result = verifyQuote(source, { path: 'src/app.ts', startLine: 7, endLine: 8, quote })
    expect(result.check).toBe('match')
  })
})

describe('verifyQuote: relocation', () => {
  const source = sourceOf({ 'src/app.ts': APP })

  it('relocates a quote found exactly once elsewhere and computes the true line range', () => {
    const result = verifyQuote(source, {
      path: 'src/app.ts',
      startLine: 1,
      endLine: 1,
      quote: "res.json(user)\n})\n\napp.get('/health'",
    })
    expect(result.check).toBe('relocated')
    expect(result.location).toEqual({ path: 'src/app.ts', startLine: 10, endLine: 13 })
    expect(result.snippet).toBe("  res.json(user)\n})\n\napp.get('/health', (req, res) => res.send('ok'))")
  })

  it('maps offsets to lines correctly with CRLF, tabs, and blank lines', () => {
    const content = 'a = 1\r\n\r\n\t\tfoo(  bar,\r\n\t\t\tbaz )\r\n\r\nz = 2\r\n'
    const crlf = sourceOf({ 'x.py': content })
    const result = verifyQuote(
      crlf,
      { path: 'x.py', startLine: 6, endLine: 6, quote: 'foo( bar, baz )' },
      { slackLines: 0 },
    )
    expect(result.check).toBe('relocated')
    expect(result.location).toEqual({ path: 'x.py', startLine: 3, endLine: 4 })
    expect(result.snippet).toBe('\t\tfoo(  bar,\n\t\t\tbaz )')
  })

  it('maps a quote that starts mid-line and ends at the end of the file without a trailing newline', () => {
    const content = 'one\ntwo three four\nfive six seven'
    const s = sourceOf({ 'f.txt': content })
    const result = verifyQuote(
      s,
      { path: 'f.txt', startLine: 1, endLine: 1, quote: 'four five six seven' },
      { slackLines: 0 },
    )
    expect(result).toMatchObject({ check: 'relocated', location: { path: 'f.txt', startLine: 2, endLine: 3 } })
  })

  it('relocates when the cited lines are out of range', () => {
    const result = verifyQuote(source, {
      path: 'src/app.ts',
      startLine: 900,
      endLine: 905,
      quote: 'export default app',
    })
    expect(result).toMatchObject({ check: 'relocated', location: { startLine: 15, endLine: 15 } })
  })

  it('relocates when the cited range is reversed or not an integer', () => {
    expect(
      verifyQuote(source, { path: 'src/app.ts', startLine: 9, endLine: 2, quote: 'const app = express()' }),
    ).toMatchObject({
      check: 'relocated',
      location: { startLine: 4, endLine: 4 },
    })
    expect(
      verifyQuote(source, { path: 'src/app.ts', startLine: 0, endLine: 0, quote: 'const app = express()' }).check,
    ).toBe('relocated')
    expect(
      verifyQuote(source, { path: 'src/app.ts', startLine: Number.NaN, endLine: 4, quote: 'const app = express()' })
        .check,
    ).toBe('relocated')
  })
})

describe('verifyQuote: mismatch', () => {
  const source = sourceOf({ 'src/app.ts': APP, 'src/empty.ts': '' }, { withheld: ['.env'] })

  it('reports a quote that does not occur in the file', () => {
    const result = verifyQuote(source, { path: 'src/app.ts', startLine: 8, endLine: 8, quote: 'db.raw(req.body.sql)' })
    expect(result).toEqual({ check: 'mismatch', reason: 'quote not found' })
  })

  it('reports an ambiguous quote that occurs several times elsewhere', () => {
    const result = verifyQuote(source, { path: 'src/app.ts', startLine: 1, endLine: 1, quote: 'async (req, res) =>' })
    // Only once in the file: relocated. `(req, res) =>` occurs twice: ambiguous.
    expect(result.check).toBe('relocated')
    const twice = verifyQuote(source, { path: 'src/app.ts', startLine: 1, endLine: 1, quote: '(req, res) =>' })
    expect(twice).toEqual({
      check: 'mismatch',
      reason: 'quote ambiguous; candidate lines: 6, 13; cite the exact lines of one occurrence',
    })
  })

  it('prefers the cited occurrence over ambiguity', () => {
    const result = verifyQuote(source, { path: 'src/app.ts', startLine: 13, endLine: 13, quote: '(req, res) =>' })
    expect(result.check).toBe('match')
  })

  it('rejects quotes shorter than minQuoteChars', () => {
    expect(verifyQuote(source, { path: 'src/app.ts', startLine: 10, endLine: 10, quote: '  }) ' })).toEqual({
      check: 'mismatch',
      reason: 'quote too short',
    })
    expect(verifyQuote(source, { path: 'src/app.ts', startLine: 8, endLine: 8, quote: 'req' })).toEqual({
      check: 'mismatch',
      reason: 'quote too short',
    })
    expect(verifyQuote(source, { path: 'src/app.ts', startLine: 8, endLine: 8, quote: ' \n\t ' }).reason).toBe(
      'quote too short',
    )
  })

  it('accepts a short quote when the whole cited range is that short', () => {
    const result = verifyQuote(source, { path: 'src/app.ts', startLine: 9, endLine: 9, quote: ')' })
    expect(result).toMatchObject({ check: 'match', location: { startLine: 9, endLine: 9 }, snippet: '  )' })
    // ...but never relocates it.
    expect(verifyQuote(source, { path: 'src/app.ts', startLine: 900, endLine: 900, quote: ')' }).reason).toBe(
      'quote too short',
    )
    expect(verifyQuote(source, { path: 'src/app.ts', startLine: 11, endLine: 11, quote: '})' }).check).toBe('match')
    expect(verifyQuote(source, { path: 'src/app.ts', startLine: 12, endLine: 12, quote: ')' }).reason).toBe(
      'quote not found',
    )
  })

  it('honors a custom minQuoteChars', () => {
    const cited = { path: 'src/app.ts', startLine: 4, endLine: 4, quote: 'express()' }
    expect(verifyQuote(source, cited).check).toBe('match')
    expect(verifyQuote(source, cited, { minQuoteChars: 20 }).reason).toBe('quote too short')
  })

  it('reports out-of-range lines when relocation fails', () => {
    const result = verifyQuote(source, {
      path: 'src/app.ts',
      startLine: 50,
      endLine: 52,
      quote: 'nothing like this here',
    })
    expect(result).toEqual({ check: 'mismatch', reason: 'lines out of range' })
    expect(
      verifyQuote(source, { path: 'src/empty.ts', startLine: 1, endLine: 1, quote: 'anything at all' }).reason,
    ).toBe('lines out of range')
  })

  it('reports unknown and invalid paths as not in the snapshot', () => {
    for (const path of ['src/missing.ts', '../src/app.ts', '/src/app.ts', 'C:\\src\\app.ts', 'src/app.ts\0', '']) {
      expect(verifyQuote(source, { path, startLine: 1, endLine: 1, quote: 'import express' }), path).toEqual({
        check: 'mismatch',
        reason: 'file not in snapshot',
      })
    }
  })

  it('never verifies quotes from withheld files', () => {
    const withheld = sourceOf({ '.env': 'API_TOKEN=abcdefghijklmnop\n' }, { withheld: ['.env'] })
    const result = verifyQuote(withheld, {
      path: '.env',
      startLine: 1,
      endLine: 1,
      quote: 'API_TOKEN=abcdefghijklmnop',
    })
    expect(result).toEqual({ check: 'mismatch', reason: 'withheld file' })
    expect(withheld.redactCalls).toBe(0)
  })

  it('does not throw on malformed citations', () => {
    const bad = { path: 'src/app.ts', startLine: 1, endLine: 1, quote: undefined as unknown as string }
    expect(verifyQuote(source, bad)).toEqual({ check: 'mismatch', reason: 'quote too short' })
  })
})

describe('verifyQuote: redacted content', () => {
  const content = `const client = new Octokit({\n  auth: "${TOKEN}",\n})\n`

  it('compares against redacted content so quotes with redaction markers match', async () => {
    const snapshot = snapshotOf({ 'src/gh.ts': content })
    const source = snapshotQuoteSource(snapshot, new Redactor(await scanSecrets(snapshot)))
    const result = verifyQuote(source, {
      path: 'src/gh.ts',
      startLine: 2,
      endLine: 2,
      quote: 'auth: "[REDACTED:github-token]",',
    })
    expect(result.check).toBe('match')
    expect(result.snippet).toBe('  auth: "[REDACTED:github-token]",')
    expect(result.snippet).not.toContain(TOKEN)
  })

  it('does not match (and does not crash on) a quote holding the raw secret', async () => {
    const snapshot = snapshotOf({ 'src/gh.ts': content })
    const source = snapshotQuoteSource(snapshot, new Redactor(await scanSecrets(snapshot)))
    const result = verifyQuote(source, { path: 'src/gh.ts', startLine: 2, endLine: 2, quote: `auth: "${TOKEN}",` })
    expect(result).toEqual({ check: 'mismatch', reason: 'quote not found' })
  })

  it('relocates within redacted content and never leaks the secret in the snippet', async () => {
    const snapshot = snapshotOf({ 'src/gh.ts': content })
    const source = snapshotQuoteSource(snapshot, new Redactor([]))
    const result = verifyQuote(
      source,
      { path: 'src/gh.ts', startLine: 3, endLine: 3, quote: 'new Octokit({ auth:' },
      { slackLines: 0 },
    )
    expect(result).toMatchObject({ check: 'relocated', location: { startLine: 1, endLine: 2 } })
    expect(result.snippet).toContain('[REDACTED:github-token]')
    expect(result.snippet).not.toContain(TOKEN)
  })

  it('withholds sensitive paths through snapshotQuoteSource', () => {
    const snapshot = snapshotOf({ '.env': 'A=1\n', 'config/secrets.yml': 'k: v\n', 'conf/x.yml': 'k: v\n' })
    const source = snapshotQuoteSource(snapshot, new Redactor([]), ['conf/**'])
    expect(source.isWithheld('.env')).toBe(true)
    expect(source.isWithheld('config/secrets.yml')).toBe(true)
    expect(source.isWithheld('conf/x.yml')).toBe(true)
    expect(
      verifyQuote(source, { path: 'config/secrets.yml', startLine: 1, endLine: 1, quote: 'k: v and more' }).reason,
    ).toBe('withheld file')
  })

  it('redacts each file version once', () => {
    const source = sourceOf({ 'src/app.ts': APP })
    for (let i = 0; i < 5; i++)
      verifyQuote(source, { path: 'src/app.ts', startLine: 4, endLine: 4, quote: 'const app = express()' })
    expect(source.redactCalls).toBe(1)
  })
})

describe('verifyQuote: snippet limits', () => {
  it('caps snippets at 12 lines and 1500 characters', () => {
    const lines = Array.from({ length: 30 }, (_, i) => `line_${i + 1} = ${'x'.repeat(200)}`)
    const source = sourceOf({ 'big.py': lines.join('\n') })
    const result = verifyQuote(source, { path: 'big.py', startLine: 1, endLine: 30, quote: 'line_1 = xxxxxxxx' })
    expect(result.check).toBe('match')
    expect(result.snippet!.length).toBeLessThanOrEqual(SNIPPET_MAX_CHARS)
    expect(result.snippet!.split('\n').length).toBeLessThanOrEqual(12)

    const short = Array.from({ length: 30 }, (_, i) => `v${i + 1} = ${i}`)
    const s2 = sourceOf({ 's.py': short.join('\n') })
    const r2 = verifyQuote(s2, { path: 's.py', startLine: 1, endLine: 30, quote: short.join('\n') })
    expect(r2.location).toEqual({ path: 's.py', startLine: 1, endLine: 30 })
    expect(r2.snippet!.split('\n')).toHaveLength(12)
    expect(r2.snippet!.endsWith('v12 = 11 …')).toBe(true)
  })
})

/** A 60-line file where `isAdmin(req.user)` occurs on lines 8 and 30 and a unique statement on line 50. */
const ADMIN = Array.from({ length: 60 }, (_, i) => {
  const line = i + 1
  if (line === 8) return '  if (!isAdmin(req.user)) return res.status(403).end()'
  if (line === 30) return '  const canExport = isAdmin(req.user)'
  if (line === 50) return '  const config = loadConfig(process.env.CONFIG_PATH)'
  return `const filler${line} = ${line}`
}).join('\n')

describe('verifyQuote: cited ranges are narrowed and bounded', () => {
  const source = sourceOf({ 'src/admin.ts': ADMIN })
  const cite = (startLine: number, endLine: number, quote: string) =>
    verifyQuote(source, { path: 'src/admin.ts', startLine, endLine, quote })
  const CONFIG = 'const config = loadConfig(process.env.CONFIG_PATH)'

  it('does not let a wide cited range verify a quote that occurs twice (audit repro)', () => {
    expect(cite(20, 20, 'isAdmin(req.user)')).toEqual({
      check: 'mismatch',
      reason: 'quote ambiguous; candidate lines: 8, 30; cite the exact lines of one occurrence',
    })
    const wide = cite(1, 40, 'isAdmin(req.user)')
    expect(wide).toEqual({
      check: 'mismatch',
      reason:
        'quote ambiguous: it occurs 2 times in lines 1-43; candidate lines: 8, 30; cite the exact lines of one occurrence',
    })
  })

  it('stores the occurrence itself, not the cited range, as location and snippet', () => {
    expect(cite(10, 50, CONFIG)).toEqual({
      check: 'match',
      location: { path: 'src/admin.ts', startLine: 50, endLine: 50 },
      snippet: '  const config = loadConfig(process.env.CONFIG_PATH)',
      quote: CONFIG,
    })
    // An occurrence within the slack window is also reported at its own line.
    expect(cite(11, 11, 'if (!isAdmin(req.user))')).toMatchObject({
      check: 'match',
      location: { startLine: 8, endLine: 8 },
      snippet: '  if (!isAdmin(req.user)) return res.status(403).end()',
    })
  })

  it('rejects a cited range wider than the quote lines + 40 and says how to cite', () => {
    expect(cite(1, 60, CONFIG)).toEqual({
      check: 'mismatch',
      reason: 'cited range too wide: lines 1-60 (60 lines) for a 1-line quote; cite only the lines the quote is on',
    })
    expect(cite(10, 50, CONFIG).check).toBe('match') // 41 lines
    expect(cite(10, 51, CONFIG).reason).toMatch(/^cited range too wide: lines 10-51 \(42 lines\)/)
    // The allowance grows with the quote's own lines, ignoring blank lines around it.
    const threeLines = '\nconst filler48 = 48\nconst filler49 = 49\n  const config = loadConfig(\n'
    expect(cite(8, 50, threeLines)).toMatchObject({ check: 'match', location: { startLine: 48, endLine: 50 } })
    expect(cite(7, 50, threeLines).reason).toMatch(/^cited range too wide: lines 7-50 \(44 lines\) for a 3-line quote/)
    // Wide citations past the end of the file are rejected too instead of being relocated.
    expect(cite(1, 10_000, CONFIG).reason).toMatch(/^cited range too wide/)
    // Blank lines inside the quote do not buy a wider range: matching collapses them anyway.
    const padded = `loadConfig(${'\n'.repeat(40)}process.env.CONFIG_PATH)`
    expect(cite(1, 60, padded).reason).toMatch(/^cited range too wide: lines 1-60 \(60 lines\) for a 2-line quote/)
  })

  it('honors a custom maxExtraLines', () => {
    const cited = { path: 'src/admin.ts', startLine: 45, endLine: 50, quote: 'loadConfig(process.env.CONFIG_PATH)' }
    expect(verifyQuote(source, cited).check).toBe('match')
    expect(verifyQuote(source, cited, { maxExtraLines: 4 }).reason).toMatch(/^cited range too wide/)
    expect(verifyQuote(source, cited, { maxExtraLines: 5 }).check).toBe('match')
  })

  it('accepts a repeated quote only when the cited range is tight, taking the nearest occurrence', () => {
    const lines = ['a()', 'check(user.id)', 'b()', 'check(user.id)', 'c()', 'd()', 'e()', 'f()', 'g()', 'h()']
    const near = sourceOf({ 'a.ts': lines.join('\n') })
    const at = (startLine: number, endLine: number, options = {}) =>
      verifyQuote(near, { path: 'a.ts', startLine, endLine, quote: 'check(user.id)' }, options)
    expect(at(4, 4)).toMatchObject({ check: 'match', location: { startLine: 4, endLine: 4 } })
    expect(at(2, 2)).toMatchObject({ check: 'match', location: { startLine: 2, endLine: 2 } })
    expect(at(5, 5)).toMatchObject({ check: 'match', location: { startLine: 4, endLine: 4 } })
    expect(at(1, 7)).toMatchObject({ check: 'match', location: { startLine: 2, endLine: 2 } }) // 7 <= 1 + 2 × 3
    expect(at(1, 8).reason).toBe(
      'quote ambiguous: it occurs 2 times in lines 1-10; candidate lines: 2, 4; cite the exact lines of one occurrence',
    )
    expect(at(2, 4, { slackLines: 0 }).reason).toMatch(/^quote ambiguous: it occurs 2 times in lines 2-4/)
    expect(at(2, 2, { slackLines: 0 })).toMatchObject({ check: 'match', location: { startLine: 2, endLine: 2 } })
  })

  it('narrows a short quote accepted from a short cited range to its own line', () => {
    const s = sourceOf({ 'b.ts': 'x()\n})\n\n\ny()\n' })
    expect(verifyQuote(s, { path: 'b.ts', startLine: 2, endLine: 4, quote: '})' })).toEqual({
      check: 'match',
      location: { path: 'b.ts', startLine: 2, endLine: 2 },
      snippet: '})',
      quote: '})',
      commentOnly: true,
    })
  })
})

describe('verifyQuote: comment-only quotes', () => {
  const API = [
    'export function handler(req, res) {', // 1
    '  // input sanitized upstream by the gateway', // 2
    '  const id = clean(req.query.id) // validated by the gateway', // 3
    '  /*', // 4
    '   * Safe: the ORM escapes every value.', // 5
    '   */', // 6
    "  const url = 'https://api.example.com/v1/items'", // 7
    '  return db.find(id, url)', // 8
    '}', // 9
  ].join('\n')
  const source = sourceOf({
    'src/api.ts': API,
    'app/db.py': 'def find(q):\n    """Input is validated upstream."""\n    return run(q)\n',
    'README.md': 'All input is sanitized upstream.\n',
  })
  const check = (path: string, line: number, quote: string) =>
    verifyQuote(source, { path, startLine: line, endLine: line, quote })

  it('flags matches that lie entirely in comments, docstrings, or documentation', () => {
    expect(check('src/api.ts', 2, '// input sanitized upstream by the gateway')).toMatchObject({
      check: 'match',
      commentOnly: true,
    })
    expect(check('src/api.ts', 2, 'input sanitized upstream').commentOnly).toBe(true)
    expect(check('src/api.ts', 3, 'validated by the gateway').commentOnly).toBe(true)
    expect(check('src/api.ts', 5, 'Safe: the ORM escapes every value.').commentOnly).toBe(true)
    expect(check('src/api.ts', 4, '/*\n * Safe: the ORM escapes every value.\n */').commentOnly).toBe(true)
    expect(check('app/db.py', 2, '"""Input is validated upstream."""').commentOnly).toBe(true)
    expect(check('README.md', 1, 'All input is sanitized upstream.').commentOnly).toBe(true)
    // Relocated comment quotes are flagged as well.
    expect(
      verifyQuote(
        source,
        { path: 'src/api.ts', startLine: 9, endLine: 9, quote: 'Safe: the ORM escapes' },
        { slackLines: 0 },
      ),
    ).toMatchObject({ check: 'relocated', commentOnly: true })
  })

  it('does not flag quotes that contain code', () => {
    expect(check('src/api.ts', 3, 'const id = clean(req.query.id)').commentOnly).toBeUndefined()
    expect(check('src/api.ts', 3, 'clean(req.query.id) // validated').commentOnly).toBeUndefined()
    expect(check('src/api.ts', 7, "const url = 'https://api.example.com/v1/items'").commentOnly).toBeUndefined()
    expect(check('app/db.py', 3, 'return run(q)')).toMatchObject({ check: 'match' })
    expect(check('app/db.py', 3, 'return run(q)').commentOnly).toBeUndefined()
  })
})

describe('excerpt', () => {
  const source = sourceOf({ 'src/app.ts': APP, '.env': 'A=1' }, { withheld: ['.env'] })

  it('returns numbered redacted lines', () => {
    expect(excerpt(source, { path: 'src/app.ts', startLine: 9, endLine: 11 })).toBe(
      ' 9|   )\n10|   res.json(user)\n11| })',
    )
  })

  it('clamps to the file and cuts after maxLines', () => {
    expect(excerpt(source, { path: 'src/app.ts', startLine: 14, endLine: 99 })).toBe('14|\n15| export default app')
    expect(excerpt(source, { path: 'src/app.ts', startLine: 1, endLine: 15 }, 2)).toBe(
      "1| import express from 'express'\n2| import { db } from './db'\n… (13 more lines)",
    )
  })

  it('returns undefined for withheld, unknown, invalid, or empty ranges', () => {
    expect(excerpt(source, { path: '.env', startLine: 1, endLine: 1 })).toBeUndefined()
    expect(excerpt(source, { path: 'nope.ts', startLine: 1, endLine: 1 })).toBeUndefined()
    expect(excerpt(source, { path: '../src/app.ts', startLine: 1, endLine: 1 })).toBeUndefined()
    expect(excerpt(source, { path: 'src/app.ts', startLine: 40, endLine: 50 })).toBeUndefined()
  })

  it('applies redaction', async () => {
    const snapshot = snapshotOf({ 'gh.ts': `const t = "${TOKEN}"\n` })
    const s = snapshotQuoteSource(snapshot, new Redactor(await scanSecrets(snapshot)))
    expect(excerpt(s, { path: 'gh.ts', startLine: 1, endLine: 1 })).toBe('1| const t = "[REDACTED:github-token]"')
  })
})

describe('checkStaleness', () => {
  it('compares hashes case-insensitively and treats a missing file as stale', () => {
    const h = sha('x')
    expect(checkStaleness(h, h)).toBe('same')
    expect(checkStaleness(h.toUpperCase(), h)).toBe('same')
    expect(checkStaleness(sha('y'), h)).toBe('stale')
    expect(checkStaleness(undefined, h)).toBe('stale')
  })
})
