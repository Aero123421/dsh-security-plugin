import { describe, expect, it } from 'vitest'
import { compileLineMatcher, type LineMatcher, MAX_PATTERN_LENGTH } from '../../../../src/host/agents/tools/search.ts'

function compile(pattern: string, options: Parameters<typeof compileLineMatcher>[1] = {}): LineMatcher {
  const result = compileLineMatcher(pattern, options)
  if (!result.ok) throw new Error(result.error)
  return result.matcher
}

describe('compileLineMatcher', () => {
  it('matches literals case-insensitively by default, line by line', () => {
    const matcher = compile('Eval(')
    expect(matcher.kind).toBe('literal')
    const outcome = matcher.scan(['x = 1\r\ny = eval(input)\n', 'EVAL(a)\nno\n'], 10)
    expect(outcome).toEqual({
      hits: [
        { text: 0, line: 1, column: 4 },
        { text: 1, line: 0, column: 0 },
      ],
      timedOut: false,
    })
  })

  it('treats regex metacharacters literally unless regex is set', () => {
    expect(
      compile('a.b')
        .scan(['axb', 'a.b'], 10)
        .hits.map(h => h.text),
    ).toEqual([1])
    expect(
      compile('a.b', { regex: true })
        .scan(['axb', 'a.b'], 10)
        .hits.map(h => h.text),
    ).toEqual([0, 1])
  })

  it('supports case-sensitive matching', () => {
    expect(
      compile('Foo', { caseSensitive: true })
        .scan(['foo', 'Foo'], 10)
        .hits.map(h => h.text),
    ).toEqual([1])
    expect(
      compile('^Foo', { regex: true, caseSensitive: true })
        .scan(['foo', 'Foo'], 10)
        .hits.map(h => h.text),
    ).toEqual([1])
  })

  it('runs regexes per line: anchors apply to lines and nothing spans lines', () => {
    const matcher = compile('^\\s*app\\.(get|post)\\(', { regex: true })
    expect(matcher.scan(["const app = x\napp.get('/a')\n  app.post('/b')\n"], 10).hits.map(h => h.line)).toEqual([1, 2])
    expect(
      compile('a$', { regex: true })
        .scan(['xa\r\nya\n'], 10)
        .hits.map(h => h.line),
    ).toEqual([0, 1])
    expect(compile('a[\\s\\S]*b', { regex: true }).scan(['a\nb'], 10).hits).toEqual([])
  })

  it('stops after maxHits', () => {
    expect(compile('x').scan(['x\nx\nx', 'x'], 2).hits).toHaveLength(2)
    expect(compile('x', { regex: true }).scan(['x\nx\nx', 'x'], 2).hits).toHaveLength(2)
  })

  it('rejects empty, multi-line, and overlong patterns', () => {
    expect(compileLineMatcher('')).toMatchObject({ ok: false })
    expect(compileLineMatcher('a\nb')).toMatchObject({ ok: false })
    const long = compileLineMatcher('x'.repeat(MAX_PATTERN_LENGTH + 1), { regex: true })
    expect(long.ok).toBe(false)
    expect(!long.ok && long.error).toContain(`limit is ${MAX_PATTERN_LENGTH}`)
    expect(compileLineMatcher('x'.repeat(MAX_PATTERN_LENGTH)).ok).toBe(true)
  })

  it('reports invalid regex syntax', () => {
    const result = compileLineMatcher('(unclosed', { regex: true })
    expect(result.ok).toBe(false)
    expect(!result.ok && result.error).toMatch(/^Invalid regular expression: .*literal search\.$/)
    expect(compileLineMatcher('(unclosed').ok).toBe(true)
  })

  it('interrupts catastrophic backtracking and remembers the spent budget', () => {
    const matcher = compile('(a+)+$', { regex: true, timeBudgetMs: 150 })
    const evil = `${'a'.repeat(40)}!`
    const started = performance.now()
    const outcome = matcher.scan(['fine', evil, 'aaa'], 10)
    expect(outcome.timedOut).toBe(true)
    expect(performance.now() - started).toBeLessThan(5_000)
    // The budget is per matcher: a later scan does not get a fresh one.
    expect(matcher.scan(['aaa'], 10)).toEqual({ hits: [], timedOut: true })
  })

  it('keeps the hits found before a timeout', () => {
    const matcher = compile('(a+)+$', { regex: true, timeBudgetMs: 150 })
    const evil = `${'a'.repeat(40)}!`
    const outcome = matcher.scan(['x\naaa', `aa\n${evil}`, 'aaa'], 10)
    expect(outcome.timedOut).toBe(true)
    expect(outcome.hits).toEqual([
      { text: 0, line: 1, column: 0 },
      { text: 1, line: 0, column: 0 },
    ])
  })

  it('does not let the pattern escape the sandbox as code', () => {
    const pattern = "'\\); globalThis.pwned = 1; \\('"
    const matcher = compile(pattern, { regex: true })
    expect(matcher.scan(["'); globalThis.pwned = 1; ('"], 10).hits).toHaveLength(1)
    expect((globalThis as { pwned?: unknown }).pwned).toBeUndefined()
  })
})
