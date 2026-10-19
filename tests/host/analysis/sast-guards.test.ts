import { describe, expect, it } from 'vitest'
import { jsRegexCharset, patternCharset, pyPatternCharset } from '../../../src/host/analysis/sast/guards.ts'
import { hits, PY_MODES, sast } from './sast-helpers.ts'

describe('allow-list pattern character sets', () => {
  it.each([
    ['[\\w-]+', { shellSafe: true, pathSafe: true, segmentSafe: true }],
    ['\\d{1,6}', { shellSafe: true, pathSafe: true, segmentSafe: true }],
    ['[a-z0-9_]+', { shellSafe: true, pathSafe: true, segmentSafe: true }],
    ['[\\w.-]+', { shellSafe: true, pathSafe: false, segmentSafe: true }],
    ['[\\w./-]+', { shellSafe: true, pathSafe: false, segmentSafe: false }],
    ['v\\d+(?:\\.\\d+)*', { shellSafe: true, pathSafe: false, segmentSafe: true }],
  ])('%s admits %o', (body, expected) => {
    expect(patternCharset(body)).toEqual(expected)
  })

  it.each(['[\\w ]+', '[^;]+', 'a|b', '.+', '[\\s\\S]+', '\\w+;', '[!-~]+', '', '(?=x)\\w+'])(
    '%s is not an allow-list it can judge',
    body => {
      expect(patternCharset(body)).toBeUndefined()
    },
  )

  it('needs JavaScript patterns anchored at both ends, without the multiline flag', () => {
    expect(jsRegexCharset('/^[\\w.-]+$/')).toBeDefined()
    expect(jsRegexCharset('/^[\\w.-]+$/i')).toBeDefined()
    expect(jsRegexCharset('/[\\w.-]+/')).toBeUndefined()
    expect(jsRegexCharset('/^[\\w.-]+/')).toBeUndefined()
    expect(jsRegexCharset('/^[\\w.-]+$/m')).toBeUndefined()
  })

  it('anchors Python patterns according to the re function', () => {
    expect(pyPatternCharset('[\\w.-]+', 'fullmatch')).toBeDefined()
    expect(pyPatternCharset('[\\w.-]+$', 'match')).toBeDefined()
    expect(pyPatternCharset('[\\w.-]+\\Z', 'match')).toBeDefined()
    expect(pyPatternCharset('[\\w.-]+', 'match')).toBeUndefined()
    expect(pyPatternCharset('^[\\w.-]+$', 'search')).toBeDefined()
    expect(pyPatternCharset('[\\w.-]+$', 'search')).toBeUndefined()
  })
})

describe.each(PY_MODES)('Python allow-list guards and re flags (%s mode)', (_mode, handle) => {
  const program = (guard: string, head = ''): string =>
    [
      'import re',
      'import subprocess',
      'from flask import abort, request',
      head,
      '@app.post("/check")',
      'def check():',
      '    branch = request.form["branch"]',
      guard,
      '    subprocess.run(f"git checkout {branch}", shell=True)',
      '    return "ok"',
    ].join('\n')
  const verdict = async (code: string): Promise<string[]> =>
    hits(await sast({ 'app.py': code }, handle), 'py.command-injection')

  it('treats an unflagged anchored allow-list as a guard', async () => {
    expect(await verdict(program('    if not re.match(r"^[\\w.-]+$", branch): abort(400)'))).toEqual(['9 sink'])
    const compiled = program('    if not SAFE.match(branch): abort(400)', 'SAFE = re.compile(r"^[\\w.-]+$")')
    expect(await verdict(compiled)).toEqual(['9 sink'])
  })

  it('keeps IGNORECASE-only flags as a guard', async () => {
    expect(await verdict(program('    if not re.match(r"^[\\w.-]+$", branch, re.I): abort(400)'))).toEqual(['9 sink'])
    const compiled = program(
      '    if not SAFE.match(branch): abort(400)',
      'SAFE = re.compile(r"^[\\w.-]+$", re.IGNORECASE)',
    )
    expect(await verdict(compiled)).toEqual(['9 sink'])
  })

  it.each([
    'branch, re.M',
    'branch, re.MULTILINE',
    'branch, re.I | re.M',
    'branch, flags=re.M',
    'branch, FLAGS',
  ])('does not trust re.match(…, %s): "$" also matches before a newline', async args => {
    const code = program(`    if not re.match(r"^[\\w.-]+$", ${args}): abort(400)`)
    expect(await verdict(code)).toEqual(['9 vulnerability'])
  })

  it.each(['re.M', 're.MULTILINE', 're.I | re.M', 'FLAGS', 're.X'])(
    'does not trust a compiled pattern with flags %s',
    async flags => {
      const code = program('    if not SAFE.match(branch): abort(400)', `SAFE = re.compile(r"^[\\w.-]+$", ${flags})`)
      expect(await verdict(code)).toEqual(['9 vulnerability'])
    },
  )

  it('does not trust an inline (?m) flag', async () => {
    expect(await verdict(program('    if not re.match(r"(?m)^[\\w.-]+$", branch): abort(400)'))).toEqual([
      '9 vulnerability',
    ])
  })
})
