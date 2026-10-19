import { describe, expect, it } from 'vitest'
import { jsRegexCharset, patternCharset, pyPatternCharset } from '../../../src/host/analysis/sast/guards.ts'

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
