import { describe, expect, it } from 'vitest'
import {
  isWhitespace,
  normalizeForMatch,
  normalizePath,
  normalizeWithOffsets,
} from '../../../src/host/evidence/normalize.ts'
import {
  clipText,
  countLines,
  lineOfOffset,
  lineStarts,
  maskRoot,
  numberLines,
  splitLines,
} from '../../../src/host/evidence/text.ts'

describe('normalizePath', () => {
  it.each([
    ['src/app.ts', 'src/app.ts'],
    ['./a', 'a'],
    ['././a/./b', 'a/b'],
    ['a//b', 'a/b'],
    ['a\\b', 'a/b'],
    ['src\\routes\\users.ts', 'src/routes/users.ts'],
    ['a/b/', 'a/b'],
    ['  src/x.ts  ', 'src/x.ts'],
    ['.env', '.env'],
    ['..foo/bar', '..foo/bar'],
    ['a/..b', 'a/..b'],
  ])('accepts %j as %j', (input, expected) => {
    expect(normalizePath(input)).toBe(expected)
  })

  it.each([
    ['../x'],
    ['a/../x'],
    ['a/b/..'],
    ['..'],
    ['..\\x'],
    ['/etc/passwd'],
    ['//server/share'],
    ['\\\\server\\share'],
    ['C:\\x'],
    ['C:/x'],
    ['c:x'],
    ['file:///etc/passwd'],
    ['a\0b'],
    ['\0'],
    [''],
    ['   '],
    ['.'],
    ['./'],
  ])('rejects %j', input => {
    expect(normalizePath(input)).toBeUndefined()
  })
})

describe('normalizeForMatch', () => {
  it('collapses every whitespace run and trims', () => {
    expect(normalizeForMatch('  a\t\tb\r\n  c  ')).toBe('a b c')
    expect(normalizeForMatch('x\u00a0\u2028y\u3000z')).toBe('x y z')
    expect(normalizeForMatch('')).toBe('')
    expect(normalizeForMatch(' \n\t ')).toBe('')
  })
})

describe('normalizeWithOffsets', () => {
  it('produces the same text as normalizeForMatch', () => {
    for (const text of ['', ' ', 'a', '  a  b\n\n c\t', '\r\n\tfoo(bar)\r\n', 'x\u00a0\ufeffy', 'emoji 😀  ok']) {
      expect(normalizeWithOffsets(text).text, JSON.stringify(text)).toBe(normalizeForMatch(text))
    }
  })

  it('maps every normalized character back to its original offset', () => {
    const text = '\t\tif (a)\r\n\t\t\treturn  b\n'
    const { text: norm, offsets } = normalizeWithOffsets(text)
    expect(norm).toBe('if (a) return b')
    expect(offsets).toHaveLength(norm.length)
    for (let k = 0; k < norm.length; k++) {
      if (norm[k] === ' ') expect(isWhitespace(text.charCodeAt(offsets[k]!))).toBe(true)
      else expect(text[offsets[k]!]).toBe(norm[k])
    }
    // Offsets increase strictly.
    for (let k = 1; k < offsets.length; k++) expect(offsets[k]!).toBeGreaterThan(offsets[k - 1]!)
  })

  it('agrees with the regex \\s class on every BMP code point', () => {
    const re = /\s/
    for (let code = 0; code <= 0xffff; code++) {
      if (isWhitespace(code) !== re.test(String.fromCharCode(code))) {
        throw new Error(`mismatch at U+${code.toString(16)}`)
      }
    }
  })
})

describe('line helpers', () => {
  it('splits and counts lines without a phantom trailing line', () => {
    expect(splitLines('')).toEqual([])
    expect(splitLines('a')).toEqual(['a'])
    expect(splitLines('a\n')).toEqual(['a'])
    expect(splitLines('a\n\n')).toEqual(['a', ''])
    expect(splitLines('a\r\nb\r\n')).toEqual(['a\r', 'b\r'])
    for (const text of ['', 'a', 'a\n', 'a\n\n', '\n', 'a\nb', 'a\r\nb\r\n']) {
      expect(countLines(text), JSON.stringify(text)).toBe(splitLines(text).length)
    }
  })

  it('maps offsets to 1-based lines', () => {
    const text = 'ab\r\ncd\n\nef'
    const starts = lineStarts(text)
    expect(starts).toEqual([0, 4, 7, 8])
    expect([0, 1, 2, 3].map(o => lineOfOffset(starts, o))).toEqual([1, 1, 1, 1])
    expect(lineOfOffset(starts, 4)).toBe(2)
    expect(lineOfOffset(starts, 7)).toBe(3)
    expect(lineOfOffset(starts, 9)).toBe(4)
  })

  it('numbers lines with aligned prefixes and strips CR', () => {
    expect(numberLines(['a\r', '', 'c'], 8)).toBe(' 8| a\n 9|\n10| c')
    expect(numberLines(['x'.repeat(10)], 1, 5)).toBe('1| xxxx… [line clipped: 6 more chars]')
  })

  it('clips text without exceeding the limit or splitting surrogate pairs', () => {
    expect(clipText('abcdef', 10)).toBe('abcdef')
    expect(clipText('abcdef', 4)).toBe('abc…')
    const clipped = clipText('ab😀cd', 4)
    expect(clipped.length).toBeLessThanOrEqual(4)
    expect(clipped).toBe('ab…')
  })
})

describe('maskRoot', () => {
  it('masks the root where a path starts with it', () => {
    expect(maskRoot('at /home/u/proj/src/a.ts:3', '/home/u/proj')).toBe('at <root>/src/a.ts:3')
    expect(maskRoot('"/home/u/proj"', '/home/u/proj/')).toBe('"<root>"')
    expect(maskRoot('file:///home/u/proj/x', '/home/u/proj')).toBe('file://<root>/x')
    expect(maskRoot('/home/u/project/x', '/home/u/proj')).toBe('<root>ect/x')
    expect(maskRoot('src/home/u/proj', '/home/u/proj')).toBe('src/home/u/proj')
    expect(maskRoot('/home/u/proj and /home/u/proj/x', '/home/u/proj')).toBe('<root> and <root>/x')
  })

  it('requires an end boundary for single-segment roots', () => {
    expect(maskRoot("route('/app') and /app/x", '/app')).toBe("route('<root>') and <root>/x")
    expect(maskRoot('/apple /application', '/app')).toBe('/apple /application')
    expect(maskRoot('C:\\work\\x C:\\workshop', 'C:\\work')).toBe('<root>\\x C:\\workshop')
  })

  it('masks Windows spellings and ignores trivial roots', () => {
    expect(maskRoot('C:\\work\\app\\x.ts and C:/work/app/y', 'C:\\work\\app')).toBe('<root>\\x.ts and <root>/y')
    expect(maskRoot('/etc/passwd', '/')).toBe('/etc/passwd')
    expect(maskRoot('C:\\x', 'C:\\')).toBe('C:\\x')
  })
})
