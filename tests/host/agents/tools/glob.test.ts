import { describe, expect, it } from 'vitest'
import {
  compileGlob,
  expandBraces,
  MAX_GLOB_ALTERNATIVES,
  matchGlob,
  normalizeGlob,
} from '../../../../src/host/agents/tools/glob.ts'
import { levenshtein, normalizeDir, suggestPaths } from '../../../../src/host/agents/tools/paths.ts'

describe('matchGlob', () => {
  it.each([
    // * stays within a segment
    ['src/*.ts', 'src/app.ts', true],
    ['src/*.ts', 'src/a/app.ts', false],
    ['src/*', 'src/.env', true],
    ['*', 'README.md', true],
    // patterns without a slash match file names at any depth
    ['*.ts', 'a/b/c.ts', true],
    ['*.ts', 'a/b/c.tsx', false],
    ['package.json', 'apps/web/package.json', true],
    ['.env', 'config/.env', true],
    // ** spans zero or more directories
    ['src/**/*.ts', 'src/app.ts', true],
    ['src/**/*.ts', 'src/a/b/app.ts', true],
    ['src/**/*.ts', 'lib/app.ts', false],
    ['**/routes/*.py', 'routes/users.py', true],
    ['**/routes/*.py', 'app/api/routes/users.py', true],
    ['src/**', 'src/a/b', true],
    ['src/**', 'srcx/a', false],
    ['a/**/b/**/c', 'a/b/c', true],
    ['a/**/b/**/c', 'a/x/y/b/z/c', true],
    ['a/**/b/**/c', 'a/x/c', false],
    // ? matches exactly one non-slash character
    ['file?.js', 'file1.js', true],
    ['file?.js', 'file10.js', false],
    ['a?b', 'a/b', false],
    // braces
    ['src/{routes,api}/**', 'src/api/v1/x.ts', true],
    ['src/{routes,api}/**', 'src/lib/x.ts', false],
    ['*.{ts,tsx}', 'ui/Button.tsx', true],
    ['*.{ts,tsx}', 'ui/Button.jsx', false],
    ['{src,lib}/**/*.{js,{c,m}js}', 'lib/x/y.mjs', true],
    ['{a,b/c}.ts', 'deep/a.ts', true],
    ['{a,b/c}.ts', 'b/c.ts', true],
    ['{a,b/c}.ts', 'x/b/c.ts', false],
    // literal brackets and unmatched braces
    ['app/[id]/page.tsx', 'app/[id]/page.tsx', true],
    ['app/[id]/page.tsx', 'app/i/page.tsx', false],
    ['{a.ts', '{a.ts', true],
    ['{a}.ts', '{a}.ts', true],
    // trailing slash means "everything below"
    ['src/', 'src/a/b.ts', true],
    // case-sensitive
    ['*.TS', 'a.ts', false],
  ])('%s vs %s → %s', (glob, path, expected) => {
    expect(matchGlob(glob, path)).toBe(expected)
  })

  it('handles adversarial patterns in linear-ish time', () => {
    const glob = `${'*a'.repeat(40)}b`
    const path = 'a'.repeat(5000)
    const started = performance.now()
    expect(matchGlob(glob, path)).toBe(false)
    const deep = `${'**/'.repeat(50)}x`
    expect(matchGlob(deep, `${'d/'.repeat(500)}y`)).toBe(false)
    expect(performance.now() - started).toBeLessThan(1000)
  })
})

describe('normalizeGlob', () => {
  it('normalizes separators, dots, and trailing slashes', () => {
    expect(normalizeGlob('./src//**\\*.ts')).toBe('src/**/*.ts')
    expect(normalizeGlob('src/')).toBe('src/**')
    expect(normalizeGlob('src/**/')).toBe('src/**')
  })

  it.each([[''], ['  '], ['/etc/*'], ['C:/x/*'], ['../*'], ['a/../b'], ['a\0b'], ['x'.repeat(301)], ['./']])(
    'rejects %j',
    glob => {
      expect(normalizeGlob(glob)).toBeUndefined()
    },
  )
})

describe('expandBraces', () => {
  it('expands nested groups and de-duplicates', () => {
    expect(expandBraces('a{b,c{d,e}}f')).toEqual(['abf', 'acdf', 'acef'])
    expect(expandBraces('{a,a}')).toEqual(['a'])
    expect(expandBraces('{,x}y')).toEqual(['y', 'xy'])
  })

  it('refuses explosive expansions', () => {
    expect(expandBraces('{a,b}'.repeat(9))).toBeUndefined()
    expect(() => compileGlob('{a,b}'.repeat(9))).toThrow(RangeError)
    expect(expandBraces('{a,b}'.repeat(8))).toHaveLength(MAX_GLOB_ALTERNATIVES)
  })
})

describe('path helpers', () => {
  it('normalizes directories', () => {
    expect(normalizeDir('')).toBe('')
    expect(normalizeDir('.')).toBe('')
    expect(normalizeDir('./')).toBe('')
    expect(normalizeDir('src/routes/')).toBe('src/routes')
    expect(normalizeDir('/src')).toBeUndefined()
    expect(normalizeDir('..')).toBeUndefined()
  })

  it('computes capped edit distance', () => {
    expect(levenshtein('kitten', 'sitting')).toBe(3)
    expect(levenshtein('', 'abc')).toBe(3)
    expect(levenshtein('same', 'same')).toBe(0)
    expect(levenshtein('aaaaaaaaaa', 'bbbbbbbbbb', 2)).toBe(3)
  })

  it('suggests close paths deterministically', () => {
    const paths = ['src/routes/users.ts', 'src/routes/user.ts', 'src/models/users.ts', 'README.md', 'src/app.ts']
    expect(suggestPaths('routes/users.ts', paths)[0]).toBe('src/routes/users.ts')
    expect(suggestPaths('src/Routes/Users.ts', paths)[0]).toBe('src/routes/users.ts')
    expect(suggestPaths('src/routes/usres.ts', paths)).toContain('src/routes/users.ts')
    expect(suggestPaths('lib/users.ts', paths).slice(0, 2)).toEqual(['src/models/users.ts', 'src/routes/users.ts'])
    expect(suggestPaths('zzz/qqqqqqqq.go', paths)).toEqual([])
    expect(suggestPaths('users.ts', paths, 1)).toHaveLength(1)
  })
})
