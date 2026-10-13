import { describe, expect, it } from 'vitest'
import { enclosingSymbol, findSymbol, outlineFile, resolveRelativeImport } from '../../../src/host/analysis/outline.ts'
import type { FileOutline } from '../../../src/host/analysis/types.ts'
import { fileOf, snapshotOf } from './helpers.ts'
import { MODES } from './sast-helpers.ts'

/** `kind name start-end [exported]` per symbol. */
function symbols(outline: FileOutline): string[] {
  return outline.symbols.map(s => `${s.kind} ${s.name} ${s.startLine}-${s.endLine}${s.exported ? ' exported' : ''}`)
}

const TS = `import fs from 'node:fs'
import { readFile as rf, type Stats } from 'fs/promises'
import * as path from 'path'
import type { Foo } from './foo'
export { x } from './x'
const lazy = await import('./lazy')
// function commentedOut() { }
const s = '}' + "{" + \`\${ { a: 1 }.a } }\`
const re = /[}{]/g
/* class Fake {
} */
export function alpha(a: number): string {
  if (a) { return '}' }
  return \`\${a}}\`
}
export const beta = async (x: number) => {
  return x * 2
}
export const LIMIT = 10
const internal = 5
export default class Gamma extends Base<T> {
  private field = 1
  constructor(private readonly svc: Svc) { super() }
  get value(): number { return 1 }
  async method(a: string): Promise<void> {
    const inner = () => 1
  }
  static create() { return new Gamma() }
}
function delta() {}
export { delta as renamed }
`

const CJS = `'use strict'
const express = require('express')
const { join, resolve: res } = require('path')
const db = require('./db').default
require('./side-effect')
function handler(req, res) {
  res.send('ok')
}
const helper = function (x) { return x }
exports.util = (a) => a
module.exports = { handler, helper }
class Thing {
  method() {}
}
`

const PY = `import os, sys as system
from collections import OrderedDict, defaultdict as dd
from . import views
from ..pkg.mod import (
    a,
    b as bee,
)

CONSTANT = 1
_private = 2

def outer(x,
          y=3):
    """Doc with
a dedented line: def fake():
    """
    s = '''
class NotAClass:
'''
    def inner():
        return x
# a comment at column 0 does not end the block
    return inner

class Klass(Base, metaclass=Meta):
    attr = 1

    @property
    def prop(self):
        return 1

    async def amethod(self):
        pass

@decorator
def decorated():
    pass
`

describe.each(MODES)('outlineFile (%s mode)', (_mode, handle) => {
  it('outlines TypeScript imports and symbols, skipping strings, templates, regexes and comments', () => {
    const outline = outlineFile(fileOf('src/a.ts', TS), handle)
    expect(outline.path).toBe('src/a.ts')
    expect(outline.language).toBe('typescript')
    expect(outline.imports).toEqual([
      { source: 'node:fs', names: ['fs'], line: 1 },
      { source: 'fs/promises', names: ['rf', 'Stats'], line: 2 },
      { source: 'path', names: ['path'], line: 3 },
      { source: './foo', names: ['Foo'], line: 4 },
      { source: './x', names: ['x'], line: 5 },
      { source: './lazy', names: ['lazy'], line: 6 },
    ])
    expect(symbols(outline)).toEqual([
      'function alpha 12-15 exported',
      'function beta 16-18 exported',
      'variable LIMIT 19-19 exported',
      'class Gamma 21-29 exported',
      'method constructor 23-23',
      'method value 24-24',
      'method method 25-27',
      'method create 28-28',
      'function delta 30-30 exported',
    ])
  })

  it('outlines CommonJS: require() imports and module.exports/exports.* symbols', () => {
    const outline = outlineFile(fileOf('src/b.js', CJS), handle)
    expect(outline.imports).toEqual([
      { source: 'express', names: ['express'], line: 2 },
      { source: 'path', names: ['join', 'res'], line: 3 },
      { source: './db', names: ['db'], line: 4 },
      { source: './side-effect', names: [], line: 5 },
    ])
    expect(symbols(outline)).toEqual([
      'function handler 6-8 exported',
      'function helper 9-9 exported',
      'function util 10-10 exported',
      'class Thing 12-14',
      'method method 13-13',
    ])
  })

  it('outlines Python imports and symbols with indentation-based ranges', () => {
    const outline = outlineFile(fileOf('pkg/sub/c.py', PY), handle)
    expect(outline.language).toBe('python')
    expect(outline.imports).toEqual([
      { source: 'os', names: ['os'], line: 1 },
      { source: 'sys', names: ['system'], line: 1 },
      { source: 'collections', names: ['OrderedDict', 'dd'], line: 2 },
      { source: '.', names: ['views'], line: 3 },
      { source: '..pkg.mod', names: ['a', 'bee'], line: 4 },
    ])
    expect(symbols(outline)).toEqual([
      'variable CONSTANT 9-9 exported',
      'function outer 12-23 exported',
      'function inner 20-21',
      'class Klass 25-33 exported',
      'method prop 28-30',
      'method amethod 32-33',
      'function decorated 35-37 exported',
    ])
  })

  it('handles tricky JavaScript in the brace fallback the same way as the AST', () => {
    const code = [
      "const a = '{' // }",
      // biome-ignore lint/suspicious/noTemplateCurlyInString: template literal source under test
      'const b = `${"}"} ${`${{ x: "{" }.x}`}`',
      '/* function ghost() { */',
      'const re = /\\}+/',
      'function first() {',
      "  const s = '}'",
      '  return `}`',
      '}',
      'class K {',
      '  m() { return "{" }',
      '  handle = () => { return 1 }',
      '}',
      "const obj = { method() { return '}' } }",
      'export default function () {}',
    ].join('\n')
    expect(symbols(outlineFile(fileOf('t.js', code), handle))).toEqual([
      'function first 5-8',
      'class K 9-12',
      'method m 10-10',
      'method handle 11-11',
      'method method 13-13',
      'function default 14-14 exported',
    ])
  })

  it('handles tricky Python in the indentation fallback the same way as the AST', () => {
    const code = [
      'def a():',
      '    x = """',
      'def ghost():',
      '    pass',
      '"""',
      '    y = {',
      "'k': 1}",
      '    return x',
      '',
      '',
      '# trailing comment at col 0',
      'class B:',
      '    def m(self): return 1',
      '',
      '    def n(self):',
      "        s = 'def fake(): pass'",
      '        return s',
      'async def c(): pass',
      'X: int = 3',
      '__all__ = ["a", "X"]',
    ].join('\n')
    expect(symbols(outlineFile(fileOf('t.py', code), handle))).toEqual([
      'function a 1-8 exported',
      'class B 12-17',
      'method m 13-13',
      'method n 15-17',
      'function c 18-18',
      'variable X 19-19 exported',
    ])
  })

  it('returns an empty outline for files that are not code', () => {
    expect(outlineFile(fileOf('README.md', '# def x():\nfunction y() {}\n'), handle)).toEqual({
      path: 'README.md',
      language: 'markdown',
      imports: [],
      symbols: [],
    })
  })
})

describe.each(MODES)('findSymbol (%s mode)', (_mode, handle) => {
  const snapshot = snapshotOf({
    'src/a.ts': 'export function target() {}\ntarget()\nconst x = target\n',
    'src/b.js': 'const target = () => 1\nmodule.exports = { target }\n',
    'src/c.py': 'def target():\n    pass\n\ntarget()\n',
    'src/d.ts': 'class Svc {\n  target() { return 1 }\n}\nclass Other {\n  target() {}\n}\n',
    'src/e.ts': "import { target } from './a'\ntarget()\nfoo.target = 1\n",
    'src/gen.ts': '// @generated\nexport function target() {}\n',
    'src/f.ts': 'export const target = 5\n',
    'docs/target.md': '# target\n',
  })

  it('returns definitions only, sorted by path, skipping generated files', () => {
    expect(findSymbol(snapshot, 'target', { astGrep: handle })).toEqual([
      { path: 'src/a.ts', startLine: 1, endLine: 1, kind: 'function' },
      { path: 'src/b.js', startLine: 1, endLine: 1, kind: 'function' },
      { path: 'src/c.py', startLine: 1, endLine: 2, kind: 'function' },
      { path: 'src/d.ts', startLine: 2, endLine: 2, kind: 'method' },
      { path: 'src/d.ts', startLine: 5, endLine: 5, kind: 'method' },
      { path: 'src/f.ts', startLine: 1, endLine: 1, kind: 'variable' },
    ])
  })

  it('applies the limit (default 20) and narrows Class.method', () => {
    expect(findSymbol(snapshot, 'target', { astGrep: handle, limit: 2 }).map(r => r.path)).toEqual([
      'src/a.ts',
      'src/b.js',
    ])
    expect(findSymbol(snapshot, 'Svc.target', { astGrep: handle })).toEqual([
      { path: 'src/d.ts', startLine: 2, endLine: 2, kind: 'method' },
    ])
    const many: Record<string, string> = {}
    for (let i = 0; i < 30; i++) many[`m/f${String(i).padStart(2, '0')}.ts`] = 'export function dup() {}\n'
    expect(findSymbol(snapshotOf(many), 'dup', { astGrep: handle })).toHaveLength(20)
  })

  it('returns nothing for unknown or malformed names', () => {
    expect(findSymbol(snapshot, 'nope', { astGrep: handle })).toEqual([])
    expect(findSymbol(snapshot, 'a b', { astGrep: handle })).toEqual([])
    expect(findSymbol(snapshot, '(.*)', { astGrep: handle })).toEqual([])
  })
})

describe('resolveRelativeImport', () => {
  const snapshot = snapshotOf({
    'index.ts': '',
    'src/a.ts': '',
    'src/b/index.ts': '',
    'src/c.tsx': '',
    'src/d.js': '',
    'src/e.mts': '',
    'src/f/index.js': '',
    'lib/util.js': '',
    'pkg/__init__.py': '',
    'pkg/mod.py': '',
    'pkg/sub/__init__.py': '',
    'pkg/sub/deep.py': '',
    'src/app/__init__.py': '',
    'src/app/models.py': '',
    'stubs/typed.pyi': '',
  })

  it.each([
    ['src/x.ts', './a', 'src/a.ts'],
    ['src/x.ts', './a.js', 'src/a.ts'],
    ['src/x.ts', './b', 'src/b/index.ts'],
    ['src/x.ts', './c', 'src/c.tsx'],
    ['src/x.ts', './c.jsx', 'src/c.tsx'],
    ['src/x.ts', './d', 'src/d.js'],
    ['src/x.ts', './d.js', 'src/d.js'],
    ['src/x.ts', './e.mjs', 'src/e.mts'],
    ['src/x.ts', './f', 'src/f/index.js'],
    ['src/x.ts', '../lib/util', 'lib/util.js'],
    ['src/x.ts', '..', 'index.ts'],
    ['src/x.ts', '../../escape', undefined],
    ['src/x.ts', 'react', undefined],
    ['src/x.ts', './missing', undefined],
  ])('JS: %s imports %s → %s', (from, specifier, expected) => {
    expect(resolveRelativeImport(from, specifier, snapshot)).toBe(expected)
  })

  it.each([
    ['pkg/sub/deep.py', '.', 'pkg/sub/__init__.py'],
    ['pkg/sub/deep.py', '..', 'pkg/__init__.py'],
    ['pkg/sub/deep.py', '..mod', 'pkg/mod.py'],
    ['pkg/sub/deep.py', '...', undefined],
    ['pkg/x.py', '.sub.deep', 'pkg/sub/deep.py'],
    ['pkg/x.py', 'pkg.mod', 'pkg/mod.py'],
    ['pkg/x.py', 'pkg.sub', 'pkg/sub/__init__.py'],
    ['pkg/x.py', 'pkg', 'pkg/__init__.py'],
    ['pkg/x.py', 'pkg.sub.deep', 'pkg/sub/deep.py'],
    ['src/app/views.py', 'app.models', 'src/app/models.py'],
    ['src/app/views.py', '.models', 'src/app/models.py'],
    ['pkg/x.py', 'stubs.typed', 'stubs/typed.pyi'],
    ['pkg/x.py', 'os.path', undefined],
    ['pkg/x.py', 'pkg.mod-x', undefined],
  ])('Python: %s imports %s → %s', (from, specifier, expected) => {
    expect(resolveRelativeImport(from, specifier, snapshot)).toBe(expected)
  })
})

describe('enclosingSymbol', () => {
  const outline = outlineFile(fileOf('src/a.ts', TS))

  it('returns the innermost symbol containing the line', () => {
    expect(enclosingSymbol(outline, 13)?.name).toBe('alpha')
    expect(enclosingSymbol(outline, 26)).toMatchObject({ name: 'method', kind: 'method' })
    expect(enclosingSymbol(outline, 22)).toMatchObject({ name: 'Gamma', kind: 'class' })
    expect(enclosingSymbol(outline, 21)?.name).toBe('Gamma')
  })

  it('returns undefined outside every symbol', () => {
    expect(enclosingSymbol(outline, 1)).toBeUndefined()
    expect(enclosingSymbol(outline, 999)).toBeUndefined()
  })
})
