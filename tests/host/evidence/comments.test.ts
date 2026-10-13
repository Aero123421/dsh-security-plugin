import { describe, expect, it } from 'vitest'
import { commentMask, isCommentOnlyRange } from '../../../src/host/evidence/comments.ts'

/** Whether the first occurrence of `fragment` in `text` is comment-only for `path`. */
function commentOnly(path: string, text: string, fragment: string): boolean {
  const index = text.indexOf(fragment)
  if (index < 0) throw new Error(`fragment not in text: ${fragment}`)
  return isCommentOnlyRange(text, commentMask(text, path), index, index + fragment.length)
}

describe('commentMask', () => {
  it('recognizes C-style line and block comments, including `*` continuation lines', () => {
    const ts = [
      '// input sanitized upstream',
      '/**',
      ' * @remarks validated by the gateway',
      ' */',
      'const id = clean(req.query.id) // trailing note',
      'class A { #secret = 1 }',
    ].join('\n')
    expect(commentOnly('src/a.ts', ts, '// input sanitized upstream')).toBe(true)
    expect(commentOnly('src/a.ts', ts, ' * @remarks validated by the gateway')).toBe(true)
    expect(commentOnly('src/a.ts', ts, '/**\n * @remarks validated by the gateway\n */')).toBe(true)
    expect(commentOnly('src/a.ts', ts, 'trailing note')).toBe(true)
    expect(commentOnly('src/a.ts', ts, 'clean(req.query.id) // trailing')).toBe(false)
    expect(commentOnly('src/a.ts', ts, '#secret = 1')).toBe(false)
  })

  it('treats comment markers inside strings and template literals as code', () => {
    const js = ['const url = \'https://example.com/a\' + "/* x */"', 'const t = `line', '// still a string`'].join('\n')
    expect(commentOnly('a.js', js, '//example.com/a')).toBe(false)
    expect(commentOnly('a.js', js, '/* x */')).toBe(false)
    expect(commentOnly('a.js', js, '// still a string')).toBe(false)
  })

  it('recognizes hash comments and Python docstrings, but not string literals', () => {
    const py = [
      'def find(q):',
      '    """Input is validated upstream."""',
      '    query = """SELECT * FROM t"""',
      '    run("a # b")  # safe',
      "    '''",
      '    Multi-line docstring.',
      "    '''",
    ].join('\n')
    expect(commentOnly('app/db.py', py, '"""Input is validated upstream."""')).toBe(true)
    expect(commentOnly('app/db.py', py, 'Multi-line docstring.')).toBe(true)
    expect(commentOnly('app/db.py', py, '"""SELECT * FROM t"""')).toBe(false)
    expect(commentOnly('app/db.py', py, '# b')).toBe(false)
    expect(commentOnly('app/db.py', py, '# safe')).toBe(true)
    expect(commentOnly('config.yml', 'key: value # note\n# whole line\n', '# whole line')).toBe(true)
    expect(commentOnly('config.yml', 'key: value # note\n', 'key: value')).toBe(false)
    expect(commentOnly('Dockerfile', '# base image\nFROM node:22\n', '# base image')).toBe(true)
    expect(commentOnly('.env.example', '# required\nA=1\n', '# required')).toBe(true)
  })

  it('recognizes HTML, SQL, and template comments', () => {
    const html = '<!-- escaped by the template -->\n<p>{{ note }}</p>\n{# jinja note #}\n'
    expect(commentOnly('t.html', html, 'escaped by the template')).toBe(true)
    expect(commentOnly('t.html', html, '<p>{{ note }}</p>')).toBe(false)
    expect(commentOnly('t.j2', html, '{# jinja note #}')).toBe(true)
    expect(commentOnly('q.sql', 'SELECT 1; -- parameterized\n', '-- parameterized')).toBe(true)
    expect(commentOnly('q.sql', 'SELECT 1; -- parameterized\n', 'SELECT 1;')).toBe(false)
  })

  it('treats documentation files as prose and unknown files conservatively', () => {
    expect(commentOnly('docs/SECURITY.md', '# Security\n\nAll input is sanitized.\n', 'All input is sanitized.')).toBe(
      true,
    )
    expect(commentOnly('notes.txt', 'sanitized upstream', 'sanitized upstream')).toBe(true)
    // Unknown extension: line comments only at the start of a line.
    expect(commentOnly('run.weird', '# setup\nvalue # not a comment\n', '# setup')).toBe(true)
    expect(commentOnly('run.weird', '# setup\nvalue # not a comment\n', 'not a comment')).toBe(false)
  })

  it('never calls blank or empty ranges comment-only', () => {
    const text = '// a\n\n'
    const mask = commentMask(text, 'a.ts')
    expect(isCommentOnlyRange(text, mask, 4, 6)).toBe(false)
    expect(isCommentOnlyRange(text, mask, 2, 2)).toBe(false)
  })

  it('scans a long single line in linear time', () => {
    const line = `const a = [${'1, '.repeat(200_000)}] // end`
    const started = performance.now()
    expect(commentOnly('min.js', line, '// end')).toBe(true)
    expect(performance.now() - started).toBeLessThan(2_000)
  })
})
