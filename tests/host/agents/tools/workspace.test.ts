import { describe, expect, it } from 'vitest'
import { type ToolResult, toolSchema, type WorkerTool } from '../../../../src/host/agents/runtime/tool.ts'
import {
  createWorkspaceTools,
  looksLikeRegex,
  WORKSPACE_TOOL_NAMES,
  type WorkspaceToolOptions,
  type WorkspaceView,
  workspaceQuoteSource,
} from '../../../../src/host/agents/tools/workspace.ts'
import { Redactor, scanSecrets } from '../../../../src/host/analysis/secrets.ts'
import type { Endpoint, Snapshot } from '../../../../src/host/analysis/types.ts'
import { verifyQuote } from '../../../../src/host/evidence/quote.ts'
import { fileOf, snapshotOf } from '../../analysis/helpers.ts'

// Assembled at runtime so this file never contains a contiguous token.
const j = (...parts: string[]): string => parts.join('')
const TOKEN = j('ghp', '_', 'aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA5')
const ROOT = '/home/alice/projects/acme-shop'

const FILES: Record<string, string> = {
  'src/app.ts': [
    "import express from 'express'",
    "import { usersRouter } from './routes/users'",
    '',
    'const app = express()',
    "app.use('/users', usersRouter)",
    'app.listen(3000)',
    '',
  ].join('\n'),
  'src/routes/users.ts': [
    "import { Router } from 'express'",
    "import { db } from '../db'",
    '',
    'export const usersRouter = Router()',
    '',
    "usersRouter.get('/:id', async (req, res) => {",
    "  const rows = await db.query('SELECT * FROM users WHERE id = ' + req.params.id)",
    '  res.json(rows)',
    '})',
    '',
  ].join('\n'),
  'src/db.ts': [
    "import { Pool } from 'pg'",
    '',
    'export const db = new Pool({ connectionString: process.env.DATABASE_URL })',
    '',
  ].join('\n'),
  'src/github.ts': [
    "import { Octokit } from '@octokit/rest'",
    '',
    `const octokit = new Octokit({ auth: "${TOKEN}" })`,
    `// cache dir: ${ROOT}/.cache`,
    'export default octokit',
    '',
  ].join('\n'),
  'src/services/user.ts': [
    "import { db } from '../db'",
    "import bcrypt from 'bcrypt'",
    '',
    'export function createUser(name: string) {',
    '  return db.insert(name)',
    '}',
    '',
    'export class UserService {',
    '  create(name: string) {',
    '    return createUser(name)',
    '  }',
    '}',
    '',
  ].join('\n'),
  'app/views.py': [
    'import os',
    'from flask import Flask, request',
    '',
    'app = Flask(__name__)',
    '',
    'def create_user():',
    "    return os.getenv('X')",
    '',
  ].join('\n'),
  'tests/users.test.ts': "import { usersRouter } from '../src/routes/users'\ntest('db.query works', () => {})\n",
  'src/app.spec.ts': "describe('app', () => { it('db.query', () => {}) })\n",
  '.env': 'DATABASE_URL=postgres://admin:hunter2hunter2@db.internal:5432/app\n',
  'config/secrets.yml': 'production:\n  db.query_password: s3cr3t-value\n',
  'README.md': '# Acme shop\n',
}

const ENDPOINTS: Endpoint[] = [
  {
    id: 'GET /users/:id @ src/routes/users.ts:6',
    framework: 'express',
    method: 'GET',
    route: '/users/:id',
    declaredAt: { path: 'src/routes/users.ts', startLine: 6, endLine: 6 },
    handler: { path: 'src/routes/users.ts', startLine: 6, endLine: 9 },
    middleware: [],
    authHints: [],
    params: ['id'],
  },
  {
    id: 'POST /admin/users @ src/admin/routes.ts:3',
    framework: 'express',
    method: 'POST',
    route: '/admin/users',
    declaredAt: { path: 'src/admin/routes.ts', startLine: 3, endLine: 3 },
    middleware: ['requireAuth', 'rateLimit'],
    authHints: ['requireAuth'],
    params: [],
  },
  {
    id: 'ANY /webhook @ app/views.py:10',
    framework: 'flask',
    method: 'ANY',
    route: '/webhook',
    declaredAt: { path: 'app/views.py', startLine: 10, endLine: 10 },
    middleware: [],
    authHints: [],
    params: [],
  },
]

interface Harness {
  readonly tools: Map<string, WorkerTool<unknown, never>>
  readonly reads: string[]
  readonly view: WorkspaceView
  call(name: string, args: unknown, signal?: AbortSignal): Promise<ToolResult>
}

async function harness(
  files: Record<string, string> = FILES,
  options: WorkspaceToolOptions = {},
  overrides: Partial<WorkspaceView> & { snapshot?: Snapshot } = {},
): Promise<Harness> {
  const snapshot = overrides.snapshot ?? snapshotOf(files, ROOT)
  const reads: string[] = []
  const view: WorkspaceView = {
    snapshot,
    redactor: new Redactor(await scanSecrets(snapshot)),
    withheldGlobs: [],
    endpoints: ENDPOINTS,
    onRead: path => reads.push(path),
    ...overrides,
  }
  const tools = new Map(createWorkspaceTools(view, options).map(tool => [tool.name, tool]))
  return {
    tools,
    reads,
    view,
    async call(name, args, signal = new AbortController().signal) {
      const tool = tools.get(name)
      if (!tool?.execute) throw new Error(`no tool ${name}`)
      const parsed = tool.input.parse(args)
      const result = await tool.execute(parsed, { signal, workerId: 'w1', turn: 1 })
      // Global invariants for every output.
      expect(result.text).not.toContain(ROOT)
      expect(result.text).not.toContain(TOKEN)
      expect(result.text).not.toContain('hunter2')
      return result
    },
  }
}

describe('createWorkspaceTools', () => {
  it('masks known generic values in prose, header dictionaries, generated and oversized files', async () => {
    const secret = 'rT8!pL2@vM6#xN4$qK9%zB7'
    const snapshot = snapshotOf(
      {
        'src/config.ts': `const password = "${secret}"`,
        'docs/runbook.md': `credential copied here: ${secret}`,
        'src/headers.ts': `const headers = { Authorization: "Bearer ${secret}" }`,
        'src/generated.ts': `// @generated\n// credential ${secret}`,
        'src/large.ts': `// credential ${secret}\n${' '.repeat(2 * 1024 * 1024)}`,
        'src/normal.ts': 'export const count = 42',
      },
      ROOT,
    )
    // The skipped files have no recorded spans; only the copy in config establishes this value.
    const generated = snapshot.files.get('src/generated.ts')!
    const files = new Map(snapshot.files)
    files.set(generated.path, { ...generated, isGenerated: true })
    const frozen = { ...snapshot, files }
    const matches = await scanSecrets(frozen)
    expect(matches.some(m => m.ruleId === 'generic-secret')).toBe(true)
    expect(matches.some(m => /generated|large/.test(m.path))).toBe(false)
    const h = await harness({}, {}, { snapshot: frozen, redactor: new Redactor(matches) })
    for (const path of ['docs/runbook.md', 'src/headers.ts', 'src/generated.ts', 'src/large.ts']) {
      const result = await h.call('read_file', { path, end_line: 1 })
      expect(result.text).not.toContain(secret)
      const full = await h.call('read_file', { path })
      expect(full.text).toContain('[REDACTED:generic-secret]')
    }
    const search = await h.call('search_code', { pattern: 'credential|Bearer', regex: true })
    expect(search.text).not.toContain(secret)
    expect(search.text).toContain('[REDACTED:generic-secret]')
    expect((await h.call('read_file', { path: 'src/normal.ts' })).text).toContain('export const count = 42')
    // Query echoes and error text are also tool output.
    expect((await h.call('search_code', { pattern: secret })).text).not.toContain(secret)
  })

  it('masks canonical, registered and case-variant roots without changing suffix semantics', async () => {
    const canonical = 'C:\\Users\\Alice\\Projects\\Acme'
    const registered = 'C:\\Users\\Alice\\Links\\Acme'
    const snapshot = {
      ...snapshotOf(
        { 'app.ts': 'const p = "c:/users/ALICE/projects/acme-old/file"\n// C:/USERS/ALICE/LINKS/ACME/src' },
        canonical,
      ),
      workspaceRoot: canonical,
      registeredWorkspaceRoot: registered,
    }
    const h = await harness({}, {}, { snapshot })
    const text = (await h.call('read_file', { path: 'app.ts' })).text
    expect(text).toContain('<root>-old/file')
    expect(text).toContain('<root>/src')
    expect(text).not.toMatch(/users/i)
  })

  it('creates the non-terminal tools with described inputs', async () => {
    const h = await harness()
    expect([...h.tools.keys()]).toEqual([...WORKSPACE_TOOL_NAMES])
    for (const tool of h.tools.values()) {
      expect(tool.terminal).toBeUndefined()
      const schema = toolSchema(tool)
      expect(schema.description.length).toBeGreaterThan(40)
      const properties = schema.parameters.properties as Record<string, { description?: string }>
      for (const [key, property] of Object.entries(properties)) {
        expect(property.description, `${tool.name}.${key}`).toBeTruthy()
      }
    }
  })
})

describe('list_files', () => {
  it('lists non-test files with language and line counts in path order', async () => {
    const h = await harness()
    const { text, isError } = await h.call('list_files', {})
    expect(isError).toBeUndefined()
    const lines = text.split('\n')
    expect(lines[0]).toBe('9 files:')
    expect(lines.slice(1, 10)).toEqual([
      '.env  [withheld]',
      'README.md  (markdown, 1 lines)',
      'app/views.py  (python, 7 lines)',
      'config/secrets.yml  [withheld]',
      'src/app.ts  (typescript, 6 lines)',
      'src/db.ts  (typescript, 3 lines)',
      'src/github.ts  (typescript, 5 lines)',
      'src/routes/users.ts  (typescript, 9 lines)',
      'src/services/user.ts  (typescript, 12 lines)',
    ])
    expect(text).toContain('2 test/fixture/example files hidden')
    expect(text).not.toContain('users.test.ts')
  })

  it('filters by glob and directory', async () => {
    const h = await harness()
    expect((await h.call('list_files', { glob: 'src/**/*.ts', under: 'src/routes' })).text).toBe(
      '1 file under src/routes/ matching "src/**/*.ts":\nsrc/routes/users.ts  (typescript, 9 lines)',
    )
    // A glob is also tried relative to `under`.
    expect((await h.call('list_files', { glob: 'routes/*.ts', under: 'src' })).text).toContain('src/routes/users.ts')
    expect((await h.call('list_files', { glob: '*.py' })).text).toContain('app/views.py')
    expect((await h.call('list_files', { glob: '{app,config}/**' })).text.split('\n').slice(1)).toEqual([
      'app/views.py  (python, 7 lines)',
      'config/secrets.yml  [withheld]',
    ])
  })

  it('shows test files when explicitly targeted or enabled', async () => {
    const h = await harness()
    expect((await h.call('list_files', { under: 'tests' })).text).toContain('tests/users.test.ts')
    expect((await h.call('list_files', { glob: '**/*.spec.ts' })).text).toContain('src/app.spec.ts')
    const all = await harness(FILES, { includeTests: true })
    const text = (await all.call('list_files', {})).text
    expect(text).toContain('tests/users.test.ts')
    expect(text).not.toContain('hidden')
  })

  it('applies the limit and reports how many more exist', async () => {
    const many = Object.fromEntries(
      Array.from({ length: 30 }, (_, i) => [`src/m${String(i).padStart(2, '0')}.ts`, 'x\n']),
    )
    const h = await harness(many)
    const { text } = await h.call('list_files', { limit: 5 })
    const lines = text.split('\n')
    expect(lines[0]).toBe('30 files:')
    expect(lines.slice(1, 6)).toEqual(Array.from({ length: 5 }, (_, i) => `src/m0${i}.ts  (typescript, 1 lines)`))
    expect(lines[6]).toBe('… 25 more not shown; raise limit (max 500) or narrow with glob/under.')
    expect((await h.call('list_files', { limit: 10_000 })).text.split('\n')).toHaveLength(31)
  })

  it('rejects invalid directories and globs', async () => {
    const h = await harness()
    for (const args of [
      { under: '../' },
      { under: '/etc' },
      { under: 'C:\\Windows' },
      { glob: '/etc/*' },
      { glob: '../**' },
    ]) {
      const result = await h.call('list_files', args)
      expect(result.isError, JSON.stringify(args)).toBe(true)
    }
    expect((await h.call('list_files', { glob: '{a,b}'.repeat(9) })).isError).toBe(true)
  })

  it('says when nothing matches', async () => {
    const h = await harness()
    expect((await h.call('list_files', { glob: '*.rs' })).text).toMatch(/^No files match matching "\*\.rs"\./)
  })

  it('honors user withheld globs', async () => {
    const h = await harness(FILES, {}, { withheldGlobs: ['src/db.ts'] })
    expect((await h.call('list_files', { under: 'src' })).text).toContain('src/db.ts  [withheld]')
    expect((await h.call('read_file', { path: 'src/db.ts' })).isError).toBe(true)
  })
})

describe('read_file', () => {
  it('returns numbered, redacted lines with a header and tracks the read', async () => {
    const h = await harness()
    const { text, isError } = await h.call('read_file', { path: 'src/github.ts' })
    expect(isError).toBeUndefined()
    expect(text).toBe(
      [
        'src/github.ts (lines 1-5 of 5)',
        "1| import { Octokit } from '@octokit/rest'",
        '2|',
        '3| const octokit = new Octokit({ auth: "[REDACTED:github-token]" })',
        '4| // cache dir: <root>/.cache',
        '5| export default octokit',
      ].join('\n'),
    )
    expect(h.reads).toEqual(['src/github.ts'])
  })

  it('normalizes the path', async () => {
    const h = await harness()
    expect((await h.call('read_file', { path: './src\\db.ts' })).text).toMatch(/^src\/db\.ts \(lines 1-3 of 3\)/)
    expect(h.reads).toEqual(['src/db.ts'])
  })

  it('reads a range and right-aligns line numbers', async () => {
    const h = await harness()
    const { text } = await h.call('read_file', { path: 'src/services/user.ts', start_line: 8, end_line: 10 })
    expect(text).toBe(
      'src/services/user.ts (lines 8-10 of 12)\n 8| export class UserService {\n 9|   create(name: string) {\n10|     return createUser(name)',
    )
  })

  it('caps lines per call and says how to continue', async () => {
    const long = Array.from({ length: 25 }, (_, i) => `line ${i + 1}`).join('\n')
    const h = await harness({ 'big.txt': long }, { maxReadLines: 10 })
    const first = (await h.call('read_file', { path: 'big.txt' })).text.split('\n')
    expect(first[0]).toBe('big.txt (lines 1-10 of 25)')
    expect(first.at(-1)).toBe('[15 more lines; call read_file with start_line=11 to continue.]')
    const ranged = (await h.call('read_file', { path: 'big.txt', start_line: 5, end_line: 25 })).text.split('\n')
    expect(ranged[0]).toBe('big.txt (lines 5-14 of 25)')
    expect(ranged.at(-1)).toBe('[11 more lines in the requested range; call read_file with start_line=15 to continue.]')
    const last = (await h.call('read_file', { path: 'big.txt', start_line: 21 })).text.split('\n')
    expect(last[0]).toBe('big.txt (lines 21-25 of 25)')
    expect(last.at(-1)).toBe('25| line 25')
  })

  it('reports ranges past the end and reversed ranges', async () => {
    const h = await harness()
    const past = await h.call('read_file', { path: 'src/db.ts', start_line: 99 })
    expect(past).toEqual({ text: 'start_line 99 is past the end of src/db.ts, which has 3 lines.', isError: true })
    expect((await h.call('read_file', { path: 'src/db.ts', start_line: 3, end_line: 2 })).isError).toBe(true)
    expect(h.reads).toEqual([])
  })

  it('refuses withheld files without revealing their content', async () => {
    const h = await harness()
    for (const path of ['.env', 'config/secrets.yml']) {
      const result = await h.call('read_file', { path })
      expect(result.isError).toBe(true)
      expect(result.text).toContain('this file may contain credentials and is never shown')
      expect(result.text).toContain('reason about it from its usage instead')
      expect(result.text).not.toContain('s3cr3t')
    }
    expect(h.reads).toEqual([])
  })

  it('suggests close paths for unknown files', async () => {
    const h = await harness()
    const result = await h.call('read_file', { path: 'routes/users.ts' })
    expect(result.isError).toBe(true)
    expect(result.text).toMatch(
      /^File not found in the snapshot: routes\/users\.ts\nDid you mean:\n {2}src\/routes\/users\.ts/,
    )
    expect(result.text.split('\n').length).toBeLessThanOrEqual(2 + 5)
    const typo = await h.call('read_file', { path: 'src/servces/user.ts' })
    expect(typo.text).toContain('src/services/user.ts')
  })

  it('explains directories and excluded paths', async () => {
    const h = await harness()
    expect((await h.call('read_file', { path: 'src/routes' })).text).toContain('is a directory')
    const snapshot: Snapshot = {
      ...snapshotOf({ 'a.ts': 'x\n' }, ROOT),
      excluded: [{ path: 'dist/bundle.js', reason: 'gitignore' }],
    }
    const excluded = await harness({}, {}, { snapshot })
    const result = await excluded.call('read_file', { path: 'dist/bundle.js' })
    expect(result).toMatchObject({ isError: true })
    expect(result.text).toContain('not part of the analyzed snapshot (excluded: gitignore)')
  })

  it('rejects absolute, escaping, and NUL paths', async () => {
    const h = await harness()
    for (const path of [
      '/etc/passwd',
      '../secrets',
      'src/../../x',
      'C:\\Windows\\win.ini',
      'src/app.ts\0',
      `${ROOT}/src/app.ts`,
    ]) {
      const result = await h.call('read_file', { path })
      expect(result.isError, path).toBe(true)
      expect(result.text, path).toMatch(/^Invalid path\./)
    }
    expect(h.reads).toEqual([])
  })

  it('handles empty files and CRLF content', async () => {
    const h = await harness({ 'empty.ts': '', 'win.py': 'a = 1\r\nb = 2\r\n' })
    expect((await h.call('read_file', { path: 'empty.ts' })).text).toBe('empty.ts (empty file)')
    expect((await h.call('read_file', { path: 'win.py' })).text).toBe('win.py (lines 1-2 of 2)\n1| a = 1\n2| b = 2')
  })

  it('swallows onRead listener errors', async () => {
    const h = await harness(
      FILES,
      {},
      {
        onRead: () => {
          throw new Error('boom')
        },
      },
    )
    expect((await h.call('read_file', { path: 'src/db.ts' })).isError).toBeUndefined()
  })

  it('shows exactly what quote verification checks against', async () => {
    const h = await harness()
    const text = (await h.call('read_file', { path: 'src/github.ts', start_line: 3, end_line: 4 })).text
    const quote = text
      .split('\n')
      .slice(1)
      .map(line => line.replace(/^\s*\d+\|\s?/, ''))
      .join('\n')
    const result = verifyQuote(workspaceQuoteSource(h.view), { path: 'src/github.ts', startLine: 3, endLine: 4, quote })
    expect(result.check).toBe('match')
    expect(result.snippet).not.toContain(ROOT)
  })
})

describe('search_code', () => {
  it('finds literal text case-insensitively, skipping withheld and test files', async () => {
    const h = await harness()
    const { text, isError } = await h.call('search_code', { pattern: 'DB.QUERY' })
    expect(isError).toBeUndefined()
    expect(text).toBe(
      [
        '1 match for text "DB.QUERY":',
        "src/routes/users.ts:7: const rows = await db.query('SELECT * FROM users WHERE id = ' + req.params.id)",
        '(2 withheld files not searched.)',
        '(2 test/fixture/example files not searched; set path_glob to a test location to include them.)',
      ].join('\n'),
    )
  })

  it('includes test files when path_glob targets them', async () => {
    const h = await harness()
    const { text } = await h.call('search_code', { pattern: 'db.query', path_glob: 'tests/**' })
    expect(text).toContain('tests/users.test.ts:2:')
    expect(text).not.toContain('src/routes/users.ts')
  })

  it('redacts secrets and masks the root in matching lines', async () => {
    const h = await harness()
    const { text } = await h.call('search_code', { pattern: 'octokit(' })
    expect(text).toContain('src/github.ts:3: const octokit = new Octokit({ auth: "[REDACTED:github-token]" })')
    expect((await h.call('search_code', { pattern: 'cache dir' })).text).toContain(
      'src/github.ts:4: // cache dir: <root>/.cache',
    )
    // Searching for the raw secret finds nothing: the search runs on redacted text.
    expect((await h.call('search_code', { pattern: TOKEN.slice(0, 20) })).text).toMatch(/^No matches/)
  })

  it('supports regular expressions and path globs', async () => {
    const h = await harness()
    const pattern = '^import .* from [\'"]\\.\\.?/'
    const { text } = await h.call('search_code', { pattern, regex: true, path_glob: 'src/**/*.ts' })
    expect(text.split('\n')).toEqual([
      `3 matches for regex ${JSON.stringify(pattern)}:`,
      "src/app.ts:2: import { usersRouter } from './routes/users'",
      "src/routes/users.ts:2: import { db } from '../db'",
      "src/services/user.ts:1: import { db } from '../db'",
      '(1 test/fixture/example file not searched; set path_glob to a test location to include them.)',
    ])
    // Case-sensitive regex.
    const sensitive = await h.call('search_code', { pattern: '^IMPORT', regex: true, case_sensitive: true })
    expect(sensitive.text).toMatch(/^No matches/)
  })

  it('runs a regex-looking pattern as a regular expression when regex is unset and nothing matches literally', async () => {
    const h = await harness()
    const { text } = await h.call('search_code', { pattern: 'usersRouter\\.(get|post)\\(' })
    expect(text.split('\n')).toEqual([
      'No literal matches for "usersRouter\\\\.(get|post)\\\\("; it looks like a regular expression, so it was run as one (set regex=false to search literally only).',
      '1 match for regex "usersRouter\\\\.(get|post)\\\\(":',
      "src/routes/users.ts:6: usersRouter.get('/:id', async (req, res) => {",
      '(2 withheld files not searched.)',
      '(2 test/fixture/example files not searched; set path_glob to a test location to include them.)',
    ])
    expect((await h.call('search_code', { pattern: 'req.params.id|DATABASE_URL' })).text).toContain(
      '2 matches for regex "req.params.id|DATABASE_URL":',
    )
    // regex=false keeps the literal meaning, and a literal hit is never second-guessed.
    expect((await h.call('search_code', { pattern: 'req.params.id|req.query', regex: false })).text).toMatch(
      /^No matches for text/,
    )
    expect((await h.call('search_code', { pattern: 'req.params.id' })).text).toMatch(/^1 match for text/)
  })

  it.each([
    ['a|b', true],
    ['router\\.get', true],
    ['\\bauth\\b', true],
    ['select.*from', true],
    ['^import', true],
    ['req.body$', true],
    ['[A-Z]+Error', true],
    ['(?:get|post)', true],
    ['db.query(', false],
    ['req.params.id', false],
    ['$scope.user', false],
    ['a || b', true],
  ])('recognizes regex syntax in %j: %s', (pattern, expected) => {
    expect(looksLikeRegex(pattern)).toBe(expected)
  })

  it('says how to fix a regex-looking pattern that is not a valid regular expression, and skips match-all ones', async () => {
    const h = await harness()
    const { text, isError } = await h.call('search_code', { pattern: 'query\\(|(unclosed' })
    expect(isError).toBeUndefined()
    expect(text.split('\n')[0]).toMatch(
      /^The pattern looks like a regular expression but is not a valid one \(Invalid regular expression: .+\)\. Set regex=true with a valid pattern, or search for a literal fragment\.$/,
    )
    // An empty alternative would match every line: the literal answer stands.
    expect((await h.call('search_code', { pattern: 'a || b' })).text).toMatch(/^No matches for text "a \|\| b"/)
  })

  it('caps results and says more exist', async () => {
    const many = Object.fromEntries(Array.from({ length: 5 }, (_, i) => [`src/f${i}.ts`, 'eval(x)\neval(y)\n']))
    const h = await harness(many, { maxSearchResults: 4 })
    const { text } = await h.call('search_code', { pattern: 'eval' })
    const lines = text.split('\n')
    expect(lines[0]).toBe('4+ matches for text "eval":')
    expect(lines.slice(1, 5)).toEqual([
      'src/f0.ts:1: eval(x)',
      'src/f0.ts:2: eval(y)',
      'src/f1.ts:1: eval(x)',
      'src/f1.ts:2: eval(y)',
    ])
    expect(lines[5]).toBe('[More matches exist beyond 4; narrow with path_glob or a more specific pattern.]')
    expect((await h.call('search_code', { pattern: 'eval', max_results: 1 })).text.split('\n')[1]).toBe(
      'src/f0.ts:1: eval(x)',
    )
    expect((await h.call('search_code', { pattern: 'eval', max_results: 99 })).text).toContain('4+ matches')
  })

  it('clips long lines around the match', async () => {
    const line = `${'a'.repeat(500)} TARGET ${'b'.repeat(500)}`
    const h = await harness({ 'min.txt': `${line}\n` })
    const { text } = await h.call('search_code', { pattern: 'target' })
    const hit = text.split('\n')[1]!
    expect(hit).toMatch(/^min\.txt:1: …a+ TARGET b+…$/)
    expect(hit.length).toBeLessThanOrEqual('min.txt:1: '.length + 202)
  })

  it('rejects invalid and overlong regexes', async () => {
    const h = await harness()
    const invalid = await h.call('search_code', { pattern: '(unclosed', regex: true })
    expect(invalid.isError).toBe(true)
    expect(invalid.text).toMatch(/^Invalid regular expression/)
    const long = await h.call('search_code', { pattern: 'a'.repeat(201) })
    expect(long).toMatchObject({ isError: true })
    expect(long.text).toContain('the limit is 200')
    expect((await h.call('search_code', { pattern: 'a\nb' })).isError).toBe(true)
    expect((await h.call('search_code', { pattern: 'x', path_glob: '../**' })).isError).toBe(true)
  })

  it('bounds catastrophic patterns by per-line, time-limited execution', async () => {
    const evil = `${'a'.repeat(36)}!`
    const h = await harness({ 'a.txt': `ok\n${evil}\n`, 'b.txt': 'aaa\n' }, { regexTimeBudgetMs: 200 })
    const started = performance.now()
    const { text, isError } = await h.call('search_code', { pattern: '(a+)+$', regex: true })
    expect(performance.now() - started).toBeLessThan(5_000)
    expect(isError).toBeUndefined()
    expect(text).toContain('the regular expression took too long')
    // A quadratic-looking pattern stays fast because it only ever sees one line.
    const lines = Array.from({ length: 2000 }, (_, i) => `const v${i} = f(${i})`).join('\n')
    const fast = await harness({ 'big.ts': lines })
    const result = await fast.call('search_code', { pattern: '.*.*=.*f\\(1999\\)', regex: true })
    expect(result.text).toContain('big.ts:2000:')
  })

  it('lists the matches found before a regex search stopped early', async () => {
    const evil = `${'a'.repeat(36)}!`
    const h = await harness({ 'a.txt': `aaa\n${evil}\n`, 'b.txt': 'aaa\n' }, { regexTimeBudgetMs: 200 })
    const { text, isError } = await h.call('search_code', { pattern: '(a+)+$', regex: true })
    expect(isError).toBeUndefined()
    expect(text).toContain('a.txt:1: aaa')
    expect(text).not.toContain('b.txt')
    expect(text).toContain('[Search stopped early: the regular expression took too long')
    expect(text).toContain('Only the matches found before it stopped are listed')
  })

  it('stops scanning at the byte cap', async () => {
    const files = Object.fromEntries(Array.from({ length: 4 }, (_, i) => [`f${i}.txt`, `${'x'.repeat(100)}\n`]))
    const h = await harness(files, { maxSearchScanBytes: 250 })
    const { text } = await h.call('search_code', { pattern: 'x' })
    expect(text).toContain('f1.txt:1:')
    expect(text).not.toContain('f2.txt')
    expect(text).toContain('[Search stopped after 2 files (202 B): the per-call scan limit is 250 B.')
  })

  it('honors the abort signal', async () => {
    const h = await harness()
    const controller = new AbortController()
    controller.abort(new Error('worker cancelled'))
    const tool = h.tools.get('search_code')!
    await expect(
      tool.execute!({ pattern: 'db' }, { signal: controller.signal, workerId: 'w', turn: 1 }),
    ).rejects.toThrow('worker cancelled')

    const files = Object.fromEntries(
      Array.from({ length: 200 }, (_, i) => [`f${String(i).padStart(3, '0')}.ts`, 'nothing\n']),
    )
    const big = await harness(files)
    const late = new AbortController()
    const pending = big.tools.get('search_code')!.execute!(
      { pattern: 'zzz' },
      { signal: late.signal, workerId: 'w', turn: 1 },
    )
    late.abort(new Error('stop'))
    await expect(pending).rejects.toThrow('stop')
  })
})

describe('find_symbol', () => {
  it('lists definitions with ranges and kinds', async () => {
    const h = await harness()
    expect((await h.call('find_symbol', { name: 'createUser' })).text).toBe(
      '1 definition of "createUser":\nsrc/services/user.ts:4-6 function',
    )
    expect((await h.call('find_symbol', { name: 'UserService.create' })).text).toBe(
      '1 definition of "UserService.create":\nsrc/services/user.ts:9-11 method',
    )
    expect((await h.call('find_symbol', { name: 'create_user' })).text).toContain('app/views.py:6-7 function')
  })

  it('explains when nothing is found and rejects non-identifiers', async () => {
    const h = await harness()
    expect((await h.call('find_symbol', { name: 'doesNotExist' })).text).toMatch(
      /^No definitions named "doesNotExist" found\.\n.*search_code/,
    )
    const bad = await h.call('find_symbol', { name: 'foo(bar)' })
    expect(bad.isError).toBe(true)
  })

  it('hides definitions in test files unless enabled', async () => {
    const files = { 'src/a.ts': 'export function helper() {}\n', 'tests/a.test.ts': 'export function helper() {}\n' }
    const h = await harness(files)
    const text = (await h.call('find_symbol', { name: 'helper' })).text
    expect(text).toBe('1 definition of "helper":\nsrc/a.ts:1-1 function\n(1 definition in test files not shown.)')
    const all = await harness(files, { includeTests: true })
    expect((await all.call('find_symbol', { name: 'helper' })).text).toContain('tests/a.test.ts:1-1 function')
  })
})

describe('file_outline', () => {
  it('lists imports and symbols', async () => {
    const h = await harness()
    expect((await h.call('file_outline', { path: 'src/services/user.ts' })).text).toBe(
      [
        'src/services/user.ts (typescript, 12 lines)',
        'imports:',
        '  1: ../db  [db]',
        '  2: bcrypt  [bcrypt]',
        'symbols:',
        '  4-6 function createUser (exported)',
        '  8-12 class UserService (exported)',
        '  9-11 method create',
      ].join('\n'),
    )
    expect((await h.call('file_outline', { path: 'app/views.py' })).text).toContain('  4 variable app (exported)')
  })

  it('handles unsupported, withheld, unknown, and invalid paths', async () => {
    const h = await harness()
    expect((await h.call('file_outline', { path: 'README.md' })).text).toContain('No imports or symbols found')
    expect((await h.call('file_outline', { path: '.env' })).isError).toBe(true)
    const unknown = await h.call('file_outline', { path: 'src/servics/user.ts' })
    expect(unknown).toMatchObject({ isError: true })
    expect(unknown.text).toContain('src/services/user.ts')
    expect((await h.call('file_outline', { path: '/etc/hosts' })).isError).toBe(true)
  })
})

describe('list_endpoints', () => {
  it('lists endpoints sorted by route with middleware and auth hints', async () => {
    const h = await harness()
    expect((await h.call('list_endpoints', {})).text).toBe(
      [
        '3 endpoints:',
        'POST /admin/users  src/admin/routes.ts:3  middleware=[requireAuth, rateLimit] auth=[requireAuth]',
        'GET /users/:id  src/routes/users.ts:6  middleware=[] auth=[]  handler=src/routes/users.ts:6-9',
        'ANY /webhook  app/views.py:10  middleware=[] auth=[]',
      ].join('\n'),
    )
  })

  it('filters by directory and method (ANY always included)', async () => {
    const h = await harness()
    expect((await h.call('list_endpoints', { under: 'src/admin' })).text.split('\n')).toHaveLength(2)
    const posts = (await h.call('list_endpoints', { method: 'post' })).text
    expect(posts).toContain('POST /admin/users')
    expect(posts).toContain('ANY /webhook')
    expect(posts).not.toContain('GET /users')
    expect((await h.call('list_endpoints', { limit: 1 })).text).toContain('… 2 more not shown')
    expect((await h.call('list_endpoints', { under: 'lib' })).text).toBe(
      'No endpoints match the filters (3 endpoints detected in total).',
    )
    expect((await h.call('list_endpoints', { under: '/api' })).isError).toBe(true)
  })

  it('says when no endpoints were detected and hints at manual search', async () => {
    const h = await harness(FILES, {}, { endpoints: [] })
    const { text, isError } = await h.call('list_endpoints', {})
    expect(isError).toBeUndefined()
    expect(text).toMatch(/^No endpoints were detected\..*search_code/s)
  })
})

describe('root confidentiality', () => {
  it('masks absolute root paths in content and never echoes absolute input', async () => {
    const files = {
      'src/paths.ts': [
        `export const a = '${ROOT}'`,
        `export const b = "${ROOT}/uploads/" + name`,
        `// file://${ROOT}/src/paths.ts`,
        `export const c = '${ROOT}-backup/x'`,
        'export const d = "src/app/page.tsx"',
        '',
      ].join('\n'),
    }
    const h = await harness(files)
    const read = (await h.call('read_file', { path: 'src/paths.ts' })).text
    expect(read).toContain("1| export const a = '<root>'")
    expect(read).toContain('2| export const b = "<root>/uploads/" + name')
    expect(read).toContain('3| // file://<root>/src/paths.ts')
    // A multi-segment root is masked even when a sibling directory extends its last segment.
    expect(read).toContain("4| export const c = '<root>-backup/x'")
    expect((await h.call('search_code', { pattern: 'uploads' })).text).toContain(
      'src/paths.ts:2: export const b = "<root>/uploads/"',
    )
    for (const path of [ROOT, `${ROOT}/src/paths.ts`, `file://${ROOT}/src/paths.ts`]) {
      const result = await h.call('read_file', { path })
      expect(result.isError).toBe(true)
      expect(result.text).toMatch(/^Invalid path\./)
    }
  })

  it('does not mangle relative paths that merely share text with a short root', async () => {
    const snapshot = snapshotOf({ 'src/app/page.tsx': "export default function Page() { return '/app' }\n" }, '/app')
    const h = await harness({}, {}, { snapshot })
    expect((await h.call('list_files', {})).text).toContain('src/app/page.tsx  (typescript, 1 lines)')
    const read = (await h.call('read_file', { path: 'src/app/page.tsx' })).text
    expect(read).toBe("src/app/page.tsx (lines 1-1 of 1)\n1| export default function Page() { return '<root>' }")
  })

  it('works with a file built directly through fileOf', async () => {
    const file = fileOf('lib/x.ts', 'export const x = 1\n')
    const snapshot: Snapshot = { ...snapshotOf({}, ROOT), files: new Map([[file.path, file]]) }
    const h = await harness({}, {}, { snapshot })
    expect((await h.call('read_file', { path: 'lib/x.ts' })).text).toBe(
      'lib/x.ts (lines 1-1 of 1)\n1| export const x = 1',
    )
  })
})

describe('integration with runWorker', () => {
  it('serves tool calls inside the worker loop and verifies the cited quote', async () => {
    const { runWorker } = await import('../../../../src/host/agents/runtime/worker.ts')
    const { FakeLlm, callReply, makeSpec, submitReport, SUBMISSION } = await import('../runtime/helpers.ts')
    const h = await harness()
    const llm = new FakeLlm([
      callReply('c1', 'search_code', { pattern: 'db.query' }),
      callReply('c2', 'read_file', { path: 'src/routes/users.ts', start_line: 6, end_line: 9 }),
      callReply('c3', 'read_file', { path: '.env' }),
      callReply('c4', 'submit_report', SUBMISSION),
    ])
    const tools = [...createWorkspaceTools(h.view), submitReport]
    const { spec, events } = makeSpec(llm, { tools })
    const result = await runWorker(spec)
    expect(result.status).toBe('submitted')
    expect(events.filter(e => e.type === 'tool').map(e => (e.type === 'tool' ? [e.name, e.ok] : []))).toEqual([
      ['search_code', true],
      ['read_file', true],
      ['read_file', false],
      ['submit_report', true],
    ])
    const toolTexts = llm
      .messages(3)
      .flatMap(m => (m.role === 'tool' ? [m.content[0]] : []))
      .map(block => (block?.type === 'text' ? (block as { text?: string }).text : undefined) ?? '')
    expect(toolTexts[1]).toContain(
      "\n7|   const rows = await db.query('SELECT * FROM users WHERE id = ' + req.params.id)",
    )
    expect(toolTexts[2]).toContain('never shown')
    expect(h.reads).toEqual(['src/routes/users.ts'])
    const verdict = verifyQuote(workspaceQuoteSource(h.view), {
      path: 'src/routes/users.ts',
      startLine: 7,
      endLine: 7,
      quote: "db.query('SELECT * FROM users WHERE id = ' + req.params.id)",
    })
    expect(verdict.check).toBe('match')
  })
})
