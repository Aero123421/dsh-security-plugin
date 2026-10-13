import { readdir, readFile } from 'node:fs/promises'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'
import { parse as parseYaml } from 'yaml'
import {
  isDependencyFileName,
  LineIndex,
  parseDependencies,
  readLockYaml,
} from '../../../src/host/analysis/dependencies.ts'
import type { Dependency, Snapshot } from '../../../src/host/analysis/types.ts'
import { snapshotOf } from './helpers.ts'

const FIXTURES = fileURLToPath(new URL('../../fixtures/', import.meta.url))
const REPO_LOCK = fileURLToPath(new URL('../../../pnpm-lock.yaml', import.meta.url))
const PACKAGES = 16_000

function packageName(i: number): string {
  return i % 5 === 0 ? `@scope${i % 37}/pkg-${i}` : `pkg-${i}`
}

function packageVersion(i: number): string {
  return `1.${i % 50}.${i}`
}

function integrity(i: number): string {
  return `sha512-${((i * 2654435761) >>> 0).toString(36)}==`
}

/** A pnpm v9 lock with `count` packages, and the line of each package's `packages:` key. */
function pnpmLock(count: number): { content: string; lines: Map<string, number> } {
  const out = ["lockfileVersion: '9.0'", '', 'settings:', '  autoInstallPeers: true', '', 'importers:', '', '  .:']
  for (const [section, from] of [
    ['dependencies', 0],
    ['devDependencies', 20],
  ] as const) {
    out.push(`    ${section}:`)
    for (let i = from; i < from + 20; i++) {
      out.push(
        `      '${packageName(i)}':`,
        `        specifier: ^${packageVersion(i)}`,
        `        version: ${packageVersion(i)}`,
      )
    }
  }
  out.push('', 'packages:', '')
  const lines = new Map<string, number>()
  for (let i = 0; i < count; i++) {
    const key = `${packageName(i)}@${packageVersion(i)}`
    lines.set(key, out.length + 1)
    out.push(key.startsWith('@') ? `  '${key}':` : `  ${key}:`, `    resolution: {integrity: ${integrity(i)}}`)
    if (i % 50 === 0) out.push("    engines: {node: '>=18'}")
    out.push('')
  }
  out.push('snapshots:', '')
  for (let i = 0; i < count; i++) {
    const key = `${packageName(i)}@${packageVersion(i)}`
    const children = [2 * i + 1].filter(child => child < count && child >= 40)
    if (children.length === 0) {
      out.push(key.startsWith('@') ? `  '${key}': {}` : `  ${key}: {}`, '')
      continue
    }
    out.push(key.startsWith('@') ? `  '${key}':` : `  ${key}:`, '    dependencies:')
    for (const child of children) out.push(`      '${packageName(child)}': ${packageVersion(child)}`)
    out.push('')
  }
  return { content: `${out.join('\n')}\n`, lines }
}

/** A package-lock v3 with `count` packages, and the line of each package's `node_modules/` key. */
function packageLock(count: number): { content: string; lines: Map<string, number> } {
  const packages: Record<string, unknown> = {
    '': {
      name: 'big',
      version: '1.0.0',
      dependencies: Object.fromEntries(Array.from({ length: 20 }, (_, i) => [packageName(i), `^${packageVersion(i)}`])),
    },
  }
  for (let i = 0; i < count; i++) {
    const child = 2 * i + 1
    packages[`node_modules/${packageName(i)}`] = {
      version: packageVersion(i),
      resolved: `https://registry.npmjs.org/${packageName(i)}/-/pkg-${packageVersion(i)}.tgz`,
      integrity: integrity(i),
      ...(i >= 20 && i % 3 === 0 ? { dev: true } : {}),
      ...(child < count ? { dependencies: { [packageName(child)]: `^${packageVersion(child)}` } } : {}),
    }
  }
  const content = `${JSON.stringify({ name: 'big', version: '1.0.0', lockfileVersion: 3, requires: true, packages }, null, 2)}\n`
  const lines = new Map<string, number>()
  content.split('\n').forEach((line, i) => {
    const key = /^ {4}"node_modules\/(.+)": \{$/.exec(line)?.[1]
    if (key) lines.set(key, i + 1)
  })
  return { content, lines }
}

/** Run `parseDependencies` and count event-loop turns that happened meanwhile. */
async function timedParse(
  snapshot: Snapshot,
): Promise<{ ms: number; turns: number; result: Awaited<ReturnType<typeof parseDependencies>> }> {
  let turns = 0
  let running = true
  const spin = (): void => {
    if (!running) return
    turns++
    setImmediate(spin)
  }
  setImmediate(spin)
  const started = performance.now()
  const result = await parseDependencies(snapshot)
  const ms = performance.now() - started
  running = false
  return { ms, turns, result }
}

describe('large lock files', () => {
  for (const [name, generate] of [
    ['pnpm-lock.yaml', pnpmLock],
    ['package-lock.json', packageLock],
  ] as const) {
    it(`parses a ${PACKAGES}-package ${name} in well under the old quadratic time, yielding to the event loop`, async () => {
      const { content, lines } = generate(PACKAGES)
      const snapshot = snapshotOf({ [name]: content })
      // Best of three runs: the first one also pays for JIT warm-up of the parsers. Before the
      // line lookups were indexed, each of these took 8-10 s.
      let best = Number.POSITIVE_INFINITY
      for (let run = 0; run < 3; run++) {
        const { ms, turns, result } = await timedParse(snapshot)
        best = Math.min(best, ms)
        expect(turns).toBeGreaterThan(2)
        expect(result.warnings).toEqual([])
        expect(result.dependencies).toHaveLength(PACKAGES)
        const keyOf = (dep: Dependency): string =>
          name === 'package-lock.json' ? dep.name : `${dep.name}@${dep.version}`
        expect(result.dependencies.filter(dep => dep.line !== lines.get(keyOf(dep))).map(keyOf)).toEqual([])
        expect(result.dependencies.filter(dep => dep.direct)).toHaveLength(name === 'package-lock.json' ? 20 : 40)
      }
      // Typically 0.2-0.4 s locally; the bound leaves headroom for slow CI runners while still
      // catching a return to quadratic lookups (8-10 s).
      expect(best).toBeLessThan(2500)
    })
  }
})

// ---------------------------------------------------------------------------
// The line lookups the parsers used to do: a scan from the start of the file per needle.
// ---------------------------------------------------------------------------

function lineOf(content: string, index: number): number {
  return content.slice(0, index).split('\n').length
}

function oldFind(content: string, needle: string): number | undefined {
  const index = content.indexOf(needle)
  return index < 0 ? undefined : lineOf(content, index)
}

function oldFindLineStartingWith(content: string, prefix: string): number | undefined {
  let from = 0
  for (;;) {
    const index = content.indexOf(prefix, from)
    if (index < 0) return undefined
    const lineStart = content.lastIndexOf('\n', index - 1) + 1
    if (content.slice(lineStart, index).trim() === '') return lineOf(content, index)
    from = index + 1
  }
}

async function fixtureFiles(): Promise<{ path: string; content: string }[]> {
  const out: { path: string; content: string }[] = []
  const walk = async (dir: string): Promise<void> => {
    for (const entry of await readdir(dir, { withFileTypes: true })) {
      const abs = join(dir, entry.name)
      if (entry.isDirectory()) await walk(abs)
      else if (isDependencyFileName(entry.name)) out.push({ path: abs, content: await readFile(abs, 'utf8') })
    }
  }
  await walk(join(FIXTURES, 'deps'))
  await walk(join(FIXTURES, 'apps'))
  out.push({ path: REPO_LOCK, content: await readFile(REPO_LOCK, 'utf8') })
  return out
}

describe('LineIndex', () => {
  it('answers JSON lookups exactly like a scan from the start of the file', async () => {
    let checked = 0
    for (const { path, content } of await fixtureFiles()) {
      if (!path.endsWith('.json') && !path.endsWith('.lock')) continue
      if (!content.trimStart().startsWith('{')) continue
      const index = new LineIndex(content)
      for (const literal of new Set(content.match(/"(?:[^"\\]|\\.)*"/g))) {
        expect(index.find(literal), `${path} ${literal}`).toBe(oldFind(content, literal))
        expect(index.find(`${literal}:`), `${path} ${literal}:`).toBe(oldFind(content, `${literal}:`))
        checked++
      }
      expect(index.find('"no such key"')).toBeUndefined()
      expect(index.find('lockfileVersion')).toBe(oldFind(content, 'lockfileVersion'))
    }
    expect(checked).toBeGreaterThan(100)
  })

  it('finds the YAML keys the pnpm and yarn berry parsers look up on the same lines as before', async () => {
    let checked = 0
    for (const { path, content } of await fixtureFiles()) {
      if (!path.endsWith('pnpm-lock.yaml') && !path.endsWith('yarn.lock')) continue
      if (path.endsWith('yarn.lock') && !/^__metadata:/m.test(content)) continue
      const doc = parseYaml(content) as Record<string, unknown>
      const index = new LineIndex(content)
      const keys = path.endsWith('yarn.lock')
        ? Object.keys(doc).flatMap(header => [`"${header}"`, header])
        : Object.keys((doc.packages ?? {}) as Record<string, unknown>).flatMap(key => [key, `'${key}'`])
      for (const key of keys) {
        expect(index.yamlKey(key), `${path} ${key}`).toBe(oldFindLineStartingWith(content, key))
        checked++
      }
    }
    expect(checked).toBeGreaterThan(50)
  })

  it('matches whole YAML keys only, unlike the old prefix search', () => {
    const content = 'packages:\n  foo@1.0.0-beta.1:\n    x: 1\n  foo@1.0.0:\n    x: 1\n'
    expect(oldFindLineStartingWith(content, 'foo@1.0.0')).toBe(2)
    expect(new LineIndex(content).yamlKey('foo@1.0.0')).toBe(4)
  })
})

describe('readLockYaml', () => {
  const yamlParse = (text: string): unknown => parseYaml(text, { maxAliasCount: 100, uniqueKeys: false })

  it('equals the YAML library on real and generated lock files', async () => {
    const inputs = (await fixtureFiles())
      .filter(file => file.path.endsWith('.yaml') || /^__metadata:/m.test(file.content))
      .map(file => file.content)
    inputs.push(pnpmLock(300).content, inputs[0]!.replace(/\n/g, '\r\n'))
    expect(inputs.length).toBeGreaterThanOrEqual(5)
    for (const text of inputs) {
      const fast = await readLockYaml(text)
      expect(fast).toBeDefined()
      expect(fast).toEqual(yamlParse(text))
    }
  })

  it('equals the YAML library on the constructs it accepts', async () => {
    const text = [
      '# comment',
      'a: plain value',
      "'quoted '' key': 'single ''quoted'''",
      '"dq key": "say \\"hi\\" \\\\ there"',
      'num: 12',
      'neg: -3',
      'bools: {t: true, f: False, list: [x, \'y\', "z", 7]}',
      'empty: {}',
      'emptyList: []',
      'nothing:',
      'nested:',
      '  deeper:',
      '    url: https://example.com/a:b',
      '  seq:',
      '  - one',
      '  - two',
      '  after: 1',
      '  indentedSeq:',
      '    - three',
      'dup: 1',
      'dup: 2',
      'version: 1.2.3',
      'range: ^1.0.0 || >=2',
      '',
    ].join('\n')
    const fast = await readLockYaml(text)
    expect(fast).toBeDefined()
    expect(fast).toEqual(yamlParse(text))
  })

  it('leaves everything else to the YAML library', async () => {
    for (const text of [
      'a: &anchor 1\nb: *anchor\n',
      'a: |\n  block\n',
      'a: >\n  folded\n',
      '---\na: 1\n---\nb: 2\n',
      'a: 1 # trailing comment\n',
      'a:\n\tb: 1\n',
      'a: multi\n  line\n',
      'a: 1.5\n',
      'a: ~\n',
      'a: null\n',
      'a: !!str 1\n',
      'a: "unterminated\n',
      'a: {b: 1,\n  c: 2}\n',
      '? complex\n: key\n',
      'list:\n  - a: 1\n',
      '1: numeric key\n',
      '  indented: root\n',
      'a: "\\u0041"\n',
      '__proto__: x\n',
    ]) {
      expect(await readLockYaml(text), text).toBeUndefined()
    }
  })
})

describe('oversized lock files', () => {
  it('warns about lock files the snapshot left out for size, and falls back to package.json', async () => {
    const base = snapshotOf({ 'web/package.json': '{"dependencies":{"left-pad":"1.3.0"}}' })
    const snapshot: Snapshot = {
      ...base,
      excluded: [
        { path: 'web/pnpm-lock.yaml', reason: 'too-large' },
        { path: 'assets/data.json', reason: 'too-large' },
        { path: 'api/poetry.lock', reason: 'gitignore' },
      ],
    }
    const { dependencies, warnings } = await parseDependencies(snapshot)
    expect(warnings).toEqual([
      'web/pnpm-lock.yaml: not analyzed, larger than the 32 MiB limit for dependency files; its dependencies are missing from this scan',
    ])
    expect(dependencies.map(dep => `${dep.name}@${dep.version} ${dep.manifest}`)).toEqual([
      'left-pad@1.3.0 web/package.json',
    ])
  })

  it('recognizes exactly the files the parser reads', () => {
    for (const name of [
      'package-lock.json',
      'npm-shrinkwrap.json',
      'pnpm-lock.yaml',
      'yarn.lock',
      'package.json',
      'poetry.lock',
      'uv.lock',
      'Pipfile.lock',
      'Cargo.lock',
      'go.mod',
      'requirements.txt',
      'requirements-dev.txt',
    ]) {
      expect(isDependencyFileName(name), name).toBe(true)
    }
    for (const name of ['package.json5', 'Package-Lock.json', 'pnpm-lock.yml', 'data.json', 'go.sum', 'reqs.txt']) {
      expect(isDependencyFileName(name), name).toBe(false)
    }
  })
})
