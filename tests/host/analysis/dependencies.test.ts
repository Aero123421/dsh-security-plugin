import { readdir, readFile } from 'node:fs/promises'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'
import { normalizePypiName, parseDependencies } from '../../../src/host/analysis/dependencies.ts'
import type { Dependency } from '../../../src/host/analysis/types.ts'
import { snapshotOf } from './helpers.ts'

const FIXTURES = fileURLToPath(new URL('../../fixtures/deps/', import.meta.url))

/** Load one fixture directory as a snapshot rooted at that directory. */
async function fixture(name: string): Promise<ReturnType<typeof snapshotOf>> {
  const dir = join(FIXTURES, name)
  const files: Record<string, string> = {}
  for (const entry of await readdir(dir)) files[entry] = await readFile(join(dir, entry), 'utf8')
  return snapshotOf(files, dir)
}

function pick(deps: readonly Dependency[], name: string): Dependency[] {
  return deps.filter(dep => dep.name === name)
}

function summary(dep: Dependency): string {
  return `${dep.name}@${dep.version}${dep.exact ? '' : ' (range)'}${dep.direct ? ' direct' : ''}${dep.dev ? ' dev' : ''}`
}

describe('npm', () => {
  it('parses package-lock v1 nested dependencies', async () => {
    const { dependencies, warnings } = await parseDependencies(await fixture('npm-v1'))
    expect(warnings).toEqual([])
    expect(dependencies.map(summary)).toEqual([
      'debug@3.1.0 dev',
      'lodash@4.17.11 direct',
      'mocha@5.2.0 direct dev',
      'ms@2.0.0 dev',
    ])
    expect(dependencies.every(dep => dep.manifest === 'package-lock.json' && dep.ecosystem === 'npm')).toBe(true)
    expect(pick(dependencies, 'lodash')[0]!.line).toBe(7)
  })

  it('parses package-lock v3 packages including nested and scoped, skipping links', async () => {
    const { dependencies, warnings } = await parseDependencies(await fixture('npm-v3'))
    expect(warnings).toEqual([])
    expect(dependencies.map(summary)).toEqual([
      '@types/node@20.11.0 direct',
      'body-parser@1.20.1',
      'express@4.18.2 direct',
      'qs@6.11.0',
      'vitest@1.2.0 direct dev',
    ])
  })

  it('parses pnpm v6 lock files', async () => {
    const { dependencies, warnings } = await parseDependencies(await fixture('pnpm-v6'))
    expect(warnings).toEqual([])
    expect(dependencies.map(summary)).toEqual([
      '@babel/core@7.23.0 dev',
      'react@18.2.0',
      'react-dom@18.2.0 direct',
      'typescript@5.3.3 direct dev',
    ])
    expect(pick(dependencies, 'react-dom')[0]!.line).toBe(19)
  })

  it('parses pnpm v9 lock files and derives dev from snapshots', async () => {
    const { dependencies, warnings } = await parseDependencies(await fixture('pnpm-v9'))
    expect(warnings).toEqual([])
    expect(dependencies.map(summary)).toEqual([
      '@vitest/runner@1.0.4 direct dev',
      'axios@1.6.2 direct',
      'follow-redirects@1.15.3',
      'p-limit@5.0.0 dev',
    ])
  })

  it('parses yarn classic lock files', async () => {
    const { dependencies, warnings } = await parseDependencies(await fixture('yarn-v1'))
    expect(warnings).toEqual([])
    expect(dependencies.map(summary)).toEqual([
      '@babel/code-frame@7.12.13 direct dev',
      'minimist@0.0.10',
      'minimist@1.2.5 direct',
    ])
    expect(pick(dependencies, 'minimist').find(d => d.version === '1.2.5')!.line).toBe(12)
  })

  it('parses yarn berry lock files and skips workspace entries', async () => {
    const { dependencies, warnings } = await parseDependencies(await fixture('yarn-berry'))
    expect(warnings).toEqual([])
    expect(dependencies.map(summary)).toEqual(['@scope/pkg@1.0.0', 'lodash@4.17.21 direct'])
  })

  it('falls back to package.json ranges when no lock exists', async () => {
    const { dependencies } = await parseDependencies(await fixture('pkg-only'))
    expect(dependencies.map(summary)).toEqual([
      'chalk@^5.0.0 (range) direct',
      'eslint@~8.50.0 (range) direct dev',
      'left-pad@1.3.0 direct',
    ])
    expect(dependencies.every(dep => dep.manifest === 'package.json')).toBe(true)
  })

  it('ignores package.json when a sibling lock exists', async () => {
    const { dependencies } = await parseDependencies(await fixture('npm-v3'))
    expect(dependencies.some(dep => dep.manifest === 'package.json')).toBe(false)
  })
})

describe('Python', () => {
  it('parses requirements files', async () => {
    const { dependencies, warnings } = await parseDependencies(await fixture('python'))
    // The fixture references an absent base.txt; coverage loss is now explicit.
    expect(warnings).toEqual(["requirements.txt: line 2: requirement include 'base.txt' is missing from the snapshot"])
    expect(dependencies.map(dep => `${summary(dep)} [${dep.manifest}:${dep.line}]`)).toEqual([
      'cryptography@41.0.5 direct [requirements.txt:11]',
      'django@4.2.7 direct [requirements.txt:4]',
      'flask@>=2.0,<3 (range) direct [requirements.txt:6]',
      'numpy@==1.26.* (range) direct [requirements.txt:10]',
      'pytest@7.4.3 direct dev [requirements-dev.txt:1]',
      'pyyaml@* (range) direct [requirements.txt:8]',
      'requests@2.31.0 direct [requirements.txt:5]',
      'zope-interface@6.1 direct [requirements.txt:7]',
    ])
  })

  it('parses poetry.lock with category and normalized names', async () => {
    const { dependencies } = await parseDependencies(await fixture('poetry'))
    expect(dependencies.map(summary)).toEqual(['jinja2@3.1.2', 'markupsafe@2.1.3', 'pytest@7.4.3 dev'])
    expect(pick(dependencies, 'jinja2')[0]!.line).toBe(3)
  })

  it('parses poetry 1.5+ groups', async () => {
    const lock =
      '[[package]]\nname = "ruff"\nversion = "0.1.0"\ngroups = ["lint"]\n\n[[package]]\nname = "attrs"\nversion = "23.1.0"\ngroups = ["main", "dev"]\n'
    const { dependencies } = await parseDependencies(snapshotOf({ 'poetry.lock': lock }))
    expect(dependencies.map(summary)).toEqual(['attrs@23.1.0', 'ruff@0.1.0 dev'])
  })

  it('parses Pipfile.lock default and develop sections', async () => {
    const { dependencies } = await parseDependencies(await fixture('pipfile'))
    expect(dependencies.map(summary)).toEqual(['black@23.11.0 dev', 'urllib3@1.26.5'])
  })

  it('parses uv.lock and skips the editable project itself', async () => {
    const { dependencies } = await parseDependencies(await fixture('uv'))
    expect(dependencies.map(summary)).toEqual(['anyio@4.2.0', 'pillow@10.1.0'])
  })

  it('normalizes PyPI names per PEP 503', () => {
    expect(normalizePypiName('Zope.Interface')).toBe('zope-interface')
    expect(normalizePypiName('typing__extensions')).toBe('typing-extensions')
    expect(normalizePypiName('A-_.B')).toBe('a-b')
  })
})

describe('Go and Rust', () => {
  it('parses go.mod require lines', async () => {
    const { dependencies } = await parseDependencies(await fixture('go'))
    expect(dependencies.map(dep => `${summary(dep)} :${dep.line}`)).toEqual([
      'github.com/gin-gonic/gin@v1.9.1 direct :5',
      'github.com/golang-jwt/jwt/v4@v4.5.0 direct :9',
      'golang.org/x/net@v0.17.0 :8',
    ])
  })

  it('parses Cargo.lock registry packages only', async () => {
    const { dependencies } = await parseDependencies(await fixture('cargo'))
    expect(dependencies.map(summary)).toEqual(['serde@1.0.193', 'time@0.1.45'])
    expect(dependencies.every(dep => dep.ecosystem === 'crates.io')).toBe(true)
  })
})

describe('robustness', () => {
  it('turns malformed files into warnings', async () => {
    const { dependencies, warnings } = await parseDependencies(
      snapshotOf({
        'a/package-lock.json': '{ "lockfileVersion": 3, "packages": {',
        'b/pnpm-lock.yaml': "lockfileVersion: '9.0'\npackages:\n  foo@1.0.0: [unclosed\n",
        'c/Pipfile.lock': '[]',
        'd/poetry.lock': 'not toml at all',
        'e/go.mod': 'module x\n',
      }),
    )
    expect(dependencies).toEqual([])
    expect(warnings).toHaveLength(4)
    expect(warnings.find(w => w.startsWith('a/package-lock.json'))).toMatch(/invalid JSON/)
    expect(warnings.find(w => w.startsWith('b/pnpm-lock.yaml'))).toMatch(/invalid YAML/)
  })

  it('de-duplicates identical entries and merges direct/dev flags', async () => {
    const lock = 'requests==2.31.0\nrequests==2.31.0\n'
    const { dependencies } = await parseDependencies(snapshotOf({ 'requirements.txt': lock }))
    expect(dependencies).toHaveLength(1)
    expect(dependencies[0]!.line).toBe(1)
  })
})
