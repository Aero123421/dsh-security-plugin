import { mkdir, symlink, truncate, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { DEPENDENCY_FILE_MAX_BYTES } from '../../../src/host/analysis/dependencies.ts'
import {
  detectLanguage,
  isGeneratedContent,
  isTestPath,
  takeSnapshot,
  verifySnapshotFile,
} from '../../../src/host/analysis/snapshot.ts'
import type { SnapshotOptions } from '../../../src/host/analysis/types.ts'
import { makeTempDir, writeTree } from './helpers.ts'

const LIMITS: SnapshotOptions = {
  excludeGlobs: [],
  maxFiles: 10_000,
  maxFileBytes: 1024 * 1024,
  maxTotalBytes: 50 * 1024 * 1024,
}

/** File and directory symlinks need Developer Mode or admin rights on Windows; skip those tests without them. */
const canSymlink = await (async () => {
  const probe = await makeTempDir('dsh-symlink-probe-')
  try {
    await writeTree(probe.dir, { 'a.txt': 'x' })
    await symlink(join(probe.dir, 'a.txt'), join(probe.dir, 'b.txt'))
    await symlink(probe.dir, `${probe.dir}-dir-link`, 'dir')
    const { rm } = await import('node:fs/promises')
    await rm(`${probe.dir}-dir-link`, { force: true })
    return true
  } catch {
    return false
  } finally {
    await probe.cleanup()
  }
})()

function reasonOf(snapshot: Awaited<ReturnType<typeof takeSnapshot>>, path: string): string | undefined {
  return snapshot.excluded.find(entry => entry.path === path)?.reason
}

describe('takeSnapshot', () => {
  let dir: string
  let cleanup: () => Promise<void>

  beforeEach(async () => {
    ;({ dir, cleanup } = await makeTempDir())
  })
  afterEach(async () => {
    await cleanup()
  })

  it('captures text files with hashes, languages, and sorted POSIX paths', async () => {
    await writeTree(dir, {
      'src/b.ts': 'export const b = 1\n',
      'src/a.py': 'print("hi")\n',
      'README.md': '# readme\n',
    })
    const snapshot = await takeSnapshot(dir, LIMITS)
    expect([...snapshot.files.keys()]).toEqual(['README.md', 'src/a.py', 'src/b.ts'])
    const b = snapshot.files.get('src/b.ts')!
    expect(b.language).toBe('typescript')
    expect(b.size).toBe(19)
    expect(b.sha256).toMatch(/^[0-9a-f]{64}$/)
    expect(snapshot.totalBytes).toBe(19 + 12 + 9)
    expect(snapshot.truncated).toBe(false)
    expect(snapshot.root).toBe(snapshot.root.replace(/[\\/]$/, ''))
    expect(Number.isNaN(Date.parse(snapshot.takenAt))).toBe(false)
  })

  it('applies nested .gitignore files relative to their own directory', async () => {
    await writeTree(dir, {
      '.gitignore': '*.log\nsecret-dir/\n',
      'app.log': 'x',
      'keep.ts': 'x',
      'secret-dir/a.ts': 'x',
      'pkg/.gitignore': 'local.txt\n!important.log\n/rooted.ts\n',
      'pkg/local.txt': 'x',
      'pkg/important.log': 'x',
      'pkg/rooted.ts': 'x',
      'pkg/sub/rooted.ts': 'x',
      'local.txt': 'x',
    })
    const snapshot = await takeSnapshot(dir, LIMITS)
    const paths = [...snapshot.files.keys()]
    expect(paths).toContain('keep.ts')
    expect(paths).toContain('local.txt') // pkg/.gitignore does not reach the parent
    expect(paths).toContain('pkg/important.log') // re-included by the nested negation
    expect(paths).toContain('pkg/sub/rooted.ts') // `/rooted.ts` is anchored to pkg/
    expect(reasonOf(snapshot, 'app.log')).toBe('gitignore')
    expect(reasonOf(snapshot, 'secret-dir')).toBe('gitignore')
    expect(reasonOf(snapshot, 'pkg/local.txt')).toBe('gitignore')
    expect(reasonOf(snapshot, 'pkg/rooted.ts')).toBe('gitignore')
  })

  it('applies default ignores but keeps lock files', async () => {
    await writeTree(dir, {
      'node_modules/x/index.js': 'x',
      'dist/out.js': 'x',
      'web/vendor/lib.js': 'x',
      'app.min.js': 'x',
      'app.js.map': '{}',
      'venv/pyvenv.cfg': 'home = /usr',
      'venv/lib/site.py': 'x',
      'env/config.py': 'x', // not a virtualenv
      'package-lock.json': '{}',
      'pnpm-lock.yaml': 'lockfileVersion: 9.0\n',
      'yarn.lock': '',
      'requirements-dev.txt': 'pytest\n',
      'go.sum': '',
      '.git/HEAD': 'ref: refs/heads/main\n',
    })
    const snapshot = await takeSnapshot(dir, LIMITS)
    for (const path of ['node_modules', 'dist', 'web/vendor', 'app.min.js', 'app.js.map', 'venv', '.git']) {
      expect(reasonOf(snapshot, path), path).toBe('default-ignore')
    }
    for (const path of ['package-lock.json', 'pnpm-lock.yaml', 'yarn.lock', 'requirements-dev.txt', 'go.sum']) {
      expect(snapshot.files.has(path), path).toBe(true)
    }
    expect(snapshot.files.has('env/config.py')).toBe(true)
  })

  it('applies user exclude globs', async () => {
    await writeTree(dir, { 'docs/a.md': 'x', 'src/a.ts': 'x', 'src/gen/b.ts': 'x' })
    const snapshot = await takeSnapshot(dir, { ...LIMITS, excludeGlobs: ['docs/', 'src/gen/**'] })
    expect([...snapshot.files.keys()]).toEqual(['src/a.ts'])
    expect(reasonOf(snapshot, 'docs')).toBe('user-exclude')
  })

  it.skipIf(!canSymlink)('never follows symlinks, including ones pointing outside the root', async () => {
    const outside = await makeTempDir('dsh-outside-')
    try {
      await writeTree(outside.dir, { 'secret.txt': 'TOP SECRET' })
      await writeTree(dir, { 'real.ts': 'x' })
      await symlink(join(outside.dir, 'secret.txt'), join(dir, 'link.txt'))
      await symlink(outside.dir, join(dir, 'linkdir'), 'dir')
      await symlink(join(dir, 'real.ts'), join(dir, 'inside-link.ts'))
      const snapshot = await takeSnapshot(dir, LIMITS)
      expect([...snapshot.files.keys()]).toEqual(['real.ts'])
      expect(reasonOf(snapshot, 'link.txt')).toBe('symlink')
      expect(reasonOf(snapshot, 'linkdir')).toBe('symlink')
      expect(reasonOf(snapshot, 'inside-link.ts')).toBe('symlink')
      for (const file of snapshot.files.values()) expect(file.content).not.toContain('TOP SECRET')
    } finally {
      await outside.cleanup()
    }
  })

  it.skipIf(!canSymlink)('resolves a symlinked root to its real path', async () => {
    const link = `${dir}-link`
    await writeTree(dir, { 'a.ts': 'x' })
    await symlink(dir, link, 'dir')
    try {
      const snapshot = await takeSnapshot(link, LIMITS)
      expect(snapshot.files.has('a.ts')).toBe(true)
      expect(snapshot.root).not.toBe(link)
    } finally {
      const { rm } = await import('node:fs/promises')
      await rm(link, { force: true })
    }
  })

  it('rejects a root that is not a directory', async () => {
    await writeTree(dir, { 'file.txt': 'x' })
    await expect(takeSnapshot(join(dir, 'file.txt'), LIMITS)).rejects.toThrow(/not a directory/)
  })

  it('excludes binaries by extension and by NUL bytes', async () => {
    await writeTree(dir, {
      'logo.png': 'not really a png',
      'data.bin.txt': Buffer.from([0x61, 0x00, 0x62]),
      'lib.wasm': 'x',
      'ok.txt': 'fine',
    })
    const snapshot = await takeSnapshot(dir, LIMITS)
    expect([...snapshot.files.keys()]).toEqual(['ok.txt'])
    expect(reasonOf(snapshot, 'logo.png')).toBe('binary')
    expect(reasonOf(snapshot, 'data.bin.txt')).toBe('binary')
    expect(reasonOf(snapshot, 'lib.wasm')).toBe('binary')
  })

  it('excludes files over maxFileBytes', async () => {
    await writeTree(dir, { 'big.ts': 'x'.repeat(2000), 'small.ts': 'x' })
    const snapshot = await takeSnapshot(dir, { ...LIMITS, maxFileBytes: 1000 })
    expect(reasonOf(snapshot, 'big.ts')).toBe('too-large')
    expect(snapshot.files.has('small.ts')).toBe(true)
    expect(snapshot.truncated).toBe(false)
  })

  it('exempts dependency manifests and lock files from maxFileBytes up to their own ceiling', async () => {
    const lock = `${JSON.stringify({ lockfileVersion: 3, packages: { '': {}, pad: 'x'.repeat(3000) } })}\n`
    await writeTree(dir, {
      'package-lock.json': lock,
      'api/poetry.lock': `[[package]]\nname = "x"\nversion = "1.0.0"\n# ${'x'.repeat(3000)}\n`,
      'requirements-dev.txt': `pytest==8.0.0\n# ${'x'.repeat(3000)}\n`,
      // Same size, but not a file the dependency parser reads. (Another directory, so the name does not collide
      // with package-lock.json on case-insensitive file systems.)
      'data.json': lock,
      'other/Package-Lock.json': lock,
    })
    const snapshot = await takeSnapshot(dir, { ...LIMITS, maxFileBytes: 1000 })
    expect([...snapshot.files.keys()]).toEqual(['api/poetry.lock', 'package-lock.json', 'requirements-dev.txt'])
    expect(snapshot.totalBytes).toBe([...snapshot.files.values()].reduce((sum, file) => sum + file.size, 0))
    expect(reasonOf(snapshot, 'data.json')).toBe('too-large')
    expect(reasonOf(snapshot, 'other/Package-Lock.json')).toBe('too-large')
  })

  it('still excludes lock files over the dependency-file ceiling and counts lock files toward maxTotalBytes', async () => {
    await writeTree(dir, { 'a/yarn.lock': '', 'b/Cargo.lock': 'x'.repeat(5000), 'b/main.rs': 'fn main() {}\n' })
    // A sparse file: over the ceiling on disk without writing 32 MiB.
    await truncate(join(dir, 'a', 'yarn.lock'), DEPENDENCY_FILE_MAX_BYTES + 1)
    const snapshot = await takeSnapshot(dir, { ...LIMITS, maxFileBytes: 1000, maxTotalBytes: 4000 })
    expect(reasonOf(snapshot, 'a/yarn.lock')).toBe('too-large')
    expect(reasonOf(snapshot, 'b/Cargo.lock')).toBe('limit-bytes')
    expect(snapshot.truncated).toBe(true)
  })

  it('records an oversized lock file even when the excluded list is full', async () => {
    await writeTree(dir, {
      ...Object.fromEntries(Array.from({ length: 5005 }, (_, i) => [`m/b${String(i).padStart(4, '0')}.png`, 'x'])),
      'z/pnpm-lock.yaml': '',
    })
    await truncate(join(dir, 'z', 'pnpm-lock.yaml'), DEPENDENCY_FILE_MAX_BYTES + 1)
    const snapshot = await takeSnapshot(dir, LIMITS)
    expect(snapshot.excluded.filter(e => e.reason === 'binary')).toHaveLength(5000)
    expect(reasonOf(snapshot, 'z/pnpm-lock.yaml')).toBe('too-large')
  })

  it('stops at maxFiles and marks the snapshot truncated', async () => {
    await writeTree(dir, Object.fromEntries(Array.from({ length: 10 }, (_, i) => [`f${i}.ts`, 'x'])))
    const snapshot = await takeSnapshot(dir, { ...LIMITS, maxFiles: 3 })
    expect(snapshot.files.size).toBe(3)
    expect(snapshot.truncated).toBe(true)
    expect(snapshot.excluded.filter(e => e.reason === 'limit-files')).toHaveLength(1)
  })

  it('stops before exceeding maxTotalBytes', async () => {
    await writeTree(dir, { 'a.ts': 'x'.repeat(40), 'b.ts': 'x'.repeat(40), 'c.ts': 'x'.repeat(40) })
    const snapshot = await takeSnapshot(dir, { ...LIMITS, maxTotalBytes: 100 })
    expect(snapshot.files.size).toBe(2)
    expect(snapshot.totalBytes).toBe(80)
    expect(snapshot.truncated).toBe(true)
    expect(reasonOf(snapshot, 'c.ts')).toBe('limit-bytes')
  })

  it('strips a UTF-8 BOM from content but hashes the raw bytes', async () => {
    const raw = Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from('const a = 1\n')])
    await writeTree(dir, { 'bom.ts': raw })
    const snapshot = await takeSnapshot(dir, LIMITS)
    const file = snapshot.files.get('bom.ts')!
    expect(file.content).toBe('const a = 1\n')
    expect(file.size).toBe(raw.length)
    const { createHash } = await import('node:crypto')
    expect(file.sha256).toBe(createHash('sha256').update(raw).digest('hex'))
  })

  it('reads the HEAD commit from loose refs and packed-refs without running git', async () => {
    const sha = 'a'.repeat(40)
    await writeTree(dir, { '.git/HEAD': 'ref: refs/heads/main\n', '.git/refs/heads/main': `${sha}\n`, 'a.ts': 'x' })
    expect((await takeSnapshot(dir, LIMITS)).commit).toBe(sha)

    const packed = 'b'.repeat(40)
    await writeTree(dir, {
      '.git/HEAD': 'ref: refs/heads/dev\n',
      '.git/packed-refs': `# pack-refs with: peeled fully-peeled sorted\n${packed} refs/heads/dev\n`,
    })
    expect((await takeSnapshot(dir, LIMITS)).commit).toBe(packed)
  })

  it('follows a .git file pointing at a worktree gitdir', async () => {
    const gitDir = await makeTempDir('dsh-gitdir-')
    try {
      const sha = 'c'.repeat(40)
      await writeTree(gitDir.dir, { HEAD: `${sha}\n` })
      await writeTree(dir, { '.git': `gitdir: ${gitDir.dir}\n`, 'a.ts': 'x' })
      const snapshot = await takeSnapshot(dir, LIMITS)
      expect(snapshot.commit).toBe(sha)
      expect(reasonOf(snapshot, '.git')).toBe('default-ignore')
    } finally {
      await gitDir.cleanup()
    }
  })

  it('omits commit for a malformed .git directory', async () => {
    await writeTree(dir, { '.git/HEAD': 'ref: ../../etc/passwd\n', 'a.ts': 'x' })
    expect((await takeSnapshot(dir, LIMITS)).commit).toBeUndefined()
  })

  it('honors an aborted signal', async () => {
    await writeTree(dir, { 'a.ts': 'x' })
    const controller = new AbortController()
    controller.abort(new Error('stop'))
    await expect(takeSnapshot(dir, { ...LIMITS, signal: controller.signal })).rejects.toThrow('stop')
  })

  it('caps the excluded list', async () => {
    await mkdir(join(dir, 'imgs'))
    await Promise.all(Array.from({ length: 5100 }, (_, i) => writeFile(join(dir, 'imgs', `${i}.png`), '')))
    const snapshot = await takeSnapshot(dir, LIMITS)
    expect(snapshot.excluded.length).toBe(5000)
  })

  it('flags test and generated files', async () => {
    await writeTree(dir, {
      'src/app.test.ts': 'x',
      'bundle.js': `${'a'.repeat(1500)}\n`,
      'gen.go': '// Code generated by protoc-gen-go. DO NOT EDIT.\npackage x\n',
    })
    const snapshot = await takeSnapshot(dir, LIMITS)
    expect(snapshot.files.get('src/app.test.ts')!.isTest).toBe(true)
    expect(snapshot.files.get('bundle.js')!.isGenerated).toBe(true)
    expect(snapshot.files.get('gen.go')!.isGenerated).toBe(true)
  })
})

describe('verifySnapshotFile', () => {
  it('reports same, changed, and missing', async () => {
    const { dir, cleanup } = await makeTempDir()
    try {
      await writeTree(dir, { 'a.ts': 'one', 'b.ts': 'two' })
      const snapshot = await takeSnapshot(dir, LIMITS)
      const a = snapshot.files.get('a.ts')!
      const b = snapshot.files.get('b.ts')!
      expect(await verifySnapshotFile(dir, a)).toBe('same')
      await writeFile(join(dir, 'a.ts'), 'ONE')
      expect(await verifySnapshotFile(dir, a)).toBe('changed')
      const { rm } = await import('node:fs/promises')
      await rm(join(dir, 'b.ts'))
      expect(await verifySnapshotFile(dir, b)).toBe('missing')
      expect(await verifySnapshotFile(dir, { ...a, path: '../escape.ts' })).toBe('missing')
    } finally {
      await cleanup()
    }
  })
})

describe('detectLanguage', () => {
  it.each([
    ['a.ts', 'typescript'],
    ['a.tsx', 'typescript'],
    ['a.mts', 'typescript'],
    ['a.cjs', 'javascript'],
    ['a.jsx', 'javascript'],
    ['a.pyi', 'python'],
    ['Dockerfile', 'dockerfile'],
    ['Dockerfile.prod', 'dockerfile'],
    ['api.dockerfile', 'dockerfile'],
    ['.env', 'env'],
    ['.env.local', 'env'],
    ['main.tf', 'terraform'],
    ['App.vue', 'vue'],
    ['Page.svelte', 'svelte'],
    ['Gemfile', 'ruby'],
    ['a.yml', 'yaml'],
    ['LICENSE', 'other'],
    ['weird.', 'other'],
  ])('%s → %s', (path, language) => {
    expect(detectLanguage(path)).toBe(language)
  })
})

describe('isTestPath', () => {
  it.each([
    ['tests/a.py', true],
    ['src/__tests__/x.ts', true],
    ['pkg/testdata/in.json', true],
    ['examples/demo.js', true],
    ['src/__mocks__/fs.ts', true],
    ['src/app.test.ts', true],
    ['src/app.spec.tsx', true],
    ['test_views.py', true],
    ['views_test.py', true],
    ['handler_test.go', true],
    ['conftest.py', true],
    ['src/testing.ts', false],
    ['src/contest.py', false],
    ['src/latest/app.ts', false],
  ])('%s → %s', (path, expected) => {
    expect(isTestPath(path)).toBe(expected)
  })
})

describe('isGeneratedContent', () => {
  it('detects long lines only in JS/CSS', () => {
    const long = `${'x'.repeat(1200)}\n`
    expect(isGeneratedContent('a.js', long)).toBe(true)
    expect(isGeneratedContent('a.css', long)).toBe(true)
    expect(isGeneratedContent('a.py', long)).toBe(false)
  })

  it('detects generated-file header comments', () => {
    expect(isGeneratedContent('a.ts', '/* @generated */\nexport {}\n')).toBe(true)
    expect(isGeneratedContent('a.py', '# Code generated by tool. DO NOT EDIT.\n')).toBe(true)
    expect(isGeneratedContent('a.ts', 'const msg = "DO NOT EDIT"\n')).toBe(false)
  })
})
