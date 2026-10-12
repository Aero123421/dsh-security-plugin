import { createHash } from 'node:crypto'
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { detectLanguage, isGeneratedContent, isTestPath } from '../../../src/host/analysis/snapshot.ts'
import type { Snapshot, SnapshotFile } from '../../../src/host/analysis/types.ts'

/** Create a temp directory and return it with a cleanup function. */
export async function makeTempDir(prefix = 'dsh-analysis-'): Promise<{ dir: string; cleanup: () => Promise<void> }> {
  const dir = await mkdtemp(join(tmpdir(), prefix))
  return { dir, cleanup: () => rm(dir, { recursive: true, force: true }) }
}

/** Write a tree of files (`relative path → content`) under `root`. */
export async function writeTree(root: string, files: Record<string, string | Buffer>): Promise<void> {
  for (const [rel, content] of Object.entries(files)) {
    const abs = join(root, ...rel.split('/'))
    await mkdir(dirname(abs), { recursive: true })
    await writeFile(abs, content)
  }
}

/** Build a snapshot file from text, without touching the disk. */
export function fileOf(path: string, content: string, overrides: Partial<SnapshotFile> = {}): SnapshotFile {
  const bytes = Buffer.from(content, 'utf8')
  return {
    path,
    size: bytes.length,
    sha256: createHash('sha256').update(bytes).digest('hex'),
    language: detectLanguage(path),
    content,
    isTest: isTestPath(path),
    isGenerated: isGeneratedContent(path, content),
    ...overrides,
  }
}

/** Build an in-memory snapshot from `path → content`. */
export function snapshotOf(files: Record<string, string>, root = '/workspace'): Snapshot {
  const list = Object.entries(files).map(([path, content]) => fileOf(path, content))
  return {
    root,
    files: new Map(list.map(file => [file.path, file])),
    excluded: [],
    totalBytes: list.reduce((sum, file) => sum + file.size, 0),
    truncated: false,
    takenAt: new Date(0).toISOString(),
  }
}
