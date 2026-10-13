/**
 * A real `Toolkit` whose managed Gitleaks is a test script: the script is
 * "installed" in the toolkit directory with a matching `installed.json`, so
 * the Host resolves and runs it exactly like a verified download.
 */

import { createHash } from 'node:crypto'
import { chmod, mkdir, readFile, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { platformKey, Toolkit, type ToolkitLock } from '../../../src/host/analysis/toolkit.ts'

const GITLEAKS_VERSION = '8.21.2'
const PINNED = 'a'.repeat(64)

/** A lock with a pinned Gitleaks and OSV-Scanner for this platform (the URLs are never reachable). */
export function testLock(): ToolkitLock {
  const asset = (name: string) => ({
    url: `https://example.invalid/${name}.tar.gz`,
    sha256: PINNED,
    size: 1024,
    archive: 'tar.gz' as const,
    binary: name,
  })
  return {
    schemaVersion: 1,
    tools: {
      gitleaks: {
        name: 'Gitleaks',
        version: GITLEAKS_VERSION,
        license: 'MIT',
        homepage: 'https://github.com/gitleaks/gitleaks',
        assets: { [platformKey()]: asset('gitleaks') },
      },
      'osv-scanner': {
        name: 'OSV-Scanner',
        version: '2.0.0',
        license: 'Apache-2.0',
        homepage: 'https://github.com/google/osv-scanner',
        assets: { [platformKey()]: asset('osv-scanner') },
      },
    },
  }
}

/**
 * Install `script` (a Node.js program) as the managed Gitleaks under
 * `<dataDir>/toolkit` and return a Toolkit over that directory. POSIX only.
 */
export async function fakeGitleaksToolkit(
  dataDir: string,
  script: string,
  options: { readonly fetch?: typeof fetch; readonly allowManagedInstall?: boolean } = {},
): Promise<Toolkit> {
  const dir = join(dataDir, 'toolkit')
  const versionDir = join(dir, 'gitleaks', GITLEAKS_VERSION)
  await mkdir(versionDir, { recursive: true })
  const program = join(versionDir, 'fake-gitleaks.cjs')
  await writeFile(program, script)
  const binary = join(versionDir, 'gitleaks')
  await writeFile(binary, `#!/bin/sh\nexec "${process.execPath}" "${program}" "$@"\n`)
  await chmod(binary, 0o755)
  const binarySha256 = createHash('sha256')
    .update(await readFile(binary))
    .digest('hex')
  await writeFile(
    join(versionDir, 'installed.json'),
    JSON.stringify({
      id: 'gitleaks',
      version: GITLEAKS_VERSION,
      binary: 'gitleaks',
      assetSha256: PINNED,
      binarySha256,
      installedAt: new Date().toISOString(),
    }),
  )
  return new Toolkit({
    dir,
    lock: testLock(),
    allowManagedInstall: options.allowManagedInstall ?? true,
    fetch:
      options.fetch ??
      (async () => {
        throw new Error('network access is disabled in tests')
      }),
  })
}

/**
 * Source of a fake Gitleaks that writes `findings` (paths relative to the
 * scanned root, which is the last argument) to `--report-path`.
 */
export function gitleaksReporting(
  findings: readonly { file: string; line: number; ruleId: string; text: string }[],
): string {
  return `const fs = require('node:fs')
const path = require('node:path')
const args = process.argv.slice(2)
const report = args[args.indexOf('--report-path') + 1]
const root = args[args.length - 1]
const findings = ${JSON.stringify(findings)}
fs.writeFileSync(report, JSON.stringify(findings.map(f => ({
  RuleID: f.ruleId, Description: f.ruleId, File: path.join(root, f.file),
  StartLine: f.line, EndLine: f.line, Match: f.text, Line: f.text,
}))))
`
}

/** Source of a fake Gitleaks that fails with `stderr`. */
export function gitleaksFailing(stderr: string): string {
  return `process.stderr.write(${JSON.stringify(`${stderr}\n`)}); process.exit(2)\n`
}
