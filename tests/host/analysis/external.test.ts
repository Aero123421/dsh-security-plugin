import { chmod, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { parseGitleaksReport, runGitleaks } from '../../../src/host/analysis/external/gitleaks.ts'
import { findExecutable, parseVersion, probeVersion } from '../../../src/host/analysis/external/locate.ts'
import { parseOsvScannerReport, runOsvScanner } from '../../../src/host/analysis/external/osv-scanner.ts'
import { runTool, scrubbedEnv } from '../../../src/host/analysis/external/process.ts'
import { parseSemgrepOutput, runSemgrep } from '../../../src/host/analysis/external/semgrep.ts'
import { Redactor, scanSecrets } from '../../../src/host/analysis/secrets.ts'
import { makeTempDir, snapshotOf } from './helpers.ts'

const NODE = process.execPath
const isPosix = process.platform !== 'win32'

function isAlive(pid: number): boolean {
  try {
    process.kill(pid, 0)
    return true
  } catch {
    return false
  }
}

async function waitFor(check: () => boolean, timeoutMs = 5000): Promise<boolean> {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    if (check()) return true
    await new Promise(resolve => setTimeout(resolve, 50))
  }
  return check()
}

describe('runTool', () => {
  it('captures stdout, stderr, and the exit code without a shell', async () => {
    const result = await runTool(
      NODE,
      ['-e', 'process.stdout.write("out $HOME"); process.stderr.write("err"); process.exit(3)'],
      { cwd: tmpdir(), timeoutMs: 10_000, maxOutputBytes: 1024 },
    )
    expect(result).toMatchObject({ code: 3, stdout: 'out $HOME', stderr: 'err', timedOut: false, truncated: false })
  })

  it('passes arguments verbatim (no shell interpretation)', async () => {
    const tricky = '$(touch /tmp/pwned); `id` && echo "x" | cat'
    const result = await runTool(NODE, ['-e', 'process.stdout.write(process.argv[1])', tricky], {
      cwd: tmpdir(),
      timeoutMs: 10_000,
      maxOutputBytes: 1024,
    })
    expect(result.stdout).toBe(tricky)
  })

  it('scrubs the environment down to the allowlist plus explicit additions', async () => {
    process.env.DSH_TEST_SECRET_TOKEN = 'should-not-leak'
    try {
      const result = await runTool(NODE, ['-e', 'process.stdout.write(JSON.stringify(Object.keys(process.env)))'], {
        cwd: tmpdir(),
        timeoutMs: 10_000,
        maxOutputBytes: 64 * 1024,
        env: { EXTRA_FLAG: '1' },
      })
      const keys = JSON.parse(result.stdout) as string[]
      expect(keys).toContain('EXTRA_FLAG')
      expect(keys).not.toContain('DSH_TEST_SECRET_TOKEN')
      expect(keys).not.toContain('NODE_OPTIONS')
      expect(
        Object.keys(scrubbedEnv()).every(k =>
          /^(PATH|HOME|USERPROFILE|SystemRoot|SYSTEMROOT|TEMP|TMP|TMPDIR|LANG)$/.test(k),
        ),
      ).toBe(true)
    } finally {
      delete process.env.DSH_TEST_SECRET_TOKEN
    }
  })

  it('caps captured output', async () => {
    const result = await runTool(NODE, ['-e', 'process.stdout.write("x".repeat(100000))'], {
      cwd: tmpdir(),
      timeoutMs: 10_000,
      maxOutputBytes: 1000,
    })
    expect(result.stdout).toHaveLength(1000)
    expect(result.truncated).toBe(true)
  })

  it.runIf(isPosix)('kills the whole process tree on timeout', async () => {
    // The child spawns a long-lived grandchild, prints its pid, then hangs.
    const script = `
      const { spawn } = require('node:child_process')
      const g = spawn(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], { stdio: 'ignore' })
      process.stdout.write(String(g.pid))
      setInterval(() => {}, 1000)
    `
    const started = Date.now()
    const result = await runTool(NODE, ['-e', script], { cwd: tmpdir(), timeoutMs: 500, maxOutputBytes: 1024 })
    expect(result.timedOut).toBe(true)
    expect(result.code).toBeNull()
    expect(Date.now() - started).toBeLessThan(8000)
    const grandchild = Number(result.stdout)
    expect(grandchild).toBeGreaterThan(0)
    expect(await waitFor(() => !isAlive(grandchild))).toBe(true)
  })

  it.runIf(isPosix)('escalates to SIGKILL when SIGTERM is ignored', async () => {
    const script = 'process.on("SIGTERM", () => {}); process.stdout.write("ready"); setInterval(() => {}, 1000)'
    const result = await runTool(NODE, ['-e', script], { cwd: tmpdir(), timeoutMs: 300, maxOutputBytes: 1024 })
    expect(result.timedOut).toBe(true)
    expect(result.signal).toBe('SIGKILL')
  })

  it('kills the child and rejects with the abort reason', async () => {
    const controller = new AbortController()
    const promise = runTool(NODE, ['-e', 'process.stdout.write(String(process.pid)); setInterval(() => {}, 1000)'], {
      cwd: tmpdir(),
      timeoutMs: 30_000,
      maxOutputBytes: 1024,
      signal: controller.signal,
    })
    setTimeout(() => controller.abort(new Error('user cancelled')), 300)
    await expect(promise).rejects.toThrow('user cancelled')
  })

  it('rejects immediately when already aborted, and on spawn errors', async () => {
    const controller = new AbortController()
    controller.abort(new Error('nope'))
    await expect(
      runTool(NODE, ['-e', ''], { cwd: tmpdir(), timeoutMs: 1000, maxOutputBytes: 10, signal: controller.signal }),
    ).rejects.toThrow('nope')
    await expect(
      runTool('/definitely/not/a/binary', [], { cwd: tmpdir(), timeoutMs: 1000, maxOutputBytes: 10 }),
    ).rejects.toMatchObject({ code: 'ENOENT' })
  })
})

describe('locate', () => {
  let dir: string
  let cleanup: () => Promise<void>
  beforeEach(async () => {
    ;({ dir, cleanup } = await makeTempDir())
  })
  afterEach(async () => {
    await cleanup()
  })

  it.runIf(isPosix)('finds executables in extra dirs before PATH and skips non-executables', async () => {
    const tool = join(dir, 'mytool')
    await writeFile(tool, '#!/bin/sh\necho mytool v1.2.3\n')
    expect(await findExecutable('mytool', [dir])).toBeUndefined()
    await chmod(tool, 0o755)
    expect(await findExecutable('mytool', [dir])).toBe(tool)
    expect(await findExecutable('mytool', ['relative/dir'])).toBeUndefined()
    expect(await findExecutable('../mytool', [dir])).toBeUndefined()
    expect(await findExecutable('node', [])).toBeDefined()
    expect(await probeVersion(tool, ['--version'])).toBe('1.2.3')
  })

  it('parses versions from tool output', () => {
    expect(parseVersion('gitleaks version v8.28.0')).toBe('8.28.0')
    expect(parseVersion('osv-scanner version: 2.2.2\ncommit: abc')).toBe('2.2.2')
    expect(parseVersion('1.95.0')).toBe('1.95.0')
    expect(parseVersion('no version here')).toBeUndefined()
  })
})

/** A fake tool: a Node script launched through a tiny POSIX wrapper. */
async function fakeTool(dir: string, name: string, body: string): Promise<string> {
  const script = join(dir, `${name}.cjs`)
  await writeFile(script, body)
  const wrapper = join(dir, name)
  await writeFile(wrapper, `#!/bin/sh\nexec "${NODE}" "${script}" "$@"\n`)
  await chmod(wrapper, 0o755)
  return wrapper
}

describe('gitleaks', () => {
  const root = '/repo'

  it('parses a report into redacted secret signals', () => {
    const warnings: string[] = []
    const signals = parseGitleaksReport(
      [
        {
          RuleID: 'github-pat',
          Description: 'GitHub Personal Access Token',
          File: '/repo/src/config.ts',
          StartLine: 3,
          EndLine: 3,
          Match: 'token = "REDACTED"',
          Line: `const token = "${['ghp', '_', 'aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA5'].join('')}"`,
          Secret: 'REDACTED',
          Entropy: 4.81,
          Tags: [],
        },
        { RuleID: 'generic-api-key', File: '/elsewhere/x.ts', StartLine: 1, EndLine: 1, Match: 'x' },
        { not: 'a finding' },
      ],
      { root },
      warnings,
    )
    expect(signals).toHaveLength(1)
    expect(signals[0]).toMatchObject({
      analyzer: 'gitleaks',
      kind: 'secret',
      category: 'secrets',
      cwe: 'CWE-798',
      ruleId: 'github-pat',
      location: { path: 'src/config.ts', startLine: 3, endLine: 3 },
      snippet: 'const token = "[REDACTED:github-token]"',
    })
    expect(warnings).toEqual(['1 gitleaks findings had an unexpected shape and were skipped'])
    expect(parseGitleaksReport({}, { root }, warnings)).toEqual([])
  })

  it('drops findings for files outside the snapshot', () => {
    const snapshot = snapshotOf({ 'src/a.ts': 'x' }, root)
    const signals = parseGitleaksReport(
      [{ RuleID: 'r', File: 'node_modules/x/a.js', StartLine: 1, EndLine: 1, Match: 'x' }],
      { root, snapshot },
      [],
    )
    expect(signals).toEqual([])
  })

  it.runIf(isPosix)('stops a tool whose report exceeds the cap while still running', async () => {
    const { dir, cleanup } = await makeTempDir()
    try {
      const tool = await fakeTool(
        dir,
        'oversized-gitleaks',
        `
        const fs = require('node:fs')
        const args = process.argv.slice(2)
        const report = args[args.indexOf('--report-path') + 1]
        const fd = fs.openSync(report, 'w')
        fs.ftruncateSync(fd, 128 * 1024 * 1024 + 1)
        fs.closeSync(fd)
        process.on('SIGTERM', () => {})
        setInterval(() => {}, 1000)
      `,
      )
      const start = Date.now()
      const run = await runGitleaks({
        root: dir,
        tool: { path: tool, source: 'path', version: '8.30.1' },
        timeoutMs: 10_000,
      })
      expect(run.signals).toEqual([])
      expect(run.status.reason).toMatch(/report.*size limit/)
      expect(Date.now() - start).toBeLessThan(5000)
    } finally {
      await cleanup()
    }
  })

  it('reports unavailable when no tool is resolved', async () => {
    const run = await runGitleaks({ tool: undefined, root })
    expect(run.status).toMatchObject({ id: 'gitleaks', available: false })
    expect(run.signals).toEqual([])
  })

  it.runIf(isPosix)('runs the dir subcommand with a plugin config and reads the report', async () => {
    const { dir, cleanup } = await makeTempDir()
    try {
      const argsFile = join(dir, 'args.json')
      const tool = await fakeTool(
        dir,
        'gitleaks',
        `
        const fs = require('node:fs')
        const args = process.argv.slice(2)
        fs.writeFileSync(${JSON.stringify(argsFile)}, JSON.stringify(args))
        const report = args[args.indexOf('--report-path') + 1]
        fs.writeFileSync(report, JSON.stringify([{ RuleID: 'aws-access-token', Description: 'AWS', File: ${JSON.stringify(`${dir}/src/a.ts`)}, StartLine: 2, EndLine: 2, Match: 'REDACTED', Line: 'key = REDACTED' }]))
        `,
      )
      const run = await runGitleaks({ tool: { path: tool, source: 'path', version: '8.28.0' }, root: dir })
      expect(run.status).toMatchObject({ id: 'gitleaks', available: true, source: 'path', version: '8.28.0' })
      expect(run.signals.map(s => s.location.path)).toEqual(['src/a.ts'])
      const { readFile } = await import('node:fs/promises')
      const args = JSON.parse(await readFile(argsFile, 'utf8')) as string[]
      expect(args[0]).toBe('dir')
      expect(args).toContain('--redact')
      expect(args).toContain('--ignore-gitleaks-allow')
      expect(args).not.toContain('git')
      expect(args).toContain('--no-banner')
      expect(args[args.indexOf('--exit-code') + 1]).toBe('0')
      expect(args[args.indexOf('--config') + 1]).toMatch(/gitleaks\.toml$/)
      expect(args.at(-1)).toBe(dir)

      const legacy = await runGitleaks({ tool: { path: tool, source: 'path', version: '8.18.4' }, root: dir })
      expect(legacy.status.available).toBe(true)
      const legacyArgs = JSON.parse(await readFile(argsFile, 'utf8')) as string[]
      expect(legacyArgs.slice(0, 4)).toEqual(['detect', '--no-git', '--source', dir])
    } finally {
      await cleanup()
    }
  })

  it.runIf(isPosix)('reports failure on a non-zero exit', async () => {
    const { dir, cleanup } = await makeTempDir()
    try {
      const tool = await fakeTool(dir, 'gitleaks', 'process.stderr.write("boom\\n"); process.exit(2)')
      const run = await runGitleaks({ tool: { path: tool, source: 'managed', version: '8.28.0' }, root: dir })
      expect(run.status).toMatchObject({ available: false, source: 'managed' })
      expect(run.status.reason).toMatch(/boom/)
    } finally {
      await cleanup()
    }
  })
})

describe('osv-scanner', () => {
  const report = (root: string) => ({
    results: [
      {
        source: { path: `${root}/package-lock.json`, type: 'lockfile' },
        packages: [
          {
            package: { name: 'minimist', version: '1.2.5', ecosystem: 'npm' },
            vulnerabilities: [
              {
                id: 'GHSA-xvch-5gv4-984h',
                summary: 'Prototype Pollution in minimist',
                aliases: ['CVE-2021-44906'],
                database_specific: { severity: 'CRITICAL' },
                affected: [
                  {
                    package: { ecosystem: 'npm', name: 'minimist' },
                    ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '1.2.6' }] }],
                  },
                ],
              },
            ],
          },
        ],
      },
    ],
  })

  it.runIf(isPosix)(
    'stages only non-withheld snapshot manifests, preserves npm/pnpm/requirements layout and maps paths back',
    async () => {
      const { dir, cleanup } = await makeTempDir()
      try {
        const capture = join(dir, 'capture.json')
        // Excluded live files must not be available to the scanner, even when they were added after the snapshot.
        await writeFile(join(dir, 'requirements.txt'), 'excluded-live-package==99.0.0')
        const contents = {
          'apps/web/package.json': '{"dependencies":{"public-npm":"1.0.0"}}',
          'apps/web/package-lock.json':
            '{"lockfileVersion":3,"packages":{"node_modules/public-npm":{"version":"1.0.0"}}}',
          'apps/pnpm/pnpm-lock.yaml': "lockfileVersion: '9.0'\npackages:\n  public-pnpm@1.0.0: {}\n",
          'apps/python/requirements.txt': 'public-python==1.0.0',
          'private/package-lock.json': '{"private-package":"9.0.0"}',
          '.aws/config': 'credential-package',
          'apps/web/osv-scanner.toml': '[[IgnoredVulns]]',
          'apps/web/source.ts': 'source-never-staged',
        }
        const tool = await fakeTool(
          dir,
          'osv-scanner',
          `
        const fs = require('node:fs'), path = require('node:path')
        const args = process.argv.slice(2), root = args.at(-1), files = {}
        function walk(dir) { for (const entry of fs.readdirSync(dir, {withFileTypes:true})) {
          const p = path.join(dir, entry.name)
          if (entry.isDirectory()) walk(p); else files[path.relative(root,p).replaceAll('\\\\','/')] = fs.readFileSync(p,'utf8')
        } }
        walk(root)
        fs.writeFileSync(${JSON.stringify(capture)}, JSON.stringify({args, cwd:process.cwd(), files}))
        process.stdout.write(JSON.stringify({results:[{source:{path:path.join(root,'apps/web/package-lock.json')},packages:[{package:{name:'public-npm',version:'1.0.0',ecosystem:'npm'}}]}]}))
      `,
        )
        const snapshot = { ...snapshotOf(contents, dir), pathPrefix: 'apps' }
        const run = await runOsvScanner({
          tool: { path: tool, source: 'path', version: '2.7.0' },
          root: dir,
          snapshot,
          offline: false,
          withheldGlobs: ['private/**'],
        })
        const { readFile } = await import('node:fs/promises')
        const seen = JSON.parse(await readFile(capture, 'utf8'))
        expect(seen.files).toEqual(
          Object.fromEntries(
            Object.entries(contents).filter(
              ([path]) =>
                /(?:package(?:-lock)?\.json|pnpm-lock\.yaml|requirements\.txt)$/.test(path) &&
                !path.startsWith('private/'),
            ),
          ),
        )
        expect(seen.args).not.toContain(dir)
        expect(seen.cwd).not.toBe(dir)
        expect(JSON.stringify(seen.files)).not.toMatch(
          /private-package|credential-package|source-never-staged|excluded-live-package/,
        )
        expect(run.checkedDependencies).toBe(1)
        expect(run.status.available).toBe(true)
      } finally {
        await cleanup()
      }
    },
  )

  it('parses JSON output into dependency signals', () => {
    const snapshot = snapshotOf(
      { 'package-lock.json': '{\n  "packages": {\n    "node_modules/minimist": {}\n' },
      '/repo',
    )
    const signals = parseOsvScannerReport(report('/repo'), { root: '/repo', snapshot }, [])
    expect(signals).toHaveLength(1)
    expect(signals[0]).toMatchObject({
      analyzer: 'osv-scanner',
      kind: 'dependency',
      severity: 'critical',
      ruleId: 'GHSA-xvch-5gv4-984h',
      location: { path: 'package-lock.json', startLine: 3 },
      fingerprintParts: ['osv', 'GHSA-xvch-5gv4-984h', 'npm', 'minimist', '1.2.5'],
    })
    expect(signals[0]!.recommendation).toContain('1.2.6')
  })

  it('reports unavailable in offline mode without a local database', async () => {
    const { dir, cleanup } = await makeTempDir()
    try {
      const run = await runOsvScanner({
        tool: { path: '/bin/false', source: 'path' },
        root: dir,
        offline: true,
        localDbDir: dir,
      })
      expect(run.status).toMatchObject({ id: 'osv-scanner', available: false })
      expect(run.status.reason).toMatch(/offline/)
    } finally {
      await cleanup()
    }
  })

  it.runIf(isPosix).each([
    {
      name: 'clean package results',
      raw: {
        results: [
          {
            source: { path: 'package-lock.json' },
            packages: [{ package: { name: 'minimist', version: '1.2.8', ecosystem: 'npm' } }],
          },
        ],
      },
      code: 0,
      checked: 1,
    },
    { name: 'no packages', raw: { results: [] }, code: 0, checked: 0 },
    { name: 'malformed output', raw: { results: 'invalid' }, code: 0, checked: 0 },
    {
      name: 'excluded manifest',
      raw: {
        results: [
          {
            source: { path: 'excluded.json' },
            packages: [{ package: { name: 'minimist', version: '1.2.8', ecosystem: 'npm' } }],
          },
        ],
      },
      code: 0,
      checked: 0,
    },
    { name: 'no lock files', raw: {}, code: 128, checked: 0 },
  ])('tracks dependency coverage for $name', async ({ raw, code, checked }) => {
    const { dir, cleanup } = await makeTempDir()
    try {
      const tool = await fakeTool(
        dir,
        'osv-scanner',
        `process.stdout.write(${JSON.stringify(JSON.stringify(raw))}); process.exit(${code})`,
      )
      const run = await runOsvScanner({
        tool: { path: tool, source: 'path', version: '2.7.0' },
        root: dir,
        offline: false,
        snapshot: snapshotOf({ 'package-lock.json': '{}' }, dir),
      })
      expect(run.status.available).toBe(true)
      expect(run.signals).toEqual([])
      expect(run.checkedDependencies ?? 0).toBe(checked)
    } finally {
      await cleanup()
    }
  })

  it.runIf(isPosix)('runs `scan source` with safe flags and accepts exit code 1', async () => {
    const { dir, cleanup } = await makeTempDir()
    try {
      const argsFile = join(dir, 'args.json')
      const configCopy = join(dir, 'config-seen.toml')
      const tool = await fakeTool(
        dir,
        'osv-scanner',
        `
        const fs = require('node:fs')
        const args = process.argv.slice(2)
        const config = args[args.indexOf('--config') + 1]
        fs.writeFileSync(${JSON.stringify(argsFile)}, JSON.stringify(args))
        fs.writeFileSync(${JSON.stringify(configCopy)}, fs.readFileSync(config, 'utf8'))
        const report = ${JSON.stringify(report(''))}
        report.results[0].source.path = args.at(-1) + '/package-lock.json'
        process.stdout.write(JSON.stringify(report))
        process.exit(1)
        `,
      )
      // A repository config that would hide the advisory if osv-scanner loaded it.
      await writeFile(join(dir, 'osv-scanner.toml'), '[[IgnoredVulns]]\nid = "GHSA-xvch-5gv4-984h"\n')
      const run = await runOsvScanner({
        tool: { path: tool, source: 'path', version: '2.2.2' },
        root: dir,
        offline: false,
        snapshot: snapshotOf({ 'package-lock.json': '{}' }, dir),
      })
      expect(run.status.available).toBe(true)
      expect(run.checkedDependencies).toBe(1)
      expect(run.signals).toHaveLength(1)
      const { readFile } = await import('node:fs/promises')
      const args = JSON.parse(await readFile(argsFile, 'utf8')) as string[]
      expect(args.slice(0, 2)).toEqual(['scan', 'source'])
      expect(args).toEqual(expect.arrayContaining(['--format', 'json', '--recursive', '--no-resolve']))
      expect(args).not.toContain('--offline')
      expect(args).not.toContain('--include-git-root')
      expect(args).not.toContain('--call-analysis')
      expect(args).toContain('--no-call-analysis=all')
      // The repository's osv-scanner.toml ([[IgnoredVulns]]) is overridden by a plugin-written, empty config.
      expect(args[args.indexOf('--config') + 1]).toMatch(/dsh-osv-scanner-[^/]+\/osv-scanner\.toml$/)
      expect(args[args.indexOf('--config') + 1]?.startsWith(dir)).toBe(false)
      expect(args).not.toContain(dir)
      expect(args.at(-1)).toMatch(/dsh-osv-scanner-[^/]+\/snapshot$/)
      expect(args.indexOf('--config')).toBeLessThan(args.length - 1)
      const seen = await readFile(configCopy, 'utf8')
      expect(seen).not.toContain('IgnoredVulns')
      expect(seen.replace(/#.*$/gm, '').trim()).toBe('')

      await runOsvScanner({
        tool: { path: tool, source: 'path', version: '1.9.2' },
        root: dir,
        offline: false,
        snapshot: snapshotOf({ 'package-lock.json': '{}' }, dir),
      })
      const legacy = JSON.parse(await readFile(argsFile, 'utf8')) as string[]
      expect(legacy[legacy.indexOf('--config') + 1]).toMatch(/osv-scanner\.toml$/)
      expect(legacy).toContain('--no-call-analysis=all')
      expect(legacy).not.toContain('--docker')
    } finally {
      await cleanup()
    }
  })
})

describe('semgrep', () => {
  it('parses results with severity, CWE, and redacted snippets from the snapshot', async () => {
    const token = ['ghp', '_', 'aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA5'].join('')
    const snapshot = snapshotOf({ 'app.py': `import os\nos.system(cmd)  # ${token}\n`, 'other.py': 'x' }, '/repo')
    const redactor = new Redactor(await scanSecrets(snapshot))
    const output = {
      results: [
        {
          check_id: 'rules.python.os-system-injection',
          path: 'app.py',
          start: { line: 2, col: 1 },
          end: { line: 2, col: 15 },
          extra: {
            message: 'Command built from user input passed to os.system',
            severity: 'ERROR',
            lines: 'requires login',
            metadata: {
              cwe: ['CWE-78: Improper Neutralization of Special Elements used in an OS Command'],
              confidence: 'HIGH',
              references: ['https://owasp.org/x'],
            },
          },
        },
        {
          check_id: 'rules.info',
          path: '/repo/other.py',
          start: { line: 1 },
          end: { line: 1 },
          extra: { message: 'note', severity: 'INFO' },
        },
        { check_id: 'outside', path: '/etc/passwd', start: { line: 1 }, end: { line: 1 }, extra: {} },
      ],
      errors: [{ message: 'Syntax error in x.py', level: 'warn' }],
    }
    const warnings: string[] = []
    const signals = parseSemgrepOutput(output, { root: '/repo', snapshot, redactor }, warnings)
    expect(signals).toHaveLength(2)
    expect(signals[0]).toMatchObject({
      analyzer: 'semgrep',
      kind: 'vulnerability',
      severity: 'high',
      confidence: 'high',
      cwe: 'CWE-78',
      category: 'command-execution',
      location: { path: 'app.py', startLine: 2, endLine: 2 },
      snippet: 'os.system(cmd)  # [REDACTED:github-token]',
      references: ['https://owasp.org/x'],
    })
    expect(signals[1]).toMatchObject({ severity: 'low', location: { path: 'other.py' } })
    expect(warnings).toEqual(['semgrep: Syntax error in x.py'])
  })

  it('refuses to run without a local config path', async () => {
    const run = await runSemgrep({ tool: { path: '/usr/bin/semgrep', source: 'path' }, root: '/repo' })
    expect(run.status).toMatchObject({ id: 'semgrep', available: false })
    expect(run.status.reason).toMatch(/rules/)
  })

  it.runIf(isPosix)('passes a local config and disables metrics', async () => {
    const { dir, cleanup } = await makeTempDir()
    try {
      const rules = join(dir, 'rules.yml')
      await writeFile(rules, 'rules: []\n')
      const argsFile = join(dir, 'args.json')
      const tool = await fakeTool(
        dir,
        'semgrep',
        `
        require('node:fs').writeFileSync(${JSON.stringify(argsFile)}, JSON.stringify({ args: process.argv.slice(2), metrics: process.env.SEMGREP_SEND_METRICS }))
        process.stdout.write(JSON.stringify({ results: [], errors: [] }))
        `,
      )
      const run = await runSemgrep({ tool: { path: tool, source: 'path' }, root: dir, configPath: rules })
      expect(run.status.available).toBe(true)
      const { readFile } = await import('node:fs/promises')
      const { args, metrics } = JSON.parse(await readFile(argsFile, 'utf8')) as { args: string[]; metrics: string }
      expect(args[0]).toBe('scan')
      expect(args).toEqual(
        expect.arrayContaining([
          '--json',
          '--metrics=off',
          '--disable-version-check',
          '--disable-nosem',
          '--no-git-ignore',
        ]),
      )
      expect(args[args.indexOf('--config') + 1]).toBe(rules)
      expect(args).not.toContain('auto')
      expect(metrics).toBe('off')
    } finally {
      await cleanup()
    }
  })
})
