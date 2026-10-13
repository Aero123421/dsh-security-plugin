import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'
import { describe, expect, it } from 'vitest'
import {
  FIXTURE_APPS_DIR,
  type FixtureManifest,
  loadFixtures,
  matchesExpected,
  parseFixtureManifest,
} from '../../bench/fixtures.ts'
import { FINDING_CATEGORIES, SEVERITIES } from '../../src/shared/domain.ts'

const HEADER = 'INTENTIONALLY VULNERABLE TEST FIXTURE — do not deploy'
const EXPECTED_APPS = ['express-shop', 'fastapi-notes', 'flask-secure', 'next-saas']

/** First-line header expected for each kind of source file. */
const HEADER_BY_EXTENSION: Readonly<Record<string, string>> = {
  ts: `// ${HEADER}`,
  tsx: `// ${HEADER}`,
  js: `// ${HEADER}`,
  jsx: `// ${HEADER}`,
  mjs: `// ${HEADER}`,
  cjs: `// ${HEADER}`,
  py: `# ${HEADER}`,
  html: `{# ${HEADER} #}`,
}

const manifests = await loadFixtures()

function filesUnder(dir: string): string[] {
  const out: string[] = []
  for (const name of readdirSync(dir)) {
    const abs = join(dir, name)
    if (statSync(abs).isDirectory()) out.push(...filesUnder(abs))
    else out.push(abs)
  }
  return out
}

function linesOf(manifest: FixtureManifest, path: string): string[] {
  return readFileSync(join(manifest.dir, ...path.split('/')), 'utf8').split(/\r?\n/)
}

function entriesOf(manifest: FixtureManifest) {
  return [
    ...manifest.findings.map(entry => ({ kind: 'finding', ...entry })),
    ...manifest.negatives.map(entry => ({ kind: 'negative', ...entry })),
  ]
}

describe('fixture app manifests', () => {
  it('loads one manifest per fixture app', () => {
    expect(manifests.map(m => m.app)).toEqual(EXPECTED_APPS)
  })

  it('uses ids that are unique across every app', () => {
    const ids = manifests.flatMap(m => entriesOf(m).map(e => e.id))
    expect(ids.length).toBeGreaterThan(0)
    expect(new Set(ids).size).toBe(ids.length)
  })

  describe.each(manifests.map(m => [m.app, m] as const))('%s', (_app, manifest) => {
    it('points every entry at an existing file, a line inside it, and an anchor on that exact line', () => {
      const problems: string[] = []
      for (const entry of entriesOf(manifest)) {
        const where = `${entry.id} ${entry.path}:${entry.line}`
        const abs = join(manifest.dir, ...entry.path.split('/'))
        if (!existsSync(abs)) {
          problems.push(`${where}: file does not exist`)
          continue
        }
        const lines = linesOf(manifest, entry.path)
        const text = lines[entry.line - 1]
        if (text === undefined) problems.push(`${where}: line is past the end of the file (${lines.length} lines)`)
        else if (!text.includes(entry.anchor))
          problems.push(`${where}: anchor ${JSON.stringify(entry.anchor)} not on line`)
      }
      expect(problems).toEqual([])
    })

    it('uses valid categories, severities, CWEs and detectors', () => {
      for (const finding of manifest.findings) {
        expect(FINDING_CATEGORIES, finding.id).toContain(finding.category)
        expect(SEVERITIES, finding.id).toContain(finding.severity)
        if (finding.cwe !== undefined) expect(finding.cwe, finding.id).toMatch(/^CWE-\d+$/)
        expect(finding.detectableBy.length, finding.id).toBeGreaterThan(0)
        // Dependency findings point at lock/manifest entries and nothing else does.
        expect(finding.category === 'dependency', finding.id).toBe(finding.detectableBy.includes('dependency'))
      }
      for (const negative of manifest.negatives) expect(FINDING_CATEGORIES, negative.id).toContain(negative.category)
    })

    it('has at least two negative controls, none on a planted line', () => {
      expect(manifest.negatives.length).toBeGreaterThanOrEqual(2)
      const planted = new Set(manifest.findings.map(f => `${f.path}:${f.line}`))
      for (const negative of manifest.negatives)
        expect(planted, negative.id).not.toContain(`${negative.path}:${negative.line}`)
    })

    it('marks every source file with the intentional-fixture header and ships a README', () => {
      const files = filesUnder(manifest.dir)
      expect(files.some(f => f.split(/[\\/]/).includes('node_modules'))).toBe(false)
      const sources = files.filter(f => (f.split('.').pop() ?? '') in HEADER_BY_EXTENSION)
      expect(sources.length).toBeGreaterThanOrEqual(6)
      const missing = sources.filter(f => {
        const header = HEADER_BY_EXTENSION[f.split('.').pop() ?? '']
        return readFileSync(f, 'utf8').split(/\r?\n/, 1)[0] !== header
      })
      expect(missing.map(f => relative(manifest.dir, f))).toEqual([])
      const readme = join(manifest.dir, 'README.md')
      expect(existsSync(readme)).toBe(true)
      expect(readFileSync(readme, 'utf8')).toContain(HEADER.replace(' — do not deploy', ''))
    })

    it('contains only obviously fake credentials', () => {
      const token =
        /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|sk_live_[A-Za-z0-9]{20,}|rk_live_[A-Za-z0-9]{20,}|AKIA[A-Z0-9]{16})\b/g
      for (const file of filesUnder(manifest.dir)) {
        for (const [match] of readFileSync(file, 'utf8').matchAll(token)) {
          expect(/FAKE|x{8,}/.test(match), `${relative(manifest.dir, file)}: ${match.slice(0, 8)}…`).toBe(true)
          expect(match).not.toBe('AKIAIOSFODNN7EXAMPLE')
        }
      }
    })
  })

  it('keeps flask-secure to exactly one low-severity finding', () => {
    const flask = manifests.find(m => m.app === 'flask-secure')
    expect(flask?.findings.map(f => f.severity)).toEqual(['low'])
  })
})

describe('parseFixtureManifest', () => {
  const dir = join(FIXTURE_APPS_DIR, 'demo')
  const finding = {
    id: 'DM-01',
    title: 'Example',
    category: 'injection',
    cwe: 'CWE-89',
    severity: 'high',
    path: 'src/a.ts',
    line: 3,
    anchor: 'db.query(',
    detectableBy: ['sast'],
    notes: 'why',
  }
  const negative = {
    id: 'DM-N1',
    path: 'src/a.ts',
    line: 9,
    anchor: 'x',
    description: 'safe',
    category: 'injection',
  }
  const valid = { app: 'demo', language: 'typescript', frameworks: [], findings: [finding], negatives: [negative] }

  it('accepts a valid manifest and records its directory', () => {
    const manifest = parseFixtureManifest(valid, dir)
    expect(manifest.dir).toBe(dir)
    expect(manifest.findings[0]?.cwe).toBe('CWE-89')
  })

  it('reports every invalid field at once', () => {
    const bad = {
      ...valid,
      app: 'other',
      findings: [{ ...finding, category: 'sqli', severity: 'urgent', line: 0, detectableBy: ['grep'], path: '../x' }],
      negatives: [{ ...negative, id: 'DM-01' }],
    }
    let message = ''
    try {
      parseFixtureManifest(bad, dir)
    } catch (error) {
      message = error instanceof Error ? error.message : String(error)
    }
    for (const fragment of ['"app"', '"category"', '"severity"', '"line"', '"detectableBy"', '"path"', 'duplicate id'])
      expect(message).toContain(fragment)
  })
})

describe('matchesExpected', () => {
  const expected = { path: 'src/routes/orders.ts', line: 25, category: 'authz' as const, cwe: 'CWE-639' }
  const at = (startLine: number, endLine = startLine) => ({ path: 'src/routes/orders.ts', startLine, endLine })

  it('matches within the line tolerance or inside the reported range', () => {
    expect(matchesExpected(expected, { ...at(28), category: 'authz' })).toBe(true)
    expect(matchesExpected(expected, { ...at(29), category: 'authz' })).toBe(false)
    expect(matchesExpected(expected, { ...at(29), category: 'authz' }, 4)).toBe(true)
    expect(matchesExpected(expected, { ...at(10, 40), category: 'authz' })).toBe(true)
  })

  it('needs the same path and the same category or CWE', () => {
    expect(matchesExpected(expected, { ...at(25), path: 'src/routes/admin.ts', category: 'authz' })).toBe(false)
    expect(matchesExpected(expected, { ...at(25), path: './src/routes/orders.ts', category: 'authz' })).toBe(true)
    expect(matchesExpected(expected, { ...at(25), category: 'business-logic', cwe: 'CWE-639' })).toBe(true)
    expect(matchesExpected(expected, { ...at(25), category: 'business-logic', cwe: 'CWE-284' })).toBe(false)
    expect(matchesExpected(expected, { ...at(25), category: 'injection' })).toBe(false)
  })
})
