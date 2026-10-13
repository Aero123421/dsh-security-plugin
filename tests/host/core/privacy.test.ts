import { appendFile, mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { Redactor, scanSecrets } from '../../../src/host/analysis/secrets.ts'
import type { Signal } from '../../../src/host/analysis/types.ts'
import { planReviewTasks } from '../../../src/host/scan/planning.ts'
import { ModelPrivacy, WITHHELD_PLACEHOLDER } from '../../../src/host/scan/privacy.ts'
import { snapshotOf } from '../analysis/helpers.ts'
import { findingRecord } from './factories.ts'
import {
  AI_SETTINGS,
  copyFixture,
  createHarness,
  type Harness,
  oracleLlm,
  type RecordingLlm,
  roleOf,
  type TempWorkspace,
} from './helpers.ts'
import { fakeGitleaksToolkit, gitleaksReporting } from './toolkit-helpers.ts'

/** Values that live only in withheld files; none may ever reach a model. */
const ENV_SECRET = 'pw-marker-Hq72vXk9Lr'
const ENV_BLOB = 'withheld-marker-Zt81qPw3'
const SAST_MARKER = 'withheld-sast-marker-Kd93'
const STRIPE_PREFIX = 'sk_live_51Pq8Rm'

const isPosix = process.platform !== 'win32'

describe.skipIf(!isPosix)('withheld files never reach a model (full research scan)', () => {
  let app: TempWorkspace
  let dataDir: string
  let llm: RecordingLlm
  let h: Harness
  let scanId: string

  beforeAll(async () => {
    app = await copyFixture('next-saas')
    await appendFile(join(app.root, '.env.local'), `INTERNAL_ADMIN_PASSWORD=${ENV_SECRET}\nFEATURE_BLOB=${ENV_BLOB}\n`)
    await mkdir(join(app.root, 'lib', 'internal'), { recursive: true })
    await writeFile(
      join(app.root, 'lib', 'internal', 'render.ts'),
      `export function handler(req, res) {\n  res.send(eval(req.query.code)) // ${SAST_MARKER}\n}\n`,
    )
    dataDir = await mkdtemp(join(tmpdir(), 'dshsec-data-'))
    // An external analyzer reports the withheld line with its raw (unredacted) text.
    const toolkit = await fakeGitleaksToolkit(
      dataDir,
      gitleaksReporting([{ file: '.env.local', line: 9, ruleId: 'internal-blob', text: `FEATURE_BLOB=${ENV_BLOB}` }]),
    )
    llm = await oracleLlm()
    h = createHarness({
      llm,
      toolkit,
      workspaces: [{ id: 'ws-saas', path: app.root, title: 'next-saas' }],
      settings: { ...AI_SETTINGS, privacy: { sendCodeToModel: true, withheldGlobs: ['lib/internal/**'] } },
    })
    const scan = await h.controller.create({ workspaceId: 'ws-saas', mode: 'research' })
    expect(await h.settle(scan.id)).toBe('completed')
    scanId = scan.id
  })

  afterAll(async () => {
    await h?.controller.dispose()
    await app?.cleanup()
    if (dataDir) await rm(dataDir, { recursive: true, force: true })
  })

  it('detects the withheld issues deterministically', () => {
    const findings = h.store.listFindings(scanId)
    const at = (path: string) => findings.filter(f => f.location?.path === path)
    expect(at('.env.local').some(f => f.source === 'secret' && f.location?.startLine === 8)).toBe(true)
    expect(at('.env.local').some(f => f.source === 'external' && f.ruleId === 'internal-blob')).toBe(true)
    expect(at('lib/internal/render.ts').some(f => f.source === 'sast')).toBe(true)
  })

  it('sends no secret value or withheld content in any model request', () => {
    expect(llm.calls.length).toBeGreaterThan(0)
    const roles = new Set(llm.calls.map(roleOf))
    expect(roles).toEqual(new Set(['planner', 'hunter', 'skeptic', 'chain']))
    for (const call of llm.calls) {
      const json = JSON.stringify({ system: call.system, messages: call.messages, tools: call.tools })
      for (const value of [ENV_SECRET, ENV_BLOB, SAST_MARKER, STRIPE_PREFIX]) expect(json).not.toContain(value)
      expect(json).not.toContain(app.root)
    }
  })

  it('schedules no review or hunt whose only evidence is in a withheld file', () => {
    const findings = h.store.listFindings(scanId)
    const withheld = findings.filter(
      f => f.location?.path === '.env.local' || f.location?.path.startsWith('lib/internal/'),
    )
    expect(withheld.length).toBeGreaterThanOrEqual(3)
    const tasks = h.store.listTasks(scanId)
    const ids = new Set(withheld.map(f => f.id))
    expect(tasks.filter(t => t.kind === 'review' && ids.has(t.input.findingId ?? ''))).toEqual([])
    expect(tasks.some(t => t.kind === 'review')).toBe(true)
    for (const task of tasks) {
      expect(task.input.targetPaths.filter(p => p === '.env.local' || p.startsWith('lib/internal/'))).toEqual([])
    }
    // Left at their deterministic verification.
    for (const f of withheld) expect(f.review).toBeUndefined()
    expect(withheld.find(f => f.ruleId === 'internal-blob')?.verification).toBe('potential')
  })
})

describe('ModelPrivacy', () => {
  async function privacyFor(files: Record<string, string>, withheldGlobs: string[] = []) {
    const snapshot = snapshotOf(files)
    const redactor = new Redactor(await scanSecrets(snapshot))
    return new ModelPrivacy({ snapshot, redactor, withheldGlobs })
  }

  const signal = (path: string, snippet: string): Signal => ({
    analyzer: 'gitleaks',
    ruleId: 'internal-blob',
    kind: 'secret',
    title: `Hard-coded secret: ${snippet}`,
    category: 'secrets',
    severity: 'high',
    confidence: 'medium',
    location: { path, startLine: 1, endLine: 1 },
    snippet,
    message: `matched ${snippet}`,
    fingerprintParts: ['x'],
    metadata: { source: snippet },
  })

  it('replaces withheld code with a placeholder but keeps the path and rule id', async () => {
    const privacy = await privacyFor({ '.env': `TOKEN=${ENV_BLOB}\n`, 'src/a.ts': 'x\n' }, ['secret/**'])
    const safe = privacy.signal(signal('.env', `TOKEN=${ENV_BLOB}`))
    expect(safe.ruleId).toBe('internal-blob')
    expect(safe.location.path).toBe('.env')
    expect(safe.snippet).toBe(WITHHELD_PLACEHOLDER)
    expect(JSON.stringify(safe)).not.toContain(ENV_BLOB)
    expect(privacy.isWithheld('secret/notes.ts')).toBe(true)
    expect(privacy.isWithheld('src/a.ts')).toBe(false)
  })

  it('redacts known secret values in snippets of visible files, including clipped ones', async () => {
    const privacy = await privacyFor({
      '.env.local': `ADMIN_PASSWORD=${ENV_SECRET}\n`,
      'src/config.ts': `const admin = '${ENV_SECRET}'\n`,
    })
    const visible = privacy.signal(signal('src/config.ts', `const admin = '${ENV_SECRET}'`))
    expect(visible.snippet).toContain('[REDACTED:')
    expect(JSON.stringify(visible)).not.toContain(ENV_SECRET)
    expect(privacy.scrub(`prefix ${ENV_SECRET.slice(0, 12)}…`)).not.toContain(ENV_SECRET.slice(0, 12))
    expect(privacy.scrub('nothing to see here')).toBe('nothing to see here')
  })

  it('only reviews findings with evidence outside withheld files', async () => {
    const privacy = await privacyFor({ 'src/a.ts': 'x\n' }, ['private/**'])
    const hidden = findingRecord({
      id: 'hidden',
      source: 'external',
      location: { path: 'private/x.ts', startLine: 1, endLine: 1 },
    })
    const shown = findingRecord({
      id: 'shown',
      source: 'sast',
      location: { path: 'src/a.ts', startLine: 1, endLine: 1 },
    })
    expect(privacy.reviewable(hidden)).toBe(false)
    expect(privacy.reviewable(shown)).toBe(true)
    const tasks = planReviewTasks([hidden, shown], 'deep', 'low', 10, path => privacy.isWithheld(path))
    expect(tasks.map(t => t.input.findingId)).toEqual(['shown'])
  })
})
