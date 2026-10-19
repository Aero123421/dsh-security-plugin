import { mkdir, mkdtemp, realpath, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import type { LlmGenerateOptions, LlmStreamChunk } from '../../../src/host/dsh/ports.ts'
import { callReply, reply, textBlock } from '../agents/runtime/helpers.ts'
import { AI_SETTINGS, createHarness, roleOf, scriptedLlm } from './helpers.ts'

const DB_LINE = 'export const db = { query: async (q: string) => [q] }'
let root: string

/** One Express route with a SQL injection rule hit, and a db helper the hunter cites as the "defense". */
beforeAll(async () => {
  root = await realpath(await mkdtemp(join(tmpdir(), 'dshsec-dismiss-')))
  const put = async (path: string, text: string) => {
    await mkdir(dirname(join(root, path)), { recursive: true })
    await writeFile(join(root, path), text)
  }
  await put('package.json', JSON.stringify({ name: 'dismiss-app', dependencies: { express: '4.19.2' } }))
  await put(
    'src/app.ts',
    "import express from 'express'\nimport orders from './routes/orders'\nexport const app = express()\napp.use('/api/orders', orders)\n",
  )
  await put(
    'src/routes/orders.ts',
    [
      "import { Router } from 'express'",
      "import { db } from '../db'",
      'const router = Router()',
      `router.get('/', async (req, res) => { res.json(await db.query("SELECT * FROM orders WHERE name = '" + req.query.q + "'")) })`,
      'export default router',
      '',
    ].join('\n'),
  )
  await put('src/db.ts', `${DB_LINE}\n`)
})

afterAll(async () => {
  await rm(root, { recursive: true, force: true })
})

function text(options: LlmGenerateOptions, index: number): string {
  return options.messages[index]?.content.map(block => (block as { text?: string }).text ?? '').join('\n') ?? ''
}

/** Hunters call every rule hit a false positive with verified code; the reviewer behaves as `skeptic` says. */
function dismissingModel(skeptic: 'no-tools' | 'confirms') {
  let id = 0
  return scriptedLlm(async function* (options: LlmGenerateOptions): AsyncGenerator<LlmStreamChunk> {
    const role = roleOf(options)
    const replies = options.messages.filter(message => message.role === 'assistant').length
    if (role === 'planner') {
      yield* callReply(`p${++id}`, 'submit_threat_model', { summary: 'An orders API.' })
      return
    }
    if (role === 'chain') {
      yield* callReply(`c${++id}`, 'submit_chains', { chains: [] })
      return
    }
    if (role === 'hunter') {
      if (replies === 0) {
        yield* callReply(`h${++id}`, 'read_file', { path: 'src/db.ts' })
        return
      }
      const ids = [...text(options, 0).matchAll(/^(S\d+):/gm)].map(match => match[1])
      yield* callReply(`h${++id}`, 'submit_findings', {
        findings: [],
        signal_assessments: ids.map(s => ({
          id: s,
          verdict: 'false_positive',
          reason: 'The db helper escapes input',
          evidence: { path: 'src/db.ts', start_line: 1, end_line: 1, quote: DB_LINE, description: 'db helper' },
        })),
      })
      return
    }
    if (skeptic === 'no-tools') {
      yield* reply([textBlock(0, 'I think this is fine.')])
      return
    }
    yield* callReply(`s${++id}`, 'submit_verdict', {
      verdict: 'confirmed',
      reasoning: 'The query concatenates request input.',
      supporting_evidence: [
        {
          path: 'src/routes/orders.ts',
          start_line: 4,
          end_line: 4,
          quote: `router.get('/', async (req, res) => { res.json(await db.query("SELECT * FROM orders WHERE name = '" + req.query.q + "'")) })`,
          description: 'concatenated query',
        },
      ],
    })
  })
}

const NOTE =
  'An AI hunter assessed this rule hit as a false positive (The db helper escapes input — db helper), but no independent review confirmed the cited defense, so it stays open.'

describe('hunter dismissals that waited for a review', () => {
  it('apply as inconclusive when the planned review did not complete', async () => {
    const h = createHarness({
      llm: dismissingModel('no-tools'),
      workspaces: [{ id: 'ws', path: root, title: 'dismiss-app' }],
      settings: AI_SETTINGS,
    })
    const scan = await h.controller.create({ workspaceId: 'ws', mode: 'deep' })
    expect(await h.settle(scan.id)).toBe('completed')
    const reviews = h.store.listTasks(scan.id).filter(task => task.kind === 'review')
    expect(reviews.length).toBeGreaterThan(0)
    expect(reviews.some(task => task.status === 'done')).toBe(false)

    const disputed = h.store.listFindings(scan.id).filter(finding => finding.limitations.includes(NOTE))
    expect(disputed.length).toBeGreaterThan(0)
    for (const finding of disputed) {
      expect(finding.verification).toBe('inconclusive')
      expect(finding.review).toBeUndefined()
    }
    expect(h.events(scan.id).some(event => event.type === 'hunter-dismissals-applied')).toBe(true)
  })

  it('leave the outcome to a review that completed', async () => {
    const h = createHarness({
      llm: dismissingModel('confirms'),
      workspaces: [{ id: 'ws', path: root, title: 'dismiss-app' }],
      settings: AI_SETTINGS,
    })
    const scan = await h.controller.create({ workspaceId: 'ws', mode: 'deep' })
    expect(await h.settle(scan.id)).toBe('completed')
    const reviews = h.store.listTasks(scan.id).filter(task => task.kind === 'review')
    expect(reviews.length).toBeGreaterThan(0)
    expect(reviews.every(task => task.status === 'done')).toBe(true)
    const findings = h.store.listFindings(scan.id)
    expect(findings.some(finding => finding.counterEvidenceIds.length > 0)).toBe(true)
    expect(findings.some(finding => finding.limitations.includes(NOTE))).toBe(false)
    expect(h.events(scan.id).some(event => event.type === 'hunter-dismissals-applied')).toBe(false)
  })
})
