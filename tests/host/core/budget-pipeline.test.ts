import { mkdir, mkdtemp, realpath, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import type { LlmGenerateOptions, LlmStreamChunk } from '../../../src/host/dsh/ports.ts'
import type { SettingsPatch } from '../../../src/shared/settings.ts'
import { callReply } from '../agents/runtime/helpers.ts'
import { AI_SETTINGS, createHarness, roleOf, scriptedLlm } from './helpers.ts'

const ROUTERS = 10
let root: string

/** An Express app with one SQL injection per router: ten reviewable rule hits in ten endpoint files. */
beforeAll(async () => {
  root = await realpath(await mkdtemp(join(tmpdir(), 'dshsec-budget-')))
  const put = async (path: string, text: string) => {
    await mkdir(dirname(join(root, path)), { recursive: true })
    await writeFile(join(root, path), text)
  }
  await put('package.json', JSON.stringify({ name: 'budget-app', dependencies: { express: '4.19.2' } }))
  let app = "import express from 'express'\n"
  for (let i = 0; i < ROUTERS; i++) app += `import r${i} from './routes/r${i}'\n`
  app += 'export const app = express()\n'
  for (let i = 0; i < ROUTERS; i++) app += `app.use('/api/r${i}', r${i})\n`
  await put('src/app.ts', app)
  for (let i = 0; i < ROUTERS; i++) {
    await put(
      `src/routes/r${i}.ts`,
      [
        "import { Router } from 'express'",
        "import { db } from '../db'",
        'const router = Router()',
        `router.get('/', async (req, res) => { res.json(await db.query("SELECT * FROM t${i} WHERE name = '" + req.query.q + "'")) })`,
        `router.post('/:id', async (req, res) => { res.json(await db.run('UPDATE t${i} SET v = ? WHERE id = ?', [req.body.v, req.params.id])) })`,
        'export default router',
        '',
      ].join('\n'),
    )
  }
  await put('src/db.ts', 'export const db = { query: async (q: string) => [q], run: async () => ({}) }\n')
})

afterAll(async () => {
  await rm(root, { recursive: true, force: true })
})

/**
 * A model that investigates for `turns` replies per task before submitting,
 * and submits at once when a last-chance note asks for it, as real models do.
 */
function patientModel(turns: Record<'planner' | 'critic' | 'hunter' | 'skeptic' | 'chain', number>) {
  const wrapUps = { planner: 0, critic: 0, hunter: 0, skeptic: 0, chain: 0 }
  const calls = { planner: 0, critic: 0, hunter: 0, skeptic: 0, chain: 0 }
  let id = 0
  const llm = scriptedLlm(async function* (options: LlmGenerateOptions): AsyncGenerator<LlmStreamChunk> {
    const role = roleOf(options)
    calls[role]++
    const last = options.messages.at(-1)
    const note =
      last?.role === 'user' ? last.content.map(block => (block as { text?: string }).text ?? '').join('\n') : ''
    if (note.includes('budget for this work is used up')) wrapUps[role]++
    const lastChance = /Call submit_\w+ now|This is your final turn/.test(note)
    const replies = options.messages.filter(message => message.role === 'assistant').length
    if (!lastChance && replies < turns[role]) {
      yield* callReply(`r${++id}`, 'read_file', { path: `src/routes/r${replies % ROUTERS}.ts` })
      return
    }
    const task = options.messages[0]?.content.map(block => (block as { text?: string }).text ?? '').join('\n') ?? ''
    const ids = [...task.matchAll(/^(S\d+):/gm)].map(match => match[1])
    const submissions = {
      // No units: the Host's gap filling plans the endpoint tasks.
      planner: ['submit_review_plan', { summary: 'An API.' }],
      critic: ['submit_coverage_review', { done: true }],
      hunter: [
        'submit_findings',
        {
          findings: [],
          signal_assessments: ids.map(s => ({ id: s, verdict: 'uncertain', reason: 'Not decided here.' })),
        },
      ],
      skeptic: ['submit_verdict', { verdict: 'inconclusive', reasoning: 'Depends on deployment.' }],
      chain: ['submit_chains', { chains: [] }],
    } as const
    const [name, args] = submissions[role]
    yield* callReply(`s${++id}`, name, args)
  })
  return { llm, wrapUps, calls }
}

describe('budget reserve for the independent review', () => {
  const settings: SettingsPatch = {
    ...AI_SETTINGS,
    scan: { parallelWorkers: 2 },
    budgets: { deep: { maxLlmCalls: 200, maxTasks: 60 } },
  }

  it('caps hunting so every pending review still runs, and lets running hunters submit their work', async () => {
    const model = patientModel({ planner: 1, critic: 1, hunter: 14, skeptic: 3, chain: 1 })
    const h = createHarness({ llm: model.llm, workspaces: [{ id: 'ws', path: root, title: 'budget-app' }], settings })
    const scan = await h.controller.create({ workspaceId: 'ws', mode: 'deep' })
    expect(await h.settle(scan.id)).toBe('completed')
    const tasks = h.store.listTasks(scan.id)
    const reviews = tasks.filter(t => t.kind === 'review')
    const hunts = tasks.filter(t => t.role === 'hunter')

    // Ten rule hits are reviewable; hunting 15 requests per task would have spent the whole budget first.
    expect(reviews).toHaveLength(ROUTERS)
    expect(reviews.every(t => t.status === 'done')).toBe(true)
    expect(model.calls.skeptic).toBe(ROUTERS * 4)

    // Hunting stopped at its ceiling: the lowest-priority work (the sweep of the remaining source files) did not
    // fit and is reported as not run for budget, never dropped silently.
    expect(hunts.every(t => t.status === 'done')).toBe(true)
    const coverage = h.store.getScan(scan.id)?.coverage
    expect(coverage?.unassignedFiles).toBe(2)
    expect(coverage?.units?.find(unit => unit.id === 'unassigned')).toMatchObject({
      status: 'not-run',
      reason: { code: 'budget' },
      paths: ['src/app.ts', 'src/db.ts'],
    })
    expect(coverage?.gapDetails?.map(gap => gap.code)).toContain('unassigned-files')

    // Hunters still running at the ceiling got a wrap-up request and submitted; none lost its work mid-run.
    expect(model.wrapUps.hunter).toBeGreaterThan(0)
    const runs = h.store.listAgentRuns(scan.id).filter(run => run.role === 'hunter')
    expect(runs.some(run => run.status === 'budget_exhausted')).toBe(false)
    expect(runs.filter(run => run.status === 'submitted')).toHaveLength(hunts.filter(t => t.status === 'done').length)

    const usage = h.store.getScan(scan.id)?.usage
    expect(usage?.llmCalls).toBeLessThanOrEqual(200)
  })

  it('keeps nothing back from hunting when nothing needs a review', async () => {
    const model = patientModel({ planner: 1, critic: 1, hunter: 14, skeptic: 3, chain: 1 })
    const h = createHarness({
      llm: model.llm,
      workspaces: [{ id: 'ws', path: root, title: 'budget-app' }],
      // Reviews only for critical findings: the rule hits here are high.
      settings: { ...settings, scan: { parallelWorkers: 2, reviewThreshold: 'critical' } },
    })
    const scan = await h.controller.create({ workspaceId: 'ws', mode: 'deep' })
    expect(await h.settle(scan.id)).toBe('completed')
    const tasks = h.store.listTasks(scan.id)
    expect(tasks.filter(t => t.kind === 'review')).toHaveLength(0)
    // The same hunt tasks that were capped above all run now.
    const hunts = tasks.filter(t => t.role === 'hunter')
    expect(hunts.length).toBeGreaterThan(ROUTERS)
    expect(hunts.every(t => t.status === 'done')).toBe(true)
    expect(h.notices(scan.id)).not.toContain('hunt-budget-reserved')
    // Only the coverage critic's reserve is kept: hunters running into the wave ceiling wrap up there and submit.
    expect(model.wrapUps.hunter).toBeGreaterThan(0)
    expect(model.calls.hunter).toBeLessThan(hunts.length * 15)
    expect(
      h.store
        .listAgentRuns(scan.id)
        .filter(run => run.role === 'hunter')
        .every(run => run.status === 'submitted'),
    ).toBe(true)
    expect(tasks.find(t => t.kind === 'critic')?.status).toBe('done')
  })
})
