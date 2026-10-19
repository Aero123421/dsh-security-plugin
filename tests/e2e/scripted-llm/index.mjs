// @ts-check
/**
 * A deterministic "model" for end-to-end tests of DSH Security without an
 * API key. Load it into a DSH profile with a patch overlay:
 *
 *   - insert:
 *       - id: scripted-llm
 *         name: /absolute/path/to/tests/e2e/scripted-llm/index.mjs
 *         config:
 *           fixturesDir: /absolute/path/to/tests/fixtures/apps
 *
 * It registers the provider `scripted` with the model `oracle`. The oracle
 * plays every DSH Security role by reading files through the plugin's own
 * tools and answering from the fixture ground truth (`expected.json`), so
 * the full loop — tool calls, quote verification, independent review,
 * persistence, and the UI — runs for real. It also submits one fabricated
 * finding per hunter run to prove that unverifiable claims are discarded.
 *
 * This is test scaffolding for plumbing, not a measure of detection quality.
 */

import { readdirSync, readFileSync, existsSync } from 'node:fs'
import { join } from 'node:path'

export const name = 'scripted-llm'
export const inject = ['llm']

/** @param {any} ctx @param {{ fixturesDir?: string, delayMs?: number }} config */
export function apply(ctx, config = {}) {
  const apps = loadTruth(config.fixturesDir)
  const delayMs = config.delayMs ?? 30
  const adapter = {
    providerInfo: (/** @type {string} */ provider) => ({ id: provider, name: 'Scripted (tests)' }),
    providerRetryPolicy: () => undefined,
    imageRequestPricing: () => undefined,
    listModels: async (/** @type {string} */ provider) => [
      { provider, id: 'oracle', name: 'Oracle (fixture-aware test model)' },
    ],
    resolveModel: async (/** @type {string} */ provider, /** @type {string} */ model) => ({
      provider,
      id: model,
      name: model,
      context: { contextWindow: 128000 },
    }),
    prepareCall: async (/** @type {string} */ provider, /** @type {string} */ model) => ({
      model: { provider, id: model, name: model },
      stream: (/** @type {any} */ options) => stream(options),
    }),
    stream: (/** @type {any} */ options) => stream(options),
  }
  ctx.effect(() => ctx.llm.registerAdapter(['scripted'], adapter), 'scripted-llm: adapter')

  /** @param {any} options */
  async function* stream(options) {
    await new Promise(resolve => setTimeout(resolve, delayMs))
    const reply = decide(options, apps)
    let index = 0
    for (const block of reply.blocks) {
      yield { type: 'block-start', index, blockType: block.type }
      yield { type: 'block-end', index, block }
      index++
    }
    yield {
      type: 'usage',
      usage: { inputTokens: 1200 + JSON.stringify(options.messages).length / 4, outputTokens: 300 },
    }
    yield { type: 'finish', reason: { kind: reply.blocks.some(b => b.type === 'tool-call') ? 'tool-calls' : 'stop' } }
  }
}

/**
 * @typedef {{ findings: any[], negatives: any[] }} Truth
 * @typedef {Truth & { app: string, paths: Set<string> }} AppTruth
 */

/**
 * One ground truth per fixture app. A DSH profile usually holds several of
 * these apps as separate projects, so every answer is scoped to the app the
 * worker is looking at (see {@link pickApp}); mixing them would make one
 * project's scan report or review another project's planted issues.
 * @param {string | undefined} dir
 * @returns {AppTruth[]}
 */
function loadTruth(dir) {
  /** @type {AppTruth[]} */
  const apps = []
  if (!dir || !existsSync(dir)) return apps
  for (const app of readdirSync(dir)) {
    const file = join(dir, app, 'expected.json')
    if (!existsSync(file)) continue
    const manifest = JSON.parse(readFileSync(file, 'utf8'))
    const findings = manifest.findings ?? []
    const negatives = manifest.negatives ?? []
    apps.push({ app, findings, negatives, paths: new Set([...findings, ...negatives].map(entry => entry.path)) })
  }
  return apps
}

/** @type {Truth} */
const NO_TRUTH = { findings: [], negatives: [] }

/**
 * The fixture app whose answer-key paths best overlap the files this worker
 * has seen (a `list_files` listing, read files, and paths in the task).
 * Returns no truth when nothing overlaps, so an unrelated project gets no
 * planted answers. With a single app, that app is used.
 * @param {AppTruth[]} apps
 * @param {Set<string>} seen
 * @returns {Truth}
 */
function pickApp(apps, seen) {
  if (apps.length === 1) return apps[0] ?? NO_TRUTH
  let best
  let bestScore = 0
  let tied = false
  for (const app of apps) {
    let score = 0
    for (const path of app.paths) if (seen.has(path)) score++
    if (score > bestScore) {
      best = app
      bestScore = score
      tied = false
    } else if (score === bestScore && score > 0) {
      tied = true
    }
  }
  return best && !tied ? best : NO_TRUTH
}

let callCounter = 0
const call = (/** @type {string} */ name, /** @type {any} */ args) => ({
  type: 'tool-call',
  id: `call_${++callCounter}`,
  name,
  arguments: JSON.stringify(args),
})

/**
 * @param {any} options
 * @param {AppTruth[]} apps
 */
function decide(options, apps) {
  const system = String(options.system ?? '')
  const messages = options.messages
  const first = messages[0]?.content?.map((/** @type {any} */ b) => b.text ?? '').join('\n') ?? ''
  const tools = new Set((options.tools ?? []).map((/** @type {any} */ t) => t.name))
  const reads = collectReads(messages)
  const listed = collectListed(messages)
  const role = /"planner"/.test(system)
    ? 'planner'
    : /"independent reviewer"/.test(system)
      ? 'skeptic'
      : /"attack-chain researcher"/.test(system)
        ? 'chain'
        : 'hunter'
  // First turn: look at the project layout, like a real reviewer, so the
  // answers below come from this project's ground truth only.
  if (apps.length > 1 && listed.size === 0 && tools.has('list_files')) {
    return { blocks: [{ type: 'text', text: 'Listing the project files.' }, call('list_files', { limit: 500 })] }
  }
  const targets = targetsOf(first, role)
  const truth = pickApp(apps, new Set([...listed, ...reads.keys(), ...targets]))
  const unread = targets.filter(path => !reads.has(path))
  // First turns: read what the task points at (only while non-terminal tools are offered).
  if (unread.length > 0 && tools.has('read_file')) {
    return {
      blocks: [
        { type: 'text', text: 'Reading the relevant files.' },
        ...unread.slice(0, 4).map(path => call('read_file', { path })),
      ],
    }
  }
  switch (role) {
    case 'planner':
      return { blocks: [call('submit_threat_model', plannerAnswer(truth))] }
    case 'skeptic':
      return { blocks: [call('submit_verdict', skepticAnswer(first, reads, truth))] }
    case 'chain':
      return { blocks: [call('submit_chains', { chains: [] })] }
    default:
      return { blocks: [call('submit_findings', hunterAnswer(first, reads, truth))] }
  }
}

/** Files shown by read_file results: path → numbered content. @param {any[]} messages */
function collectReads(messages) {
  /** @type {Map<string, string>} */
  const reads = new Map()
  for (const message of messages) {
    if (message.role !== 'tool') continue
    const text = message.content.map((/** @type {any} */ b) => b.text ?? '').join('\n')
    const header = /^(\S+) \(lines \d+-\d+ of \d+\)/.exec(text)
    if (header?.[1]) reads.set(header[1], text)
  }
  return reads
}

/** Paths shown by list_files results ("path  (language, N lines)"). @param {any[]} messages */
function collectListed(messages) {
  /** @type {Set<string>} */
  const listed = new Set()
  for (const message of messages) {
    if (message.role !== 'tool') continue
    const text = message.content.map((/** @type {any} */ b) => b.text ?? '').join('\n')
    if (!/^\d+ files?\b/.test(text)) continue
    for (const line of text.split('\n').slice(1)) {
      const match = /^(\S+) {2}[[(]/.exec(line)
      if (match?.[1]) listed.add(match[1])
    }
  }
  return listed
}

/** @param {string} task @param {string} role */
function targetsOf(task, role) {
  if (role === 'skeptic') {
    const match = /- Location: ([^\s:]+):\d+/.exec(task)
    return match?.[1] ? [match[1]] : []
  }
  const start = task.indexOf('Start with these files:')
  if (start < 0) return []
  const out = []
  for (const line of task.slice(start).split('\n').slice(1)) {
    const match = /^- (\S+)$/.exec(line.trim())
    if (!match?.[1]) break
    out.push(match[1])
  }
  return out
}

/** Find the 1-based line of `anchor` in numbered read_file output. @param {string} numbered @param {string} anchor */
function lineOf(numbered, anchor) {
  for (const raw of numbered.split('\n')) {
    const match = /^\s*(\d+)\| (.*)$/.exec(raw)
    if (match?.[1] && match[2]?.includes(anchor)) return { line: Number(match[1]), text: match[2] }
  }
  return undefined
}

/** @param {{ findings: any[] }} truth */
function plannerAnswer(truth) {
  const ai = truth.findings.filter(f => f.detectableBy.includes('ai')).slice(0, 4)
  return {
    summary: 'A small web application with user accounts, an API, and an admin area (scripted test model).',
    assets: ['user accounts', 'orders and personal data'],
    actors: ['anonymous visitor', 'logged-in customer', 'administrator'],
    trust_boundaries: ['HTTP API entry points'],
    priorities: ai.map(f => ({ target: f.path, reason: f.title })),
    hypotheses: ai.map(f => ({ title: f.title, category: f.category, target_paths: [f.path], rationale: f.notes })),
  }
}

/** @param {string} task @param {Map<string, string>} reads @param {{ findings: any[], negatives: any[] }} truth */
function hunterAnswer(task, reads, truth) {
  const findings = []
  for (const [path, numbered] of reads) {
    for (const expected of truth.findings) {
      if (expected.path !== path) continue
      const hit = lineOf(numbered, expected.anchor)
      if (!hit) continue
      findings.push({
        title: expected.title,
        category: expected.category,
        ...(expected.cwe ? { cwe: expected.cwe } : {}),
        severity: expected.severity,
        confidence: 'high',
        summary: expected.notes.slice(0, 600),
        impact: `An attacker can exploit: ${expected.title}.`,
        preconditions: ['The attacker can send HTTP requests to the application.'],
        attack_path: [
          {
            description: 'The vulnerable operation.',
            path,
            start_line: hit.line,
            end_line: hit.line,
            quote: hit.text.trim(),
          },
        ],
        defenses_checked: [],
        recommendation: 'Apply the missing check or use a safe API (scripted test model).',
      })
    }
  }
  const firstPath = [...reads.keys()][0]
  if (firstPath) {
    findings.push({
      title: 'Fabricated finding that must be discarded',
      category: 'injection',
      severity: 'critical',
      confidence: 'high',
      summary: 'This claim cites code that does not exist.',
      impact: 'None.',
      preconditions: [],
      attack_path: [
        {
          description: 'Invented code.',
          path: firstPath,
          start_line: 1,
          end_line: 1,
          quote: 'eval(req.query.backdoor_that_does_not_exist)',
        },
      ],
      defenses_checked: [],
      recommendation: 'None.',
    })
  }
  const assessments = []
  for (const match of task.matchAll(/^(S\d+): \S+ — .* at ([^\s:]+):(\d+)-\d+/gm)) {
    const [, id, path, line] = match
    const negative = truth.negatives.find(n => n.path === path && Math.abs(n.line - Number(line)) <= 3)
    assessments.push({ id, verdict: negative ? 'false_positive' : 'true_positive', reason: 'Scripted assessment.' })
  }
  return { findings, signal_assessments: assessments, reviewed_paths: [...reads.keys()], notes: 'scripted' }
}

/** @param {string} task @param {Map<string, string>} reads @param {{ findings: any[], negatives: any[] }} truth */
function skepticAnswer(task, reads, truth) {
  const match = /- Location: ([^\s:]+):(\d+)/.exec(task)
  const path = match?.[1]
  const line = Number(match?.[2])
  const numbered = path ? reads.get(path) : undefined
  const negative = truth.negatives.find(n => n.path === path && Math.abs(n.line - line) <= 3)
  if (negative && numbered) {
    const hit = lineOf(numbered, negative.anchor)
    if (hit) {
      return {
        verdict: 'refuted',
        reasoning: negative.description,
        counterevidence: [
          { description: negative.description, path, start_line: hit.line, end_line: hit.line, quote: hit.text.trim() },
        ],
        supporting_evidence: [],
      }
    }
  }
  const expected = truth.findings.find(f => f.path === path && Math.abs(f.line - line) <= 3)
  if (expected && numbered) {
    const hit = lineOf(numbered, expected.anchor)
    return {
      verdict: 'confirmed',
      reasoning: `No defense applies: ${expected.notes}`.slice(0, 1900),
      counterevidence: [],
      supporting_evidence: hit
        ? [
            {
              description: 'Checked: the operation runs without a guard.',
              path,
              start_line: hit.line,
              end_line: hit.line,
              quote: hit.text.trim(),
            },
          ]
        : [],
      ...(/written in English/.test(task)
        ? {
            localized: {
              title: `【検証済み】${expected.title}`,
              summary: 'スクリプト化されたテストモデルによる日本語の要約です。',
              impact: '攻撃者がこの問題を悪用できます。',
              recommendation: '入力を検証し、安全なAPIを使ってください。',
            },
          }
        : {}),
    }
  }
  return {
    verdict: 'inconclusive',
    reasoning: 'Depends on deployment configuration (scripted).',
    counterevidence: [],
    supporting_evidence: [],
    missing_information: ['deployment configuration'],
  }
}
