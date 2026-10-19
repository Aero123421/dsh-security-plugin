import { describe, expect, it } from 'vitest'
import { affordableHuntTasks, phaseCeilings, ScanBudgetGate } from '../../../src/host/scan/budget.ts'
import type { ScanUsage } from '../../../src/shared/contracts.ts'
import type { ScanBudget } from '../../../src/shared/settings.ts'

const LIMITS: ScanBudget = { maxLlmCalls: 3, maxTokens: 1000, maxMinutes: 1, maxTurnsPerWorker: 5, maxTasks: 5 }
const ZERO: ScanUsage = { llmCalls: 0, inputTokens: 0, outputTokens: 0, toolCalls: 0, elapsedMs: 0 }

function clock(start = 1_000_000) {
  let now = start
  return {
    now: () => now,
    advance(ms: number) {
      now += ms
    },
  }
}

function gate(limits: Partial<ScanBudget> = {}, start: ScanUsage = ZERO) {
  const time = clock()
  const controller = new AbortController()
  const budget = new ScanBudgetGate({ ...LIMITS, ...limits }, start, controller.signal, time.now)
  return { budget, time, controller }
}

describe('ScanBudgetGate', () => {
  it('admits model calls until the call limit and reserves them up front', () => {
    const { budget } = gate()
    expect(budget.admit()).toEqual({ ok: true })
    expect(budget.admit()).toEqual({ ok: true })
    expect(budget.usage().llmCalls).toBe(2)
    expect(budget.exhausted()).toBeUndefined()
    expect(budget.admit()).toEqual({ ok: true })
    expect(budget.exhausted()).toBe('calls')
    expect(budget.admit()).toEqual({ ok: false, reason: 'calls' })
    // A refused admission does not count.
    expect(budget.usage().llmCalls).toBe(3)
  })

  it('stops at the token limit, counting cache writes in full and cache reads at a tenth', () => {
    const { budget } = gate({ maxLlmCalls: 100 })
    budget.admit()
    // 300 uncached + 200 cache reads charged as 20 + 50 cache writes = 370.
    budget.record({ inputTokens: 300, outputTokens: 100, cacheReadTokens: 200, cacheWriteTokens: 50 })
    expect(budget.usage()).toMatchObject({ inputTokens: 370, outputTokens: 100 })
    expect(budget.exhausted()).toBeUndefined()
    budget.admit()
    budget.record({ inputTokens: 430, outputTokens: 100 })
    expect(budget.usage()).toMatchObject({ inputTokens: 800, outputTokens: 200 })
    expect(budget.exhausted()).toBe('tokens')
    expect(budget.admit()).toEqual({ ok: false, reason: 'tokens' })
  })

  it('a cache-mostly conversation lasts about ten times longer than at full-rate charging', () => {
    const { budget } = gate({ maxLlmCalls: 10_000, maxTokens: 1000 })
    // Each turn resends a mostly cached history: 900 cached + 10 fresh tokens.
    for (let turn = 0; turn < 9; turn++) {
      expect(budget.admit()).toEqual({ ok: true })
      budget.record({ inputTokens: 10, outputTokens: 0, cacheReadTokens: 900 })
    }
    // 9 turns charged 9 * (10 + 90) = 900; full-rate charging would have stopped after one.
    expect(budget.usage().inputTokens).toBe(900)
    expect(budget.exhausted()).toBeUndefined()
    budget.admit()
    budget.record({ inputTokens: 10, outputTokens: 0, cacheReadTokens: 900 })
    expect(budget.exhausted()).toBe('tokens')
  })

  it('rounds fractional usage and ignores negative, NaN, and missing counts', () => {
    const { budget } = gate({ maxLlmCalls: 100, maxTokens: 1_000_000 })
    budget.record({ inputTokens: 1200.4, outputTokens: 299.6, cacheReadTokens: 0.5 })
    budget.record({ inputTokens: -50, outputTokens: Number.NaN, cacheWriteTokens: Number.POSITIVE_INFINITY })
    budget.addToolCalls(2.6)
    budget.addToolCalls(-3)
    const usage = budget.usage()
    expect(usage).toMatchObject({ inputTokens: 1201, outputTokens: 300, toolCalls: 3 })
    expect(Number.isInteger(usage.inputTokens) && Number.isInteger(usage.outputTokens)).toBe(true)
  })

  it('stops when the time limit is reached', () => {
    const { budget, time } = gate({ maxLlmCalls: 100, maxMinutes: 2 })
    time.advance(119_999)
    expect(budget.exhausted()).toBeUndefined()
    expect(budget.elapsedMs()).toBe(119_999)
    time.advance(1)
    expect(budget.exhausted()).toBe('time')
    expect(budget.admit()).toEqual({ ok: false, reason: 'time' })
  })

  it('never counts a clock that goes backwards as negative time', () => {
    const { budget, time } = gate()
    time.advance(-10_000)
    expect(budget.elapsedMs()).toBe(0)
  })

  it('carries usage across run segments (pause and resume)', () => {
    const first = gate({ maxLlmCalls: 10, maxTokens: 10_000, maxMinutes: 1 })
    first.budget.admit()
    first.budget.record({ inputTokens: 400, outputTokens: 100 })
    first.budget.addToolCalls(4)
    first.time.advance(45_000)
    const saved = first.budget.usage()
    expect(saved).toEqual({ llmCalls: 1, inputTokens: 400, outputTokens: 100, toolCalls: 4, elapsedMs: 45_000 })

    // A later segment starts its own clock but keeps the totals.
    const second = gate({ maxLlmCalls: 10, maxTokens: 10_000, maxMinutes: 1 }, saved)
    expect(second.budget.usage()).toEqual(saved)
    second.time.advance(10_000)
    second.budget.admit()
    expect(second.budget.usage()).toMatchObject({ llmCalls: 2, elapsedMs: 55_000 })
    second.time.advance(5_000)
    expect(second.budget.exhausted()).toBe('time')
  })

  it('a resumed scan that was already over a limit admits nothing', () => {
    const { budget } = gate({}, { ...ZERO, llmCalls: 3 })
    expect(budget.admit()).toEqual({ ok: false, reason: 'calls' })
  })

  it('reports cancelled once the signal aborts, before any other reason', () => {
    const { budget, controller } = gate({ maxLlmCalls: 1 })
    budget.admit()
    expect(budget.exhausted()).toBe('calls')
    controller.abort()
    expect(budget.exhausted()).toBe('cancelled')
    expect(budget.admit()).toEqual({ ok: false, reason: 'cancelled' })
  })

  it('reports pressure as the fraction of the tightest dimension, capped at 1', () => {
    const { budget, time } = gate({ maxLlmCalls: 10, maxTokens: 1000, maxMinutes: 10 })
    expect(budget.pressure()).toBe(0)
    budget.admit()
    expect(budget.pressure()).toBeCloseTo(0.1)
    budget.record({ inputTokens: 250, outputTokens: 0 })
    expect(budget.pressure()).toBeCloseTo(0.25)
    time.advance(5 * 60_000)
    expect(budget.pressure()).toBeCloseTo(0.5)
    budget.record({ inputTokens: 5000, outputTokens: 0 })
    expect(budget.pressure()).toBe(1)
  })
})

describe('phase budgets', () => {
  const DEEP: ScanBudget = {
    maxLlmCalls: 900,
    maxTokens: 9_000_000,
    maxMinutes: 180,
    maxTurnsPerWorker: 72,
    maxTasks: 120,
  }
  const reserve = (overrides: Partial<Parameters<typeof phaseCeilings>[0]> = {}) =>
    phaseCeilings({ limits: DEEP, mode: 'deep', reviews: 0, chain: false, workers: 2, tokensPerCall: 0, ...overrides })

  it('keeps for review what the pending reviews need, at most the mode share, plus a small wrap-up reserve', () => {
    // Nothing to review: hunting may use all but the wrap-up reserve (2 requests per worker, 3% of the time).
    expect(reserve().hunt).toEqual({ llmCalls: 896, tokens: 9_000_000 - 40_000, elapsedMs: 180 * 60_000 - 324_000 })
    // Ten reviews at six requests each.
    expect(reserve({ reviews: 10 }).hunt.llmCalls).toBe(900 - 60 - 4)
    // Many reviews: capped at 30% of the budget in Deep, 35% in Research.
    expect(reserve({ reviews: 56 }).hunt.llmCalls).toBe(900 - 270 - 4)
    expect(reserve({ reviews: 500, mode: 'research' }).hunt.llmCalls).toBe(900 - 315 - 4)
    // Quick has no review phase.
    expect(reserve({ reviews: 56, mode: 'quick' }).hunt.llmCalls).toBe(896)
    // The review phase leaves room for the chain run (Research) and wrap-ups.
    const research = reserve({ reviews: 56, mode: 'research', chain: true })
    expect(research.hunt.llmCalls).toBe(900 - 315 - 12 - 4)
    expect(research.review.llmCalls).toBe(900 - 12 - 4)
    expect(research.chain.llmCalls).toBe(896)
  })

  it('reserves tokens and time in proportion, from the observed tokens per request', () => {
    const observed = reserve({ reviews: 10, tokensPerCall: 12_000 })
    expect(observed.hunt.tokens).toBe(9_000_000 - 64 * 12_000)
    // 60 of 900 requests reserved for reviews keep 1/15 of the time, plus 3% for wrap-ups.
    expect(observed.hunt.elapsedMs).toBe(180 * 60_000 - 720_000 - 324_000)
    // A costly average never reserves more than 1.5 times the calls' share of the tokens.
    const costly = reserve({ reviews: 56, tokensPerCall: 500_000 })
    expect(costly.hunt.tokens).toBe(9_000_000 - Math.round(9_000_000 * (274 / 900) * 1.5))
  })

  it('still lets a tiny budget run: reserves never round up to the whole budget', () => {
    const tiny = phaseCeilings({ limits: LIMITS, mode: 'deep', reviews: 5, chain: true, workers: 4, tokensPerCall: 0 })
    expect(tiny.hunt.llmCalls).toBe(3)
    expect(tiny.review.llmCalls).toBe(3)
  })

  it('keeps the coverage-critic reserve inside the hunt ceiling, at most 20% of it, without touching the review reserve', () => {
    const none = reserve({ reviews: 10 })
    expect(none.wave).toEqual(none.hunt)
    // One Deep pass: the critic (8) and its wave of 8 units (12 each).
    const deep = reserve({ reviews: 10, critic: 8 + 8 * 12 })
    expect(deep.hunt).toEqual(none.hunt)
    expect(deep.review).toEqual(none.review)
    expect(deep.wave.llmCalls).toBe(none.hunt.llmCalls - 104)
    expect(deep.wave.tokens).toBeLessThan(none.hunt.tokens)
    expect(deep.wave.elapsedMs).toBeLessThan(none.hunt.elapsedMs)
    // Capped at 20% of what the hunt ceiling allows.
    expect(reserve({ critic: 10_000 }).wave.llmCalls).toBe(896 - Math.floor(896 * 0.2))
  })

  it('stops ordinary requests at the phase ceiling and lets wrap-up requests through up to the scan limits', () => {
    const { budget } = gate({ maxLlmCalls: 10, maxTokens: 10_000 })
    let ceiling = { llmCalls: 2, tokens: 10_000, elapsedMs: 60_000 }
    const phase = budget.phase(() => ceiling)
    expect(phase.admit()).toEqual({ ok: true })
    expect(phase.admit()).toEqual({ ok: true })
    expect(phase.exhausted()).toBe('calls')
    expect(phase.scanExhausted()).toBeUndefined()
    expect(phase.admit()).toEqual({ ok: false, reason: 'calls' })
    expect(phase.admit({ wrapUp: true })).toEqual({ ok: true })
    expect(budget.usage().llmCalls).toBe(3)
    // The ceiling is read on every request, so a growing reserve takes effect at once.
    ceiling = { llmCalls: 10, tokens: 500, elapsedMs: 60_000 }
    phase.record({ inputTokens: 600, outputTokens: 0 })
    expect(phase.admit()).toEqual({ ok: false, reason: 'tokens' })
    // Nothing is admitted beyond the scan limits, wrap-up or not.
    budget.record({ inputTokens: 9_400, outputTokens: 0 })
    expect(phase.admit({ wrapUp: true })).toEqual({ ok: false, reason: 'tokens' })
    expect(phase.scanExhausted()).toBe('tokens')
  })

  it('counts the hunt tasks the hunt ceiling can still pay for', () => {
    const ceiling = { llmCalls: 626, tokens: 6_000_000, elapsedMs: 1 }
    expect(affordableHuntTasks(ceiling, { ...ZERO, llmCalls: 26 }, 0)).toBe(50)
    expect(affordableHuntTasks(ceiling, { ...ZERO, llmCalls: 26, inputTokens: 5_400_000 }, 10_000)).toBe(5)
    expect(affordableHuntTasks(ceiling, { ...ZERO, llmCalls: 700 }, 0)).toBe(0)
  })
})
