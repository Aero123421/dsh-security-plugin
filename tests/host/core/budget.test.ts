import { describe, expect, it } from 'vitest'
import { ScanBudgetGate } from '../../../src/host/scan/budget.ts'
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
