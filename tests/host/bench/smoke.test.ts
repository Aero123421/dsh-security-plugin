/**
 * Smoke test of the benchmark harness: a real deterministic scan of the
 * express-shop fixture through ScanController, the in-memory store and the
 * exportReport handler, scored against its expected.json.
 */

import { describe, expect, it } from 'vitest'
import { type FixtureManifest, loadFixtures } from '../../../bench/fixtures.ts'
import { BENCH_CONFIGS, runBenchScan } from '../../../bench/harness.ts'

const manifest = (await loadFixtures()).find(m => m.app === 'express-shop') as FixtureManifest
const deterministic = BENCH_CONFIGS.filter(config => config.group === 'deterministic')

describe('bench smoke: deterministic scan of express-shop', () => {
  it('has the fixture and both deterministic configurations', () => {
    expect(manifest).toBeDefined()
    expect(deterministic.map(c => c.name)).toEqual(['deterministic', 'deterministic-builtin'])
  })

  it.for(deterministic)('$name', async (config, context) => {
    const run = await runBenchScan(manifest, config)
    if (run.status === 'skipped') context.skip(run.reason)
    expect(run.status, run.reason).toBe('completed')
    expect(run.logged.errors).toEqual([])
    const score = run.score
    if (!score || !run.report) throw new Error('no score')

    // Nothing was sent to a model and nothing left the machine.
    expect(run.report.usage.llmCalls).toBe(0)
    expect(run.report.models).toEqual({})
    expect(score.activeDetectors).toEqual(['sast', 'secrets'])

    // Every planted finding the manifest says sast or secrets catches is caught, by that detector.
    for (const detector of ['sast', 'secrets'] as const) {
      const claimed = manifest.findings.filter(f => f.detectableBy.includes(detector))
      expect(claimed.length, detector).toBeGreaterThan(0)
      const caught = score.expected.filter(
        row => row.detectableBy.includes(detector) && row.match?.detectors.includes(detector),
      )
      expect(
        caught.map(row => row.id),
        `${detector} missed planted findings`,
      ).toEqual(claimed.map(f => f.id))
      const stats = score.detectors.find(d => d.detector === detector)
      expect(stats?.recall, detector).toBe(1)
    }

    // No report lands on a documented negative control.
    expect(score.negatives.filter(n => n.hits > 0).map(n => n.id)).toEqual([])
    expect(score.totals.negativeHits).toBe(0)
    // Deterministic scans never rule anything out.
    expect(score.totals.ruledOut.total).toBe(0)
  })
})
