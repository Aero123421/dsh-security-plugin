import { describe, expect, it } from 'vitest'
import { routeSignals } from '../../../src/host/analysis/routes/signals.ts'
import { isReportableSignal, recordSignalFindings, signalFingerprint } from '../../../src/host/scan/findings.ts'
import { planHuntTasks } from '../../../src/host/scan/planning.ts'
import { openSecurityStore } from '../../../src/host/store/sqlite.ts'
import { endpointOf } from '../core/factories.ts'
import { snapshotOf } from './helpers.ts'

const snapshot = snapshotOf({ 'src/routes.ts': "app.post('/items', handler)\n" })

describe('unguarded route steering', () => {
  it.each(['POST', 'PUT', 'PATCH', 'DELETE', 'ANY'])(
    'emits a non-reportable sink for an unguarded %s route',
    method => {
      const endpoints = [endpointOf(method, '/items', 'src/routes.ts', 1)]
      const signals = routeSignals(endpoints, snapshot)
      expect(signals).toHaveLength(1)
      expect(signals[0]).toMatchObject({
        analyzer: 'routes',
        kind: 'sink',
        ruleId: 'routes.unguarded',
        category: 'authz',
      })
      expect(isReportableSignal(signals[0]!)).toBe(false)
      const plan = planHuntTasks({
        mode: 'deep',
        snapshot,
        endpoints,
        signals,
        units: [],
        includeTests: false,
        maxTasks: 1,
      })
      expect(plan.tasks[0]?.input.signalFingerprints).toContain(signalFingerprint(signals[0]!))
      const withoutSignal = planHuntTasks({
        mode: 'deep',
        snapshot,
        endpoints,
        signals: [],
        units: [],
        includeTests: false,
        maxTasks: 1,
      })
      expect(plan.tasks[0]!.priority).toBeGreaterThan(withoutSignal.tasks[0]!.priority)
      const store = openSecurityStore(':memory:')
      try {
        // A sink is skipped before any scan/finding write, including detector attribution.
        expect(recordSignalFindings(store, 'not-a-scan', signals, () => new Date().toISOString()).created).toBe(0)
      } finally {
        store.close()
      }
    },
  )

  it.each(['/admin', '/internal/jobs', '/api/debug'])('steers review of sensitive GET %s', route => {
    expect(routeSignals([endpointOf('GET', route, 'src/routes.ts', 1)], snapshot)).toHaveLength(1)
  })

  it('does not flag guarded endpoints, public GETs, or sensitive-looking substrings', () => {
    expect(
      routeSignals(
        [
          endpointOf('POST', '/items', 'src/routes.ts', 1, { authHints: ['requireAuth'] }),
          endpointOf('GET', '/admin', 'src/routes.ts', 1, { authHints: ['requireAdmin'] }),
          endpointOf('GET', '/public', 'src/routes.ts', 1),
          endpointOf('GET', '/administer', 'src/routes.ts', 1),
        ],
        snapshot,
      ),
    ).toEqual([])
  })

  it('locates the observation in the handler file so endpoint planning attaches it', () => {
    const handler = { path: 'src/routes.ts', startLine: 1, endLine: 1 }
    const [signal] = routeSignals([endpointOf('POST', '/items', 'src/mount.ts', 1, { handler })], snapshot)
    expect(signal?.location).toEqual(handler)
    expect(signal?.snippet).toBe("app.post('/items', handler)")
  })
})
