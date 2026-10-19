import { describe, expect, it } from 'vitest'
import type { FindingCategory } from '../../../src/shared/domain.ts'
import { type HuntPlanInput, planHuntTasks } from '../../../src/host/scan/planning.ts'
import { snapshotOf } from '../analysis/helpers.ts'
import { endpointOf, signalOf } from './factories.ts'

/** What AI tasks are told to look for and where they look: the hand-off from the analyzers. */

const INPUT_FLAWS: FindingCategory[] = ['injection', 'command-execution', 'ssrf', 'path-traversal', 'xss']
const at = (path: string, line: number) => ({ path, startLine: line, endLine: line })

function plan(files: Record<string, string>, overrides: Partial<HuntPlanInput> = {}) {
  return planHuntTasks({
    mode: 'deep',
    snapshot: snapshotOf(files),
    endpoints: [],
    signals: [],
    units: [],
    includeTests: false,
    maxTasks: 100,
    ...overrides,
  })
}

describe('task focus', () => {
  it('asks sweeps to look for injection, command, SSRF, path and XSS flaws', () => {
    const { tasks } = plan({
      'src/services/report.service.ts': 'export function build(name) { return exec("render " + name) }\n',
      'src/middleware/requireRole.ts': 'export const requireRole = role => (req, res, next) => next()\n',
    })
    const sweep = tasks.find(t => t.key.startsWith('sweep:'))
    expect(sweep?.input.targetPaths).toEqual(['src/middleware/requireRole.ts', 'src/services/report.service.ts'])
    expect(sweep?.input.focus).toEqual(expect.arrayContaining(['authn', 'authz', ...INPUT_FLAWS]))
  })

  it('always covers input flaws for endpoints, plus the categories of rule hits in the route file', () => {
    const endpoint = endpointOf('POST', '/files', 'src/routes/file.routes.ts', 4, {
      handler: { path: 'src/controllers/file.controller.ts', startLine: 10, endLine: 20 },
    })
    const { tasks } = plan(
      { 'src/routes/file.routes.ts': 'x\n', 'src/controllers/file.controller.ts': 'x\n' },
      {
        endpoints: [endpoint],
        signals: [
          signalOf({
            location: at('src/routes/file.routes.ts', 2),
            kind: 'sink',
            ruleId: 'js.insecure-deserialization',
            category: 'deserialization',
          }),
        ],
      },
    )
    const task = tasks.find(t => t.kind === 'hunt-endpoints')
    expect(task?.input.targetPaths).toEqual(['src/controllers/file.controller.ts', 'src/routes/file.routes.ts'])
    expect(task?.input.focus).toEqual(expect.arrayContaining(['authz', 'authn', ...INPUT_FLAWS, 'deserialization']))
  })
})

describe('Quick triage', () => {
  it('also verifies medium sinks of high/critical rules, not low or route steering sinks', () => {
    const { tasks } = plan(
      {
        'src/repositories/report.repository.ts': 'x\n',
        'src/jobs/thumbnail.ts': 'x\n',
        'src/lib/files.ts': 'x\n',
        'src/lib/merge.ts': 'x\n',
        'src/controllers/tenant.controller.ts': 'x\n',
      },
      {
        mode: 'quick',
        signals: [
          signalOf({ location: at('src/repositories/report.repository.ts', 7), kind: 'sink', severity: 'medium' }),
          signalOf({
            location: at('src/jobs/thumbnail.ts', 7),
            kind: 'sink',
            severity: 'medium',
            ruleId: 'js.command-injection',
            category: 'command-execution',
          }),
          signalOf({
            location: at('src/lib/files.ts', 3),
            kind: 'sink',
            severity: 'low',
            ruleId: 'js.path-traversal',
            category: 'path-traversal',
          }),
          signalOf({
            location: at('src/lib/merge.ts', 3),
            kind: 'sink',
            severity: 'medium',
            ruleId: 'js.prototype-pollution',
            category: 'injection',
          }),
          signalOf({
            analyzer: 'routes',
            location: at('src/controllers/tenant.controller.ts', 48),
            kind: 'sink',
            severity: 'medium',
            ruleId: 'routes.unguarded',
            category: 'authz',
          }),
        ],
      },
    )
    expect(
      tasks
        .filter(t => !t.key.startsWith('sweep:'))
        .map(t => t.key)
        .sort(),
    ).toEqual(['triage:src/jobs/thumbnail.ts#0', 'triage:src/repositories/report.repository.ts#0'])
  })
})

describe('source sweeps', () => {
  it('take the files whose names say what they enforce before large CRUD and utility files', () => {
    const big = 'x\n'.repeat(2000)
    const { tasks } = plan({
      'src/middleware/rateLimit.ts': big,
      'src/repositories/payment.repository.ts': big,
      'src/repositories/tenant.repository.ts': big,
      'src/services/payment.service.ts': big,
      'src/middleware/requireRole.ts': 'x\n',
      'src/middleware/tenantScope.ts': 'x\n',
      'src/utils/tokens.ts': 'x\n',
      'src/utils/crypto.ts': 'x\n',
      'src/middleware/upload.ts': 'x\n',
      'src/config/index.ts': 'x\n',
    })
    const swept = tasks.filter(t => t.key.startsWith('sweep:')).flatMap(t => t.input.targetPaths)
    expect(swept.slice(0, 6).sort()).toEqual([
      'src/config/index.ts',
      'src/middleware/requireRole.ts',
      'src/middleware/tenantScope.ts',
      'src/middleware/upload.ts',
      'src/utils/crypto.ts',
      'src/utils/tokens.ts',
    ])
  })
})
