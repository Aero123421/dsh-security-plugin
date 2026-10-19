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
    hypotheses: [],
    includeTests: false,
    maxTasks: 100,
    ...overrides,
  })
}

describe('task focus', () => {
  it('asks sweeps and sensitive-file reviews to look for injection, command, SSRF, path and XSS flaws', () => {
    const { tasks } = plan({
      'src/services/report.service.ts': 'export function build(name) { return exec("render " + name) }\n',
      'src/middleware/requireRole.ts': 'export const requireRole = role => (req, res, next) => next()\n',
    })
    const sweep = tasks.find(t => t.key.startsWith('sweep:'))
    const sensitive = tasks.find(t => t.key === 'file:src/middleware/requireRole.ts')
    expect(sweep?.input.targetPaths).toEqual(['src/services/report.service.ts'])
    for (const task of [sweep, sensitive]) {
      expect(task?.input.focus).toEqual(expect.arrayContaining(['authn', 'authz', ...INPUT_FLAWS]))
    }
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
