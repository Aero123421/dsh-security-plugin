import { describe, expect, it } from 'vitest'
import { extractRoutes } from '../../../src/host/analysis/routes/index.ts'
import { planHuntTasks } from '../../../src/host/scan/planning.ts'
import { snapshotOf } from './helpers.ts'
import { endpoint } from './routes-helpers.ts'
import { MODES } from './sast-helpers.ts'

const ROUTES = `import { Router } from 'express'
import * as tenants from '../controllers/tenant.controller.js'
import { getUser } from '../controllers/user.controller.js'
import orders from '../controllers/order.controller.js'
import { invoiceController } from '../controllers/index.js'
import { ReportController } from '../controllers/report.controller.js'
const legacy = require('../controllers/legacy')
const reports = new ReportController()
const asyncHandler = fn => (req, res, next) => fn(req, res, next).catch(next)
export const router = Router()
router.post('/tenants/:id/impersonate', tenants.impersonate)
router.get('/users/:id', getUser)
router.get('/orders', orders.list)
router.get('/orders/:id', asyncHandler(orders.show))
router.get('/invoices/:id', invoiceController.show.bind(invoiceController))
router.get('/reports/:id', reports.render)
router.get('/legacy', legacy.index)
router.get('/legacy/:id', legacy.show)
router.get('/external', externalHandler)
`

const FILES: Record<string, string> = {
  'src/app.ts': `import express from 'express'
import { router } from './routes/api.js'
const app = express()
app.use('/api', router)
`,
  'src/routes/api.ts': `${ROUTES.replace("from 'express'\n", "from 'express'\nimport { externalHandler } from 'some-package'\n")}`,
  'src/controllers/tenant.controller.ts': `import { tenantService } from '../services/tenant.service.js'

export async function impersonate(req, res) {
  const token = await tenantService.impersonate(req.params.id)
  res.json({ token })
}
`,
  'src/controllers/user.controller.ts': `export const getUser = async (req, res) => {
  res.json(await users.find(req.params.id))
}
`,
  'src/controllers/order.controller.ts': `function list(req, res) {
  res.json([])
}
export default {
  list,
  async show(req, res) {
    res.json(await orders.find(req.params.id))
  },
}
`,
  'src/controllers/index.ts': `export * from './invoice.controller.js'
`,
  'src/controllers/invoice.controller.ts': `export const invoiceController = {
  show: async (req, res) => {
    res.json(await invoices.find(req.params.id))
  },
}
`,
  'src/controllers/report.controller.ts': `export class ReportController {
  async render(req, res) {
    res.send(await build(req.params.id))
  }
}
`,
  'src/controllers/legacy.js': `exports.index = function (req, res) {
  res.json([])
}
module.exports.show = async (req, res) => {
  res.json({ id: req.params.id })
}
`,
}

describe.each(MODES)('handlers imported from controller modules (%s mode)', (_mode, handle) => {
  it('locates the handler in the module the route file imports it from', async () => {
    const { endpoints } = await extractRoutes(snapshotOf(FILES), { astGrep: handle })
    const handler = (method: string, route: string) => endpoint(endpoints, method, route).handler
    expect(handler('POST', '/api/tenants/:id/impersonate')).toEqual({
      path: 'src/controllers/tenant.controller.ts',
      startLine: 3,
      endLine: 6,
    })
    expect(handler('GET', '/api/users/:id')).toEqual({
      path: 'src/controllers/user.controller.ts',
      startLine: 1,
      endLine: 3,
    })
    expect(handler('GET', '/api/orders')).toEqual({
      path: 'src/controllers/order.controller.ts',
      startLine: 1,
      endLine: 3,
    })
    expect(handler('GET', '/api/orders/:id')).toEqual({
      path: 'src/controllers/order.controller.ts',
      startLine: 6,
      endLine: 8,
    })
    expect(handler('GET', '/api/invoices/:id')).toEqual({
      path: 'src/controllers/invoice.controller.ts',
      startLine: 2,
      endLine: 4,
    })
    expect(handler('GET', '/api/reports/:id')).toEqual({
      path: 'src/controllers/report.controller.ts',
      startLine: 2,
      endLine: 4,
    })
    expect(handler('GET', '/api/legacy')).toEqual({ path: 'src/controllers/legacy.js', startLine: 1, endLine: 3 })
    expect(handler('GET', '/api/legacy/:id')).toEqual({ path: 'src/controllers/legacy.js', startLine: 4, endLine: 6 })
    // A handler from a package stays unresolved.
    expect(handler('GET', '/api/external')).toBeUndefined()
    // The declaration stays in the route file.
    expect(endpoint(endpoints, 'POST', '/api/tenants/:id/impersonate').declaredAt.path).toBe('src/routes/api.ts')
  })

  it('points endpoint review tasks at the handler file and the route file', async () => {
    const snapshot = snapshotOf(FILES)
    const { endpoints } = await extractRoutes(snapshot, { astGrep: handle })
    const { tasks } = planHuntTasks({
      mode: 'deep',
      snapshot,
      endpoints,
      signals: [],
      units: [],
      includeTests: false,
      maxTasks: 50,
    })
    const endpointTasks = tasks.filter(t => t.kind === 'hunt-endpoints')
    const tenantTask = endpointTasks.find(t => t.input.targetPaths[0] === 'src/controllers/tenant.controller.ts')
    expect(tenantTask?.input.targetPaths).toEqual(['src/controllers/tenant.controller.ts', 'src/routes/api.ts'])
    expect(tenantTask?.input.endpointIds).toEqual(['POST /api/tenants/:id/impersonate @ src/routes/api.ts:12'])
    // Every handler file is the first target of some endpoint task.
    expect(new Set(endpointTasks.map(t => t.input.targetPaths[0]))).toEqual(
      new Set([
        'src/controllers/tenant.controller.ts',
        'src/controllers/user.controller.ts',
        'src/controllers/order.controller.ts',
        'src/controllers/invoice.controller.ts',
        'src/controllers/report.controller.ts',
        'src/controllers/legacy.js',
        'src/routes/api.ts',
      ]),
    )
  })
})
