import { describe, expect, it } from 'vitest'
import { expectedHits, hits, MODES, PY_MODES, sast } from './sast-helpers.ts'

/**
 * Rules that depend on the code around the match: what a receiver is, what the enclosing functions are for,
 * where a token comes from. Lines marked `VULN`/`SINK` must be reported for the rule; unmarked lines must not.
 */
interface Case {
  readonly rule: string
  readonly name: string
  readonly path?: string
  readonly code: string
}

const JS_CASES: readonly Case[] = [
  {
    rule: 'js.mass-assignment',
    name: 'only data-layer receivers write the whole body into a record',
    code: `const teamService = require('../services/teamService')
const AuditLog = require('../models/AuditLog')
router.post('/', async (req, res) => {
  await teamService.create(req.body)
  await this.usersService.create(req.body)
  await tenantService.update(req.user, req.params.id, req.body)
  await UserService.create(req.body)
  await api.create(req.body)
  await stripe.customers.create(req.body)
  await AuditLog.create({ actor: req.user.id, action: req.body.action })
  await AuditLog.create(req.body) // VULN
  await models.User.create(req.body) // VULN
  await prisma.user.create({ data: req.body }) // VULN
  await this.prisma.order.update({ where: { id }, data: req.body }) // VULN
  await this.userRepository.update(req.params.id, req.body) // VULN
  await this.userModel.findByIdAndUpdate(req.params.id, req.body) // VULN
  await knex('users').insert(req.body) // VULN
  const user = await User.findByPk(req.params.id)
  await user.update(req.body) // VULN
  const settings = loadSettings()
  await settings.update(req.body)
})`,
  },
]

describe.each(MODES)('JavaScript rules that read their context (%s mode)', (_mode, handle) => {
  it.each(JS_CASES)('$rule: $name', async ({ rule, path, code }) => {
    const signals = await sast({ [path ?? 'src/routes/team.js']: code }, handle)
    expect(hits(signals, rule)).toEqual(expectedHits(code))
  })
})

const PY_CASES: readonly Case[] = []

describe.each(PY_MODES)('Python rules that read their context (%s mode)', (_mode, handle) => {
  it.skipIf(PY_CASES.length === 0).each(PY_CASES)('$rule: $name', async ({ rule, path, code }) => {
    const signals = await sast({ [path ?? 'app/services.py']: code }, handle)
    expect(hits(signals, rule)).toEqual(expectedHits(code))
  })
})
