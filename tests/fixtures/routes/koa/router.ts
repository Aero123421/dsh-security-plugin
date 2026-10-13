// @ts-nocheck fixture: framework packages are not installed
import Router from '@koa/router'

const router = new Router({ prefix: '/v1' })

router.get('/things/:id', jwtAuth, async ctx => {
  ctx.body = { id: ctx.params.id }
})
router.post('/things', async ctx => {
  ctx.body = {}
})
router.del('/things/:id', requireRole('admin'), async ctx => {
  ctx.status = 204
})

export default router
