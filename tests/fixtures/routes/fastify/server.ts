// @ts-nocheck fixture: framework packages are not installed
import Fastify from 'fastify'
import billing from './routes/billing'

const fastify = Fastify()

fastify.get('/status', async () => ({ ok: true }))
fastify.post('/orders/:orderId', { preHandler: [fastify.authenticate] }, async (request, reply) => {
  return { id: request.params.orderId }
})
fastify.route({
  method: ['GET', 'HEAD'],
  url: '/reports/:reportId',
  onRequest: verifyJwt,
  handler: async (request, reply) => ({}),
})
fastify.register(billing, { prefix: '/billing' })
