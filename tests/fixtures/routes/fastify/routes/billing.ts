// @ts-nocheck fixture: framework packages are not installed
export default async function billing(fastify, opts) {
  fastify.addHook('preHandler', fastify.requireUser)
  fastify.get('/invoices/:invoiceId', async request => ({ id: request.params.invoiceId }))
}
