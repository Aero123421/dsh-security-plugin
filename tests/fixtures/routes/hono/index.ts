// @ts-nocheck fixture: framework packages are not installed
import { Hono } from 'hono'
import { bearerAuth } from 'hono/bearer-auth'

const app = new Hono().basePath('/api')

app.get('/hello/:name', c => c.text(`Hello ${c.req.param('name')}`))
app.post('/admin/posts', bearerAuth({ token: 'x' }), async c => c.json({}))
app.on(['PUT', 'PATCH'], '/posts/:postId', async c => c.json({}))

export default app
