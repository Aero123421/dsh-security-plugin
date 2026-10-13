// INTENTIONALLY VULNERABLE TEST FIXTURE — do not deploy
// @ts-nocheck fixture: framework packages are not installed
import express from 'express'
import helmet from 'helmet'
import { config } from './config'
import { requireAuth } from './middleware/auth'
import adminRouter from './routes/admin'
import authRouter from './routes/auth'
import invoicesRouter from './routes/invoices'
import ordersRouter from './routes/orders'
import productsRouter from './routes/products'
import profileRouter from './routes/profile'
import webhooksRouter from './routes/webhooks'

export const app = express()

app.disable('x-powered-by')
app.use(helmet())
app.use(express.json({ limit: '100kb' }))

app.get('/healthz', (_req, res) => {
  res.json({ ok: true })
})

// Public routes.
app.use('/api/auth', authRouter)
app.use('/api/products', productsRouter)

// Signed-in customers.
app.use('/api/orders', requireAuth, ordersRouter)
app.use('/api/invoices', requireAuth, invoicesRouter)
app.use('/api/profile', requireAuth, profileRouter)
app.use('/api/webhooks', requireAuth, webhooksRouter)

// Back office.
app.use('/api/admin', adminRouter)

app.use((err: Error, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
  console.error(err)
  res.status(500).json({ error: 'internal error' })
})

if (require.main === module) {
  app.listen(config.port, () => {
    console.log(`express-shop listening on :${config.port}`)
  })
}
