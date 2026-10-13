// INTENTIONALLY VULNERABLE TEST FIXTURE — do not deploy
// @ts-nocheck fixture: framework packages are not installed
import { Router } from 'express'

const router = Router()

// POST /api/webhooks/test: send a sample event so merchants can check their endpoint.
router.post('/test', async (req, res) => {
  const target = req.body.url
  const started = Date.now()
  try {
    const response = await fetch(target, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ type: 'order.test', sentAt: new Date().toISOString() }),
    })
    const body = await response.text()
    res.json({ status: response.status, ms: Date.now() - started, body: body.slice(0, 2000) })
  } catch (err) {
    res.status(502).json({ error: `delivery failed: ${(err as Error).message}` })
  }
})

export default router
