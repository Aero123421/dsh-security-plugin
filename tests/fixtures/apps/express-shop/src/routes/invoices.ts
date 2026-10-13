// INTENTIONALLY VULNERABLE TEST FIXTURE — do not deploy
// @ts-nocheck fixture: framework packages are not installed
import path from 'node:path'
import { Router } from 'express'
import { config } from '../config'

const router = Router()

// Invoices and receipts are stored per customer: <dir>/<userId>/<file>.

// GET /api/invoices/download?file=INV-2024-0042.pdf
router.get('/download', (req, res) => {
  if (typeof req.query.file !== 'string' || req.query.file === '') {
    res.status(400).json({ error: 'file is required' })
    return
  }
  const dir = path.join(config.invoiceDir, String(req.user!.id))
  res.sendFile(path.join(dir, req.query.file))
})

// GET /api/invoices/receipts/:name
router.get('/receipts/:name', (req, res) => {
  const dir = path.join(config.receiptDir, String(req.user!.id))
  const name = path.basename(req.params.name)
  res.sendFile(path.join(dir, name), err => {
    if (err && !res.headersSent) res.status(404).json({ error: 'receipt not found' })
  })
})

export default router
