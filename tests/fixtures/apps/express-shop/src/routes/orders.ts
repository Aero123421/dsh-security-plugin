// INTENTIONALLY VULNERABLE TEST FIXTURE — do not deploy
// @ts-nocheck fixture: framework packages are not installed
import { Router } from 'express'
import { db } from '../db'

const router = Router()

interface OrderRow {
  id: number
  user_id: number
  status: 'pending' | 'paid' | 'shipped' | 'cancelled'
  total_cents: number
  shipping_address: string
  created_at: string
}

// GET /api/orders: the signed-in customer's own orders.
router.get('/', (req, res) => {
  const orders = db.query<OrderRow>('SELECT * FROM orders WHERE user_id = ? ORDER BY created_at DESC', [req.user!.id])
  res.json({ orders })
})

// GET /api/orders/:id: one order with its line items, for the order
// detail page and the support console.
router.get('/:id', (req, res) => {
  const order = db.one<OrderRow>('SELECT * FROM orders WHERE id = ?', [req.params.id])
  if (!order) {
    res.status(404).json({ error: 'order not found' })
    return
  }
  const items = db.query(
    'SELECT p.name, oi.quantity, oi.unit_price_cents FROM order_items oi JOIN products p ON p.id = oi.product_id WHERE oi.order_id = ?',
    [order.id],
  )
  res.json({ order, items })
})

// POST /api/orders/:id/cancel: only pending orders owned by the caller.
router.post('/:id/cancel', (req, res) => {
  const result = db.run("UPDATE orders SET status = 'cancelled' WHERE id = ? AND user_id = ? AND status = 'pending'", [
    req.params.id,
    req.user!.id,
  ])
  if (result.changes === 0) {
    res.status(404).json({ error: 'no pending order with that id' })
    return
  }
  res.json({ ok: true })
})

export default router
