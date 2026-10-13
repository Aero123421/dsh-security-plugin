// INTENTIONALLY VULNERABLE TEST FIXTURE — do not deploy
// @ts-nocheck fixture: framework packages are not installed
import { Router } from 'express'
import { db } from '../db'

const router = Router()

interface ProductRow {
  id: number
  slug: string
  name: string
  description: string
  price_cents: number
  stock: number
}

const SORTS = new Map([
  ['name', 'name ASC'],
  ['price_asc', 'price_cents ASC'],
  ['price_desc', 'price_cents DESC'],
])

// GET /api/products/search?q=mug&sort=price_asc
router.get('/search', (req, res) => {
  const term = String(req.query.q ?? '').trim()
  const orderBy = SORTS.get(String(req.query.sort)) ?? 'name ASC'
  const products = db.query<ProductRow>("SELECT id, slug, name, price_cents FROM products WHERE active = 1 AND name LIKE '%" + term + "%' ORDER BY " + orderBy + ' LIMIT 50')
  res.json({ products })
})

// GET /api/products/:slug
router.get('/:slug', (req, res) => {
  const product = db.one<ProductRow>(
    'SELECT id, slug, name, description, price_cents, stock FROM products WHERE slug = ? AND active = 1',
    [req.params.slug],
  )
  if (!product) {
    res.status(404).json({ error: 'product not found' })
    return
  }
  res.json({ product })
})

export default router
