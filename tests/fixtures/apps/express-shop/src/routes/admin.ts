// INTENTIONALLY VULNERABLE TEST FIXTURE — do not deploy
// @ts-nocheck fixture: framework packages are not installed
import { Router } from 'express'
import { db } from '../db'
import { requireAdmin, requireAuth } from '../middleware/auth'
import { User } from '../models/user'
import { recentChanges } from '../services/changelog'

const router = Router()

// GET /api/admin/users: customer list for the support console.
router.get('/users', (_req, res) => {
  res.json({ users: User.list() })
})

// GET /api/admin/changelog?file=catalog/spring.json
router.get('/changelog', requireAuth, requireAdmin, async (req, res, next) => {
  try {
    const entries = await recentChanges(String(req.query.file ?? ''))
    res.json({ entries })
  } catch (err) {
    next(err)
  }
})

// PATCH /api/admin/users/:id/role
router.patch('/users/:id/role', requireAuth, requireAdmin, (req, res) => {
  const role = req.body.role === 'admin' ? 'admin' : 'customer'
  const result = db.run('UPDATE users SET role = ? WHERE id = ?', [role, Number(req.params.id)])
  if (result.changes === 0) {
    res.status(404).json({ error: 'user not found' })
    return
  }
  res.json({ ok: true, role })
})

export default router
