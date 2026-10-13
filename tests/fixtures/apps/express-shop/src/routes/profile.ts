// INTENTIONALLY VULNERABLE TEST FIXTURE — do not deploy
// @ts-nocheck fixture: framework packages are not installed
import { Router } from 'express'
import { User } from '../models/user'

const router = Router()

// GET /api/profile
router.get('/', (req, res) => {
  const user = User.findById(req.user!.id)
  if (!user) {
    res.status(404).json({ error: 'user not found' })
    return
  }
  res.json({ user })
})

// PATCH /api/profile: { name?, email?, address? }
router.patch('/', (req, res) => {
  if (typeof req.body !== 'object' || req.body === null || Array.isArray(req.body)) {
    res.status(400).json({ error: 'expected a JSON object' })
    return
  }
  const user = User.update(req.user!.id, req.body)
  res.json({ user })
})

export default router
