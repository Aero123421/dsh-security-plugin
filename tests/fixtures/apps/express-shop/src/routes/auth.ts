// INTENTIONALLY VULNERABLE TEST FIXTURE — do not deploy
// @ts-nocheck fixture: framework packages are not installed
import { randomUUID } from 'node:crypto'
import bcrypt from 'bcryptjs'
import { Router } from 'express'
import rateLimit from 'express-rate-limit'
import { issueToken } from '../middleware/auth'
import { User } from '../models/user'

const router = Router()

// Compared against when the email is unknown, so response time does not reveal which emails exist.
const UNKNOWN_USER_HASH = bcrypt.hashSync(randomUUID(), 10)

const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 10, standardHeaders: 'draft-7', legacyHeaders: false })

router.post('/login', loginLimiter, async (req, res) => {
  const { email, password } = req.body as { email?: unknown; password?: unknown }
  if (typeof email !== 'string' || typeof password !== 'string') {
    res.status(400).json({ error: 'email and password are required' })
    return
  }
  const user = User.findByEmail(email)
  const ok = await bcrypt.compare(password, user?.password_hash ?? UNKNOWN_USER_HASH)
  if (!user || !ok) {
    res.status(401).json({ error: 'invalid credentials' })
    return
  }
  res.json({ token: issueToken({ id: user.id, email: user.email, role: user.role }) })
})

export default router
