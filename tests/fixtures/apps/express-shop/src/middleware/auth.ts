// INTENTIONALLY VULNERABLE TEST FIXTURE — do not deploy
// @ts-nocheck fixture: framework packages are not installed
import type { NextFunction, Request, Response } from 'express'
import jwt from 'jsonwebtoken'
import { config } from '../config'

export interface AuthUser {
  id: number
  email: string
  role: 'customer' | 'admin'
}

declare global {
  namespace Express {
    interface Request {
      user?: AuthUser
    }
  }
}

interface TokenClaims {
  sub: string
  email: string
  role: AuthUser['role']
}

export function issueToken(user: AuthUser): string {
  const claims: TokenClaims = { sub: String(user.id), email: user.email, role: user.role }
  return jwt.sign(claims, config.jwtSecret, { algorithm: 'HS256', expiresIn: config.jwtExpiresIn })
}

/** Rejects the request unless it carries a valid bearer token. */
export function requireAuth(req: Request, res: Response, next: NextFunction): void {
  const header = req.headers.authorization ?? ''
  const token = header.startsWith('Bearer ') ? header.slice(7) : undefined
  if (!token) {
    res.status(401).json({ error: 'missing bearer token' })
    return
  }
  try {
    const claims = jwt.verify(token, config.jwtSecret, { algorithms: ['HS256'] }) as TokenClaims
    req.user = { id: Number(claims.sub), email: claims.email, role: claims.role }
    next()
  } catch {
    res.status(401).json({ error: 'invalid or expired token' })
  }
}

/** Must run after requireAuth. */
export function requireAdmin(req: Request, res: Response, next: NextFunction): void {
  if (req.user?.role !== 'admin') {
    res.status(403).json({ error: 'administrator role required' })
    return
  }
  next()
}
