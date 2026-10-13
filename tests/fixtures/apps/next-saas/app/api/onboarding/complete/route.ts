// INTENTIONALLY VULNERABLE TEST FIXTURE — do not deploy
// @ts-nocheck fixture: framework packages are not installed
import { NextResponse } from 'next/server'
import { getSession } from '@/lib/auth'
import { prisma } from '@/lib/db'

// The onboarding wizard posts here when it finishes; send the user to their dashboard.
export async function POST(req: Request) {
  const user = await getSession()
  if (!user) return NextResponse.json({ error: 'unauthorized' }, { status: 401 })
  await prisma.user.update({ where: { id: user.id }, data: { onboardedAt: new Date() } })
  return NextResponse.redirect(new URL('/dashboard', req.url))
}
