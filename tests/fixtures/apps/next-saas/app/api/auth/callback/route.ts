// INTENTIONALLY VULNERABLE TEST FIXTURE — do not deploy
// @ts-nocheck fixture: framework packages are not installed
import { redirect } from 'next/navigation'
import { type NextRequest, NextResponse } from 'next/server'
import { getSession } from '@/lib/auth'

// Landing point after the GitHub sign-in round trip. `next` carries the page
// the user was on when middleware.ts sent them to /login.
export async function GET(req: NextRequest) {
  const { searchParams } = req.nextUrl
  const user = await getSession()
  if (!user) {
    return NextResponse.redirect(new URL('/login?error=session', req.url))
  }
  redirect(searchParams.get('next') ?? '/dashboard')
}
