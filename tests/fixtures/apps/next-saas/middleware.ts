// INTENTIONALLY VULNERABLE TEST FIXTURE — do not deploy
// @ts-nocheck fixture: framework packages are not installed
import { getToken } from 'next-auth/jwt'
import { type NextRequest, NextResponse } from 'next/server'

export async function middleware(req: NextRequest) {
  const token = await getToken({ req })
  if (!token) {
    const login = new URL('/login', req.url)
    login.searchParams.set('next', req.nextUrl.pathname)
    return NextResponse.redirect(login)
  }
  return NextResponse.next()
}

// Only the dashboard pages are gated here; API route handlers are expected to
// call getSession() themselves.
export const config = {
  matcher: ['/dashboard/:path*'],
}
