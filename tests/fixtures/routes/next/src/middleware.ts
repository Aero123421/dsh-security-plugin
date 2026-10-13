// @ts-nocheck fixture: framework packages are not installed
import { NextResponse } from 'next/server'

export function middleware(request) {
  return NextResponse.next()
}
