// @ts-nocheck fixture: framework packages are not installed
import { NextResponse } from 'next/server'

export async function GET(request: Request, { params }: { params: { id: string } }) {
  return NextResponse.json({ id: params.id })
}

export const DELETE = async (request: Request) => {
  return new Response(null, { status: 204 })
}
