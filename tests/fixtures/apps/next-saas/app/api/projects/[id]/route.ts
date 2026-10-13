// INTENTIONALLY VULNERABLE TEST FIXTURE — do not deploy
// @ts-nocheck fixture: framework packages are not installed
import { NextResponse } from 'next/server'
import { getMembership, getSession } from '@/lib/auth'
import { prisma } from '@/lib/db'

type Params = { params: { id: string } }

// GET /api/projects/:id: project details for the dashboard's client components.
// Signed-in state is enforced by middleware.ts.
export async function GET(_req: Request, { params }: Params) {
  const project = await prisma.project.findUnique({ where: { id: params.id }, include: { members: true } })
  if (!project) return NextResponse.json({ error: 'not found' }, { status: 404 })
  return NextResponse.json({ project })
}

// DELETE /api/projects/:id: organization owners only.
export async function DELETE(_req: Request, { params }: Params) {
  const user = await getSession()
  if (!user) return NextResponse.json({ error: 'unauthorized' }, { status: 401 })

  const project = await prisma.project.findUnique({ where: { id: params.id }, select: { id: true, orgId: true } })
  if (!project) return NextResponse.json({ error: 'not found' }, { status: 404 })
  const membership = await getMembership(user.id, project.orgId)
  if (membership?.role !== 'owner') return NextResponse.json({ error: 'not found' }, { status: 404 })

  await prisma.project.delete({ where: { id: project.id } })
  return new NextResponse(null, { status: 204 })
}
