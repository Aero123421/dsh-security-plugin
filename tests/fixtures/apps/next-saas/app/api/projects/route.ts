// INTENTIONALLY VULNERABLE TEST FIXTURE — do not deploy
// @ts-nocheck fixture: framework packages are not installed
import { NextResponse } from 'next/server'
import { z } from 'zod'
import { getMembership, getSession } from '@/lib/auth'
import { prisma } from '@/lib/db'

const CreateProject = z.object({
  orgId: z.string().cuid(),
  name: z.string().min(1).max(120),
})

// GET /api/projects: projects in every organization the caller belongs to.
export async function GET() {
  const user = await getSession()
  if (!user) return NextResponse.json({ error: 'unauthorized' }, { status: 401 })
  const projects = await prisma.project.findMany({
    where: { org: { memberships: { some: { userId: user.id } } } },
    select: { id: true, name: true, orgId: true, createdAt: true },
    orderBy: { createdAt: 'desc' },
  })
  return NextResponse.json({ projects })
}

// POST /api/projects: create a project in an organization the caller can edit.
export async function POST(req: Request) {
  const user = await getSession()
  if (!user) return NextResponse.json({ error: 'unauthorized' }, { status: 401 })
  const parsed = CreateProject.safeParse(await req.json())
  if (!parsed.success) return NextResponse.json({ error: 'invalid input' }, { status: 400 })

  const membership = await getMembership(user.id, parsed.data.orgId)
  if (!membership || membership.role === 'viewer') return NextResponse.json({ error: 'forbidden' }, { status: 403 })

  const project = await prisma.project.create({ data: { orgId: parsed.data.orgId, name: parsed.data.name } })
  return NextResponse.json({ project }, { status: 201 })
}
