// INTENTIONALLY VULNERABLE TEST FIXTURE — do not deploy
// @ts-nocheck fixture: framework packages are not installed
import { NextResponse } from 'next/server'
import { getSession } from '@/lib/auth'
import { prisma } from '@/lib/db'

// POST /api/invites/:token/redeem: join the organization the invite belongs to.
// Organizations pay per seat; `seatLimit` is what their plan includes.
export async function POST(_req: Request, { params }: { params: { token: string } }) {
  const user = await getSession()
  if (!user) return NextResponse.json({ error: 'unauthorized' }, { status: 401 })

  const invite = await prisma.invite.findUnique({
    where: { token: params.token },
    include: { org: { select: { id: true, seatLimit: true } } },
  })
  if (!invite || invite.expiresAt < new Date()) {
    return NextResponse.json({ error: 'invite is invalid or expired' }, { status: 404 })
  }

  const seatsUsed = await prisma.membership.count({ where: { orgId: invite.orgId } })
  if (seatsUsed >= invite.org.seatLimit) {
    return NextResponse.json({ error: 'this organization has no free seats' }, { status: 409 })
  }
  await prisma.membership.create({ data: { userId: user.id, orgId: invite.orgId, role: invite.role } })
  await prisma.invite.update({ where: { id: invite.id }, data: { uses: { increment: 1 } } })

  return NextResponse.json({ orgId: invite.orgId })
}
