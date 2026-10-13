// INTENTIONALLY VULNERABLE TEST FIXTURE — do not deploy
// @ts-nocheck fixture: framework packages are not installed
'use server'

import { revalidatePath } from 'next/cache'
import { z } from 'zod'
import { getMembership, getSession } from '@/lib/auth'
import { prisma } from '@/lib/db'

const UpdateProject = z.object({
  projectId: z.string().cuid(),
  name: z.string().min(1).max(120),
  description: z.string().max(20_000),
})

export async function updateProject(formData: FormData) {
  const user = await getSession()
  if (!user) throw new Error('unauthorized')

  const input = UpdateProject.parse({
    projectId: formData.get('projectId'),
    name: formData.get('name'),
    description: formData.get('description'),
  })

  const project = await prisma.project.findUnique({ where: { id: input.projectId }, select: { orgId: true } })
  if (!project) throw new Error('not found')
  const membership = await getMembership(user.id, project.orgId)
  if (!membership || membership.role === 'viewer') throw new Error('forbidden')

  await prisma.project.update({
    where: { id: input.projectId },
    data: { name: input.name, description: input.description },
  })
  revalidatePath(`/dashboard/projects/${input.projectId}`)
}
