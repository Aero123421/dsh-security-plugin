// INTENTIONALLY VULNERABLE TEST FIXTURE — do not deploy
// @ts-nocheck fixture: framework packages are not installed
import { notFound, redirect } from 'next/navigation'
import { ProjectDescription } from '@/components/ProjectDescription'
import { getMembership, getSession } from '@/lib/auth'
import { prisma } from '@/lib/db'
import { updateProject } from './actions'

export default async function ProjectPage({ params }: { params: { id: string } }) {
  const user = await getSession()
  if (!user) redirect('/login')

  const project = await prisma.project.findUnique({ where: { id: params.id } })
  if (!project) notFound()
  const membership = await getMembership(user.id, project.orgId)
  if (!membership) notFound()

  return (
    <main className="mx-auto max-w-3xl space-y-8 p-8">
      <h1 className="text-2xl font-semibold">{project.name}</h1>
      <ProjectDescription description={project.description} />

      {membership.role !== 'viewer' && (
        <form action={updateProject} className="space-y-4">
          <input type="hidden" name="projectId" value={project.id} />
          <input name="name" defaultValue={project.name} className="input" />
          <textarea name="description" defaultValue={project.description} rows={12} className="textarea" />
          <button type="submit" className="btn">
            Save
          </button>
        </form>
      )}
    </main>
  )
}
