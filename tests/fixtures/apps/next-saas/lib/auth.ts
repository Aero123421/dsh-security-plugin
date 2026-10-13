// INTENTIONALLY VULNERABLE TEST FIXTURE — do not deploy
// @ts-nocheck fixture: framework packages are not installed
import { type NextAuthOptions, getServerSession } from 'next-auth'
import GitHubProvider from 'next-auth/providers/github'
import { prisma } from './db'

export const authOptions: NextAuthOptions = {
  session: { strategy: 'jwt' },
  providers: [
    GitHubProvider({
      clientId: process.env.GITHUB_CLIENT_ID ?? '',
      clientSecret: process.env.GITHUB_CLIENT_SECRET ?? '',
    }),
  ],
  callbacks: {
    async jwt({ token, account }) {
      // Link by the stable GitHub account id, never by the (changeable) profile email.
      if (account?.provider === 'github') {
        const user = await prisma.user.findUnique({ where: { githubId: account.providerAccountId } })
        if (user) token.uid = user.id
      }
      return token
    },
    async session({ session, token }) {
      return { ...session, userId: token.uid as string | undefined }
    },
  },
}

export interface SessionUser {
  id: string
  email: string
}

/** The signed-in user, or null. */
export async function getSession(): Promise<SessionUser | null> {
  const session = await getServerSession(authOptions)
  const id = (session as { userId?: string } | null)?.userId
  if (!id || !session?.user?.email) return null
  return { id, email: session.user.email }
}

/** Membership row for the user in `orgId`, or null when they do not belong to it. */
export async function getMembership(userId: string, orgId: string) {
  return prisma.membership.findUnique({ where: { userId_orgId: { userId, orgId } } })
}
