# next-saas (intentionally vulnerable test fixture)

> **INTENTIONALLY VULNERABLE TEST FIXTURE — do not deploy, do not install, do not run.**
> This directory is evaluation data for the dsh-security-plugin scanner. Nothing here is
> executed or installed. `.env.local` is committed **on purpose** as a planted finding; the
> Stripe-style key in it is fake (it contains `FAKE`).

"Projectly": a small multi-tenant SaaS on the Next.js App Router, NextAuth (GitHub) and
Prisma. Users belong to organizations through `Membership` rows (`owner`, `member`, `viewer`);
organizations own projects and pay per seat (`Org.seatLimit`).

## Layout

| Path | Purpose |
| --- | --- |
| `middleware.ts` | Redirects signed-out visitors to `/login`; its matcher covers `/dashboard` only |
| `lib/auth.ts` | NextAuth options, `getSession()`, `getMembership()` |
| `lib/db.ts` | Prisma client |
| `app/api/projects/[id]/route.ts` | Project read (GET) and delete (DELETE) |
| `app/api/auth/callback/route.ts` | Post-sign-in landing that honours `?next=` |
| `app/api/invites/[token]/redeem/route.ts` | Join an organization with an invite |
| `app/api/onboarding/complete/route.ts` | Marks onboarding done, redirects to the dashboard |
| `app/dashboard/projects/[id]/` | Project page and its `updateProject` server action |
| `components/ProjectDescription.tsx` | Renders the project's Markdown description |
| `prisma/schema.prisma` | Data model |
| `.env.example` / `.env.local` | Placeholder template / committed local secrets |

## Planted issues

See [`expected.json`](./expected.json) for exact lines, CWE, severity and expected detectors.

- **NS-01** Broken access control: `GET /api/projects/:id` returns any project (with its member
  list) by id. It never calls `getSession()` or checks membership, and `middleware.ts` does not
  cover `/api`, so it is reachable even without signing in.
- **NS-02** Open redirect: the auth callback calls `redirect(searchParams.get('next') ...)`.
- **NS-03** Stored XSS: project descriptions are Markdown rendered with `marked` (no sanitizer)
  into `dangerouslySetInnerHTML`; any non-viewer member can attack the rest of the org.
- **NS-04** Race condition: invite redemption counts seats, then creates the membership in a
  separate query with no transaction or lock, so concurrent redemptions exceed `seatLimit`.
- **NS-05** `.env.local` is committed with a Stripe live secret key.

## Negative controls (must not be reported)

- The `updateProject` server action validates input with zod and checks org membership and role.
- `DELETE /api/projects/:id` checks the caller is an owner of the project's org.
- `POST /api/onboarding/complete` redirects to a fixed target: `new URL('/dashboard', req.url)`.
- `.env.example` contains placeholders only (`sk_live_xxxx…`, `USER:PASSWORD`).
- The project page renders `project.name` through normal JSX escaping.
