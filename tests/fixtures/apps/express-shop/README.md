# express-shop (intentionally vulnerable test fixture)

> **INTENTIONALLY VULNERABLE TEST FIXTURE — do not deploy, do not install, do not run.**
> This directory is evaluation data for the dsh-security-plugin scanner. It is never
> executed by the test suite; `package-lock.json` is hand-written and nothing is installed.
> Every credential-looking value is fake (`FAKE` appears in each token).

A small Express + TypeScript web shop: JWT bearer auth, a thin SQLite helper (`src/db.ts`),
customers, orders, invoices, webhooks and a back-office router.

## Layout

| Path | Purpose |
| --- | --- |
| `src/app.ts` | App setup and router mounting (where auth middleware is attached) |
| `src/config.ts` | Settings, including the JWT signing secret |
| `src/db.ts` | `db.query` / `db.one` / `db.run` wrappers around prepared statements |
| `src/middleware/auth.ts` | `requireAuth` (bearer JWT) and `requireAdmin` |
| `src/models/user.ts` | `User` model with a column allow-list for updates |
| `src/routes/*.ts` | Route handlers |
| `src/services/changelog.ts` | `git log` wrapper used by the admin changelog |
| `scripts/sync-catalog.ts` | One-off catalog import script |

## Planted issues

The authoritative list, with exact lines, CWE, severity and which detector is expected to
find each one, is [`expected.json`](./expected.json). In short:

- **ES-01** IDOR: `GET /api/orders/:id` loads any order by id with no ownership check.
- **ES-02** SQL injection in product search (string concatenation of `req.query.q`).
- **ES-03** Missing authentication: `/api/admin` is mounted without `requireAuth`, and
  `GET /api/admin/users` has no route-level guard (its siblings do).
- **ES-04** SSRF: `POST /api/webhooks/test` fetches a caller-supplied URL from the server.
- **ES-05** Path traversal: invoice download joins `req.query.file` onto the invoice directory.
- **ES-06** Hard-coded JWT signing secret in `src/config.ts`.
- **ES-07** Mass assignment: `PATCH /api/profile` passes `req.body` to `User.update`, whose
  allow-list includes `role`, so a customer can make themselves an admin.
- **ES-08** Fake GitHub token committed in `scripts/sync-catalog.ts`.
- **ES-09 / ES-10** `package-lock.json` pins `lodash@4.17.15` and `jsonwebtoken@8.5.0`.

## Negative controls (must not be reported)

- `GET /api/orders` filters by `req.user.id`; `POST /api/orders/:id/cancel` scopes the update to the caller.
- Product lookup by slug and the admin role update use `?` placeholders.
- `services/changelog.ts` runs `execFile('git', [...,'--', name])`: no shell, `--` ends option parsing.
- `PATCH /api/admin/users/:id/role` and `GET /api/admin/changelog` are guarded by `requireAuth, requireAdmin`.
- The receipts route strips directories with `path.basename` before `sendFile`.
