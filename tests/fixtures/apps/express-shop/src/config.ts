// INTENTIONALLY VULNERABLE TEST FIXTURE — do not deploy
// @ts-nocheck fixture: framework packages are not installed
import path from 'node:path'

const root = path.resolve(__dirname, '..')

export const config = {
  port: Number(process.env.PORT ?? 3000),
  databaseFile: process.env.DATABASE_FILE ?? path.join(root, 'data', 'shop.sqlite'),

  // Access tokens issued by POST /api/auth/login.
  jwtSecret: 'Sh0pJwt9vQ2mX7pL4wR8zN3bFAKE',
  jwtExpiresIn: '12h',

  invoiceDir: path.join(root, 'storage', 'invoices'),
  receiptDir: path.join(root, 'storage', 'receipts'),
  repoDir: root,
}
