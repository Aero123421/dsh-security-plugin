// INTENTIONALLY VULNERABLE TEST FIXTURE — do not deploy
// @ts-nocheck fixture: framework packages are not installed
import { db, type SqlParam } from '../db'

export interface UserRow {
  id: number
  email: string
  name: string
  address: string | null
  role: 'customer' | 'admin'
  created_at: string
}

const COLUMNS = 'id, email, name, address, role, created_at'

// Columns User.update may write. Shared by the profile page and the admin
// console, so it covers every editable column.
const WRITABLE_COLUMNS = ['email', 'name', 'address', 'role'] as const

export const User = {
  findById(id: number): UserRow | undefined {
    return db.one<UserRow>(`SELECT ${COLUMNS} FROM users WHERE id = ?`, [id])
  },

  findByEmail(email: string): (UserRow & { password_hash: string }) | undefined {
    return db.one(`SELECT ${COLUMNS}, password_hash FROM users WHERE email = ?`, [email.toLowerCase()])
  },

  list(): UserRow[] {
    return db.query<UserRow>(`SELECT ${COLUMNS} FROM users ORDER BY id`)
  },

  update(id: number, fields: Record<string, unknown>): UserRow | undefined {
    const sets: string[] = []
    const values: SqlParam[] = []
    for (const column of WRITABLE_COLUMNS) {
      if (fields[column] === undefined) continue
      sets.push(`${column} = ?`)
      values.push(fields[column] as SqlParam)
    }
    if (sets.length > 0) {
      db.run(`UPDATE users SET ${sets.join(', ')} WHERE id = ?`, [...values, id])
    }
    return User.findById(id)
  },
}
