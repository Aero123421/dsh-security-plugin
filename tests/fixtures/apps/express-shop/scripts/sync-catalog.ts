// INTENTIONALLY VULNERABLE TEST FIXTURE — do not deploy
// @ts-nocheck fixture: framework packages are not installed
// Pulls the product catalog JSON from the private catalog repository and
// upserts it into the local database. Run with: npx tsx scripts/sync-catalog.ts
import _ from 'lodash'
import { db } from '../src/db'

const GITHUB_TOKEN = 'ghp_R7mQ2xFAKE9kL4vT8nB3wY6cH1jF5gD0sA2e'
const CATALOG_URL = 'https://api.github.com/repos/example-shop/catalog/contents/products.json?ref=main'

interface CatalogProduct {
  slug: string
  name: string
  description: string
  priceCents: number
  stock: number
}

async function main(): Promise<void> {
  const response = await fetch(CATALOG_URL, {
    headers: {
      Authorization: `Bearer ${GITHUB_TOKEN}`,
      Accept: 'application/vnd.github.raw+json',
    },
  })
  if (!response.ok) throw new Error(`catalog fetch failed: ${response.status}`)
  // The export sometimes lists a product twice; keep the first occurrence.
  const products = _.uniqBy((await response.json()) as CatalogProduct[], 'slug')

  db.transaction(() => {
    for (const p of products) {
      db.run(
        `INSERT INTO products (slug, name, description, price_cents, stock, active)
         VALUES (?, ?, ?, ?, ?, 1)
         ON CONFLICT(slug) DO UPDATE SET name = excluded.name, description = excluded.description,
           price_cents = excluded.price_cents, stock = excluded.stock`,
        [p.slug, p.name, p.description, p.priceCents, p.stock],
      )
    }
  })
  console.log(`synced ${products.length} products`)
}

main().catch(err => {
  console.error(err)
  process.exit(1)
})
