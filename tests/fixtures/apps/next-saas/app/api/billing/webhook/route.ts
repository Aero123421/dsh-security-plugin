// INTENTIONALLY VULNERABLE TEST FIXTURE — do not deploy
// @ts-nocheck fixture: framework packages are not installed
import { NextResponse } from 'next/server'
import type Stripe from 'stripe'
import { stripe } from '@/lib/billing'
import { prisma } from '@/lib/db'

// POST /api/billing/webhook: Stripe subscription events. Authenticated by the
// Stripe signature rather than a user session.
export async function POST(req: Request) {
  const secret = process.env.STRIPE_WEBHOOK_SECRET
  if (!secret) return NextResponse.json({ error: 'webhook not configured' }, { status: 500 })
  const signature = req.headers.get('stripe-signature')
  if (!signature) return NextResponse.json({ error: 'missing signature' }, { status: 400 })

  let event: Stripe.Event
  try {
    event = stripe.webhooks.constructEvent(await req.text(), signature, secret)
  } catch {
    return NextResponse.json({ error: 'invalid signature' }, { status: 400 })
  }

  if (event.type === 'customer.subscription.updated') {
    const subscription = event.data.object as Stripe.Subscription
    const orgId = subscription.metadata.orgId
    const seats = subscription.items.data[0]?.quantity ?? 0
    if (orgId) await prisma.org.update({ where: { id: orgId }, data: { seatLimit: seats } })
  }
  return NextResponse.json({ received: true })
}
