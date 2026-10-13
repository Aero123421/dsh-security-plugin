// INTENTIONALLY VULNERABLE TEST FIXTURE — do not deploy
// @ts-nocheck fixture: framework packages are not installed
import Stripe from 'stripe'

export const stripe = new Stripe(process.env.STRIPE_SECRET_KEY ?? '', { apiVersion: '2024-06-20' })

/** Keep the subscription's seat quantity in step with the organization's seat limit. */
export async function setSeatQuantity(subscriptionId: string, seats: number): Promise<void> {
  const subscription = await stripe.subscriptions.retrieve(subscriptionId)
  const item = subscription.items.data[0]
  if (!item) throw new Error(`subscription ${subscriptionId} has no items`)
  await stripe.subscriptionItems.update(item.id, { quantity: seats, proration_behavior: 'create_prorations' })
}
