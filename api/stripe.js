import { createHmac, timingSafeEqual } from 'node:crypto';
import { getSql, ready } from '../lib/db.js';
import { isFounderSale } from '../lib/founder.js';

// Stripe webhook: POST /api/stripe
// When someone pays for the Founder Pack, Stripe calls this and their founder perks turn on.
// Needs STRIPE_WEBHOOK_SECRET (the "Signing secret" from the webhook in Stripe) in Vercel's environment variables.

const json = (data, status = 200) => new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' } });

// Checks Stripe's signature so nobody can fake a payment.
export function verifyStripe(raw, header, secret, toleranceSec = 300, nowMs = Date.now()) {
  if (!raw || !header || !secret) return false;
  const parts = String(header).split(',').map(p => p.trim().split('='));
  const t = (parts.find(([k]) => k === 't') || [])[1];
  const sigs = parts.filter(([k]) => k === 'v1').map(([, v]) => v).filter(Boolean);
  if (!t || !sigs.length || !/^\d+$/.test(t)) return false;
  if (Math.abs(nowMs / 1000 - Number(t)) > toleranceSec) return false;
  const expected = Buffer.from(createHmac('sha256', secret).update(`${t}.${raw}`, 'utf8').digest('hex'));
  return sigs.some(s => { const b = Buffer.from(s); return b.length === expected.length && timingSafeEqual(b, expected); });
}

// Records the payment once and turns on founder perks for the member who paid.
export async function grantFounder(sql, s) {
  const m = /^ff_founder_(\d+)$/.exec(String(s.client_reference_id || ''));
  const ref = m ? Number(m[1]) : 0;
  const email = String((s.customer_details && s.customer_details.email) || s.customer_email || '').trim().toLowerCase().slice(0, 254);
  let rows = Number.isInteger(ref) && ref > 0 ? await sql`SELECT id FROM ff_users WHERE id = ${ref}` : [];
  if (!rows.length && email) rows = await sql`SELECT id FROM ff_users WHERE email = ${email}`;
  const uid = rows[0] ? rows[0].id : null;
  await sql`INSERT INTO ff_payments (session_id, user_id, email, amount, currency, kind)
            VALUES (${String(s.id)}, ${uid}, ${email}, ${Number(s.amount_total) || 0}, ${String(s.currency || '')}, 'founder')
            ON CONFLICT (session_id) DO NOTHING`;
  if (uid) await sql`UPDATE ff_users SET founder = TRUE, founder_at = COALESCE(founder_at, now()) WHERE id = ${uid}`;
  return uid;
}

export async function POST(request) {
  const secret = String(process.env.STRIPE_WEBHOOK_SECRET || '').trim();
  if (!secret) return json({ ok: false, error: 'Stripe isn’t set up yet.' }, 503);
  const raw = await request.text();
  if (!verifyStripe(raw, request.headers.get('stripe-signature'), secret)) return json({ ok: false, error: 'Bad signature.' }, 400);
  let event;
  try { event = JSON.parse(raw); } catch { return json({ ok: false, error: 'Bad JSON.' }, 400); }

  const type = String(event.type || '');
  const s = (event.data && event.data.object) || {};
  const done = type === 'checkout.session.completed' || type === 'checkout.session.async_payment_succeeded';
  // Only Founder Pack purchases count. Anything else on your Stripe account is ignored.
  if (!done || !isFounderSale(s)) {
    return json({ received: true, ignored: true });
  }
  const sql = getSql();
  if (!sql) return json({ ok: false, error: 'Database not connected.' }, 503);
  try {
    await ready(sql);
    await grantFounder(sql, s);
  } catch (e) {
    console.error('founder grant failed', String((e && e.message) || e));
    return json({ ok: false, error: 'Couldn’t save that. Stripe will try again.' }, 500);
  }
  return json({ received: true });
}

export function GET() {
  return new Response('FrickFake Stripe webhook. Stripe sends payments here.', { status: 200, headers: { 'Content-Type': 'text/plain' } });
}
