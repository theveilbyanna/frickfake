// Founder Pack settings.
// link: the Stripe Payment Link for the Founder Pack (a public buy.stripe.com URL, safe to keep here).
// The app adds ?client_reference_id=ff_founder_<member id> to it, so Stripe tells us exactly who paid.
// paymentLinkId (optional, starts with plink_): if filled in, only purchases through that exact link count.
// If it's empty, a purchase counts when it carries an ff_founder_ reference and is at least `cents` in USD,
// so your other Stripe sales (The Veil, Pocket Built and so on) never turn on founder perks.
// The Founder Pack window only shows in the app once `link` is filled in.
export const FOUNDER = {
  price: '$10',
  cents: 1000,
  link: '',
  paymentLinkId: ''
};

// Looks that only Founders can pick (they're drawn in app.html, in THEMES).
export const FOUNDER_THEMES = ['holo', 'neon', 'outlaw'];

export const founderOffer = () => (FOUNDER.link ? { price: FOUNDER.price, link: FOUNDER.link } : null);

// Is this finished Stripe Checkout session a Founder Pack purchase?
export function isFounderSale(s) {
  if (!s || s.payment_status !== 'paid') return false;
  if (FOUNDER.paymentLinkId) return s.payment_link === FOUNDER.paymentLinkId;
  return /^ff_founder_\d+$/.test(String(s.client_reference_id || '')) &&
    Number(s.amount_total) >= FOUNDER.cents && String(s.currency || '').toLowerCase() === 'usd';
}
