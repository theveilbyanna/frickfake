import { put, get, list } from '@vercel/blob';
import { createHash } from 'node:crypto';
import { TERMS_VERSION } from '../lib/terms.js';

const EMAIL_RE = /^[^\s@]{1,64}@[^\s@]{1,190}\.[^\s@]{2,24}$/;
const clean = (v, n) => String(v ?? '').replace(/[\u0000-\u001f\u007f]/g, ' ').trim().slice(0, n);

// Works with a private Blob store (preferred) or a public one.
async function readRecord(pathname) {
  for (const access of ['private', 'public']) {
    try {
      const r = await get(pathname, { access, useCache: false });
      if (r && r.stream) return JSON.parse(await new Response(r.stream).text());
      if (r === null) return null;
    } catch { /* try the other access type */ }
  }
  return null;
}

async function save(pathname, data, overwrite = false) {
  const opts = { contentType: 'application/json', addRandomSuffix: false, allowOverwrite: overwrite };
  try {
    return await put(pathname, data, { ...opts, access: 'private' });
  } catch (e) {
    const msg = String((e && e.message) || '');
    if (/already exists/i.test(msg)) throw e;
    return await put(pathname, data, { ...opts, access: 'public' });
  }
}

async function countSignups() {
  let count = 0;
  let cursor;
  do {
    const r = await list({ prefix: 'signups/', cursor, limit: 1000 });
    count += r.blobs.length;
    cursor = r.hasMore ? r.cursor : undefined;
  } while (cursor);
  return count;
}

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({ ok: false, error: 'Use POST.' });
  }
  let body = req.body;
  if (typeof body === 'string') { try { body = JSON.parse(body); } catch { body = {}; } }
  body = body || {};

  // Honeypot: real people never fill this hidden field.
  if (body.website) return res.status(200).json({ ok: true });

  const name = clean(body.name, 60);
  const email = clean(body.email, 254).toLowerCase();
  if (!name) return res.status(400).json({ ok: false, error: 'Add your first name or screen name.' });
  if (!EMAIL_RE.test(email)) return res.status(400).json({ ok: false, error: 'That email doesn’t look right. Check it and try again.' });
  if (body.human !== true) return res.status(400).json({ ok: false, error: 'Check the box to confirm you’re a real human, 18 or older, and OK with the Terms.' });

  const salt = 'ff-2026-real-humans-only';
  const id = createHash('sha256').update(salt + ':' + email).digest('hex').slice(0, 32);
  const pathname = `signups/${id}.json`;

  // Same email again: give back the number they already have.
  const existing = await readRecord(pathname);
  if (existing && !existing.deleted) return res.status(200).json({ ok: true, already: true, number: existing.number || null });
  // existing.deleted: they deleted their account before. Their info was erased; give them back their old number.
  const returning = Boolean(existing && existing.deleted);

  let number = returning ? (existing.number || null) : null;
  if (!returning) { try { number = (await countSignups()) + 1; } catch { number = null; } }

  const record = {
    number,
    name,
    email,
    city: clean(body.city, 80),
    why: clean(body.why, 500),
    ref: clean(body.ref, 40),
    joinedAt: new Date().toISOString(),
    // The box they checked also confirms 18+ and agreement to the Terms, Guidelines and Privacy Policy of this date.
    terms: TERMS_VERSION
  };

  try {
    await save(pathname, JSON.stringify(record), returning);
  } catch (e) {
    const msg = String((e && e.message) || '');
    if (/already exists/i.test(msg)) {
      const again = await readRecord(pathname);
      return res.status(200).json({ ok: true, already: true, number: (again && again.number) || null });
    }
    console.error('signup save failed', msg);
    return res.status(500).json({ ok: false, error: 'Something broke on our end. Try again in a minute.' });
  }
  return res.status(200).json({ ok: true, number });
}
