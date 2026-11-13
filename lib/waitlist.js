import { put, get, list } from '@vercel/blob';
import { createHash } from 'node:crypto';

// Same storage rules as api/join.js, so app accounts and the waitlist share one set of numbers.
const SALT = 'ff-2026-real-humans-only';
const pathFor = email => `signups/${createHash('sha256').update(SALT + ':' + email).digest('hex').slice(0, 32)}.json`;
const hasBlob = () => Boolean(process.env.BLOB_READ_WRITE_TOKEN);

export async function waitlistLookup(email) {
  if (!hasBlob()) return null;
  const pathname = pathFor(email);
  for (const access of ['private', 'public']) {
    try {
      const r = await get(pathname, { access, useCache: false });
      if (r && r.stream) return JSON.parse(await new Response(r.stream).text());
      if (r === null) return null;
    } catch { /* try the other access type */ }
  }
  return null;
}

export async function waitlistCount() {
  if (!hasBlob()) return 0;
  let count = 0;
  let cursor;
  do {
    const r = await list({ prefix: 'signups/', cursor, limit: 1000 });
    count += r.blobs.length;
    cursor = r.hasMore ? r.cursor : undefined;
  } while (cursor);
  return count;
}

// Adds an app sign-up to the waitlist list too, so the next waitlist number skips past it.
export async function waitlistAdd(record) {
  if (!hasBlob()) return;
  const pathname = pathFor(record.email);
  const data = JSON.stringify(record);
  const opts = { contentType: 'application/json', addRandomSuffix: false, allowOverwrite: false };
  try {
    await put(pathname, data, { ...opts, access: 'private' });
  } catch (e) {
    if (/already exists/i.test(String((e && e.message) || ''))) return;
    try { await put(pathname, data, { ...opts, access: 'public' }); } catch { /* best effort */ }
  }
}
