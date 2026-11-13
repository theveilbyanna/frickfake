import { list } from '@vercel/blob';

export default async function handler(req, res) {
  try {
    let count = 0;
    let cursor;
    do {
      const r = await list({ prefix: 'signups/', cursor, limit: 1000 });
      count += r.blobs.length;
      cursor = r.hasMore ? r.cursor : undefined;
    } while (cursor && count < 200000);
    res.setHeader('Cache-Control', 's-maxage=60, stale-while-revalidate=300');
    return res.status(200).json({ count });
  } catch (e) {
    console.error('count failed', String((e && e.message) || ''));
    return res.status(200).json({ count: null });
  }
}
