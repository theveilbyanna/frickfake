import { list, get } from '@vercel/blob';
import { timingSafeEqual } from 'node:crypto';

const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const csvCell = s => '"' + String(s ?? '').replace(/"/g, '""') + '"';

function sameKey(a, b) {
  const A = Buffer.from(String(a || ''));
  const B = Buffer.from(String(b || ''));
  return A.length > 0 && A.length === B.length && timingSafeEqual(A, B);
}

async function readAll() {
  const blobs = [];
  let cursor;
  do {
    const r = await list({ prefix: 'signups/', cursor, limit: 1000 });
    blobs.push(...r.blobs);
    cursor = r.hasMore ? r.cursor : undefined;
  } while (cursor);
  const rows = [];
  for (let i = 0; i < blobs.length; i += 20) {
    const batch = await Promise.all(blobs.slice(i, i + 20).map(async b => {
      try {
        const g = await get(b.url, { access: 'private', useCache: false });
        return g && g.stream ? JSON.parse(await new Response(g.stream).text()) : null;
      } catch { return null; }
    }));
    rows.push(...batch.filter(Boolean));
  }
  rows.sort((a, b) => (a.number || 1e9) - (b.number || 1e9) || String(a.joinedAt).localeCompare(String(b.joinedAt)));
  return rows;
}

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Robots-Tag', 'noindex, nofollow');
  if (!sameKey(req.query.key, process.env.ADMIN_KEY)) {
    res.status(401).setHeader('Content-Type', 'text/plain; charset=utf-8');
    return res.send('Not allowed.');
  }
  let rows;
  try { rows = await readAll(); } catch (e) {
    res.status(500).setHeader('Content-Type', 'text/plain; charset=utf-8');
    return res.send('Could not load sign-ups: ' + String((e && e.message) || ''));
  }

  if (req.query.format === 'csv') {
    const head = ['number', 'name', 'email', 'city', 'why', 'ref', 'joinedAt'];
    const csv = [head.join(',')].concat(rows.map(r => head.map(h => csvCell(r[h])).join(','))).join('\n');
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="frickfake-waitlist.csv"');
    return res.status(200).send(csv);
  }

  const byRef = {};
  const byCity = {};
  rows.forEach(r => {
    const k = r.ref || 'direct'; byRef[k] = (byRef[k] || 0) + 1;
    const c = (r.city || '').trim(); if (c) byCity[c] = (byCity[c] || 0) + 1;
  });
  const tally = o => Object.entries(o).sort((a, b) => b[1] - a[1]).map(([k, v]) => `<span class="chip">${esc(k)} · ${v}</span>`).join('') || '<span class="muted">none yet</span>';
  const emails = rows.map(r => r.email).join(', ');
  const key = encodeURIComponent(String(req.query.key));

  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  return res.status(200).send(`<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="robots" content="noindex"><title>FrickFake sign-ups</title>
<style>
:root{--ink:#0d0c0b;--bone:#f3ece0;--muted:#b2a796;--red:#e5322b;--line:#34302c;color-scheme:dark}
*{box-sizing:border-box}body{margin:0;background:var(--ink);color:var(--bone);font:16px/1.45 system-ui,-apple-system,Roboto,sans-serif}
.wrap{max-width:900px;margin:0 auto;padding:20px 16px 40px}h1{font:700 26px/1.1 Impact,'Arial Narrow Bold',sans-serif;text-transform:uppercase;letter-spacing:.02em;margin:0 0 4px}
.big{font:700 44px/1 ui-monospace,Menlo,monospace;color:var(--red);margin:10px 0 2px}.muted{color:var(--muted)}
.row{display:flex;flex-wrap:wrap;gap:8px;margin:14px 0}.btn{display:inline-flex;align-items:center;min-height:42px;padding:8px 14px;border:2px solid var(--bone);background:transparent;color:var(--bone);font-weight:700;text-decoration:none;cursor:pointer;font-size:15px}
.btn.red{background:var(--red);border-color:var(--red)}.chip{display:inline-block;padding:4px 8px;border:1px solid var(--line);margin:0 6px 6px 0;font-size:14px}
h2{font-size:15px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);margin:18px 0 6px}
.card{border:1px solid var(--line);padding:12px;margin:0 0 10px}.card b{font-family:ui-monospace,Menlo,monospace;color:var(--red)}.card .why{color:var(--muted);margin-top:6px;font-size:15px}
</style></head><body><div class="wrap">
<h1>FrickFake sign-ups</h1><div class="big">${rows.length}</div><div class="muted">real humans on the list</div>
<div class="row"><button class="btn red" id="copy">Copy all emails</button><a class="btn" href="/api/admin?key=${key}&format=csv">Download CSV</a></div>
<h2>Where they came from</h2><div>${tally(byRef)}</div>
<h2>Cities</h2><div>${tally(byCity)}</div>
<h2>Everyone</h2>
${rows.map(r => `<div class="card"><b>#${String(r.number || '?').padStart(6, '0')}</b> &nbsp;<strong>${esc(r.name)}</strong> · ${esc(r.email)}${r.city ? ' · ' + esc(r.city) : ''}<div class="muted" style="font-size:13px">${esc(r.joinedAt)}${r.ref ? ' · from ' + esc(r.ref) : ''}</div>${r.why ? `<div class="why">“${esc(r.why)}”</div>` : ''}</div>`).join('') || '<p class="muted">Nobody yet. Share your link!</p>'}
</div><script>
document.getElementById('copy').addEventListener('click',function(){var t=${JSON.stringify(emails).replace(/</g, '\\u003c')};if(navigator.clipboard)navigator.clipboard.writeText(t).then(function(){alert('Copied '+${rows.length}+' emails')});});
</script></body></html>`);
}
