import { scrypt as scryptCb, randomBytes, timingSafeEqual, createHash } from 'node:crypto';
import { promisify } from 'node:util';
import { getSql, ready } from '../lib/db.js';
import { waitlistLookup, waitlistCount, waitlistAdd, waitlistForget } from '../lib/waitlist.js';
import { TERMS_VERSION } from '../lib/terms.js';
import { FOUNDER_THEMES, founderOffer } from '../lib/founder.js';

// FrickFake app API. Every request is POST /api/app with JSON { action, ... }.

const scrypt = promisify(scryptCb);
const COOKIE = 'ff_session';
const SESSION_DAYS = 90;
const STATUSES = ['free', 'away', 'dnd', 'invisible'];
const IDEA_STATES = ['open', 'planned', 'done', 'hidden'];
const RESERVED = new Set(['admin', 'frickfake', 'support', 'moderator', 'mod', 'official', 'staff', 'root', 'system', 'help']);
const EMAIL_RE = /^[^\s@]{1,64}@[^\s@]{1,190}\.[^\s@]{2,24}$/;
const SN_RE = /^[A-Za-z0-9_.-]{3,20}$/;
// Profile looks members can pick (the app has the colors for each one).
const THEMES = ['classic', 'midnight', 'bubblegum', 'toxic', 'ocean', 'coffin', 'sunset', 'lavender', 'gold', 'denim', ...FOUNDER_THEMES];
const ACCENT_RE = /^#[0-9a-f]{6}$/i;
const PHOTO_MAX = 250000; // bytes, after the app shrinks it to 400x400
// Same admin key as api/admin.js (only its SHA-256 is stored). FF_ADMIN_KEY in Vercel also works.
const ADMIN_KEY_SHA256S = [
  '049e2ae46c9c007df49a21f695ba0289026e3c76d4840cfbe2dbb6ba8d7b2880', // original key
  'fa5b3c954316ef19124652c04b63470ce8ea6cbebfadfcd7ba0e0a163ee05fe0'  // second key (Nov 18, 2026)
];

class Oops extends Error {
  constructor(message, status = 400, code = 'bad') { super(message); this.status = status; this.code = code; }
}
const oops = (m, s, c) => new Oops(m, s, c);

const clean = (v, n) => String(v ?? '').replace(/[\u0000-\u001f\u007f]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, n);
const cleanText = (v, n) => String(v ?? '').replace(/\r\n?/g, '\n').replace(/[\u0000-\u0009\u000b-\u001f\u007f]/g, ' ').replace(/\n{4,}/g, '\n\n\n').trim().slice(0, n);
const int = v => { const n = Number(v); return Number.isInteger(n) && n > 0 && n < 2147483647 ? n : null; };
const sha = s => createHash('sha256').update(String(s)).digest('hex');
const likePat = s => '%' + String(s).toLowerCase().replace(/[\\%_]/g, c => '\\' + c) + '%';

async function hashPw(pw) {
  const salt = randomBytes(16);
  const key = await scrypt(pw, salt, 64, { N: 16384, r: 8, p: 1 });
  return `s1$${salt.toString('base64')}$${key.toString('base64')}`;
}
async function checkPw(pw, stored) {
  const [tag, s, k] = String(stored || '').split('$');
  if (tag !== 's1' || !s || !k) return false;
  const want = Buffer.from(k, 'base64');
  const got = await scrypt(pw, Buffer.from(s, 'base64'), want.length, { N: 16384, r: 8, p: 1 });
  return got.length === want.length && timingSafeEqual(got, want);
}

// Forgives phone-keyboard slips: extra spaces, quotes or backticks, a trailing period, a capital first letter.
function keyVariants(key) {
  const raw = String(key ?? '');
  const t = raw.trim();
  const n = t.replace(/[`'"\u201c\u201d\u2018\u2019\s]/g, '').replace(/[.,;:!]+$/, '');
  return [...new Set([raw, t, n, n.toLowerCase()])].filter(Boolean);
}

function adminOk(key) {
  if (!key) return false;
  const ok = [...ADMIN_KEY_SHA256S, process.env.FF_ADMIN_KEY ? sha(process.env.FF_ADMIN_KEY) : null].filter(Boolean);
  return keyVariants(key).some(k => {
    const a = Buffer.from(sha(k));
    return ok.some(h => { const b = Buffer.from(h); return a.length === b.length && timingSafeEqual(a, b); });
  });
}

function readCookie(req, name) {
  const raw = (req.headers && req.headers.cookie) || '';
  for (const part of raw.split(';')) {
    const i = part.indexOf('=');
    if (i > 0 && part.slice(0, i).trim() === name) return decodeURIComponent(part.slice(i + 1).trim());
  }
  return '';
}
function setSessionCookie(res, token) {
  res.setHeader('Set-Cookie', `${COOKIE}=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${SESSION_DAYS * 86400}`);
}
function clearSessionCookie(res) {
  res.setHeader('Set-Cookie', `${COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`);
}

async function startSession(sql, res, userId) {
  const token = randomBytes(32).toString('base64url');
  const expires = new Date(Date.now() + SESSION_DAYS * 86400000).toISOString();
  await sql`INSERT INTO ff_sessions (token_hash, user_id, expires_at) VALUES (${sha(token)}, ${userId}, ${expires})`;
  await sql`DELETE FROM ff_sessions WHERE user_id = ${userId} AND expires_at < now()`;
  setSessionCookie(res, token);
}

async function currentUser(ctx) {
  const token = readCookie(ctx.req, COOKIE);
  if (!token) return null;
  const rows = await ctx.sql`SELECT u.* FROM ff_sessions s JOIN ff_users u ON u.id = s.user_id
                             WHERE s.token_hash = ${sha(token)} AND s.expires_at > now()`;
  const u = rows[0];
  if (!u) return null;
  if (u.banned) {
    await ctx.sql`DELETE FROM ff_sessions WHERE user_id = ${u.id}`;
    clearSessionCookie(ctx.res);
    throw oops('This account was removed for breaking the house rules.', 403, 'banned');
  }
  return u;
}

// photo_v counts up each time a photo changes; it goes negative when the photo is removed.
const pv = u => Math.max(Number(u.photo_v) || 0, 0);
const idList = s => [...new Set(String(s || '').split(',').map(x => int(x)).filter(Boolean))].slice(0, 8);

const meOut = u => ({
  id: u.id, number: u.number, screen_name: u.screen_name, email: u.email,
  city: u.city, interests: u.interests, bio: u.bio, status: u.status, away_msg: u.away_msg,
  verified: u.verified, from_waitlist: u.from_waitlist, created_at: u.created_at,
  photo_v: pv(u), theme: u.theme || 'classic', accent: u.accent || '', song: u.song || '', top8: idList(u.top8),
  founder: Boolean(u.founder), founder_offer: u.verified && !u.founder ? founderOffer() : null
});

// Accepts Spotify, YouTube and SoundCloud links and stores a clean copy.
function songNorm(raw) {
  const s = clean(raw, 400);
  if (!s) return '';
  const bad = oops('Paste a song link from Spotify, YouTube or SoundCloud.', 400, 'song');
  let u;
  try { u = new URL(/^https?:\/\//i.test(s) ? s : 'https://' + s); } catch { throw bad; }
  const host = u.hostname.toLowerCase().replace(/^(www|m)\./, '');
  if (host === 'open.spotify.com') {
    const m = u.pathname.match(/^\/(?:intl-[a-z]{2}(?:-[a-z]{2})?\/)?(track|album|playlist|episode|artist|show)\/([A-Za-z0-9]{10,40})/);
    if (m) return `https://open.spotify.com/${m[1]}/${m[2]}`;
  }
  if (host === 'youtube.com' || host === 'music.youtube.com') {
    let id = u.searchParams.get('v');
    if (!id) { const m = u.pathname.match(/^\/(?:shorts|embed|live)\/([A-Za-z0-9_-]{11})/); if (m) id = m[1]; }
    if (id && /^[A-Za-z0-9_-]{11}$/.test(id)) return `https://www.youtube.com/watch?v=${id}`;
  }
  if (host === 'youtu.be') {
    const id = u.pathname.slice(1).split('/')[0];
    if (/^[A-Za-z0-9_-]{11}$/.test(id)) return `https://www.youtube.com/watch?v=${id}`;
  }
  if (host === 'soundcloud.com') {
    const p = u.pathname.replace(/\/+$/, '');
    if (/^\/[A-Za-z0-9_-]+\/(?:sets\/)?[A-Za-z0-9_-]+$/.test(p)) return `https://soundcloud.com${p}`;
  }
  throw bad;
}

// When two people stop being buddies, they come out of each other's Top 8.
async function dropFromTop8(sql, a, b) {
  await sql`UPDATE ff_users SET top8 = COALESCE(array_to_string(array_remove(string_to_array(NULLIF(top8, ''), ','), ${String(b)}), ','), '') WHERE id = ${a}`;
  await sql`UPDATE ff_users SET top8 = COALESCE(array_to_string(array_remove(string_to_array(NULLIF(top8, ''), ','), ${String(a)}), ','), '') WHERE id = ${b}`;
}

async function buddyIds(sql, id) {
  const rows = await sql`SELECT CASE WHEN from_id = ${id} THEN to_id ELSE from_id END AS other
                         FROM ff_buddies WHERE state = 'accepted' AND (from_id = ${id} OR to_id = ${id})`;
  return new Set(rows.map(r => r.other));
}

// The buddy row between two people, whichever way it was sent.
async function pair(sql, a, b) {
  const rows = await sql`SELECT * FROM ff_buddies
    WHERE LEAST(from_id, to_id) = LEAST(${a}::int, ${b}::int) AND GREATEST(from_id, to_id) = GREATEST(${a}::int, ${b}::int)`;
  return rows[0] || null;
}
async function blockedEither(sql, a, b) {
  const rows = await sql`SELECT blocker_id FROM ff_blocks
    WHERE (blocker_id = ${a} AND blocked_id = ${b}) OR (blocker_id = ${b} AND blocked_id = ${a})`;
  return { iBlocked: rows.some(r => r.blocker_id === a), theyBlocked: rows.some(r => r.blocker_id === b) };
}
async function mustBeBuddies(sql, me, other) {
  const p = await pair(sql, me, other);
  if (!p || p.state !== 'accepted') throw oops('You can only message people on your buddy list.', 403, 'not_buddies');
  const bl = await blockedEither(sql, me, other);
  if (bl.iBlocked || bl.theyBlocked) throw oops('You can’t message this person.', 403, 'blocked');
}
function relFor(row, me) {
  if (!row) return null;
  if (row.state === 'accepted') return 'buddies';
  if (row.from_id === me) return 'sent';
  return row.state === 'pending' ? 'received' : null;
}

async function findTarget(sql, who) {
  const s = clean(who, 40);
  if (!s) return null;
  let rows;
  if (/^#?\d{1,9}$/.test(s)) rows = await sql`SELECT * FROM ff_users WHERE number = ${Number(s.replace('#', ''))}`;
  else rows = await sql`SELECT * FROM ff_users WHERE sn_key = ${s.toLowerCase()}`;
  return rows[0] || null;
}

function checkScreenName(sn) {
  if (!SN_RE.test(sn) || !/[A-Za-z]/.test(sn)) throw oops('Screen names are 3 to 20 letters, numbers, dots, dashes or underscores.', 400, 'screen_name');
  if (RESERVED.has(sn.toLowerCase())) throw oops('That screen name is taken. Try another.', 400, 'screen_name');
}
function uniqueErr(e) {
  if (!e || e.code !== '23505') return null;
  const m = String(e.constraint || '') + ' ' + String(e.message || '');
  if (/email/.test(m)) return 'email';
  if (/sn_key/.test(m)) return 'screen_name';
  if (/number/.test(m)) return 'number';
  return 'other';
}

// ---------- public actions ----------
const PUBLIC = {
  async me(ctx) {
    const u = await currentUser(ctx);
    return { me: u ? meOut(u) : null };
  },

  async signup(ctx) {
    const { sql, body: b } = ctx;
    if (b.website) throw oops('Something went wrong. Try again.');
    const screen = clean(b.screen_name, 40);
    checkScreenName(screen);
    const email = clean(b.email, 254).toLowerCase();
    if (!EMAIL_RE.test(email)) throw oops('That email doesn’t look right. Check it and try again.', 400, 'email');
    const pw = String(b.password ?? '');
    if (pw.length < 8) throw oops('Make your password at least 8 characters.', 400, 'password');
    if (pw.length > 200) throw oops('That password is too long.', 400, 'password');
    // The box confirms they're a real human, 18 or older, and agree to the Terms, Guidelines and Privacy Policy.
    if (b.human !== true) throw oops('Check the box to confirm you’re a real human, 18 or older, and OK with the Terms.', 400, 'human');
    const city = clean(b.city, 80);
    const interests = clean(b.interests, 200);

    if ((await sql`SELECT 1 FROM ff_users WHERE email = ${email}`).length) throw oops('That email already has an account. Log in instead.', 400, 'exists');
    if ((await sql`SELECT 1 FROM ff_users WHERE sn_key = ${screen.toLowerCase()}`).length) throw oops('That screen name is taken. Try another.', 400, 'screen_name');

    const passHash = await hashPw(pw);
    let wl = null;
    try { wl = await waitlistLookup(email); } catch { wl = null; }
    let keep = null;
    if (wl && int(wl.number)) {
      const taken = await sql`SELECT 1 FROM ff_users WHERE number = ${wl.number}`;
      if (!taken.length) keep = wl.number;
    }

    let user = null;
    for (let attempt = 0; attempt < 6 && !user; attempt++) {
      let n = keep;
      if (!n) {
        const [{ m }] = await sql`SELECT COALESCE(MAX(number), 0)::int AS m FROM ff_users`;
        let wc = 0;
        try { wc = await waitlistCount(); } catch { wc = 0; }
        n = Math.max(m, wc) + 1 + attempt;
      }
      try {
        const rows = await sql`INSERT INTO ff_users
            (number, screen_name, sn_key, email, pass_hash, city, interests, from_waitlist, waitlist_name, why, terms_at, terms_v)
          VALUES (${n}, ${screen}, ${screen.toLowerCase()}, ${email}, ${passHash}, ${city || clean(wl && wl.city, 80)}, ${interests},
                  ${Boolean(keep)}, ${clean(wl && wl.name, 60)}, ${clean(wl && wl.why, 500)}, now(), ${TERMS_VERSION})
          RETURNING *`;
        user = rows[0];
      } catch (e) {
        const which = uniqueErr(e);
        if (which === 'email') throw oops('That email already has an account. Log in instead.', 400, 'exists');
        if (which === 'screen_name') throw oops('That screen name is taken. Try another.', 400, 'screen_name');
        if (which === 'number') { keep = null; continue; }
        throw e;
      }
    }
    if (!user) throw oops('Couldn’t hand out a number just now. Try again in a minute.', 500, 'number');

    if (!wl || wl.deleted) {
      waitlistAdd({ number: user.number, name: screen, email, city, why: '', ref: 'app', joinedAt: new Date().toISOString(), terms: TERMS_VERSION },
        { overwrite: Boolean(wl && wl.deleted) }).catch(() => {});
    }
    // Bought the Founder Pack before making an account? Hook it up now.
    try {
      const paid = await sql`UPDATE ff_payments SET user_id = ${user.id} WHERE user_id IS NULL AND email = ${email} AND kind = 'founder' RETURNING session_id`;
      if (paid.length) user = (await sql`UPDATE ff_users SET founder = TRUE, founder_at = now() WHERE id = ${user.id} RETURNING *`)[0];
    } catch (e) { console.error('founder link-up failed', String((e && e.message) || e)); }
    await startSession(sql, ctx.res, user.id);
    return { me: meOut(user), kept_number: Boolean(keep) };
  },

  async login(ctx) {
    const { sql, body: b } = ctx;
    const id = clean(b.login, 254);
    const pw = String(b.password ?? '');
    if (!id || !pw) throw oops('Enter your login and password.', 400, 'login');
    let rows;
    if (id.includes('@')) rows = await sql`SELECT * FROM ff_users WHERE email = ${id.toLowerCase()}`;
    else if (/^#?\d{1,9}$/.test(id)) rows = await sql`SELECT * FROM ff_users WHERE number = ${Number(id.replace('#', ''))}`;
    else rows = await sql`SELECT * FROM ff_users WHERE sn_key = ${id.toLowerCase()}`;
    const u = rows[0];
    const bad = oops('That login and password don’t match.', 401, 'login');
    if (!u) { await hashPw(pw); throw bad; }
    if (u.locked_until && new Date(u.locked_until) > new Date()) throw oops('Too many wrong tries. Wait 15 minutes and try again.', 429, 'locked');
    if (!(await checkPw(pw, u.pass_hash))) {
      const fails = (u.fails || 0) + 1;
      if (fails >= 8) await sql`UPDATE ff_users SET fails = 0, locked_until = now() + interval '15 minutes' WHERE id = ${u.id}`;
      else await sql`UPDATE ff_users SET fails = ${fails} WHERE id = ${u.id}`;
      throw bad;
    }
    if (u.banned) throw oops('This account was removed for breaking the house rules.', 403, 'banned');
    await sql`UPDATE ff_users SET fails = 0, locked_until = NULL, last_seen = now() WHERE id = ${u.id}`;
    await startSession(sql, ctx.res, u.id);
    return { me: meOut(u) };
  },

  async logout(ctx) {
    const token = readCookie(ctx.req, COOKIE);
    if (token) await ctx.sql`DELETE FROM ff_sessions WHERE token_hash = ${sha(token)}`;
    clearSessionCookie(ctx.res);
    return {};
  }
};

// ---------- signed-in actions (pending members can use these) ----------
const USER = {
  async poll(ctx) {
    const { sql, me, body: b } = ctx;
    if (!me.last_seen || Date.now() - new Date(me.last_seen).getTime() > 20000) {
      await sql`UPDATE ff_users SET last_seen = now() WHERE id = ${me.id}`;
    }
    if (!me.verified) return { me: meOut(me) };
    const id = me.id;

    const buddies = await sql`
      SELECT u.id, u.number, u.screen_name, u.city, u.status, u.away_msg, GREATEST(u.photo_v, 0) AS photo_v, u.founder,
        CASE WHEN u.status = 'invisible' OR u.last_seen IS NULL OR u.last_seen < now() - interval '150 seconds'
             THEN 'offline' ELSE u.status END AS presence,
        CASE WHEN u.status = 'invisible' THEN NULL ELSE u.last_seen END AS last_seen,
        (SELECT COUNT(*)::int FROM ff_messages m WHERE m.from_id = u.id AND m.to_id = ${id} AND m.read_at IS NULL) AS unread
      FROM ff_buddies b JOIN ff_users u ON u.id = CASE WHEN b.from_id = ${id} THEN b.to_id ELSE b.from_id END
      WHERE b.state = 'accepted' AND (b.from_id = ${id} OR b.to_id = ${id}) AND NOT u.banned
      ORDER BY u.sn_key`;
    const buddyOut = buddies.map(x => ({
      id: x.id, number: x.number, screen_name: x.screen_name, city: x.city, presence: x.presence, photo_v: x.photo_v,
      away_msg: x.presence === 'away' || x.presence === 'dnd' ? x.away_msg : '', last_seen: x.last_seen, unread: x.unread, founder: x.founder
    }));

    const incoming = await sql`
      SELECT r.id AS req_id, u.id, u.number, u.screen_name, u.city, u.interests, GREATEST(u.photo_v, 0) AS photo_v,
        (SELECT COALESCE(array_agg(m.screen_name ORDER BY m.sn_key), '{}')
           FROM ff_buddies b2 JOIN ff_users m ON m.id = CASE WHEN b2.from_id = u.id THEN b2.to_id ELSE b2.from_id END
           WHERE b2.state = 'accepted' AND (b2.from_id = u.id OR b2.to_id = u.id) AND NOT m.banned
             AND m.id IN (SELECT CASE WHEN b3.from_id = ${id} THEN b3.to_id ELSE b3.from_id END
                          FROM ff_buddies b3 WHERE b3.state = 'accepted' AND (b3.from_id = ${id} OR b3.to_id = ${id}))) AS mutual
      FROM ff_buddies r JOIN ff_users u ON u.id = r.from_id
      WHERE r.to_id = ${id} AND r.state = 'pending' AND NOT u.banned
        AND NOT EXISTS (SELECT 1 FROM ff_blocks k WHERE k.blocker_id = ${id} AND k.blocked_id = u.id)
      ORDER BY r.id`;

    const outgoing = await sql`
      SELECT u.id, u.number, u.screen_name FROM ff_buddies b JOIN ff_users u ON u.id = b.to_id
      WHERE b.from_id = ${id} AND b.state IN ('pending', 'declined') AND NOT u.banned ORDER BY b.id`;

    const out = { me: meOut(me), buddies: buddyOut, incoming, outgoing };

    const chat = int(b.chat);
    if (chat && buddies.some(x => x.id === chat)) {
      const after = int(b.after) || 0;
      out.messages = await sql`
        SELECT id, from_id, body, created_at FROM ff_messages
        WHERE ((from_id = ${id} AND to_id = ${chat}) OR (from_id = ${chat} AND to_id = ${id})) AND id > ${after}
        ORDER BY id LIMIT 200`;
      await sql`UPDATE ff_messages SET read_at = now() WHERE to_id = ${id} AND from_id = ${chat} AND read_at IS NULL`;
      const seen = await sql`SELECT COALESCE(MAX(id), 0)::int AS s FROM ff_messages
                             WHERE from_id = ${id} AND to_id = ${chat} AND read_at IS NOT NULL`;
      out.seen_up_to = seen[0].s;
      out.unread_cleared = chat;
    }
    return out;
  },

  async update_profile(ctx) {
    const { sql, me, body: b } = ctx;
    const next = {
      screen_name: me.screen_name, city: me.city, interests: me.interests, bio: me.bio, status: me.status, away_msg: me.away_msg
    };
    if (b.screen_name !== undefined) {
      const sn = clean(b.screen_name, 40);
      if (sn !== me.screen_name) {
        checkScreenName(sn);
        const taken = await sql`SELECT 1 FROM ff_users WHERE sn_key = ${sn.toLowerCase()} AND id <> ${me.id}`;
        if (taken.length) throw oops('That screen name is taken. Try another.', 400, 'screen_name');
        next.screen_name = sn;
      }
    }
    if (b.city !== undefined) next.city = clean(b.city, 80);
    if (b.interests !== undefined) next.interests = clean(b.interests, 200);
    if (b.bio !== undefined) next.bio = cleanText(b.bio, 300);
    if (b.status !== undefined) {
      if (!STATUSES.includes(b.status)) throw oops('Pick a status from the list.');
      next.status = b.status;
    }
    if (b.away_msg !== undefined) next.away_msg = clean(b.away_msg, 120);
    next.theme = me.theme || 'classic'; next.accent = me.accent || ''; next.song = me.song || ''; next.top8 = me.top8 || '';
    if (b.theme !== undefined) {
      if (!THEMES.includes(b.theme)) throw oops('Pick a look from the list.', 400, 'theme');
      if (FOUNDER_THEMES.includes(b.theme) && !me.founder) throw oops('That look comes with the Founder Pack.', 403, 'founder');
      next.theme = b.theme;
    }
    if (b.accent !== undefined) {
      const a = clean(b.accent, 7).toLowerCase();
      if (a && !ACCENT_RE.test(a)) throw oops('That color didn’t work. Pick another.', 400, 'accent');
      next.accent = a;
    }
    if (b.song !== undefined) next.song = songNorm(b.song);
    if (b.top8 !== undefined) {
      const want = Array.isArray(b.top8) ? idList(b.top8.join(',')) : [];
      const mine = await buddyIds(sql, me.id);
      next.top8 = want.filter(id => mine.has(id)).join(',');
    }
    let rows;
    try {
      rows = await sql`UPDATE ff_users SET screen_name = ${next.screen_name}, sn_key = ${next.screen_name.toLowerCase()},
          city = ${next.city}, interests = ${next.interests}, bio = ${next.bio}, status = ${next.status},
          away_msg = ${next.away_msg}, theme = ${next.theme}, accent = ${next.accent}, song = ${next.song},
          top8 = ${next.top8}, last_seen = now()
        WHERE id = ${me.id} RETURNING *`;
    } catch (e) {
      if (uniqueErr(e) === 'screen_name') throw oops('That screen name is taken. Try another.', 400, 'screen_name');
      throw e;
    }
    return { me: meOut(rows[0]) };
  },

  async set_photo(ctx) {
    const { sql, me, body: b } = ctx;
    const m = String(b.photo || '').match(/^data:image\/jpeg;base64,([A-Za-z0-9+/]+={0,2})$/);
    const buf = m ? Buffer.from(m[1], 'base64') : null;
    if (!buf || buf.length < 400 || buf.length > PHOTO_MAX || buf[0] !== 0xff || buf[1] !== 0xd8 || buf[2] !== 0xff) {
      throw oops('That photo didn’t work. Try a different one.', 400, 'photo');
    }
    await sql`INSERT INTO ff_photos (user_id, data) VALUES (${me.id}, ${buf.toString('base64')})
              ON CONFLICT (user_id) DO UPDATE SET data = EXCLUDED.data, updated_at = now()`;
    const rows = await sql`UPDATE ff_users SET photo_v = ABS(photo_v) + 1 WHERE id = ${me.id} RETURNING *`;
    return { me: meOut(rows[0]) };
  },

  async remove_photo(ctx) {
    const { sql, me } = ctx;
    await sql`DELETE FROM ff_photos WHERE user_id = ${me.id}`;
    const rows = await sql`UPDATE ff_users SET photo_v = -ABS(photo_v) WHERE id = ${me.id} RETURNING *`;
    return { me: meOut(rows[0]) };
  },

  async change_password(ctx) {
    const { sql, me, body: b } = ctx;
    if (!(await checkPw(String(b.old ?? ''), me.pass_hash))) throw oops('Your current password isn’t right.', 400, 'password');
    const pw = String(b.new ?? '');
    if (pw.length < 8) throw oops('Make your new password at least 8 characters.', 400, 'password');
    if (pw.length > 200) throw oops('That password is too long.', 400, 'password');
    await sql`UPDATE ff_users SET pass_hash = ${await hashPw(pw)} WHERE id = ${me.id}`;
    const token = readCookie(ctx.req, COOKIE);
    await sql`DELETE FROM ff_sessions WHERE user_id = ${me.id} AND token_hash <> ${sha(token)}`;
    return {};
  },

  async delete_account(ctx) {
    const { sql, me, body: b } = ctx;
    if (!(await checkPw(String(b.password ?? ''), me.pass_hash))) throw oops('That password isn’t right.', 400, 'password');
    await sql`DELETE FROM ff_users WHERE id = ${me.id}`;
    // Also erase their waitlist sign-up, as the Privacy Policy promises.
    try { await waitlistForget(me.email); } catch (e) { console.error('waitlist erase failed', String((e && e.message) || e)); }
    clearSessionCookie(ctx.res);
    return {};
  },

  async blocked_list(ctx) {
    const rows = await ctx.sql`SELECT u.id, u.number, u.screen_name FROM ff_blocks k JOIN ff_users u ON u.id = k.blocked_id
                               WHERE k.blocker_id = ${ctx.me.id} ORDER BY k.created_at DESC`;
    return { blocked: rows };
  },

  async unblock(ctx) {
    const other = int(ctx.body.id);
    if (!other) throw oops('Who should be unblocked?');
    await ctx.sql`DELETE FROM ff_blocks WHERE blocker_id = ${ctx.me.id} AND blocked_id = ${other}`;
    return {};
  },

  // ----- suggestion box: every signed-in member (waiting room too) can drop ideas and vote -----
  async ideas(ctx) {
    const { sql, me, body: b } = ctx;
    const sort = b.sort === 'new' ? 'new' : 'top';
    const rows = await sql`
      SELECT i.id, i.body, i.state, i.created_at, u.id AS user_id, u.number, u.screen_name,
        (SELECT COUNT(*)::int FROM ff_idea_votes v WHERE v.idea_id = i.id) AS votes,
        EXISTS (SELECT 1 FROM ff_idea_votes v WHERE v.idea_id = i.id AND v.user_id = ${me.id}) AS mine_vote
      FROM ff_ideas i LEFT JOIN ff_users u ON u.id = i.user_id
      WHERE i.state <> 'hidden' AND (u.id IS NULL OR NOT u.banned)
      ORDER BY CASE WHEN ${sort}::text = 'top' THEN (SELECT COUNT(*) FROM ff_idea_votes v WHERE v.idea_id = i.id) ELSE 0 END DESC, i.id DESC
      LIMIT 100`;
    return { ideas: rows.map(r => ({ ...r, mine: r.user_id === me.id })) };
  },

  async idea_add(ctx) {
    const { sql, me, body: b } = ctx;
    const text = cleanText(b.body, 500);
    if (text.length < 4) throw oops('Tell us a little more about your idea.');
    const [{ c }] = await sql`SELECT COUNT(*)::int AS c FROM ff_ideas WHERE user_id = ${me.id} AND created_at > now() - interval '1 day'`;
    if (c >= 5) throw oops('That’s 5 ideas today. Save the next one for tomorrow!', 429, 'slow');
    const dup = await sql`SELECT 1 FROM ff_ideas WHERE user_id = ${me.id} AND lower(body) = ${text.toLowerCase()}`;
    if (dup.length) throw oops('You already dropped that one in the box.');
    const rows = await sql`INSERT INTO ff_ideas (user_id, body) VALUES (${me.id}, ${text}) RETURNING id, body, state, created_at`;
    return { idea: { ...rows[0], user_id: me.id, number: me.number, screen_name: me.screen_name, votes: 0, mine_vote: false, mine: true } };
  },

  async idea_vote(ctx) {
    const { sql, me, body: b } = ctx;
    const id = int(b.idea);
    if (!id) throw oops('Which idea?');
    const rows = await sql`SELECT user_id, state FROM ff_ideas WHERE id = ${id}`;
    if (!rows.length || rows[0].state === 'hidden') throw oops('That idea is gone.', 404, 'gone');
    if (rows[0].user_id === me.id) throw oops('It’s your idea. Let everyone else vote on it!');
    if (b.on === false) await sql`DELETE FROM ff_idea_votes WHERE idea_id = ${id} AND user_id = ${me.id}`;
    else await sql`INSERT INTO ff_idea_votes (idea_id, user_id) VALUES (${id}, ${me.id}) ON CONFLICT DO NOTHING`;
    const [{ votes }] = await sql`SELECT COUNT(*)::int AS votes FROM ff_idea_votes WHERE idea_id = ${id}`;
    const mine = await sql`SELECT 1 FROM ff_idea_votes WHERE idea_id = ${id} AND user_id = ${me.id}`;
    return { votes, mine_vote: mine.length > 0 };
  },

  async idea_delete(ctx) {
    const { sql, me, body: b } = ctx;
    const id = int(b.idea);
    if (!id) throw oops('Which idea?');
    const gone = await sql`DELETE FROM ff_ideas WHERE id = ${id} AND user_id = ${me.id} RETURNING id`;
    if (!gone.length) throw oops('You can only delete your own ideas.', 403, 'not_yours');
    return {};
  }
};

// ---------- verified-member actions ----------
const VERIFIED = {
  async add(ctx) {
    const { sql, me, body: b } = ctx;
    const t = int(b.id) ? (await sql`SELECT * FROM ff_users WHERE id = ${int(b.id)}`)[0] : await findTarget(sql, b.who);
    if (!t || !t.verified || t.banned) throw oops('No verified member has that number or screen name.', 404, 'not_found');
    if (t.id === me.id) throw oops('That’s you!', 400, 'self');
    const bl = await blockedEither(sql, me.id, t.id);
    if (bl.iBlocked) throw oops('You blocked them. Unblock them in Me first.', 400, 'blocked');
    if (bl.theyBlocked) return { state: 'sent', who: { id: t.id, number: t.number, screen_name: t.screen_name } };
    const who = { id: t.id, number: t.number, screen_name: t.screen_name };
    const [{ c }] = await sql`SELECT COUNT(*)::int AS c FROM ff_buddies WHERE from_id = ${me.id} AND created_at > now() - interval '1 day'`;
    const p = await pair(sql, me.id, t.id);
    if (!p) {
      if (c >= 40) throw oops('That’s a lot of adds for one day. Try again tomorrow.', 429, 'slow');
      try { await sql`INSERT INTO ff_buddies (from_id, to_id) VALUES (${me.id}, ${t.id})`; }
      catch (e) { if (uniqueErr(e)) return { state: 'sent', who }; throw e; }
      return { state: 'sent', who };
    }
    if (p.state === 'accepted') return { state: 'buddies', who };
    if (p.from_id === me.id) return { state: 'sent', who };
    if (p.state === 'pending') {
      await sql`UPDATE ff_buddies SET state = 'accepted', updated_at = now() WHERE id = ${p.id}`;
      return { state: 'buddies', who };
    }
    // I said nope to them before and changed my mind.
    await sql`DELETE FROM ff_buddies WHERE id = ${p.id}`;
    await sql`INSERT INTO ff_buddies (from_id, to_id) VALUES (${me.id}, ${t.id})`;
    return { state: 'sent', who };
  },

  async respond(ctx) {
    const { sql, me, body: b } = ctx;
    const id = int(b.req_id);
    if (!id) throw oops('Which request?');
    const rows = await sql`UPDATE ff_buddies SET state = ${b.allow === true ? 'accepted' : 'declined'}, updated_at = now()
                           WHERE id = ${id} AND to_id = ${me.id} AND state = 'pending' RETURNING from_id`;
    if (!rows.length) throw oops('That request is gone.', 404, 'gone');
    return { state: b.allow === true ? 'buddies' : 'declined' };
  },

  async remove(ctx) {
    const other = int(ctx.body.id);
    if (!other) throw oops('Who should be removed?');
    const me = ctx.me.id;
    await ctx.sql`DELETE FROM ff_buddies WHERE LEAST(from_id, to_id) = LEAST(${me}::int, ${other}::int)
                  AND GREATEST(from_id, to_id) = GREATEST(${me}::int, ${other}::int)`;
    await dropFromTop8(ctx.sql, me, other);
    return {};
  },

  async block(ctx) {
    const other = int(ctx.body.id);
    const me = ctx.me.id;
    if (!other || other === me) throw oops('Who should be blocked?');
    await ctx.sql`INSERT INTO ff_blocks (blocker_id, blocked_id) VALUES (${me}, ${other}) ON CONFLICT DO NOTHING`;
    await ctx.sql`DELETE FROM ff_buddies WHERE LEAST(from_id, to_id) = LEAST(${me}::int, ${other}::int)
                  AND GREATEST(from_id, to_id) = GREATEST(${me}::int, ${other}::int)`;
    await dropFromTop8(ctx.sql, me, other);
    return {};
  },

  async report(ctx) {
    const { sql, me, body: b } = ctx;
    const other = int(b.id);
    if (!other || other === me.id) throw oops('Who are you reporting?');
    const [{ c }] = await sql`SELECT COUNT(*)::int AS c FROM ff_reports WHERE reporter_id = ${me.id} AND created_at > now() - interval '1 day'`;
    if (c >= 10) throw oops('You’ve sent a lot of reports today. We’re on it.', 429, 'slow');
    await sql`INSERT INTO ff_reports (reporter_id, target_id, reason) VALUES (${me.id}, ${other}, ${cleanText(b.reason, 500)})`;
    return {};
  },

  async history(ctx) {
    const { sql, me, body: b } = ctx;
    const other = int(b.with);
    if (!other) throw oops('Who are you chatting with?');
    await mustBeBuddies(sql, me.id, other);
    const before = int(b.before) || 2147483646;
    const rows = await sql`SELECT id, from_id, body, created_at FROM ff_messages
      WHERE ((from_id = ${me.id} AND to_id = ${other}) OR (from_id = ${other} AND to_id = ${me.id})) AND id < ${before}
      ORDER BY id DESC LIMIT 50`;
    await sql`UPDATE ff_messages SET read_at = now() WHERE to_id = ${me.id} AND from_id = ${other} AND read_at IS NULL`;
    const seen = await sql`SELECT COALESCE(MAX(id), 0)::int AS s FROM ff_messages
                           WHERE from_id = ${me.id} AND to_id = ${other} AND read_at IS NOT NULL`;
    return { messages: rows.reverse(), more: rows.length === 50, seen_up_to: seen[0].s };
  },

  async send(ctx) {
    const { sql, me, body: b } = ctx;
    const to = int(b.to);
    const text = cleanText(b.body, 2000);
    if (!to) throw oops('Who is this for?');
    if (!text) throw oops('Type a message first.');
    await mustBeBuddies(sql, me.id, to);
    const [{ c }] = await sql`SELECT COUNT(*)::int AS c FROM ff_messages WHERE from_id = ${me.id} AND created_at > now() - interval '1 minute'`;
    if (c >= 25) throw oops('Whoa, slow down a little. Try again in a minute.', 429, 'slow');
    const rows = await sql`INSERT INTO ff_messages (from_id, to_id, body) VALUES (${me.id}, ${to}, ${text})
                           RETURNING id, from_id, body, created_at`;
    return { message: rows[0] };
  },

  async post(ctx) {
    const { sql, me, body: b } = ctx;
    const text = cleanText(b.body, 1000);
    if (!text) throw oops('Write something first.');
    const [{ c }] = await sql`SELECT COUNT(*)::int AS c FROM ff_posts WHERE user_id = ${me.id} AND created_at > now() - interval '1 hour'`;
    if (c >= 12) throw oops('That’s a lot of posts for one hour. Take a breather.', 429, 'slow');
    const rows = await sql`INSERT INTO ff_posts (user_id, body) VALUES (${me.id}, ${text}) RETURNING id, body, created_at`;
    const p = rows[0];
    return { post: { ...p, user_id: me.id, number: me.number, screen_name: me.screen_name, photo_v: pv(me), reals: 0, mine_real: false } };
  },

  async feed(ctx) {
    const { sql, me, body: b } = ctx;
    const before = int(b.before) || 2147483646;
    const only = int(b.user);
    const rows = await sql`
      SELECT p.id, p.body, p.created_at, u.id AS user_id, u.number, u.screen_name, GREATEST(u.photo_v, 0) AS photo_v, u.founder,
        (SELECT COUNT(*)::int FROM ff_reacts r WHERE r.post_id = p.id) AS reals,
        EXISTS (SELECT 1 FROM ff_reacts r WHERE r.post_id = p.id AND r.user_id = ${me.id}) AS mine_real
      FROM ff_posts p JOIN ff_users u ON u.id = p.user_id
      WHERE NOT u.banned AND p.id < ${before}
        AND (p.user_id = ${me.id} OR p.user_id IN (
          SELECT CASE WHEN bb.from_id = ${me.id} THEN bb.to_id ELSE bb.from_id END FROM ff_buddies bb
          WHERE bb.state = 'accepted' AND (bb.from_id = ${me.id} OR bb.to_id = ${me.id})))
        AND (${only || 0}::int = 0 OR p.user_id = ${only || 0}::int)
      ORDER BY p.id DESC LIMIT 30`;
    return { posts: rows, more: rows.length === 30 };
  },

  async real(ctx) {
    const { sql, me, body: b } = ctx;
    const id = int(b.post);
    if (!id) throw oops('Which post?');
    const rows = await sql`SELECT p.user_id FROM ff_posts p WHERE p.id = ${id}`;
    if (!rows.length) throw oops('That post is gone.', 404, 'gone');
    const owner = rows[0].user_id;
    if (owner !== me.id) {
      const p = await pair(sql, me.id, owner);
      if (!p || p.state !== 'accepted') throw oops('You can only react to your buddies’ posts.', 403, 'not_buddies');
    }
    if (b.on === false) await sql`DELETE FROM ff_reacts WHERE post_id = ${id} AND user_id = ${me.id}`;
    else await sql`INSERT INTO ff_reacts (post_id, user_id) VALUES (${id}, ${me.id}) ON CONFLICT DO NOTHING`;
    const [{ n }] = await sql`SELECT COUNT(*)::int AS n FROM ff_reacts WHERE post_id = ${id}`;
    return { reals: n, mine_real: b.on !== false };
  },

  async delete_post(ctx) {
    const id = int(ctx.body.post);
    if (!id) throw oops('Which post?');
    await ctx.sql`DELETE FROM ff_posts WHERE id = ${id} AND user_id = ${ctx.me.id}`;
    return {};
  },

  async search(ctx) {
    const { sql, me, body: b } = ctx;
    const q = clean(b.q, 60);
    const city = clean(b.city, 80);
    let rows;
    if (/^#?\d{1,9}$/.test(q)) {
      rows = await sql`SELECT id, number, screen_name, city, interests, bio, created_at, GREATEST(photo_v, 0) AS photo_v, founder FROM ff_users u
        WHERE u.number = ${Number(q.replace('#', ''))} AND u.verified AND NOT u.banned AND u.id <> ${me.id}
          AND NOT EXISTS (SELECT 1 FROM ff_blocks k WHERE (k.blocker_id = ${me.id} AND k.blocked_id = u.id) OR (k.blocker_id = u.id AND k.blocked_id = ${me.id}))`;
    } else {
      const qp = likePat(q);
      const cp = likePat(city);
      rows = await sql`SELECT id, number, screen_name, city, interests, bio, created_at, GREATEST(photo_v, 0) AS photo_v, founder FROM ff_users u
        WHERE u.verified AND NOT u.banned AND u.id <> ${me.id}
          AND NOT EXISTS (SELECT 1 FROM ff_blocks k WHERE (k.blocker_id = ${me.id} AND k.blocked_id = u.id) OR (k.blocker_id = u.id AND k.blocked_id = ${me.id}))
          AND (${q}::text = '' OR u.sn_key LIKE ${qp} OR lower(u.interests) LIKE ${qp} OR lower(u.bio) LIKE ${qp} OR lower(u.city) LIKE ${qp})
          AND (${city}::text = '' OR lower(u.city) LIKE ${cp})
        ORDER BY u.id DESC LIMIT 40`;
    }
    const rels = await sql`SELECT * FROM ff_buddies WHERE from_id = ${me.id} OR to_id = ${me.id}`;
    const relMap = new Map(rels.map(r => [r.from_id === me.id ? r.to_id : r.from_id, r]));
    return { people: rows.map(r => ({ ...r, rel: relFor(relMap.get(r.id), me.id), req_id: relMap.get(r.id) ? relMap.get(r.id).id : null })) };
  },

  async profile(ctx) {
    const { sql, me, body: b } = ctx;
    const id = int(b.id);
    const rows = id ? await sql`SELECT * FROM ff_users WHERE id = ${id}` : [];
    const u = rows[0];
    if (!u || u.banned || (!u.verified && u.id !== me.id)) throw oops('That member isn’t around.', 404, 'not_found');
    const bl = await blockedEither(sql, me.id, u.id);
    if (bl.theyBlocked) throw oops('That member isn’t around.', 404, 'not_found');
    const p = u.id === me.id ? null : await pair(sql, me.id, u.id);
    const rel = u.id === me.id ? 'me' : relFor(p, me.id);
    const out = {
      id: u.id, number: u.number, screen_name: u.screen_name, city: u.city, interests: u.interests, bio: u.bio,
      created_at: u.created_at, rel, req_id: p ? p.id : null, blocked: bl.iBlocked,
      photo_v: pv(u), theme: u.theme || 'classic', accent: u.accent || '', song: u.song || '', top8: [], founder: Boolean(u.founder)
    };
    const top = idList(u.top8);
    if (top.length) {
      const rows8 = await sql`SELECT t.id, t.number, t.screen_name, GREATEST(t.photo_v, 0) AS photo_v FROM ff_users t
        WHERE t.id = ANY(${top}::int[]) AND t.verified AND NOT t.banned
          AND EXISTS (SELECT 1 FROM ff_buddies bb WHERE bb.state = 'accepted'
                      AND LEAST(bb.from_id, bb.to_id) = LEAST(t.id, ${u.id}::int) AND GREATEST(bb.from_id, bb.to_id) = GREATEST(t.id, ${u.id}::int))
          AND NOT EXISTS (SELECT 1 FROM ff_blocks k WHERE (k.blocker_id = ${me.id} AND k.blocked_id = t.id) OR (k.blocker_id = t.id AND k.blocked_id = ${me.id}))`;
      out.top8 = top.map(id => rows8.find(r => r.id === id)).filter(Boolean);
    }
    if (rel === 'buddies') {
      const live = u.status !== 'invisible' && u.last_seen && Date.now() - new Date(u.last_seen).getTime() < 150000;
      out.presence = live ? u.status : 'offline';
      out.away_msg = live && (u.status === 'away' || u.status === 'dnd') ? u.away_msg : '';
    }
    return { profile: out };
  }
};

// ---------- admin actions (need the admin key) ----------
const ADMIN = {
  async admin_overview(ctx) {
    const { sql } = ctx;
    const [counts] = await sql`SELECT COUNT(*)::int AS total,
        COUNT(*) FILTER (WHERE verified AND NOT banned)::int AS verified,
        COUNT(*) FILTER (WHERE NOT verified AND NOT banned)::int AS pending,
        COUNT(*) FILTER (WHERE banned)::int AS banned,
        COUNT(*) FILTER (WHERE founder)::int AS founders,
        COUNT(*) FILTER (WHERE last_seen > now() - interval '150 seconds' AND NOT banned)::int AS online
      FROM ff_users`;
    const [{ messages }] = await sql`SELECT COUNT(*)::int AS messages FROM ff_messages`;
    const [{ posts }] = await sql`SELECT COUNT(*)::int AS posts FROM ff_posts`;
    const pending = await sql`SELECT u.id, u.number, u.screen_name, u.email, u.city, u.interests, u.bio, u.why, u.waitlist_name,
        u.from_waitlist, u.created_at, CASE WHEN ph.data IS NULL THEN '' ELSE 'data:image/jpeg;base64,' || ph.data END AS photo
      FROM ff_users u LEFT JOIN ff_photos ph ON ph.user_id = u.id WHERE NOT u.verified AND NOT u.banned ORDER BY u.id`;
    const members = await sql`SELECT id, number, screen_name, email, city, verified, banned, founder, last_seen, created_at
      FROM ff_users ORDER BY number LIMIT 2000`;
    // Founder Pack payments that didn't match an account (they paid with a different email, or before signing up).
    const unmatched = await sql`SELECT session_id, email, amount, currency, created_at FROM ff_payments
      WHERE user_id IS NULL ORDER BY created_at DESC LIMIT 100`;
    const [{ cents }] = await sql`SELECT COALESCE(SUM(amount), 0)::int AS cents FROM ff_payments WHERE kind = 'founder'`;
    const reports = await sql`SELECT r.id, r.reason, r.created_at, t.id AS target_id, t.screen_name AS target_name,
        t.number AS target_number, t.banned AS target_banned, rp.screen_name AS reporter_name, rp.number AS reporter_number
      FROM ff_reports r JOIN ff_users t ON t.id = r.target_id LEFT JOIN ff_users rp ON rp.id = r.reporter_id
      WHERE NOT r.resolved ORDER BY r.id DESC`;
    const ideas = await sql`SELECT i.id, i.body, i.state, i.created_at, u.screen_name, u.number,
        (SELECT COUNT(*)::int FROM ff_idea_votes v WHERE v.idea_id = i.id) AS votes
      FROM ff_ideas i LEFT JOIN ff_users u ON u.id = i.user_id
      ORDER BY (i.state = 'hidden'), votes DESC, i.id DESC LIMIT 300`;
    return { counts: { ...counts, messages, posts, ideas: ideas.filter(i => i.state !== 'hidden').length, founder_cents: cents }, pending, members, reports, ideas, unmatched };
  },

  async admin_idea(ctx) {
    const { sql, body: b } = ctx;
    const id = int(b.id);
    if (!id) throw oops('Which idea?');
    if (!IDEA_STATES.includes(b.state)) throw oops('Pick open, planned, done or hidden.');
    await sql`UPDATE ff_ideas SET state = ${b.state} WHERE id = ${id}`;
    return {};
  },

  async admin_set(ctx) {
    const { sql, body: b } = ctx;
    const id = int(b.id);
    if (!id) throw oops('Which member?');
    if (typeof b.verified === 'boolean') await sql`UPDATE ff_users SET verified = ${b.verified} WHERE id = ${id}`;
    if (typeof b.founder === 'boolean') {
      await sql`UPDATE ff_users SET founder = ${b.founder}, founder_at = CASE WHEN ${b.founder} THEN COALESCE(founder_at, now()) ELSE NULL END WHERE id = ${id}`;
      if (!b.founder) await sql`UPDATE ff_users SET theme = 'classic' WHERE id = ${id} AND theme = ANY(${FOUNDER_THEMES})`;
    }
    if (typeof b.banned === 'boolean') {
      await sql`UPDATE ff_users SET banned = ${b.banned} WHERE id = ${id}`;
      if (b.banned) await sql`DELETE FROM ff_sessions WHERE user_id = ${id}`;
    }
    return {};
  },

  async admin_reset_password(ctx) {
    const { sql, body: b } = ctx;
    const id = int(b.id);
    if (!id) throw oops('Which member?');
    const temp = 'ff-' + randomBytes(6).toString('base64url');
    await sql`UPDATE ff_users SET pass_hash = ${await hashPw(temp)}, fails = 0, locked_until = NULL WHERE id = ${id}`;
    await sql`DELETE FROM ff_sessions WHERE user_id = ${id}`;
    return { temp_password: temp };
  },

  async admin_resolve(ctx) {
    const id = int(ctx.body.id);
    if (!id) throw oops('Which report?');
    await ctx.sql`UPDATE ff_reports SET resolved = TRUE WHERE id = ${id}`;
    return {};
  }
};

// GET /api/app?photo=<member id>&v=<version>: a member's photo, only for signed-in members who can see them.
async function servePhoto(ctx, idRaw) {
  const { sql, res } = ctx;
  const nope = (code) => { res.statusCode = code; res.setHeader('Cache-Control', 'no-store'); return res.end(); };
  let me;
  try { me = await currentUser(ctx); } catch { return nope(403); }
  if (!me) return nope(401);
  const target = int(idRaw);
  if (!target) return nope(404);
  if (target !== me.id) {
    if (!me.verified) return nope(403);
    const t = (await sql`SELECT verified, banned FROM ff_users WHERE id = ${target}`)[0];
    if (!t || !t.verified || t.banned) return nope(404);
    const bl = await blockedEither(sql, me.id, target);
    if (bl.iBlocked || bl.theyBlocked) return nope(404);
  }
  const rows = await sql`SELECT data FROM ff_photos WHERE user_id = ${target}`;
  if (!rows.length) return nope(404);
  const buf = Buffer.from(rows[0].data, 'base64');
  res.statusCode = 200;
  res.setHeader('Content-Type', 'image/jpeg');
  res.setHeader('Content-Length', String(buf.length));
  res.setHeader('Cache-Control', 'private, max-age=31536000, immutable');
  return res.end(buf);
}

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  const photoId = req.method === 'GET' ? new URL(req.url || '/', 'http://x').searchParams.get('photo') : null;
  if (req.method !== 'POST' && !photoId) {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({ ok: false, error: 'Use POST.' });
  }
  let body = req.body;
  if (typeof body === 'string') { try { body = JSON.parse(body); } catch { body = {}; } }
  body = body && typeof body === 'object' ? body : {};
  const action = String(body.action || '');

  const sql = getSql();
  if (!sql) return res.status(503).json({ ok: false, code: 'no_db', error: 'FrickFake’s database isn’t connected yet.' });
  try { await ready(sql); } catch (e) {
    console.error('database setup failed', String((e && e.message) || e));
    return res.status(503).json({ ok: false, code: 'db_down', error: 'FrickFake can’t reach its database right now. Try again in a minute.' });
  }

  const ctx = { req, res, sql, body };
  if (photoId) {
    try { return await servePhoto(ctx, photoId); }
    catch (e) { console.error('photo failed', String((e && e.message) || e)); res.statusCode = 500; return res.end(); }
  }
  try {
    let out;
    if (Object.hasOwn(PUBLIC, action)) out = await PUBLIC[action](ctx);
    else if (Object.hasOwn(ADMIN, action)) {
      if (!adminOk(body.key)) return res.status(401).json({ ok: false, code: 'admin', error: 'That admin key isn’t right.' });
      out = await ADMIN[action](ctx);
    } else if (Object.hasOwn(USER, action) || Object.hasOwn(VERIFIED, action)) {
      const me = await currentUser(ctx);
      if (!me) return res.status(401).json({ ok: false, code: 'auth', error: 'Log in first.' });
      ctx.me = me;
      if (Object.hasOwn(USER, action)) out = await USER[action](ctx);
      else if (!me.verified) return res.status(403).json({ ok: false, code: 'pending', error: 'A real human still has to verify you first.' });
      else out = await VERIFIED[action](ctx);
    } else {
      return res.status(400).json({ ok: false, error: 'Unknown action.' });
    }
    return res.status(200).json({ ok: true, ...out });
  } catch (e) {
    if (e instanceof Oops) return res.status(e.status).json({ ok: false, code: e.code, error: e.message });
    console.error('app action failed', action, String((e && e.stack) || e));
    return res.status(500).json({ ok: false, code: 'server', error: 'Something broke on our end. Try again in a minute.' });
  }
}
