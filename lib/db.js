import { neon } from '@neondatabase/serverless';

// Finds the Postgres connection string that the Neon integration adds in Vercel.
export function dbUrl() {
  const env = process.env;
  const direct = env.DATABASE_URL || env.POSTGRES_URL;
  if (direct) return direct;
  for (const [k, v] of Object.entries(env)) {
    if (/(DATABASE_URL|POSTGRES_URL)$/.test(k) && /^postgres(ql)?:\/\//.test(String(v))) return v;
  }
  return '';
}

let _sql = null;
export function getSql() {
  if (globalThis.__ffSql) return globalThis.__ffSql; // used by local tests
  if (!_sql) {
    const url = dbUrl();
    if (!url) return null;
    _sql = neon(url);
  }
  return _sql;
}

const SCHEMA_VERSION = '1';
const SCHEMA = [
  `CREATE TABLE IF NOT EXISTS ff_meta (k TEXT PRIMARY KEY, v TEXT NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS ff_users (
    id SERIAL PRIMARY KEY,
    number INTEGER NOT NULL UNIQUE,
    screen_name TEXT NOT NULL,
    sn_key TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    pass_hash TEXT NOT NULL,
    city TEXT NOT NULL DEFAULT '',
    interests TEXT NOT NULL DEFAULT '',
    bio TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'free',
    away_msg TEXT NOT NULL DEFAULT '',
    verified BOOLEAN NOT NULL DEFAULT FALSE,
    banned BOOLEAN NOT NULL DEFAULT FALSE,
    from_waitlist BOOLEAN NOT NULL DEFAULT FALSE,
    waitlist_name TEXT NOT NULL DEFAULT '',
    why TEXT NOT NULL DEFAULT '',
    fails INTEGER NOT NULL DEFAULT 0,
    locked_until TIMESTAMPTZ,
    last_seen TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
  )`,
  `CREATE TABLE IF NOT EXISTS ff_sessions (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES ff_users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL
  )`,
  `CREATE INDEX IF NOT EXISTS ff_sessions_user ON ff_sessions (user_id)`,
  `CREATE TABLE IF NOT EXISTS ff_buddies (
    id SERIAL PRIMARY KEY,
    from_id INTEGER NOT NULL REFERENCES ff_users(id) ON DELETE CASCADE,
    to_id INTEGER NOT NULL REFERENCES ff_users(id) ON DELETE CASCADE,
    state TEXT NOT NULL DEFAULT 'pending',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
  )`,
  `CREATE UNIQUE INDEX IF NOT EXISTS ff_buddies_pair ON ff_buddies (LEAST(from_id, to_id), GREATEST(from_id, to_id))`,
  `CREATE INDEX IF NOT EXISTS ff_buddies_to ON ff_buddies (to_id, state)`,
  `CREATE TABLE IF NOT EXISTS ff_blocks (
    blocker_id INTEGER NOT NULL REFERENCES ff_users(id) ON DELETE CASCADE,
    blocked_id INTEGER NOT NULL REFERENCES ff_users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (blocker_id, blocked_id)
  )`,
  `CREATE TABLE IF NOT EXISTS ff_messages (
    id SERIAL PRIMARY KEY,
    from_id INTEGER NOT NULL REFERENCES ff_users(id) ON DELETE CASCADE,
    to_id INTEGER NOT NULL REFERENCES ff_users(id) ON DELETE CASCADE,
    body TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    read_at TIMESTAMPTZ
  )`,
  `CREATE INDEX IF NOT EXISTS ff_messages_pair ON ff_messages (LEAST(from_id, to_id), GREATEST(from_id, to_id), id)`,
  `CREATE INDEX IF NOT EXISTS ff_messages_unread ON ff_messages (to_id, from_id) WHERE read_at IS NULL`,
  `CREATE INDEX IF NOT EXISTS ff_messages_from ON ff_messages (from_id, created_at)`,
  `CREATE TABLE IF NOT EXISTS ff_posts (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES ff_users(id) ON DELETE CASCADE,
    body TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
  )`,
  `CREATE INDEX IF NOT EXISTS ff_posts_user ON ff_posts (user_id, id)`,
  `CREATE TABLE IF NOT EXISTS ff_reacts (
    post_id INTEGER NOT NULL REFERENCES ff_posts(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES ff_users(id) ON DELETE CASCADE,
    PRIMARY KEY (post_id, user_id)
  )`,
  `CREATE TABLE IF NOT EXISTS ff_reports (
    id SERIAL PRIMARY KEY,
    reporter_id INTEGER REFERENCES ff_users(id) ON DELETE SET NULL,
    target_id INTEGER NOT NULL REFERENCES ff_users(id) ON DELETE CASCADE,
    reason TEXT NOT NULL DEFAULT '',
    resolved BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
  )`
];

async function migrate(sql) {
  try {
    const rows = await sql`SELECT v FROM ff_meta WHERE k = 'schema'`;
    if (rows[0] && rows[0].v === SCHEMA_VERSION) return;
  } catch { /* first run: tables don't exist yet */ }
  for (const stmt of SCHEMA) await sql.query(stmt);
  await sql`INSERT INTO ff_meta (k, v) VALUES ('schema', ${SCHEMA_VERSION})
            ON CONFLICT (k) DO UPDATE SET v = EXCLUDED.v`;
}

let _ready = null;
export function ready(sql) {
  if (!_ready) _ready = migrate(sql).catch(e => { _ready = null; throw e; });
  return _ready;
}
