# FrickFake

A social network for real people only: the old-school messenger, rebuilt.

## What's here

- `index.html` – the waitlist page (retro messenger style, every sign-up gets a FrickFake number)
- `app.html` – the app at **/app**: accounts, buddy list with Allow / Nope requests, statuses and away messages, one-on-one chat, a buddies-only feed, Find people, profiles, block and report
- `app.html#boss` – **boss mode** (/app#boss): verify new members, handle reports, ban, reset passwords. Uses the same admin key as the waitlist list.
- `api/app.js` – the app's API (one function, `POST /api/app` with `{ action }`)
- `api/join.js`, `api/count.js`, `api/admin.js` – the waitlist (unchanged)
- `lib/db.js` – database connection; creates the tables on first use
- `lib/waitlist.js` – lets app accounts keep their waitlist number

## How it works

- Anyone can sign up at /app and gets a FrickFake number. If they used the same email on the waitlist, they keep that number.
- New members wait in the **waiting room** until you verify them in boss mode. Until then they can't add anyone or chat.
- Nobody can message you until you allow their buddy request. Blocked people can't find, add or message you.
- Chat updates every few seconds while open. Members show as online for about 2 minutes after they were last active.
- Members can add the app to their phone's home screen (it has an app icon and opens full screen).

## Setup on Vercel

1. **Database:** Storage → Create Database → **Neon** (free plan) → connect it to this project. That adds `DATABASE_URL`. Tables are created automatically.
2. **Blob store** (already used by the waitlist): keeps waitlist sign-ups. Optional for the app, but needed for members to keep their waitlist numbers.
3. Optional: set `FF_ADMIN_KEY` to a new secret if you ever need a different admin key. The original key keeps working too.

## Admin

- Boss mode: `/app#boss`
- Waitlist list and emails: `/api/admin?key=YOUR_ADMIN_KEY` (add `&format=csv` to download)
