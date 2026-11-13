# FrickFake

Waitlist site for FrickFake, a social network for real people only.

- `index.html` – the page (retro messenger style, every sign-up gets a FrickFake number)
- `api/join.js` – saves a sign-up to Vercel Blob (private) and assigns a number
- `api/count.js` – how many people have signed up
- `api/admin.js` – private sign-up list: `/api/admin?key=YOUR_ADMIN_KEY` (add `&format=csv` to download)

Needs on Vercel: a **Blob store** (private preferred) connected to the project, which adds `BLOB_READ_WRITE_TOKEN`. No other settings needed.
