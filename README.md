# Emergency Blood – server

A dependency-free Node.js server (Node 18+) that serves the website and stores
donor registrations, blood requests, messages and blood stock in `data/db.json`.

## Run it
    ADMIN_PASSWORD="a-long-secret-password" node server.js
Open http://localhost:3000 . Admin page: http://localhost:3000/#admin

## What the server does
| Endpoint | Who | Purpose |
|---|---|---|
| GET  /api/stock | public | read blood stock |
| POST /api/registrations, /api/requests, /api/messages | public (rate-limited, validated) | save form submissions |
| POST /api/admin/login | admin | password -> 12 h token |
| GET  /api/admin/data | admin | view submissions |
| PUT  /api/stock | admin | update shared stock |
| GET  /healthz | anyone | uptime check |

The donor card stays on each visitor's own device (browser storage).

## Publish it
**Option A – any host with Node (Render, Railway, Fly.io, a VPS):**
1. Upload this folder (or push to GitHub). Start command: `node server.js`
2. Set env vars: `ADMIN_PASSWORD` (required), `TRUST_PROXY=1`
3. Attach a persistent disk/volume and set `DATA_DIR` to its path, otherwise data is lost on every redeploy.
4. Use the HTTPS URL the platform gives you (or add your own domain).

**Option B – Docker:**
    docker build -t emergency-blood .
    docker run -d -p 3000:3000 -e ADMIN_PASSWORD="long-secret" -v ebdata:/data emergency-blood

**Option C – VPS with nginx + pm2:** `pm2 start server.js`, proxy nginx to port 3000, add HTTPS with certbot, set `TRUST_PROXY=1`.

## Before going live
- Serve over HTTPS only.
- Back up `db.json` regularly: it holds donors' phone numbers and emails.
- Health data is sensitive; add a privacy notice and follow local rules.
- Stock figures are entered by admins; they are not a live blood-bank feed.
