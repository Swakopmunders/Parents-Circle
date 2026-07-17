# Parent Circle — shared community server

A real backend so the same anonymous identity, password, and chat rooms work
from any device. No external dependencies — just Node.js.

## What's inside

- `server.js` — the whole backend: accounts, sessions, rooms, messages,
  moderation, and live updates. Pure Node core modules, nothing to `npm
  install`.
- `public/` — the frontend (served by the same server).
- `data/db.json` — created automatically on first run. This file **is** your
  database. Back it up if you care about the community's history.

## Run it locally

```
node server.js
```

Then open `http://localhost:3000`. That's it — no build step, no install step.

## ⚠️ Before real people use this: put it behind HTTPS

Right now, if you deploy this as-is on plain HTTP, passwords travel
unencrypted. For anything beyond your own local testing, you need TLS in
front of this server. Two easy ways:

1. **Use a host that gives you HTTPS automatically** — Railway, Render, and
   Fly.io all do this for free with zero config (see below).
2. **Self-hosting on your own machine/VPS** — put a reverse proxy in front of
   it. [Caddy](https://caddyserver.com) is the simplest: point a domain at
   your server and Caddy handles HTTPS certificates for you automatically.

## Deploying so other devices can reach it

You need somewhere that keeps the process running and reachable. A few
straightforward options, roughly easiest first:

**Railway or Render (recommended if you don't want to manage a server)**
1. Push this folder to a GitHub repo.
2. Create a new project on [railway.app](https://railway.app) or
   [render.com](https://render.com), point it at the repo.
3. Start command: `node server.js`
4. Set the environment variable `SESSION_SECRET` to a long random string
   (e.g. run `node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"`
   locally and paste the output). Without this, everyone gets logged out
   every time the server restarts or redeploys.
5. Add a **persistent volume** mounted at `/data` if the platform supports
   it, and change `DATA_DIR` in `server.js` to point there — otherwise
   `data/db.json` is wiped on every redeploy. (Railway and Render both
   support volumes.)
6. They give you an HTTPS URL automatically. Done.

**Your own server / VPS / home machine**
1. Install Node.js 18+.
2. Copy this folder over, run `SESSION_SECRET=<your secret> node server.js`
   (or use `pm2` / a systemd service to keep it running and auto-restart).
3. Put Caddy or Nginx in front of it for HTTPS and point your domain at it.

## Environment variables

| Variable         | Default          | Notes                                             |
|-------------------|-----------------|----------------------------------------------------|
| `PORT`            | `3000`           | What port the server listens on                    |
| `SESSION_SECRET`  | random each boot | **Set this in production** or logins reset on restart |

## Once it's running, install it as an app on any device

Open the site's URL in Chrome/Edge/Safari and use "Install app" / "Add to
Home Screen." It'll behave like a native app, and now every device signs
into the *same* account and sees the *same* rooms and messages.

## Known limits of this version (honest list)

- **Storage is a single JSON file**, not a real database. Fine for a
  small-to-mid community; if this grows large or you want redundancy, migrate
  to SQLite or Postgres — the data shape in `db.json` maps over easily.
- **Attachments are capped at 150KB** and stored inline as base64. Good
  enough for a quick photo or a short PDF; not built for large files. A
  future version could store files on disk or in object storage (S3-style)
  instead.
- **One process, one machine.** This won't horizontally scale across
  multiple servers as written (the live-update connections and in-memory
  state are per-process). Totally fine for a support community; would need
  rework for a large-scale public product.
- Moderators can pin, delete, and block — there's no ban-appeal flow or
  audit log yet.
