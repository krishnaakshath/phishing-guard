# Phishing Guard

A Chrome extension, web dashboard, and API that protect people while they
browse — real-time phishing detection, a public site security checkup tool,
a breach-checked password tool, and an admin console for reviewing reported
threats.

## What's here

- **`extension/`** — Manifest V3 Chrome extension. Auto-scans pages, warns
  before you enter a password/payment/OTP on a risky site, grades the
  current site's security posture, and flags risky outbound links.
- **`backend/`** — Flask API. Phishing detection backed by Google Safe
  Browsing + the OpenPhish community feed (in addition to local heuristics),
  a site security grader, a breach-checked password tool (via Have I Been
  Pwned's k-anonymity API), an exposed-secrets scanner, and a full
  multi-user system (auth, per-user whitelist/blacklist/history, admin
  role).
- **`dashboard/`** — React/Vite web app. Login, scan history, whitelist/
  blacklist management, the public Site Scanner and Password Checker tools,
  and an admin console (`/admin`) for reviewing reported phishing domains
  and users.

## Features

| Feature | Where | Notes |
|---|---|---|
| Real-time phishing detection | Extension + backend | Local heuristics + Safe Browsing + OpenPhish feed |
| Credential-entry protection | Extension | Warns before password/card/OTP entry on risky sites |
| Site security grade (A–F) | Extension + `/tools/site-scanner` | Headers, TLS, cookie flags — shareable, no login needed |
| Exposed secret/API key scan | `/tools/site-scanner` | Flags leaked keys/tokens in a site's client-side code |
| Password breach check | Extension popup + `/tools/password-checker` | HIBP k-anonymity — only a hash prefix is ever checked |
| Risky outbound link scanning | Extension | Flags dangerous links on the page before you click |
| Password strength micro-tip | Extension | Local-only entropy check on new-password fields, no network call |
| Whitelist / blacklist / history | Dashboard | Per-user, backed by the real API |
| Admin console | Dashboard `/admin` | Global stats, threat-report moderation, user list |

## Setup

### Backend

```bash
cd backend
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env      # optional - see below
python app.py
```

Runs at `http://localhost:5000`. Run the test suite with `pytest tests/`.

All environment variables are optional — the app runs and detects phishing
with none of them set:

- `SAFE_BROWSING_API_KEY` — free Google Safe Browsing v4 key. Without it,
  that check is silently skipped (local heuristics + OpenPhish still run).
- `ALLOWED_ORIGINS` — comma-separated CORS allowlist. Defaults to the
  extension scheme + production dashboard + local dev servers.
- `DB_PATH` — SQLite file location. In production this should point at a
  persistent disk (see `render.yaml`) so accounts survive redeploys.

To make a user an admin (needed for `/admin` in the dashboard), set
`is_admin = 1` for their row in the `users` table — there's no self-serve
promotion flow by design.

### Extension

1. `chrome://extensions` → enable Developer mode → **Load unpacked** →
   select `extension/`.
2. By default it points at the production API
   (`https://phishing-guard.onrender.com/api`, see `extension/config.js`).
   Point it at `http://localhost:5000/api` for local development.

### Dashboard

```bash
cd dashboard
npm install
npm run dev
```

Set `VITE_API_URL` (see `.env.example`) to point at your backend if not
using the default local `http://localhost:5000/api`.

## Tech stack

- **Backend**: Python, Flask, SQLite, Flask-Limiter, `requests`
- **Extension**: JavaScript (ES modules), Chrome APIs, Manifest V3
- **Dashboard**: React, Vite, react-router-dom

## License

MIT
