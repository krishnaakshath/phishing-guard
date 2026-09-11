# Phishing Guard — Architecture & API Reference

> This doc describes structure and contracts, not implementation — read the
> source files linked below for the actual code. Earlier versions of this
> file embedded full code snippets, which went stale the moment the source
> changed; this version avoids that by pointing at files instead.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      Chrome Browser                          │
│  ┌────────────┐  ┌──────────────┐  ┌───────────────────┐     │
│  │ content.js │  │ background.js│  │     popup.js       │     │
│  │ page scan, │  │ nav monitor, │  │  popup UI, quick    │     │
│  │ credential │  │ site grade,  │  │  links to dashboard │     │
│  │ alerts,    │  │ link batch   │  │  tools              │     │
│  │ link marks │  │ scan, badge  │  │                     │     │
│  └─────┬──────┘  └──────┬───────┘  └──────────┬──────────┘     │
└────────│────────────────│─────────────────────│───────────────┘
         │                │  HTTPS              │
         └────────────────┼─────────────────────┘
                           ▼
              ┌────────────────────────┐        ┌─────────────────┐
              │   Flask backend (API)  │◄──────►│  React dashboard │
              │   backend/app.py       │  HTTPS  │  dashboard/src/  │
              └───────────┬─────────────┘        └─────────────────┘
                           │
          ┌────────────────┼───────────────────┬──────────────────┐
          ▼                ▼                   ▼                  ▼
   Local heuristics   Safe Browsing /     Have I Been      SQLite (users,
   (detector.py)      OpenPhish feed      Pwned range API   whitelist/
                       (threat_intel.py)  (breach_check.py) blacklist,
                                                             history,
                                                             threat_database)
```

## Backend modules

| File | Responsibility |
|---|---|
| `backend/app.py` | Flask routes, auth middleware, rate limiting, CORS |
| `backend/detector.py` | Local URL heuristics (TLD, keywords, typosquat patterns) |
| `backend/threat_intel.py` | Domain reputation, WHOIS/SSL checks (cached), Safe Browsing, OpenPhish feed |
| `backend/security_grade.py` | Security header / TLS / cookie posture grading (A–F) |
| `backend/breach_check.py` | Password breach checking via HIBP k-anonymity |
| `backend/secret_scanner.py` | Regex-based exposed-secret detection in page HTML |
| `backend/cache.py` | SQLite-backed TTL cache used by `threat_intel.py` |
| `backend/models.py` | All database access — users, settings, whitelist/blacklist, scan history, threat reports, admin queries |

## API endpoints

All request/response shapes below are the contract other code is written
against — treat changing them as a breaking change.

### Public (no auth)

- `GET /api/health` — health check + feature list
- `GET /api/stats` — global scan counters
- `POST /api/scan` — `{url, content?}` → phishing analysis (also accepts
  `X-API-Key` optionally, to attach the scan to a user's history)
- `POST /api/batch-scan` — `{urls: [...]}` (max 50) → per-URL risk summary
- `POST /api/verify-site` — `{url}` → deep threat-intel lookup for a domain
- `POST /api/report-phishing` — `{url, reason?}` → adds to blocklist +
  the persistent, admin-reviewable threat database
- `POST /api/check-password-breach` — `{password}` → `{breached, count}`
  (only a SHA-1 hash prefix is sent to HIBP; the password itself never
  leaves this backend)
- `GET /api/site-scan?url=` — security posture grade + exposed-secret scan

### Auth

- `POST /api/auth/register` — `{email, password}` (8+ chars) → user + API key
- `POST /api/auth/login` — `{email, password}` → user + API key
- `GET /api/auth/me` — requires `X-API-Key` → current user incl. `is_admin`

### User data (require `X-API-Key`)

- `GET`/`PUT /api/settings`
- `GET`/`POST /api/whitelist`, `DELETE /api/whitelist/<domain>`
- `GET`/`POST /api/blacklist`, `DELETE /api/blacklist/<domain>`
- `GET /api/history?limit=`
- `GET /api/stats/user?days=`

### Admin (require `X-API-Key` for a user with `is_admin: true`; the server
always re-checks this — a client-side admin flag is never trusted)

- `GET /api/admin/stats` — global totals for the admin overview
- `GET /api/admin/threats` — all reported/tracked domains
- `POST /api/admin/threats/<id>/verify`
- `DELETE /api/admin/threats/<id>`
- `GET /api/admin/users` — never includes `password_hash` or `api_key`

To grant admin access, set `is_admin = 1` on a user's row directly in the
database — there is intentionally no self-serve promotion endpoint.

## Risk scoring

Combines: local URL/content heuristics (`detector.py`), domain reputation
(age, SSL, known-pattern matches — `threat_intel.py`), and external feed
hits (Safe Browsing, OpenPhish). See `PhishingDetector.analyze_url` and
`ThreatIntelligence.check_url_safety` for the exact scoring — it changes
more often than a static table here would stay accurate.

## Setup

See the root `README.md` — it has the actual up-to-date setup steps,
environment variables, and feature list, and won't drift the way embedded
code blocks did here before.
