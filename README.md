# CYBERAUDIT MONITOR

**Observe. Investigate. Understand.**
Cybersecurity Audit and Monitoring System — graduation project.

A local Flask + SQLite web application that records every security-relevant
action in a hash-chained, append-only audit trail, evaluates rule-based
detections on each write, raises alerts, and gives analysts an investigation
workspace, reports and a presentation mode.

Arabic guide: [docs/GUIDE_AR.md](docs/GUIDE_AR.md) · Demo script: [docs/PRESENTATION_SCRIPT.md](docs/PRESENTATION_SCRIPT.md)

---

## Run it on Windows

Requirements: **Python 3.10 or newer** ([python.org](https://www.python.org/downloads/) — tick
"Add python.exe to PATH"). No other software, no cloud services. The first
install needs internet for `pip`; after that the app runs fully offline.

**Easiest:** double-click `start.bat`. On the first run it creates `.venv`,
installs Flask, seeds the demo database and opens http://127.0.0.1:5000.

**Manual (PowerShell or Command Prompt), inside the project folder:**

```bat
py -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python run.py
```

Then open http://127.0.0.1:5000

| Command | Effect |
|---|---|
| `python run.py` | start the server (creates and seeds the database on first start) |
| `python run.py --reset-db` | delete the database and re-create fresh demo data (use before a presentation) |
| `python run.py --port 8080` | use another port |
| `python -m pytest -q` | run the automated tests |

The server listens on 127.0.0.1 only (not reachable from other machines).

## Demo accounts (fictional)

| Username | Password | Role | Can do |
|---|---|---|---|
| `admin` | `Admin@12345` | Administrator | everything, incl. users, rule settings, integrity check |
| `s.karim` | `Analyst@12345` | Security Analyst | simulate, acknowledge/resolve alerts, notes, exports |
| `r.jawad` | `Analyst@12345` | Security Analyst | same as above |
| `m.ali` | `Viewer@12345` | Viewer | read-only (blocked actions are audited) |
| `a.hassan`, `n.saleh` | `Viewer@12345` | Viewer | read-only |
| `svc.backup` | `Service@12345` | Viewer | service account used in seed data |

## What is real and what is simulated

| Genuinely implemented | Simulated / demonstration |
|---|---|
| Authentication, sessions, CSRF, role checks, password hashing | Demo users and the ~1,850 seeded events (origin **Demo seed**) |
| Audit recording, hash chain, append-only triggers, integrity check | Simulator events (origin **Simulated**): no files touched, no real network |
| Detection rules, thresholds, windows, alert creation | Source IPs are private/test-range labels, never geolocated |
| Alerts workflow, notes, timeline, evidence | The intro animation styling (but every step waits for a real API response) |
| Search, filters, sorting, pagination, reports, CSV, print/PDF | |
| Real sign-ins and admin actions (origin **Live**) — these also trigger rules | |

Every event shows its origin badge in the UI and exports.

## Features

- **Cinematic entry** — animated emblem, title and a start-up sequence whose
  steps complete only when `/api/health`, `/api/rules` and `/api/events`
  answer. Skippable (button or Esc), shown once after sign-in, replay from the
  profile menu or presentation mode, honours reduced-motion.
- **Dashboard** — six database-backed metric cards with 24 h trend, event
  volume chart (24 h / 7 d / 30 d, hover + keyboard tooltips), distribution
  doughnut, interactive SVG network graph (source IP → app → account) with
  details panel, live system health, and a live event stream (3 s polling,
  pause/resume).
- **Audit log explorer** — server-side search, filters (user, IP, action,
  outcome, severity, origin, dates), sortable columns, pagination, URL-synced
  state, event drawer with UTC/local time, request, metadata, hash, related
  alerts, neighbouring events and copy-ID.
- **Alert center & investigation** — status/severity/rule/date/text filters;
  workspace with rule explanation, threshold/window facts, window track,
  timeline (context → evidence → trigger → analyst actions), related
  entities, automatic finding (successful sign-in after failures?),
  recommended steps, notes, acknowledge, resolve (with required summary),
  raw event view.
- **Detection engine** — five deterministic rules evaluated after every write:

  | Rule | Fires when | Default |
  |---|---|---|
  | R-01 | failed sign-ins for one account | ≥ 5 in 10 min |
  | R-02 | distinct accounts failing from one IP | ≥ 3 in 15 min |
  | R-03 | denied operations for one account | ≥ 4 in 30 min |
  | R-04 | file deletions by one account | ≥ 10 in 5 min |
  | R-05 | any role/permission change | every change |

  Administrators can enable/disable rules and change thresholds/windows
  (validated on the server, audited as `rule.update`). No machine learning or
  threat-intelligence claims.
- **Event simulator** — 10 presets, custom events, and a 7-step guided
  "Repeated failed login investigation" that advances only on real responses.
- **User management** — create, change role (with confirmation), activate /
  deactivate, temporary password reset; cannot change own role or deactivate
  self; last active administrator protected; accounts are never deleted.
- **Reports** — period/date/user/action/outcome/severity filters, preview,
  CSV export (formula-injection escaped, UTF-8 BOM for Excel), printable HTML
  report → *Save as PDF* from the browser. Exports are audited.
- **Presentation mode** — large metrics, highlighted alert, scenario launcher,
  big live stream, 8-step guided sequence with talking points (← → / PageUp /
  PageDown).

## Security controls

| Control | Where |
|---|---|
| Password hashing (scrypt via Werkzeug), policy 10+ chars with letters & digits | `app/security.py` |
| Session cookie HttpOnly + SameSite=Lax, session cleared on login (fixation) | `app/config.py`, `security.login_user` |
| CSRF token on every POST/PUT/PATCH/DELETE (form field or `X-CSRF-Token`) | `security.check_csrf` |
| Role-based authorization on the server; denied attempts audited (`access.denied`) | `security.role_required` |
| Parameterized SQL everywhere, whitelisted sort columns, escaped `LIKE` | `app/events.py` and others |
| Input validation (dates, enums, IPs, counts, thresholds, usernames) | services + tests |
| Output escaping: Jinja autoescape + `CA.esc()` for every dynamic string | templates, `static/js` |
| CSP (`script-src 'self'`), `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy` | `security.apply_security_headers` |
| Open-redirect protection on `?next=` | `views._safe_next` |
| Secrets never logged (metadata keys like password/token/csrf are dropped) | `audit.sanitize_metadata` |
| Append-only audit table (SQLite triggers) + SHA-256 hash chain + verify UI | `app/db.py`, `app/audit.py` |
| CSV formula escaping | `reports._safe_cell` |
| Safe error pages (no stack traces to the client) | `app/__init__.py` |

**Integrity limitations (honest):** the triggers and hash chain make tampering
*detectable*, but anyone with write access to `instance/cyberaudit.db` could
drop the triggers and rebuild the whole chain. Real deployments would anchor
hashes externally (e.g. periodic signed checkpoints or WORM storage). The
built-in server is Flask's development server, appropriate for a local demo,
not for production. There is no account lockout — repeated failures are
detected and alerted instead.

## Project structure

```
cyberaudit/
├── run.py                 entry point (python run.py [--reset-db] [--port N])
├── start.bat              one-click Windows launcher
├── requirements.txt
├── app/
│   ├── __init__.py        app factory, error handlers, startup seeding
│   ├── config.py          settings; secret key stored in instance/secret_key
│   ├── db.py              SQLite schema, append-only triggers, connections
│   ├── security.py        authentication, CSRF, roles, security headers
│   ├── audit.py           event recording, hash chain, verification
│   ├── detection.py       rule engine (R-01 … R-05), rule settings
│   ├── alerts.py          alert list, investigation detail, ack/resolve/notes
│   ├── events.py          audit search/filter/sort/pagination
│   ├── stats.py           dashboard metrics, series, health, network graph
│   ├── simulator.py       presets and safe simulated events
│   ├── users.py           user administration and safeguards
│   ├── reports.py         report queries, CSV export
│   ├── seed.py            deterministic demo data (through the real pipeline)
│   ├── api.py             JSON API blueprint (/api/…)
│   ├── views.py           pages, login/logout, exports
│   ├── templates/         Jinja templates (one per page + partials)
│   └── static/            css/app.css, css/report.css, js/*.js, img/
├── tests/                 pytest suite (25 tests)
├── docs/                  Arabic guide and presentation script
└── instance/              created at runtime: cyberaudit.db, secret_key
```

## API overview

All endpoints require a signed-in session; unsafe methods need the CSRF header.

`GET /api/health` · `GET /api/stats?range=24h|7d|30d&tz=` · `GET /api/network` ·
`GET /api/events?…` · `GET /api/events/<id>` · `GET /api/alerts?…` ·
`GET /api/alerts/<uid>` · `POST /api/alerts/<uid>/acknowledge|resolve|notes` ·
`GET /api/rules` · `PUT /api/rules/<id>` (admin) · `GET /api/simulator/options` ·
`POST /api/simulate` (analyst) · `GET|POST /api/users`, `PATCH /api/users/<id>`,
`POST /api/users/<id>/reset-password` (admin) · `GET /api/reports/summary` ·
`GET /reports/export.csv` · `GET /reports/print` (analyst) ·
`POST /api/integrity/verify` (admin) · `GET /api/notifications`.

## Tests

```bat
python -m pytest -q
```

25 tests cover login and audit of failures, CSRF, open redirect, security
headers, role restrictions, simulated event persistence, R-01/R-02/R-04/R-05
detection (including real failed logins), alert acknowledge/resolve/notes,
filters/sorting/pagination and SQL-injection strings, user safeguards and
password reset, rule validation and disabling, CSV formula escaping, reports,
append-only triggers and tamper detection, health/stats consistency, every
page rendering, logout, and the full demo seed.
