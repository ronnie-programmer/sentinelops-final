# SentinelOps

A full-stack Security Operations Center (SOC) dashboard. Tracks threats, alerts, assets, compliance controls, and threat intelligence — all in one dark-themed ops interface.

## Stack

| Layer | Technology |
|-------|-----------|
| Frontend | React 18, Vite, Tailwind CSS 3, Recharts |
| Backend | FastAPI, SQLAlchemy, SQLite |
| Deploy | Vercel (frontend) + Railway (backend) |

## Features

- **Threat management** — create, triage, and track threats with MITRE ATT&CK mapping and AI-generated analysis per threat type
- **Alert log** — auto-generated alerts for HIGH/CRITICAL threats; acknowledge individually or in bulk
- **Asset inventory** — track servers, endpoints, and network devices with vulnerability counts
- **Threat intelligence** — curate CVEs, threat actors, and IOCs; one-click import as active threat
- **Compliance** — NIST 800-53 and SOC 2 control status with CSV export
- **Dashboard** — live stats, 7-day threat trend, breakdown by type
- **Integrations** — CrowdStrike, Datadog, and Splunk adapters with automatic mock mode and background polling

## Feature: MITRE ATT&CK Mapping

Every threat and alert record is automatically tagged with up to three MITRE ATT&CK technique IDs at creation time.

**How it works:**

- Threats are classified by a keyword-based classifier in `backend/services/mitre_classifier.py`. Known threat types (Ransomware, Phishing, Brute Force, etc.) map directly to a curated set of technique IDs. Unknown types fall back to keyword matching against each technique's keyword list, then to T1078 if nothing matches.
- The matched technique IDs are stored as a JSON array in the `mitre_techniques` column on both the `Threat` and `AlertLog` models (e.g. `["T1486", "T1490", "T1078"]`).
- Alert records created for HIGH/CRITICAL threats inherit the same `mitre_techniques` value from their parent threat.

**Data source:**

Technique definitions live in `backend/data/mitre_techniques.json` — a curated subset of 36 MITRE ATT&CK Enterprise techniques covering Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection, Exfiltration, Command and Control, and Impact. No external download is required; the file ships with the repo.

**Matrix page (`/mitre`):**

The Matrix page renders a heat-map grid of all techniques grouped by tactic. Each technique cell is colored by detection count over the past 30 days:

- Gray — no detections
- Blue — 1–2 detections
- Orange — 3–5 detections
- Red — 6+ detections

Clicking any cell opens a detail panel with the technique ID, name, tactic, detection count, and a direct link to `https://attack.mitre.org/techniques/{ID}/`.

**API endpoints:**

| Method | Path | Description |
|--------|------|-------------|
| GET | /api/mitre/techniques | List all 36 techniques |
| GET | /api/mitre/techniques/{id} | Get one technique by ID |
| GET | /api/mitre/matrix | Matrix grouped by tactic with 30-day detection counts |

---

## Local Setup

### Prerequisites
- Python 3.10+
- Node.js 18+

### 1. Backend

```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python seed.py          # loads demo data into sentinelops.db
uvicorn main:app --reload
```

API runs at `http://localhost:8000`. Interactive docs at `http://localhost:8000/docs`.

### 2. Frontend

```bash
cd frontend
npm install
npm run dev
```

App runs at `http://localhost:5173`. Vite proxies `/api` → `localhost:8000`.

---

## Deployment

### Backend → Railway

1. Go to [railway.app](https://railway.app) → **New Project** → **Deploy from GitHub**
2. Select the `ronnie-programmer/sentinelops` repo, set **Root Directory** to `backend`
3. Add environment variable:
   ```
   CORS_ORIGINS=https://your-app.vercel.app
   ```
4. Railway reads `railway.json` — NIXPACKS builder, pip install, uvicorn start command.

> **SQLite note:** Railway's filesystem resets on each redeploy, so `sentinelops.db` starts fresh. Fine for a demo. For persistent data, provision a Railway PostgreSQL service and update `database.py` to read `DATABASE_URL` from env.

### Frontend → Vercel

1. Go to [vercel.com](https://vercel.com) → **New Project** → import `ronnie-programmer/sentinelops`
2. Set **Root Directory** to `frontend`
3. Add environment variable:
   ```
   VITE_API_URL=https://your-backend.railway.app
   ```
4. Deploy — Vercel auto-detects Vite. `vercel.json` handles SPA routing rewrites.

### After deploying both

- Copy the Railway backend URL into Vercel's `VITE_API_URL`
- Copy the Vercel frontend URL into Railway's `CORS_ORIGINS`
- Redeploy both once so each picks up the other's URL

---

## Feature: AI Alert Summarizer

Every alert automatically receives a concise, plain-English 2-sentence summary when it is created. The first sentence identifies what happened (threat type, affected asset, and source IP); the second sentence states the risk level and the number of indicators observed.

**Environment variable:** `SUMMARIZER_PROVIDER` (default: `rule`)

| Value | Behaviour |
|-------|-----------|
| `rule` | Built-in rule-based engine — no external dependencies, works out of the box |
| `anthropic` | *(future)* Plug in an Anthropic Claude adapter |
| `openai` | *(future)* Plug in an OpenAI adapter |

**How to extend:** implement a class with the same interface as `RuleSummarizer` (a single `summarize(alert_type, asset_name, source_ip, indicator_count, risk_phrase) -> str` method) and return an instance of it from `get_summarizer()` in `backend/services/summarizer.py`. No other files need to change.

---

## Feature: Slack & PagerDuty Routing

SentinelOps automatically dispatches alerts to Slack and PagerDuty whenever a HIGH or CRITICAL threat is created. You can also configure channels and fire test notifications from the **Notifications** settings page in the UI.

### What it does

- **Auto-dispatch on threat creation** — any new threat with severity HIGH or CRITICAL fires both adapters immediately after the AlertLog entry is written.
- **Graceful no-op** — adapters check environment variables at call time. If a channel is not configured, the call returns `{status: "skipped"}` and nothing is sent.
- **Notification log** — every dispatch attempt (sent, skipped, or error) is recorded in the `notifications` table and shown in the UI.
- **Runtime settings** — the settings page (`/notifications`) allows toggling channels, updating webhook URLs/keys, and sending test alerts without restarting the server.

### Environment variables

Add these to your backend environment (Railway env vars, `.env` file, or shell export):

```
# Slack
SLACK_ENABLED=true
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/T.../B.../...

# PagerDuty
PAGERDUTY_ENABLED=true
PAGERDUTY_INTEGRATION_KEY=your-32-char-integration-key
PAGERDUTY_SEVERITY_THRESHOLD=HIGH   # LOW | MEDIUM | HIGH | CRITICAL
```

### Getting a Slack webhook URL

1. Go to [api.slack.com/apps](https://api.slack.com/apps) and create a new app (or use an existing one).
2. Under **Features**, select **Incoming Webhooks** and toggle it on.
3. Click **Add New Webhook to Workspace**, choose a channel, and authorize.
4. Copy the generated webhook URL (starts with `https://hooks.slack.com/services/`).
5. Set `SLACK_WEBHOOK_URL` to that URL and `SLACK_ENABLED=true`.

### Getting a PagerDuty integration key

1. In PagerDuty, go to **Services** and select (or create) the service that should receive SentinelOps alerts.
2. Open the **Integrations** tab and click **Add an Integration**.
3. Choose **Events API v2** and save.
4. Copy the **Integration Key** shown on the integrations list.
5. Set `PAGERDUTY_INTEGRATION_KEY` to that key and `PAGERDUTY_ENABLED=true`.
6. Optionally set `PAGERDUTY_SEVERITY_THRESHOLD` to control the minimum severity that triggers a page (default: `HIGH`).

### Test notification endpoint

```
POST /api/notifications/test
Content-Type: application/json

{ "channel": "slack" }          # or "pagerduty" or "all"
```

Response includes a `results` array showing the outcome for each channel.

---

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | /health | Health check |
| GET | /api/dashboard/stats | Aggregate stats for dashboard |
| GET/POST | /api/threats/ | List / create threats |
| POST | /api/threats/{id}/analyze | Generate AI threat analysis |
| GET/POST | /api/alerts/ | List alerts / acknowledge |
| GET/POST | /api/assets/ | List / create assets |
| GET | /api/compliance/ | NIST + SOC 2 control status |
| GET | /api/intel/ | Threat intelligence feed |
| POST | /api/intel/{id}/import | Import intel item as active threat |

| GET | /api/integrations/ | List integrations and their status |
| POST | /api/integrations/{provider}/toggle | Enable or disable an integration |
| POST | /api/integrations/{provider}/poll | Manually trigger a poll |
| GET | /api/integrations/alerts | List integration-sourced alerts |

Full interactive docs: `http://localhost:8000/docs`

## Feature: Security Tool Integrations

SentinelOps can pull alerts from CrowdStrike Falcon, Datadog Security, and Splunk Enterprise Security using an adapter pattern. Each provider has a dedicated adapter that normalizes vendor-specific payloads into the shared SentinelOps schema.

### How mock mode works

When API credentials are absent, every adapter automatically enters **mock mode**. Mock mode generates realistic, provider-shaped alerts on every poll — you get plausible CrowdStrike detections, Datadog signals, and Splunk correlation rule firings without needing any actual accounts. This lets you develop and demo the feature with zero external dependencies.

### Background polling

An APScheduler `AsyncIOScheduler` starts with the FastAPI app and polls all enabled integrations on an interval (default: 5 minutes). Each poll deduplicates by `external_id` before writing new `Threat` and `AlertLog` rows so re-runs are idempotent.

### Providers and env vars

| Provider | Env vars required |
|---|---|
| CrowdStrike Falcon | `CROWDSTRIKE_CLIENT_ID`, `CROWDSTRIKE_CLIENT_SECRET` |
| Datadog Security | `DATADOG_API_KEY`, `DATADOG_APP_KEY` |
| Splunk ES | `SPLUNK_HOST`, `SPLUNK_TOKEN` |

Set `INTEGRATION_POLL_INTERVAL_MINUTES` to change the polling cadence (default `5`).

### Adding a new integration

1. Create `backend/integrations/myprovider.py` and subclass `IntegrationAdapter` from `base.py`.
2. Implement `poll_alerts()` returning a list of dicts with keys: `external_id`, `title`, `description`, `severity`, `threat_type`, `source_ip`, `affected_system`, `source`.
3. Implement `push_acknowledgement(alert_id)`.
4. Add an entry to `ADAPTERS` in `backend/routers/integrations.py` and register the job in `backend/integrations/scheduler.py`.

## Project Structure

```
sentinelops-final/
├── backend/
│   ├── main.py          # FastAPI app, CORS config
│   ├── database.py      # SQLite + SQLAlchemy setup
│   ├── models.py        # ORM models (Threat, Asset, AlertLog, ThreatIntel, Integration)
│   ├── schemas.py       # Pydantic request/response models
│   ├── seed.py          # Demo data seeder
│   ├── Procfile         # Railway start command
│   ├── railway.json     # Railway NIXPACKS config
│   ├── routers/
│   │   ├── dashboard.py
│   │   ├── threats.py
│   │   ├── alerts.py
│   │   ├── assets.py
│   │   ├── compliance.py
│   │   ├── intel.py
│   │   └── integrations.py  # Integration CRUD + manual poll endpoints
│   └── integrations/
│       ├── base.py          # IntegrationAdapter ABC
│       ├── crowdstrike.py   # CrowdStrike Falcon adapter (mock + real)
│       ├── datadog.py       # Datadog Security adapter (mock + real)
│       ├── splunk.py        # Splunk ES adapter (mock + real)
│       └── scheduler.py     # APScheduler background polling
└── frontend/
    ├── vercel.json      # SPA rewrites + cache headers
    └── src/
        ├── api.js       # Axios client (reads VITE_API_URL)
        ├── App.jsx      # Routes
        ├── components/  # Sidebar, Navbar
        └── pages/       # Dashboard, Threats, Alerts, Assets, Compliance, ThreatIntel, Integrations
```
