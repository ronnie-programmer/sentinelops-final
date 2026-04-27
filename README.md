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

---

## Feature: IOC Enrichment

SentinelOps automatically extracts and enriches Indicators of Compromise (IOCs) from alert and threat text using VirusTotal and AbuseIPDB.

### What it does

- **Automatic extraction** — a regex-based extractor finds IPv4 addresses (skipping RFC-1918 private ranges), SHA-256/SHA-1/MD5 hashes, domains, and URLs from any text field
- **VirusTotal lookup** — each IOC is checked against the VirusTotal API; the malicious engine ratio is stored as a 0-100 score
- **AbuseIPDB lookup** — IP-type IOCs are also checked against AbuseIPDB's abuse confidence score (0-100)
- **24-hour cache** — previously enriched IOCs are reused for 24 hours to avoid rate-limit exhaustion
- **On-demand re-enrichment** — any IOC can be refreshed instantly via the UI Enrich button or the REST endpoint
- **IOC Reputation page** — `/iocs` lists all IOCs in a searchable, filterable table with color-coded risk scores
- **Dashboard widget** — the top 3 highest-scoring IOCs appear on the main dashboard

### Score color coding

| Score range | Color | Meaning |
|---|---|---|
| 75–100 | Red | High confidence malicious |
| 40–74 | Amber | Suspicious / moderate risk |
| 0–39 | Green | Clean or low risk |
| — | Gray | Not yet enriched |

---

## Feature: SOAR Playbooks

SentinelOps ships a lightweight SOAR (Security Orchestration, Automation and Response) engine. Playbooks are trigger-action workflows that fire automatically when conditions are met — for example, isolating a host the moment a CRITICAL ransomware alert fires.

### How it works

1. Each playbook has a **trigger** (expressed as YAML) and an ordered **action list** (also YAML).
2. On every relevant event, the engine calls `evaluate_trigger(trigger_yaml, context)` against the alert context dict.
3. If the trigger matches, `execute_actions(actions_yaml, context)` runs each action handler in sequence, collecting results.
4. Every run is recorded in `playbook_runs` with status (`running` / `success` / `error`) and a JSON output blob.

### Trigger types

| Type | Description |
|---|---|
| `always` | Fires on every event |
| `alert_severity_gte` | Fires when alert severity >= the specified level (LOW < MEDIUM < HIGH < CRITICAL) |
| `mitre_technique_in` | Fires when the alert's MITRE technique list contains any of the specified technique IDs |
| `custom_expression` | Evaluates a Python expression against the alert context dict |
| `time_window` | Fires only during a specified UTC hour range |

### Built-in action handlers

| Action | What it does |
|---|---|
| `notify_slack` | Posts a message to the configured Slack webhook |
| `enrich_ioc` | Queues an IOC reputation lookup (stub — returns immediately) |
| `isolate_host` | Sends an EDR isolation command (stub — logs the request) |
| `block_ip` | Queues a firewall block rule (stub — logs the request) |
| `create_jira_ticket` | Creates a Jira issue via REST API (stub when `JIRA_URL` is unset) |
| `escalate_severity` | Escalates a threat's severity to the specified level |
| `run_python_script` | Executes arbitrary Python in a limited sandbox |

All handlers are no-ops when their external dependency (Slack webhook, Jira URL, etc.) is not configured. They never crash the playbook run.

### Prebuilt playbooks (seeded on startup)

| Playbook | Trigger | Actions |
|---|---|---|
| Critical Ransomware Response | severity >= CRITICAL | Notify Slack, isolate host, block C2 IP, escalate severity |
| Suspicious Login Investigation | MITRE T1078 / T1110 / Brute Force | Notify Slack, enrich source IP, create Jira ticket |
| Malicious IOC Enrichment | severity >= HIGH | Enrich source IP, notify Slack |

Built-in playbooks are seeded at startup (idempotent — skipped if name already exists) and cannot be deleted via the API.

### React page (`/playbooks`)

- **Playbook table** — Name, trigger type badge, enable/disable toggle, run count, last run, action buttons (Run Now, Edit, Delete)
- **New Playbook form** — Name, description, Trigger YAML editor, Actions YAML editor
- **Edit modal** — Same fields, pre-populated with current values
- **Run History table** — Playbook name, triggered-by, status badge (green/red/blue), started-at, collapsible JSON output

### Environment variables

```
VIRUSTOTAL_API_KEY=    # Get from https://www.virustotal.com/gui/my-apikey
ABUSEIPDB_API_KEY=     # Get from https://www.abuseipdb.com/account/api
```

Both keys are optional. When absent, lookups return `null` scores — the extractor still runs and IOC records are created; scores populate once keys are added.

### API endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | /api/iocs/ | List all IOCs; filter with `?type=ip&search=xxx&limit=100` |
| GET | /api/iocs/top | Top 3 IOCs by highest score |
| GET | /api/iocs/{id} | Get single IOC |
| POST | /api/iocs/enrich/{id} | Re-enrich an IOC on demand |
| DELETE | /api/iocs/{id} | Delete an IOC record |

### Architecture

- `backend/services/enrichment/extractor.py` — pure-Python regex IOC extraction, no external deps
- `backend/services/enrichment/virustotal.py` — VirusTotal API v3 client; handles all four IOC types
- `backend/services/enrichment/abuseipdb.py` — AbuseIPDB v2 client; IP-only
- `backend/services/enrichment/enricher.py` — orchestrates extraction, cache check, lookup calls, and DB writes
- `backend/routers/iocs.py` — FastAPI router with list/top/get/enrich/delete endpoints
- `frontend/src/pages/IOCs.jsx` — IOC Reputation page with top-3 cards and searchable table
- `frontend/src/pages/Dashboard.jsx` — Top IOC Threats widget (conditionally rendered when data exists)

### Environment variables (SOAR Playbooks)

```
SLACK_PLAYBOOK_WEBHOOK=   # dedicated webhook for playbook notifications; falls back to SLACK_WEBHOOK_URL
JIRA_URL=
JIRA_API_TOKEN=
JIRA_PROJECT_KEY=SENTOPS
```

### API endpoints (SOAR Playbooks)

| Method | Path | Description |
|---|---|---|
| GET | /api/playbooks/ | List all playbooks |
| POST | /api/playbooks/ | Create a new playbook |
| GET | /api/playbooks/{id} | Get a single playbook |
| PUT | /api/playbooks/{id} | Update a playbook |
| DELETE | /api/playbooks/{id} | Delete (blocked for built-ins) |
| POST | /api/playbooks/{id}/toggle | Enable / disable |
| POST | /api/playbooks/{id}/run | Manually run with a test context |
| GET | /api/playbooks/{id}/runs | Run history for one playbook |
| GET | /api/playbooks/runs/all | All runs across all playbooks |

### Extending with a new action

1. Create `backend/playbooks/handlers/my_action.py` with an `execute(params, context) -> str` function.
2. Import it and add it to `HANDLERS` in `backend/playbooks/engine.py`.
3. Use it in a playbook's `actions_yaml`: `- action: my_action`.

---

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

## Feature: Compliance Reporting

Generate audit-ready PDF reports for SOC2, HIPAA, NIST 800-53, and CMMC frameworks. Each report maps framework controls to evidence collected from the platform (alerts, threats, asset records).

**Page:** `/compliance/reports`

**How it works:**

1. Pick a framework (SOC2, HIPAA, NIST, or CMMC) and a date range (preset or custom).
2. Click **Generate Report** — the backend creates a DB record with `status=generating` and kicks off a background task.
3. The background task queries alerts and threats in the date range, loads the framework's YAML control manifest, and builds a multi-page PDF using ReportLab:
   - Title page — framework name, audit period, generated timestamp
   - Executive Summary — alert count, threat count, critical count, resolved count
   - Control Details — one section per control with description, evidence source, and a dynamic narrative derived from actual platform counts
4. The report record is updated to `status=ready` with the file path. The page polls every 3 seconds while any report is generating.
5. Click **PDF** to download. Click **Delete** to remove the record and file.

**Framework manifests** live in `backend/data/compliance/` as YAML files:

| File | Framework | Controls |
|------|-----------|----------|
| `soc2.yaml` | SOC 2 Type II | CC6.1, CC7.2, CC7.3, CC8.1, A1.1 |
| `hipaa.yaml` | HIPAA Security Rule | 164.308(a)(1), 164.308(a)(5), 164.308(a)(6), 164.312(a)(1), 164.312(b) |
| `nist.yaml` | NIST SP 800-53 Rev 5 | AC-2, AU-2, IR-4, IR-6, SI-3, SI-4 |
| `cmmc.yaml` | CMMC Level 2 | AC.L1-3.1.1, AU.L2-3.3.1, IR.L2-3.6.1, SI.L1-3.14.1, SI.L2-3.14.6 |

**API endpoints:**

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/compliance/reports` | List all reports |
| `POST` | `/api/compliance/reports/generate` | Generate a new report |
| `GET` | `/api/compliance/reports/{id}` | Get report metadata |
| `GET` | `/api/compliance/reports/{id}/download` | Download PDF |
| `DELETE` | `/api/compliance/reports/{id}` | Delete report + file |

**Dependencies added:** `reportlab==4.1.0`, `pyyaml==6.0.1`

**Generated PDFs** are stored in `backend/reports/` (created automatically, gitignored).
