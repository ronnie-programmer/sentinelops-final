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

Full interactive docs: `http://localhost:8000/docs`

## Project Structure

```
sentinelops-final/
├── backend/
│   ├── main.py          # FastAPI app, CORS config
│   ├── database.py      # SQLite + SQLAlchemy setup
│   ├── models.py        # ORM models (Threat, Asset, AlertLog, ThreatIntel)
│   ├── schemas.py       # Pydantic request/response models
│   ├── seed.py          # Demo data seeder
│   ├── Procfile         # Railway start command
│   ├── railway.json     # Railway NIXPACKS config
│   └── routers/
│       ├── dashboard.py
│       ├── threats.py
│       ├── alerts.py
│       ├── assets.py
│       ├── compliance.py
│       └── intel.py
└── frontend/
    ├── vercel.json      # SPA rewrites + cache headers
    └── src/
        ├── api.js       # Axios client (reads VITE_API_URL)
        ├── App.jsx      # Routes
        ├── components/  # Sidebar, Navbar
        └── pages/       # Dashboard, Threats, Alerts, Assets, Compliance, ThreatIntel
```
