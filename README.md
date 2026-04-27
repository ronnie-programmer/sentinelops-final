# SentinelOps

A full-stack Security Operations Platform with AI-powered threat risk scoring and anomaly detection.

## Stack

| Layer | Technology |
|-------|-----------|
| Frontend | React 18, Vite, Tailwind CSS 3, Recharts |
| Backend | FastAPI, SQLAlchemy, SQLite |
| ML | scikit-learn (RandomForest + IsolationForest), pandas, joblib |
| Deploy | Vercel (frontend) + Railway (backend) |

## Local Setup

### Prerequisites
- Python 3.10+
- Node.js 18+

### 1. Backend

```bash
cd backend
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python seed.py          # loads demo threats, assets, intel into sentinelops.db
uvicorn main:app --reload
```

The ML model trains automatically on first startup once the DB has data.
API available at `http://localhost:8000` — docs at `http://localhost:8000/docs`.

### 2. Frontend

```bash
cd frontend
npm install
npm run dev
```

App available at `http://localhost:5173`. Vite proxies `/api` → `localhost:8000`.

### Verify ML endpoints

```bash
curl http://localhost:8000/api/ml/status
curl http://localhost:8000/api/ml/predictions
curl -X POST http://localhost:8000/api/ml/train
```

---

## Deployment

### Backend → Railway

1. Go to [railway.app](https://railway.app) → **New Project** → **Deploy from GitHub**
2. Select this repo, set **Root Directory** to `backend`
3. Add environment variables:
   ```
   CORS_ORIGINS=https://your-app.vercel.app
   ```
4. Railway reads `railway.json` — NIXPACKS builder, `pip install -r requirements.txt` build, uvicorn start.

> **Note on SQLite:** Railway's filesystem is ephemeral — `sentinelops.db` resets on redeploy. This is fine for a demo. For persistent data, swap to Railway PostgreSQL and update `database.py` to read `DATABASE_URL` from env.

### Frontend → Vercel

1. Go to [vercel.com](https://vercel.com) → **New Project** → import this repo
2. Set **Root Directory** to `frontend`
3. Add environment variable:
   ```
   VITE_API_URL=https://your-backend.railway.app
   ```
4. Deploy — Vercel auto-detects Vite. `vercel.json` handles SPA routing rewrites.

### After deploying both

- Copy the Railway URL into Vercel's `VITE_API_URL`
- Copy the Vercel URL into Railway's `CORS_ORIGINS`
- Redeploy both once to pick up the cross-origin config
- Hit `/api/ml/train` once to train the model on the seeded data

---

## ML Architecture

The ML module lives in `backend/ml/`:

- **`train.py`** — `run_training(db)`: reads the `threats` table, encodes categorical features (threat type, MITRE tactic), trains a `RandomForestClassifier` to predict HIGH/CRITICAL severity, and trains `IsolationForest` for anomaly detection. Pickles saved to `ml/artifacts/`.
- **`predict.py`** — `score_all_threats(db)`: loads pickles (in-memory cache), scores every threat, returns risk score + label + anomaly flag.
- **`schemas.py`** — Pydantic models for the ML API responses.

**Train-on-startup:** if no pickles exist, the server trains automatically at startup. If training fails (e.g., empty DB), the server still starts — retry via `POST /api/ml/train` after seeding.

**Pickles are gitignored** — they're regenerated on each deploy from the live DB.

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | /health | Health check |
| GET | /api/dashboard/stats | Dashboard aggregate stats |
| GET/POST | /api/threats/ | List / create threats |
| GET | /api/ml/status | Model readiness + training metadata |
| POST | /api/ml/train | Retrain model on current DB |
| GET | /api/ml/predictions | All threats with risk scores |
| GET | /api/ml/anomalies | Anomaly-flagged threats only |

Full interactive docs: `http://localhost:8000/docs`
