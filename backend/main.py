import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from database import engine, SessionLocal
from models import Base
from routers import alerts, assets, compliance, dashboard, intel, integrations, mitre, notifications, threats
from integrations.scheduler import start_scheduler, stop_scheduler

Base.metadata.create_all(bind=engine)


@asynccontextmanager
async def lifespan(app: FastAPI):
    poll_interval = int(os.getenv("INTEGRATION_POLL_INTERVAL_MINUTES", "5"))
    start_scheduler(SessionLocal, poll_interval)
    yield
    stop_scheduler()


app = FastAPI(
    title="SentinelOps API",
    description="Security Operations Platform — v3",
    version="3.0.0",
    lifespan=lifespan,
)

_raw_origins = os.getenv("CORS_ORIGINS", "http://localhost:5173,http://localhost:3000")
_cors_origins = [o.strip() for o in _raw_origins.split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(dashboard.router)
app.include_router(threats.router)
app.include_router(alerts.router)
app.include_router(assets.router)
app.include_router(compliance.router)
app.include_router(intel.router)
app.include_router(notifications.router)
app.include_router(mitre.router)
app.include_router(integrations.router)


@app.get("/")
def root():
    return {"name": "SentinelOps API", "version": "3.0.0", "status": "operational"}


@app.get("/health")
def health():
    return {"status": "ok"}
