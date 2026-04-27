import logging
from fastapi import APIRouter, Depends, BackgroundTasks, HTTPException
from pydantic import BaseModel
from sqlalchemy import or_
from sqlalchemy.orm import Session
from typing import List
from datetime import datetime

from database import get_db, SessionLocal
from models import Integration, AlertLog, Threat
from schemas import IntegrationOut, IntegrationToggle
from integrations.crowdstrike import CrowdStrikeAdapter
from integrations.datadog import DatadogAdapter
from integrations.splunk import SplunkAdapter
from integrations.edr.crowdstrike_insight import CrowdStrikeInsightAdapter
from integrations.edr.sentinelone import SentinelOneAdapter
from integrations.scheduler import _poll_integration

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/integrations", tags=["integrations"])

ADAPTERS = {
    "crowdstrike": CrowdStrikeAdapter,
    "datadog": DatadogAdapter,
    "splunk": SplunkAdapter,
    "crowdstrike_insight": CrowdStrikeInsightAdapter,
    "sentinelone": SentinelOneAdapter,
}

EDR_ADAPTERS = {
    "crowdstrike_insight": CrowdStrikeInsightAdapter,
    "sentinelone": SentinelOneAdapter,
}


def _ensure_integrations(db: Session):
    for provider in ADAPTERS:
        existing = db.query(Integration).filter(Integration.provider == provider).first()
        if not existing:
            adapter = ADAPTERS[provider]()
            integ = Integration(
                provider=provider,
                enabled=0,
                is_mock=1 if adapter.is_mock else 0,
                status="mock" if adapter.is_mock else "connected",
            )
            db.add(integ)
    db.commit()


@router.get("/", response_model=List[IntegrationOut])
def list_integrations(db: Session = Depends(get_db)):
    _ensure_integrations(db)
    integrations = db.query(Integration).all()
    result = []
    for integ in integrations:
        adapter = ADAPTERS.get(integ.provider)
        if adapter:
            a = adapter()
            integ.is_mock = 1 if a.is_mock else 0
            integ.status = "mock" if a.is_mock else ("connected" if bool(integ.enabled) else "idle")
        result.append(IntegrationOut.from_orm_model(integ))
    return result


@router.post("/{provider}/toggle", response_model=IntegrationOut)
def toggle_integration(provider: str, body: IntegrationToggle, db: Session = Depends(get_db)):
    _ensure_integrations(db)
    integ = db.query(Integration).filter(Integration.provider == provider).first()
    if not integ:
        raise HTTPException(status_code=404, detail="Integration not found")
    integ.enabled = 1 if body.enabled else 0
    integ.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(integ)
    return IntegrationOut.from_orm_model(integ)


@router.post("/{provider}/poll")
async def manual_poll(provider: str, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    adapter_class = ADAPTERS.get(provider)
    if not adapter_class:
        raise HTTPException(status_code=404, detail="Integration not found")

    background_tasks.add_task(_poll_integration, adapter_class, SessionLocal)
    return {"status": "polling", "provider": provider}


@router.get("/alerts")
def get_integration_alerts(source: str = None, limit: int = 50, db: Session = Depends(get_db)):
    query = db.query(AlertLog)
    providers = list(ADAPTERS.keys())
    # Filter to integration-sourced alerts by checking message prefix
    if source and source in providers:
        query = query.filter(AlertLog.message.like(f"[{source.upper()}]%"))
    else:
        # Show all integration alerts (any with provider prefix)
        query = query.filter(
            or_(*[AlertLog.message.like(f"[{p.upper()}]%") for p in providers])
        )
    return query.order_by(AlertLog.created_at.desc()).limit(limit).all()


class IsolateHostBody(BaseModel):
    hostname: str
    device_id: str = ""


class KillProcessBody(BaseModel):
    agent_id: str
    process_id: int


@router.get("/edr/actions")
def list_edr_actions():
    return {
        "actions": [
            {
                "provider": "crowdstrike_insight",
                "action": "isolate_host",
                "description": "Isolate a host via Falcon RTR API",
                "params": ["hostname", "device_id (optional)"],
            },
            {
                "provider": "sentinelone",
                "action": "kill_process",
                "description": "Kill a process on an endpoint via SentinelOne Remote Script Orchestration",
                "params": ["agent_id", "process_id"],
            },
        ]
    }


@router.post("/edr/{provider}/isolate")
def edr_isolate_host(provider: str, body: IsolateHostBody):
    if provider not in EDR_ADAPTERS or provider != "crowdstrike_insight":
        raise HTTPException(status_code=404, detail="EDR provider not found or does not support isolate_host")
    adapter = CrowdStrikeInsightAdapter()
    result = adapter.isolate_host(body.hostname, body.device_id)
    return result


@router.post("/edr/{provider}/kill-process")
def edr_kill_process(provider: str, body: KillProcessBody):
    if provider not in EDR_ADAPTERS or provider != "sentinelone":
        raise HTTPException(status_code=404, detail="EDR provider not found or does not support kill_process")
    adapter = SentinelOneAdapter()
    result = adapter.kill_process(body.agent_id, body.process_id)
    return result
