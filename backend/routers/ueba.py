"""UEBA router — user and entity behavior analytics endpoints."""
import json
import logging
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session

from database import get_db
from models import UserBaseline, UEBAEvent
from schemas import UserBaselineOut, UEBAEventOut, UEBAEventCreate

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/ueba", tags=["ueba"])


@router.get("/events", response_model=list[UEBAEventOut])
def list_events(
    is_anomaly: Optional[int] = None,
    limit: int = 50,
    username: Optional[str] = None,
    db: Session = Depends(get_db),
):
    query = db.query(UEBAEvent)
    if is_anomaly is not None:
        query = query.filter(UEBAEvent.is_anomaly == is_anomaly)
    if username:
        query = query.filter(UEBAEvent.username == username)
    events = query.order_by(UEBAEvent.detected_at.desc()).limit(limit).all()
    return [_coerce_event(e) for e in events]


@router.get("/events/top", response_model=list[UEBAEventOut])
def top_events(db: Session = Depends(get_db)):
    events = (
        db.query(UEBAEvent)
        .filter(UEBAEvent.anomaly_score.isnot(None))
        .order_by(UEBAEvent.anomaly_score.desc())
        .limit(20)
        .all()
    )
    return [_coerce_event(e) for e in events]


@router.get("/users", response_model=list[UserBaselineOut])
def list_users(db: Session = Depends(get_db)):
    return db.query(UserBaseline).order_by(UserBaseline.username).all()


@router.get("/users/{username}/profile")
def user_profile(username: str, db: Session = Depends(get_db)):
    baseline = db.query(UserBaseline).filter(UserBaseline.username == username).first()
    if not baseline:
        raise HTTPException(status_code=404, detail="User baseline not found")

    recent_events = (
        db.query(UEBAEvent)
        .filter(UEBAEvent.username == username)
        .order_by(UEBAEvent.detected_at.desc())
        .limit(20)
        .all()
    )
    total_events = db.query(UEBAEvent).filter(UEBAEvent.username == username).count()
    anomaly_count = (
        db.query(UEBAEvent)
        .filter(UEBAEvent.username == username, UEBAEvent.is_anomaly == 1)
        .count()
    )
    avg_score = None
    scored = [e.anomaly_score for e in recent_events if e.anomaly_score is not None]
    if scored:
        avg_score = round(sum(scored) / len(scored), 1)

    return {
        "baseline": UserBaselineOut.model_validate(baseline),
        "recent_events": [_coerce_event(e) for e in recent_events],
        "stats": {
            "total_events": total_events,
            "anomaly_count": anomaly_count,
            "avg_anomaly_score": avg_score,
        },
    }


@router.post("/retrain")
def retrain_baselines(background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    """Trigger manual retraining of all user baselines (runs in background)."""
    from database import SessionLocal
    from ueba.scheduler import retrain_all_baselines

    background_tasks.add_task(retrain_all_baselines, SessionLocal)
    return {"status": "retraining_started", "message": "Baseline retraining queued in background"}


@router.post("/events", response_model=UEBAEventOut)
def record_event(payload: UEBAEventCreate, db: Session = Depends(get_db)):
    """Record a new UEBA event and score it against the user's baseline."""
    from ueba.scoring import score_event, is_anomaly as _is_anomaly

    event_data = {}
    if payload.event_data_json:
        try:
            event_data = json.loads(payload.event_data_json)
        except json.JSONDecodeError:
            raise HTTPException(status_code=422, detail="event_data_json must be valid JSON")

    event_data.setdefault("event_type", payload.event_type)
    score = score_event(payload.username, event_data)
    flagged = 1 if _is_anomaly(score) else 0

    event = UEBAEvent(
        username=payload.username,
        event_type=payload.event_type,
        event_data_json=payload.event_data_json,
        anomaly_score=score,
        is_anomaly=flagged,
        source=payload.source,
    )
    db.add(event)
    db.commit()
    db.refresh(event)
    return _coerce_event(event)


def _coerce_event(event: UEBAEvent) -> UEBAEventOut:
    """Convert ORM UEBAEvent to schema, coercing integer is_anomaly to bool."""
    return UEBAEventOut(
        id=event.id,
        username=event.username,
        event_type=event.event_type,
        event_data_json=event.event_data_json,
        anomaly_score=event.anomaly_score,
        is_anomaly=bool(event.is_anomaly),
        detected_at=event.detected_at,
        source=event.source,
    )
