import json
import logging
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import func
from sqlalchemy.orm import Session

from database import get_db
from models import UEBAAnomaly, UEBAEvent, UEBAUser
from ueba.baseline import recompute_all
from ueba.scoring import detect_recent_anomalies

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/ueba", tags=["ueba"])


# ----- Schemas (kept local since they don't need to be reused) -----

class UEBAUserOut(BaseModel):
    id: int
    username: str
    department: Optional[str] = None
    role: Optional[str] = None
    is_privileged: bool
    baseline_updated_at: Optional[datetime] = None
    open_anomaly_count: int = 0
    max_recent_score: int = 0


class UEBAAnomalyOut(BaseModel):
    id: int
    user_id: int
    username: str
    detected_at: datetime
    window_start: datetime
    window_end: datetime
    score: int
    severity: str
    status: str
    summary: Optional[str] = None
    contributing_features: Optional[list] = None


class UEBAUserDetailOut(BaseModel):
    id: int
    username: str
    department: Optional[str] = None
    role: Optional[str] = None
    is_privileged: bool
    baseline: Optional[dict] = None
    baseline_updated_at: Optional[datetime] = None
    recent_event_count: int
    recent_anomalies: list[UEBAAnomalyOut]


class UEBAStatsOut(BaseModel):
    user_count: int
    event_count: int
    open_anomalies: int
    by_severity: dict
    last_baseline_at: Optional[datetime] = None


# ----- Endpoints -----

@router.get("/users", response_model=list[UEBAUserOut])
def list_users(db: Session = Depends(get_db)):
    users = db.query(UEBAUser).order_by(UEBAUser.username).all()
    out = []
    for u in users:
        open_count = db.query(UEBAAnomaly).filter(
            UEBAAnomaly.user_id == u.id,
            UEBAAnomaly.status == "Open",
        ).count()
        max_score_row = (
            db.query(func.max(UEBAAnomaly.score))
            .filter(UEBAAnomaly.user_id == u.id)
            .filter(UEBAAnomaly.detected_at >= datetime.utcnow() - timedelta(days=7))
            .scalar()
        )
        out.append(UEBAUserOut(
            id=u.id,
            username=u.username,
            department=u.department,
            role=u.role,
            is_privileged=bool(u.is_privileged),
            baseline_updated_at=u.baseline_updated_at,
            open_anomaly_count=open_count,
            max_recent_score=int(max_score_row or 0),
        ))
    return out


@router.get("/users/{user_id}", response_model=UEBAUserDetailOut)
def get_user(user_id: int, db: Session = Depends(get_db)):
    user = db.query(UEBAUser).filter(UEBAUser.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="user not found")

    recent_count = db.query(UEBAEvent).filter(
        UEBAEvent.user_id == user.id,
        UEBAEvent.occurred_at >= datetime.utcnow() - timedelta(days=7),
    ).count()

    anomalies = (
        db.query(UEBAAnomaly)
        .filter(UEBAAnomaly.user_id == user.id)
        .order_by(UEBAAnomaly.detected_at.desc())
        .limit(10)
        .all()
    )
    return UEBAUserDetailOut(
        id=user.id,
        username=user.username,
        department=user.department,
        role=user.role,
        is_privileged=bool(user.is_privileged),
        baseline=json.loads(user.baseline_json) if user.baseline_json else None,
        baseline_updated_at=user.baseline_updated_at,
        recent_event_count=recent_count,
        recent_anomalies=[_anomaly_to_out(a, user.username) for a in anomalies],
    )


@router.get("/anomalies", response_model=list[UEBAAnomalyOut])
def list_anomalies(
    severity: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 100,
    db: Session = Depends(get_db),
):
    q = db.query(UEBAAnomaly, UEBAUser).join(UEBAUser, UEBAUser.id == UEBAAnomaly.user_id)
    if severity:
        q = q.filter(UEBAAnomaly.severity == severity.upper())
    if status:
        q = q.filter(UEBAAnomaly.status == status)
    rows = q.order_by(UEBAAnomaly.detected_at.desc()).limit(limit).all()
    return [_anomaly_to_out(a, u.username) for a, u in rows]


class AnomalyStatusUpdate(BaseModel):
    status: str  # Open, Investigating, Resolved, False Positive


@router.post("/anomalies/{anomaly_id}/status", response_model=UEBAAnomalyOut)
def update_anomaly_status(anomaly_id: int, body: AnomalyStatusUpdate, db: Session = Depends(get_db)):
    anomaly = db.query(UEBAAnomaly).filter(UEBAAnomaly.id == anomaly_id).first()
    if not anomaly:
        raise HTTPException(status_code=404, detail="anomaly not found")
    valid = {"Open", "Investigating", "Resolved", "False Positive"}
    if body.status not in valid:
        raise HTTPException(status_code=400, detail=f"status must be one of {sorted(valid)}")
    anomaly.status = body.status
    if body.status in ("Resolved", "False Positive"):
        anomaly.resolved_at = datetime.utcnow()
    db.commit()
    db.refresh(anomaly)
    user = db.query(UEBAUser).filter(UEBAUser.id == anomaly.user_id).first()
    return _anomaly_to_out(anomaly, user.username if user else "")


@router.post("/recompute")
def recompute(db: Session = Depends(get_db)):
    n = recompute_all(db)
    anomalies = detect_recent_anomalies(db)
    return {"baselines_updated": n, "new_anomalies": len(anomalies)}


@router.get("/stats", response_model=UEBAStatsOut)
def stats(db: Session = Depends(get_db)):
    user_count = db.query(UEBAUser).count()
    event_count = db.query(UEBAEvent).count()
    open_count = db.query(UEBAAnomaly).filter(UEBAAnomaly.status == "Open").count()
    by_sev = {}
    for sev, cnt in (
        db.query(UEBAAnomaly.severity, func.count(UEBAAnomaly.id))
        .filter(UEBAAnomaly.status == "Open")
        .group_by(UEBAAnomaly.severity)
        .all()
    ):
        by_sev[sev] = cnt
    last_baseline = db.query(func.max(UEBAUser.baseline_updated_at)).scalar()
    return UEBAStatsOut(
        user_count=user_count,
        event_count=event_count,
        open_anomalies=open_count,
        by_severity=by_sev,
        last_baseline_at=last_baseline,
    )


# ----- Helpers -----

def _anomaly_to_out(a: UEBAAnomaly, username: str) -> UEBAAnomalyOut:
    contributions = None
    if a.contributing_features:
        try:
            contributions = json.loads(a.contributing_features)
        except json.JSONDecodeError:
            contributions = None
    return UEBAAnomalyOut(
        id=a.id,
        user_id=a.user_id,
        username=username,
        detected_at=a.detected_at,
        window_start=a.window_start,
        window_end=a.window_end,
        score=a.score,
        severity=a.severity,
        status=a.status,
        summary=a.summary,
        contributing_features=contributions,
    )
