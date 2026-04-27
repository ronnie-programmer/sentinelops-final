from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime

from database import get_db
from models import AlertLog
from schemas import AlertLogOut

router = APIRouter(prefix="/api/alerts", tags=["alerts"])


@router.get("/", response_model=List[AlertLogOut])
def get_alerts(
    skip: int = 0,
    limit: int = 100,
    status: Optional[str] = None,
    db: Session = Depends(get_db),
):
    query = db.query(AlertLog)
    if status:
        query = query.filter(AlertLog.status == status)
    return query.order_by(AlertLog.created_at.desc()).offset(skip).limit(limit).all()


@router.get("/unread-count")
def get_unread_count(db: Session = Depends(get_db)):
    count = db.query(AlertLog).filter(AlertLog.status.in_(["Pending", "Sent"])).count()
    return {"count": count}


@router.get("/{alert_id}", response_model=AlertLogOut)
def get_alert(alert_id: int, db: Session = Depends(get_db)):
    alert = db.query(AlertLog).filter(AlertLog.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@router.post("/{alert_id}/acknowledge", response_model=AlertLogOut)
def acknowledge_alert(alert_id: int, db: Session = Depends(get_db)):
    alert = db.query(AlertLog).filter(AlertLog.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.status = "Acknowledged"
    alert.acknowledged_at = datetime.utcnow()
    db.commit()
    db.refresh(alert)
    return alert


@router.post("/acknowledge-all")
def acknowledge_all_alerts(db: Session = Depends(get_db)):
    now = datetime.utcnow()
    updated = (
        db.query(AlertLog)
        .filter(AlertLog.status.in_(["Pending", "Sent"]))
        .all()
    )
    for alert in updated:
        alert.status = "Acknowledged"
        alert.acknowledged_at = now
    db.commit()
    return {"acknowledged": len(updated)}
