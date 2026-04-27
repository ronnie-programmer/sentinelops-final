from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func
from datetime import datetime, timedelta
from collections import defaultdict

from database import get_db
from models import Threat, Asset, AlertLog

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


@router.get("/stats")
def get_dashboard_stats(db: Session = Depends(get_db)):
    threats = db.query(Threat).all()
    assets = db.query(Asset).all()
    unread_alerts = db.query(AlertLog).filter(AlertLog.status.in_(["Pending", "Sent"])).count()

    severity_counts = defaultdict(int)
    status_counts = defaultdict(int)
    type_counts = defaultdict(int)

    for t in threats:
        severity_counts[t.severity] += 1
        status_counts[t.status] += 1
        type_counts[t.threat_type] += 1

    # Build last-7-days threat trend
    today = datetime.utcnow().date()
    day_counts = {}
    for i in range(6, -1, -1):
        day = today - timedelta(days=i)
        day_counts[day.isoformat()] = 0

    for t in threats:
        day = t.created_at.date().isoformat()
        if day in day_counts:
            day_counts[day] += 1

    threats_by_day = [{"date": d, "count": c} for d, c in day_counts.items()]

    vulnerable_assets = sum(1 for a in assets if a.status == "Vulnerable")

    return {
        "total_threats": len(threats),
        "open_threats": status_counts.get("Open", 0),
        "investigating_threats": status_counts.get("Investigating", 0),
        "resolved_threats": status_counts.get("Resolved", 0),
        "critical_threats": severity_counts.get("CRITICAL", 0),
        "high_threats": severity_counts.get("HIGH", 0),
        "medium_threats": severity_counts.get("MEDIUM", 0),
        "low_threats": severity_counts.get("LOW", 0),
        "total_assets": len(assets),
        "vulnerable_assets": vulnerable_assets,
        "unread_alerts": unread_alerts,
        "threats_by_type": dict(type_counts),
        "threats_by_day": threats_by_day,
        "recent_threats": [
            {
                "id": t.id,
                "title": t.title,
                "severity": t.severity,
                "status": t.status,
                "threat_type": t.threat_type,
                "created_at": t.created_at,
            }
            for t in sorted(threats, key=lambda x: x.created_at, reverse=True)[:5]
        ],
    }
