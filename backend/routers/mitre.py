import json
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
from typing import List

from database import get_db
from models import Threat, AlertLog
from mitre.loader import get_all_techniques, get_technique, get_tactics

router = APIRouter(prefix="/api/mitre", tags=["mitre"])


@router.get("/techniques")
def list_techniques():
    return get_all_techniques()


@router.get("/techniques/{technique_id}")
def get_one_technique(technique_id: str):
    t = get_technique(technique_id)
    if not t:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Technique not found")
    return t


@router.get("/matrix")
def get_matrix(db: Session = Depends(get_db)):
    since = datetime.utcnow() - timedelta(days=30)
    techniques = get_all_techniques()
    tactics = get_tactics()

    # Count detections per technique
    counts: dict[str, int] = {t["id"]: 0 for t in techniques}

    threats = db.query(Threat).filter(Threat.created_at >= since).all()
    for threat in threats:
        if threat.mitre_techniques:
            try:
                ids = json.loads(threat.mitre_techniques)
                for tid in ids:
                    if tid in counts:
                        counts[tid] += 1
            except (json.JSONDecodeError, TypeError):
                pass

    alerts = db.query(AlertLog).filter(AlertLog.created_at >= since).all()
    for alert in alerts:
        if alert.mitre_techniques:
            try:
                ids = json.loads(alert.mitre_techniques)
                for tid in ids:
                    if tid in counts:
                        counts[tid] += 1
            except (json.JSONDecodeError, TypeError):
                pass

    # Group by tactic
    result = []
    for tactic in tactics:
        tactic_techniques = [
            {**t, "detection_count": counts.get(t["id"], 0)}
            for t in techniques
            if t["tactic_id"] == tactic["id"]
        ]
        result.append({
            "tactic": tactic["name"],
            "tactic_id": tactic["id"],
            "techniques": tactic_techniques,
        })

    return result
