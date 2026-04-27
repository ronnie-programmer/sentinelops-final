from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime

from database import get_db
from models import ThreatIntel, Threat, AlertLog
from schemas import ThreatIntelCreate, ThreatIntelOut

router = APIRouter(prefix="/api/intel", tags=["threat-intel"])


@router.get("/", response_model=List[ThreatIntelOut])
def get_intel(
    skip: int = 0,
    limit: int = 100,
    intel_type: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    db: Session = Depends(get_db),
):
    query = db.query(ThreatIntel)
    if intel_type:
        query = query.filter(ThreatIntel.intel_type == intel_type)
    if severity:
        query = query.filter(ThreatIntel.severity == severity)
    if search:
        term = f"%{search}%"
        query = query.filter(
            ThreatIntel.title.ilike(term)
            | ThreatIntel.value.ilike(term)
            | ThreatIntel.description.ilike(term)
            | ThreatIntel.tags.ilike(term)
        )
    return query.order_by(ThreatIntel.created_at.desc()).offset(skip).limit(limit).all()


@router.get("/{intel_id}", response_model=ThreatIntelOut)
def get_intel_item(intel_id: int, db: Session = Depends(get_db)):
    item = db.query(ThreatIntel).filter(ThreatIntel.id == intel_id).first()
    if not item:
        raise HTTPException(status_code=404, detail="Intel item not found")
    return item


@router.post("/", response_model=ThreatIntelOut, status_code=201)
def create_intel(intel_in: ThreatIntelCreate, db: Session = Depends(get_db)):
    item = ThreatIntel(**intel_in.model_dump())
    db.add(item)
    db.commit()
    db.refresh(item)
    return item


@router.post("/{intel_id}/import", status_code=201)
def import_intel_as_threat(intel_id: int, db: Session = Depends(get_db)):
    intel = db.query(ThreatIntel).filter(ThreatIntel.id == intel_id).first()
    if not intel:
        raise HTTPException(status_code=404, detail="Intel item not found")
    if intel.is_imported:
        raise HTTPException(status_code=400, detail="Intel item already imported as a threat")

    # Map intel type to threat type
    type_map = {
        "CVE": "Zero-Day Exploit",
        "Threat Actor": "Lateral Movement",
        "IOC-IP": "Data Exfiltration",
        "IOC-Hash": "Malware",
        "IOC-Domain": "Phishing",
    }
    threat_type = type_map.get(intel.intel_type, "Unknown")

    threat = Threat(
        title=f"[Intel Import] {intel.title}",
        description=(
            f"Threat created from intelligence feed.\n\n"
            f"Intel Type: {intel.intel_type}\n"
            f"Indicator: {intel.value}\n"
            f"Source: {intel.source or 'Internal Feed'}\n\n"
            f"{intel.description}"
        ),
        severity=intel.severity,
        status="Open",
        threat_type=threat_type,
        mitre_tactic="Initial Access",
        affected_system=intel.value,
    )
    db.add(threat)
    db.flush()

    # Create alert if HIGH or CRITICAL
    if intel.severity in ("CRITICAL", "HIGH"):
        alert = AlertLog(
            threat_id=threat.id,
            severity=intel.severity,
            message=(
                f"[{intel.severity}] Threat imported from intel feed: '{intel.title}'. "
                f"Indicator: {intel.value}. Immediate investigation required."
            ),
            recipient="soc-team@sentinelops.internal",
            status="Pending",
        )
        db.add(alert)

    intel.is_imported = 1
    db.commit()
    db.refresh(threat)

    return {
        "message": "Intel item imported as threat successfully",
        "threat_id": threat.id,
        "threat_title": threat.title,
    }


@router.delete("/{intel_id}", status_code=204)
def delete_intel(intel_id: int, db: Session = Depends(get_db)):
    item = db.query(ThreatIntel).filter(ThreatIntel.id == intel_id).first()
    if not item:
        raise HTTPException(status_code=404, detail="Intel item not found")
    db.delete(item)
    db.commit()
