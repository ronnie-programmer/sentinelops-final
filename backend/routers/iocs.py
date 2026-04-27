import logging
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy import func
from sqlalchemy.orm import Session

from database import get_db
from models import IOC
from schemas import IOCOut
from services.enrichment import virustotal, abuseipdb

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/iocs", tags=["iocs"])


@router.get("/top", response_model=List[IOCOut])
def get_top_iocs(db: Session = Depends(get_db)):
    iocs = db.query(IOC).all()
    scored = []
    for ioc in iocs:
        best = max(
            v for v in [ioc.vt_score, ioc.abuseipdb_score] if v is not None
        ) if any(v is not None for v in [ioc.vt_score, ioc.abuseipdb_score]) else -1
        scored.append((best, ioc))
    scored.sort(key=lambda x: x[0], reverse=True)
    return [ioc for _, ioc in scored[:3]]


@router.get("/", response_model=List[IOCOut])
def list_iocs(
    type: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = 100,
    db: Session = Depends(get_db),
):
    query = db.query(IOC)
    if type:
        query = query.filter(IOC.ioc_type == type)
    if search:
        query = query.filter(IOC.value.contains(search))
    return query.order_by(IOC.created_at.desc()).limit(limit).all()


@router.get("/{ioc_id}", response_model=IOCOut)
def get_ioc(ioc_id: int, db: Session = Depends(get_db)):
    ioc = db.query(IOC).filter(IOC.id == ioc_id).first()
    if not ioc:
        raise HTTPException(status_code=404, detail="IOC not found")
    return ioc


@router.post("/enrich/{ioc_id}", response_model=IOCOut)
def enrich_ioc(ioc_id: int, db: Session = Depends(get_db)):
    ioc = db.query(IOC).filter(IOC.id == ioc_id).first()
    if not ioc:
        raise HTTPException(status_code=404, detail="IOC not found")

    try:
        vt_result = virustotal.lookup(ioc.value, ioc.ioc_type)
        if vt_result:
            ioc.vt_score = vt_result.get("vt_score")
            ioc.vt_engines_total = vt_result.get("vt_engines_total")
            ioc.vt_engines_malicious = vt_result.get("vt_engines_malicious")

        if ioc.ioc_type == "ip":
            abuse_result = abuseipdb.lookup(ioc.value)
            if abuse_result:
                ioc.abuseipdb_score = abuse_result.get("abuseipdb_score")

        ioc.last_enriched_at = datetime.utcnow()
        db.commit()
        db.refresh(ioc)
    except Exception as exc:
        logger.error("On-demand enrichment failed for IOC %s: %s", ioc_id, exc)
        db.rollback()
        raise HTTPException(status_code=500, detail="Enrichment failed")

    return ioc


@router.delete("/{ioc_id}")
def delete_ioc(ioc_id: int, db: Session = Depends(get_db)):
    ioc = db.query(IOC).filter(IOC.id == ioc_id).first()
    if not ioc:
        raise HTTPException(status_code=404, detail="IOC not found")
    db.delete(ioc)
    db.commit()
    return {"deleted": ioc_id}
