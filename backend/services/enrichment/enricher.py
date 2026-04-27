import logging
from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from models import IOC
from services.enrichment.extractor import extract_iocs
from services.enrichment import virustotal, abuseipdb

logger = logging.getLogger(__name__)

_CACHE_TTL_HOURS = 24


def enrich_alert(alert_id: int, text: str, db: Session) -> list[IOC]:
    if not text:
        return []

    ioc_dicts = extract_iocs(text)
    enriched: list[IOC] = []
    stale_cutoff = datetime.utcnow() - timedelta(hours=_CACHE_TTL_HOURS)

    for item in ioc_dicts:
        ioc_type = item["ioc_type"]
        value = item["value"]

        try:
            existing = db.query(IOC).filter(IOC.value == value).first()

            if existing:
                if existing.last_enriched_at and existing.last_enriched_at > stale_cutoff:
                    enriched.append(existing)
                    continue
                ioc_record = existing
            else:
                ioc_record = IOC(
                    ioc_type=ioc_type,
                    value=value,
                    source_alert_id=alert_id,
                )
                db.add(ioc_record)

            vt_result = virustotal.lookup(value, ioc_type)
            if vt_result:
                ioc_record.vt_score = vt_result.get("vt_score")
                ioc_record.vt_engines_total = vt_result.get("vt_engines_total")
                ioc_record.vt_engines_malicious = vt_result.get("vt_engines_malicious")

            if ioc_type == "ip":
                abuse_result = abuseipdb.lookup(value)
                if abuse_result:
                    ioc_record.abuseipdb_score = abuse_result.get("abuseipdb_score")

            ioc_record.last_enriched_at = datetime.utcnow()
            db.commit()
            db.refresh(ioc_record)
            enriched.append(ioc_record)

        except Exception as exc:
            logger.error("Enrichment failed for %s %s: %s", ioc_type, value, exc)
            try:
                db.rollback()
            except Exception:
                pass

    return enriched
