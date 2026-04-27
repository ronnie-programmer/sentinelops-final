import os
import logging
import requests

logger = logging.getLogger(__name__)

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"


def lookup(ip: str) -> dict | None:
    api_key = os.getenv("ABUSEIPDB_API_KEY", "").strip()
    if not api_key:
        return None

    try:
        resp = requests.get(
            ABUSEIPDB_URL,
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=10,
        )
        if resp.status_code != 200:
            logger.warning("AbuseIPDB returned %s for %s", resp.status_code, ip)
            return None

        score = resp.json().get("data", {}).get("abuseConfidenceScore", None)
        if score is None:
            return None
        return {"abuseipdb_score": int(score)}

    except Exception as exc:
        logger.error("AbuseIPDB lookup failed for %s: %s", ip, exc)
        return None
