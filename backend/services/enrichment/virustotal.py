import os
import hashlib
import logging
import requests

logger = logging.getLogger(__name__)

VT_BASE = "https://www.virustotal.com/api/v3"


def lookup(ioc_value: str, ioc_type: str) -> dict | None:
    api_key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
    if not api_key:
        return None

    headers = {"x-apikey": api_key}
    try:
        if ioc_type == "ip":
            url = f"{VT_BASE}/ip_addresses/{ioc_value}"
            resp = requests.get(url, headers=headers, timeout=10)
        elif ioc_type == "hash":
            url = f"{VT_BASE}/files/{ioc_value}"
            resp = requests.get(url, headers=headers, timeout=10)
        elif ioc_type == "domain":
            url = f"{VT_BASE}/domains/{ioc_value}"
            resp = requests.get(url, headers=headers, timeout=10)
        elif ioc_type == "url":
            url_id = hashlib.sha256(ioc_value.encode()).hexdigest()
            url = f"{VT_BASE}/urls/{url_id}"
            resp = requests.get(url, headers=headers, timeout=10)
            if resp.status_code == 404:
                submit = requests.post(
                    f"{VT_BASE}/urls",
                    headers=headers,
                    data={"url": ioc_value},
                    timeout=10,
                )
                if submit.status_code not in (200, 201):
                    return None
                analysis_id = submit.json().get("data", {}).get("id", "")
                if not analysis_id:
                    return None
                analysis_resp = requests.get(
                    f"{VT_BASE}/analyses/{analysis_id}",
                    headers=headers,
                    timeout=10,
                )
                if analysis_resp.status_code != 200:
                    return None
                stats = analysis_resp.json().get("data", {}).get("attributes", {}).get("stats", {})
                total = sum(stats.values())
                malicious = stats.get("malicious", 0)
                score = int(malicious / total * 100) if total > 0 else 0
                return {"vt_score": score, "vt_engines_total": total, "vt_engines_malicious": malicious}
        else:
            return None

        if resp.status_code == 404:
            return None
        if resp.status_code != 200:
            logger.warning("VirusTotal returned %s for %s", resp.status_code, ioc_value)
            return None

        stats = resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        total = sum(stats.values())
        malicious = stats.get("malicious", 0)
        score = int(malicious / total * 100) if total > 0 else 0
        return {"vt_score": score, "vt_engines_total": total, "vt_engines_malicious": malicious}

    except Exception as exc:
        logger.error("VirusTotal lookup failed for %s: %s", ioc_value, exc)
        return None
