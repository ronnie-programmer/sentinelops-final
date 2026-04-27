import json
from mitre.loader import load_techniques

THREAT_TYPE_DEFAULTS = {
    "Ransomware": ["T1486", "T1490", "T1078"],
    "Phishing": ["T1566", "T1078", "T1204"],
    "Malware": ["T1059", "T1027", "T1547"],
    "Brute Force": ["T1110", "T1078"],
    "SQL Injection": ["T1190", "T1059"],
    "Lateral Movement": ["T1021", "T1570", "T1078"],
    "Data Exfiltration": ["T1048", "T1567", "T1074"],
    "Insider Threat": ["T1078", "T1003", "T1048"],
    "DDoS": ["T1498", "T1499"],
    "Zero-Day Exploit": ["T1190", "T1068", "T1059"],
}


def classify_alert(threat_type: str = "", title: str = "", description: str = "") -> list[str]:
    """Return up to 3 MITRE technique IDs for a given alert/threat."""
    if threat_type in THREAT_TYPE_DEFAULTS:
        return THREAT_TYPE_DEFAULTS[threat_type]

    text = " ".join([threat_type, title, description]).lower()
    techniques = load_techniques()
    matches = []
    for tech_id, tech in techniques.items():
        for kw in tech.get("keywords", []):
            if kw.lower() in text:
                matches.append(tech_id)
                break
        if len(matches) >= 3:
            break
    return matches or ["T1078"]  # fallback
