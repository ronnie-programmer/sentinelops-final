import re

_PRIVATE_RANGES = re.compile(
    r"^(10\.|192\.168\.|127\.|"
    r"172\.(1[6-9]|2[0-9]|3[0-1])\.)"
)

_RE_IP = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)
_RE_SHA256 = re.compile(r"\b[0-9a-fA-F]{64}\b")
_RE_SHA1 = re.compile(r"\b[0-9a-fA-F]{40}\b")
_RE_MD5 = re.compile(r"\b[0-9a-fA-F]{32}\b")
_RE_DOMAIN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)"
    r"+(?:com|net|org|io|gov|edu|mil|co|uk|de|fr|ru|cn|info|biz|xyz)\b"
)
_RE_URL = re.compile(r"https?://[^\s<>\"{}|\\^`\[\]]+")


def extract_iocs(text: str) -> list[dict]:
    if not text:
        return []

    results = []
    seen_values: set[str] = set()

    urls = []
    for m in _RE_URL.finditer(text):
        v = m.group()
        if v not in seen_values:
            seen_values.add(v)
            urls.append(v)
            results.append({"ioc_type": "url", "value": v})

    url_domains: set[str] = set()
    for u in urls:
        dm = _RE_DOMAIN.search(u)
        if dm:
            url_domains.add(dm.group())

    for m in _RE_SHA256.finditer(text):
        v = m.group()
        if v not in seen_values:
            seen_values.add(v)
            results.append({"ioc_type": "hash", "value": v})

    sha256_values = {r["value"] for r in results if r["ioc_type"] == "hash"}

    for m in _RE_SHA1.finditer(text):
        v = m.group()
        if v not in seen_values and v not in sha256_values:
            seen_values.add(v)
            results.append({"ioc_type": "hash", "value": v})

    sha_values = {r["value"] for r in results if r["ioc_type"] == "hash"}

    for m in _RE_MD5.finditer(text):
        v = m.group()
        if v not in seen_values and v not in sha_values:
            seen_values.add(v)
            results.append({"ioc_type": "hash", "value": v})

    for m in _RE_IP.finditer(text):
        v = m.group()
        if v in seen_values:
            continue
        if _PRIVATE_RANGES.match(v):
            continue
        seen_values.add(v)
        results.append({"ioc_type": "ip", "value": v})

    for m in _RE_DOMAIN.finditer(text):
        v = m.group()
        if v in seen_values:
            continue
        if v in url_domains:
            continue
        seen_values.add(v)
        results.append({"ioc_type": "domain", "value": v})

    return results
