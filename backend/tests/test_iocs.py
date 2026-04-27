import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from services.enrichment.extractor import extract_iocs


def test_extract_ipv4():
    results = extract_iocs("Alert from 185.220.101.5 targeting 10.0.0.1")
    types = [r["ioc_type"] for r in results]
    values = [r["value"] for r in results]
    assert "ip" in types
    assert "185.220.101.5" in values
    assert "10.0.0.1" not in values  # private IP filtered


def test_extract_sha256():
    hash_val = "a" * 64
    results = extract_iocs(f"Malware hash: {hash_val}")
    assert any(r["ioc_type"] == "hash" and r["value"] == hash_val for r in results)


def test_extract_domain():
    results = extract_iocs("C2 domain: evil-server.com")
    assert any(r["ioc_type"] == "domain" for r in results)


def test_no_enrichment_without_keys(monkeypatch):
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
    from services.enrichment.virustotal import lookup
    result = lookup("185.220.101.5", "ip")
    assert result is None
