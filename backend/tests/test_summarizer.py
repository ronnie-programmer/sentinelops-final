import pytest
from services.summarizer import RuleSummarizer, RISK_PHRASES


def test_summary_contains_alert_type():
    s = RuleSummarizer()
    result = s.summarize("Malware", "web-prod-01", "1.2.3.4", 5, "Immediate action required")
    assert "Malware" in result


def test_summary_contains_asset_name():
    s = RuleSummarizer()
    result = s.summarize("Phishing", "db-primary", "10.0.0.1", 3, "High-priority response needed")
    assert "db-primary" in result


def test_summary_contains_source_ip():
    s = RuleSummarizer()
    result = s.summarize("Ransomware", "wks-finance-01", "185.220.101.1", 7, "Critical risk")
    assert "185.220.101.1" in result


def test_risk_phrases_all_severities():
    for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        assert severity in RISK_PHRASES
        assert len(RISK_PHRASES[severity]) > 10


def test_summary_is_two_sentences():
    s = RuleSummarizer()
    result = s.summarize("DDoS", "fw-edge-01", "0.0.0.0", 1, "Low-risk event")
    # Should have two sentences (two periods)
    assert result.count(".") >= 2
