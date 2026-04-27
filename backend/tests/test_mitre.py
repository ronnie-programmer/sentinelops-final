import pytest
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from services.mitre_classifier import classify_alert, THREAT_TYPE_DEFAULTS


def test_ransomware_maps_to_t1486():
    result = classify_alert(threat_type="Ransomware")
    assert "T1486" in result


def test_phishing_maps_to_t1566():
    result = classify_alert(threat_type="Phishing")
    assert "T1566" in result


def test_brute_force_maps_to_t1110():
    result = classify_alert(threat_type="Brute Force")
    assert "T1110" in result


def test_keyword_matching_ransomware_in_description():
    result = classify_alert(threat_type="Unknown", title="", description="ransomware encrypted all files")
    assert "T1486" in result


def test_keyword_matching_phishing_in_title():
    result = classify_alert(threat_type="", title="spear phish email campaign detected")
    assert "T1566" in result


def test_returns_list():
    result = classify_alert(threat_type="Malware")
    assert isinstance(result, list)
    assert len(result) > 0


def test_max_three_results():
    result = classify_alert(threat_type="Unknown", description="ransomware phish credential dump lateral movement ddos")
    assert len(result) <= 3


def test_all_threat_types_covered():
    for threat_type in THREAT_TYPE_DEFAULTS:
        result = classify_alert(threat_type=threat_type)
        assert len(result) > 0, f"No techniques for {threat_type}"


def test_loader_returns_techniques():
    from mitre.loader import load_techniques, get_all_techniques, get_tactics
    techniques = load_techniques()
    assert len(techniques) > 20
    assert "T1486" in techniques
    tactics = get_tactics()
    assert len(tactics) > 5
