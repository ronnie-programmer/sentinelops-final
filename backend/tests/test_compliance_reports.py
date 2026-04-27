import pytest
from services.compliance.report_generator import load_manifest


def test_load_soc2_manifest():
    manifest = load_manifest("SOC2")
    assert manifest["framework"] == "SOC2"
    assert len(manifest["controls"]) >= 3
    for ctrl in manifest["controls"]:
        assert "id" in ctrl
        assert "name" in ctrl
        assert "description" in ctrl


def test_load_hipaa_manifest():
    manifest = load_manifest("HIPAA")
    assert manifest["framework"] == "HIPAA"
    assert len(manifest["controls"]) >= 3


def test_load_nist_manifest():
    manifest = load_manifest("NIST")
    assert manifest["framework"] == "NIST"


def test_load_cmmc_manifest():
    manifest = load_manifest("CMMC")
    assert manifest["framework"] == "CMMC"


def test_unknown_framework_raises():
    with pytest.raises(FileNotFoundError):
        load_manifest("UNKNOWN")
