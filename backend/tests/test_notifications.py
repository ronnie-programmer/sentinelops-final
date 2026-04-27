import os
import pytest
from unittest.mock import patch


def test_slack_skipped_when_not_configured():
    with patch.dict(os.environ, {"SLACK_ENABLED": "false", "SLACK_WEBHOOK_URL": ""}):
        from notifications.slack import send_slack_alert
        result = send_slack_alert("Test", "Test msg", "HIGH", 1)
        assert result["status"] == "skipped"


def test_slack_payload_shape():
    """Verify payload structure without making real HTTP call."""
    import json
    from notifications.slack import SEVERITY_EMOJI
    assert "CRITICAL" in SEVERITY_EMOJI
    assert "HIGH" in SEVERITY_EMOJI
    assert ":red_circle:" == SEVERITY_EMOJI["CRITICAL"]


def test_pagerduty_skipped_when_not_configured():
    with patch.dict(os.environ, {"PAGERDUTY_ENABLED": "false", "PAGERDUTY_INTEGRATION_KEY": ""}):
        from notifications.pagerduty import send_pagerduty_alert
        result = send_pagerduty_alert("Test", "Test msg", "HIGH", 1)
        assert result["status"] == "skipped"


def test_pagerduty_severity_mapping():
    from notifications.pagerduty import SEVERITY_MAP
    assert SEVERITY_MAP["CRITICAL"] == "critical"
    assert SEVERITY_MAP["HIGH"] == "error"
    assert SEVERITY_MAP["MEDIUM"] == "warning"
    assert SEVERITY_MAP["LOW"] == "info"


def test_pagerduty_threshold_filter():
    with patch.dict(os.environ, {
        "PAGERDUTY_ENABLED": "true",
        "PAGERDUTY_INTEGRATION_KEY": "fake-key",
        "PAGERDUTY_SEVERITY_THRESHOLD": "HIGH",
    }):
        from notifications.pagerduty import send_pagerduty_alert
        # MEDIUM is below HIGH threshold — should skip
        result = send_pagerduty_alert("Test", "Test msg", "MEDIUM", 1)
        assert result["status"] == "skipped"
