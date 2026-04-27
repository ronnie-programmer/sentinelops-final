import pytest
import os
from unittest.mock import patch


def test_crowdstrike_mock_generates_alerts():
    with patch.dict(os.environ, {"CROWDSTRIKE_CLIENT_ID": "", "CROWDSTRIKE_CLIENT_SECRET": ""}):
        from integrations.crowdstrike import CrowdStrikeAdapter
        adapter = CrowdStrikeAdapter()
        assert adapter.is_mock is True
        alerts = adapter.poll_alerts()
        assert len(alerts) >= 2
        assert len(alerts) <= 5


def test_crowdstrike_alert_shape():
    with patch.dict(os.environ, {"CROWDSTRIKE_CLIENT_ID": "", "CROWDSTRIKE_CLIENT_SECRET": ""}):
        from integrations.crowdstrike import CrowdStrikeAdapter
        adapter = CrowdStrikeAdapter()
        alerts = adapter.poll_alerts()
        for alert in alerts:
            assert "title" in alert
            assert "severity" in alert
            assert "source" in alert
            assert alert["source"] == "crowdstrike"
            assert alert["severity"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW")


def test_datadog_mock_generates_alerts():
    with patch.dict(os.environ, {"DATADOG_API_KEY": "", "DATADOG_APP_KEY": ""}):
        from integrations.datadog import DatadogAdapter
        adapter = DatadogAdapter()
        assert adapter.is_mock is True
        alerts = adapter.poll_alerts()
        assert len(alerts) >= 1


def test_splunk_mock_generates_alerts():
    with patch.dict(os.environ, {"SPLUNK_HOST": "", "SPLUNK_TOKEN": ""}):
        from integrations.splunk import SplunkAdapter
        adapter = SplunkAdapter()
        assert adapter.is_mock is True
        alerts = adapter.poll_alerts()
        assert len(alerts) >= 1


def test_all_alerts_have_external_id():
    with patch.dict(os.environ, {"CROWDSTRIKE_CLIENT_ID": "", "CROWDSTRIKE_CLIENT_SECRET": "",
                                  "DATADOG_API_KEY": "", "DATADOG_APP_KEY": "",
                                  "SPLUNK_HOST": "", "SPLUNK_TOKEN": ""}):
        from integrations.crowdstrike import CrowdStrikeAdapter
        from integrations.datadog import DatadogAdapter
        from integrations.splunk import SplunkAdapter
        for AdapterCls in [CrowdStrikeAdapter, DatadogAdapter, SplunkAdapter]:
            alerts = AdapterCls().poll_alerts()
            for a in alerts:
                assert "external_id" in a


def test_acknowledge_mock_returns_true():
    with patch.dict(os.environ, {"CROWDSTRIKE_CLIENT_ID": "", "CROWDSTRIKE_CLIENT_SECRET": ""}):
        from integrations.crowdstrike import CrowdStrikeAdapter
        adapter = CrowdStrikeAdapter()
        assert adapter.push_acknowledgement("fake-id") is True
