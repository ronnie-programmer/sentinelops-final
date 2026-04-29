import os
from unittest.mock import patch


EDR_ENV_DISABLED = {
    "CROWDSTRIKE_INSIGHT_CLIENT_ID": "",
    "CROWDSTRIKE_INSIGHT_CLIENT_SECRET": "",
    "CROWDSTRIKE_CLIENT_ID": "",
    "CROWDSTRIKE_CLIENT_SECRET": "",
    "SENTINELONE_API_KEY": "",
    "SENTINELONE_MANAGEMENT_URL": "",
}


def test_crowdstrike_insight_mock_generates_alerts():
    with patch.dict(os.environ, EDR_ENV_DISABLED):
        from integrations.edr.crowdstrike_insight import CrowdStrikeInsightAdapter
        adapter = CrowdStrikeInsightAdapter()
        assert adapter.is_mock is True
        alerts = adapter.poll_alerts()
        assert 1 <= len(alerts) <= 3
        for a in alerts:
            assert a["source"] == "crowdstrike_insight"
            assert a["severity"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
            assert "host_id" in a
            assert "process_id" in a


def test_sentinelone_mock_generates_alerts():
    with patch.dict(os.environ, EDR_ENV_DISABLED):
        from integrations.edr.sentinelone import SentinelOneAdapter
        adapter = SentinelOneAdapter()
        assert adapter.is_mock is True
        alerts = adapter.poll_alerts()
        assert 1 <= len(alerts) <= 3
        for a in alerts:
            assert a["source"] == "sentinelone"
            assert a["severity"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
            assert "host_id" in a


def test_edr_adapters_are_distinct_from_base_crowdstrike():
    from integrations.edr.crowdstrike_insight import CrowdStrikeInsightAdapter
    from integrations.crowdstrike import CrowdStrikeAdapter
    assert CrowdStrikeInsightAdapter().provider_name == "crowdstrike_insight"
    assert CrowdStrikeAdapter().provider_name == "crowdstrike"


def test_isolate_host_in_mock_returns_ok():
    with patch.dict(os.environ, EDR_ENV_DISABLED):
        from integrations.edr.crowdstrike_insight import CrowdStrikeInsightAdapter
        from integrations.edr.sentinelone import SentinelOneAdapter
        for cls in (CrowdStrikeInsightAdapter, SentinelOneAdapter):
            r = cls().isolate_host("host-123")
            assert r["ok"] is True
            assert "host-123" in r["message"]


def test_kill_process_in_mock_returns_ok():
    with patch.dict(os.environ, EDR_ENV_DISABLED):
        from integrations.edr.crowdstrike_insight import CrowdStrikeInsightAdapter
        from integrations.edr.sentinelone import SentinelOneAdapter
        for cls in (CrowdStrikeInsightAdapter, SentinelOneAdapter):
            r = cls().kill_process("host-123", "4242")
            assert r["ok"] is True
            assert "4242" in r["message"]


def test_edr_adapters_implement_edr_base():
    from integrations.edr.base import EDRAdapter
    from integrations.edr.crowdstrike_insight import CrowdStrikeInsightAdapter
    from integrations.edr.sentinelone import SentinelOneAdapter
    assert issubclass(CrowdStrikeInsightAdapter, EDRAdapter)
    assert issubclass(SentinelOneAdapter, EDRAdapter)


def test_isolate_endpoint_rejects_non_edr_provider():
    from fastapi.testclient import TestClient
    with patch.dict(os.environ, EDR_ENV_DISABLED):
        from main import app
        client = TestClient(app)
        r = client.post("/api/integrations/datadog/isolate", json={"host_id": "x"})
        assert r.status_code == 400


def test_isolate_endpoint_calls_adapter_in_mock():
    from fastapi.testclient import TestClient
    with patch.dict(os.environ, EDR_ENV_DISABLED):
        from main import app
        client = TestClient(app)
        r = client.post("/api/integrations/sentinelone/isolate", json={"host_id": "agent-9"})
        assert r.status_code == 200
        body = r.json()
        assert body["ok"] is True
        assert body["provider"] == "sentinelone"


def test_kill_process_endpoint_calls_adapter_in_mock():
    from fastapi.testclient import TestClient
    with patch.dict(os.environ, EDR_ENV_DISABLED):
        from main import app
        client = TestClient(app)
        r = client.post(
            "/api/integrations/crowdstrike_insight/kill-process",
            json={"host_id": "device-1", "process_id": "9000"},
        )
        assert r.status_code == 200
        body = r.json()
        assert body["ok"] is True
        assert body["provider"] == "crowdstrike_insight"


def test_isolate_host_playbook_handler_uses_edr_adapter():
    from playbooks.handlers import isolate_host
    with patch.dict(os.environ, EDR_ENV_DISABLED):
        msg = isolate_host.execute({"hostname": "wks-99", "provider": "sentinelone"}, {})
        assert "wks-99" in msg or "agent" in msg.lower() or "issued" in msg.lower()
