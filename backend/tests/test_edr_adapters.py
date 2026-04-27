import pytest
from integrations.edr.crowdstrike_insight import CrowdStrikeInsightAdapter
from integrations.edr.sentinelone import SentinelOneAdapter


def test_crowdstrike_insight_mock_mode():
    """Without credentials, adapter must run in mock mode."""
    import os
    env_backup = {k: os.environ.pop(k, None) for k in [
        "CROWDSTRIKE_INSIGHT_CLIENT_ID", "CROWDSTRIKE_INSIGHT_CLIENT_SECRET",
        "CROWDSTRIKE_CLIENT_ID", "CROWDSTRIKE_CLIENT_SECRET"
    ]}
    try:
        adapter = CrowdStrikeInsightAdapter()
        assert adapter.is_mock is True
        alerts = adapter.poll_alerts()
        assert isinstance(alerts, list)
        assert len(alerts) >= 1
        for a in alerts:
            assert "title" in a
            assert "severity" in a
            assert a["source"] == "crowdstrike_insight"
    finally:
        for k, v in env_backup.items():
            if v is not None:
                os.environ[k] = v


def test_crowdstrike_insight_isolate_host_mock():
    import os
    os.environ.pop("CROWDSTRIKE_INSIGHT_CLIENT_ID", None)
    adapter = CrowdStrikeInsightAdapter()
    result = adapter.isolate_host("test-host-01")
    assert result["status"] == "mock_isolated"
    assert result["hostname"] == "test-host-01"


def test_sentinelone_mock_mode():
    import os
    env_backup = {k: os.environ.pop(k, None) for k in ["SENTINELONE_API_KEY", "SENTINELONE_MANAGEMENT_URL"]}
    try:
        adapter = SentinelOneAdapter()
        assert adapter.is_mock is True
        alerts = adapter.poll_alerts()
        assert isinstance(alerts, list)
        assert len(alerts) >= 1
        for a in alerts:
            assert "title" in a
            assert "severity" in a
            assert a["source"] == "sentinelone"
    finally:
        for k, v in env_backup.items():
            if v is not None:
                os.environ[k] = v


def test_sentinelone_kill_process_mock():
    import os
    os.environ.pop("SENTINELONE_API_KEY", None)
    adapter = SentinelOneAdapter()
    result = adapter.kill_process("agent-123", 4567)
    assert result["status"] == "mock_killed"
    assert result["agent_id"] == "agent-123"
    assert result["pid"] == 4567
