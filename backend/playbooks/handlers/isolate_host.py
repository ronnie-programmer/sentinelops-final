import logging
logger = logging.getLogger(__name__)


def execute(params: dict, context: dict) -> str:
    hostname = params.get("hostname") or context.get("affected_system") or ""
    if not hostname:
        return "skipped: no hostname"

    provider = (params.get("provider") or "crowdstrike_insight").lower()
    host_id = params.get("host_id") or hostname

    try:
        if provider == "sentinelone":
            from integrations.edr.sentinelone import SentinelOneAdapter
            adapter = SentinelOneAdapter()
        else:
            from integrations.edr.crowdstrike_insight import CrowdStrikeInsightAdapter
            adapter = CrowdStrikeInsightAdapter()
        result = adapter.isolate_host(host_id)
        return result.get("message", f"isolation issued for {hostname}")
    except Exception as exc:
        logger.error("isolate_host playbook handler failed: %s", exc)
        return f"isolation failed: {exc}"
