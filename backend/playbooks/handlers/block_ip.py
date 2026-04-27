import os, logging
logger = logging.getLogger(__name__)

def execute(params: dict, context: dict) -> str:
    ip = params.get("ip", "")
    if not ip:
        return "skipped: no ip"
    logger.info("Playbook: block_ip %s (stub — firewall API not configured)", ip)
    return f"block rule queued for {ip} (stub)"
