import os, logging
logger = logging.getLogger(__name__)

def execute(params: dict, context: dict) -> str:
    hostname = params.get("hostname", "")
    if not hostname:
        return "skipped: no hostname"
    logger.info("Playbook: isolate_host %s (stub — EDR API not configured)", hostname)
    return f"isolation command sent for {hostname} (stub)"
