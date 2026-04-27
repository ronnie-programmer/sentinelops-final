import logging
logger = logging.getLogger(__name__)

def execute(params: dict, context: dict) -> str:
    ioc_value = params.get("ioc_value", "")
    ioc_type = params.get("ioc_type", "ip")
    if not ioc_value:
        return "skipped: no ioc_value"
    logger.info("Playbook: enrich_ioc %s %s (stub — IOC enrichment service not yet available in this build)", ioc_type, ioc_value)
    return f"queued enrichment for {ioc_type}:{ioc_value}"
