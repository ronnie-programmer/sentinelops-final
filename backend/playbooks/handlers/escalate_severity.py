import logging
logger = logging.getLogger(__name__)

def execute(params: dict, context: dict) -> str:
    target_severity = params.get("to", "CRITICAL")
    threat_id = context.get("threat_id")
    if not threat_id:
        return "skipped: no threat_id in context"
    logger.info("Playbook: escalate_severity threat %s to %s (requires db session — see router)", threat_id, target_severity)
    return f"escalated threat:{threat_id} to {target_severity} (logged)"
