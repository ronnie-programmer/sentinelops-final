"""
SOAR playbook engine.
Trigger YAML schema:
  type: alert_severity_gte | mitre_technique_in | custom_expression | always
  severity: CRITICAL  # for alert_severity_gte
  techniques: [T1059, T1078]  # for mitre_technique_in
  expression: "alert.get('severity') == 'CRITICAL'"  # for custom_expression

Actions YAML schema (list of action dicts):
  - action: notify_slack
    message: "Critical alert: {alert_title}"
  - action: escalate_severity
    to: CRITICAL
  - action: enrich_ioc
    ioc_value: "{alert_source_ip}"
    ioc_type: ip
  - action: isolate_host
    hostname: "{alert_affected_system}"
  - action: block_ip
    ip: "{alert_source_ip}"
  - action: create_jira_ticket
    summary: "Security Incident: {alert_title}"
    priority: High
  - action: run_python_script
    code: "print('custom action')"
"""
import yaml
import json
import logging
from datetime import datetime
from typing import Any

logger = logging.getLogger(__name__)

def evaluate_trigger(trigger_yaml: str, context: dict[str, Any]) -> bool:
    """Returns True if the trigger conditions match the alert context."""
    try:
        trigger = yaml.safe_load(trigger_yaml)
        trigger_type = trigger.get("type", "always")

        if trigger_type == "always":
            return True
        elif trigger_type == "alert_severity_gte":
            severity_order = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
            required = severity_order.get(trigger.get("severity", "CRITICAL"), 4)
            actual = severity_order.get(context.get("severity", "LOW"), 1)
            return actual >= required
        elif trigger_type == "mitre_technique_in":
            techniques = trigger.get("techniques", [])
            alert_techniques = context.get("mitre_techniques", "") or ""
            return any(t in alert_techniques for t in techniques)
        elif trigger_type == "custom_expression":
            expr = trigger.get("expression", "False")
            alert = context  # noqa: F841 — available in eval scope
            return bool(eval(expr, {"__builtins__": {}}, {"alert": alert}))
        elif trigger_type == "time_window":
            # Trigger during a time window (hour range)
            start_hour = trigger.get("start_hour", 0)
            end_hour = trigger.get("end_hour", 23)
            current_hour = datetime.utcnow().hour
            return start_hour <= current_hour <= end_hour
    except Exception as e:
        logger.warning("Trigger evaluation failed: %s", e)
    return False

def execute_actions(actions_yaml: str, context: dict[str, Any]) -> list[dict]:
    """Execute action sequence, returns list of result dicts."""
    from playbooks.handlers import (
        notify_slack, enrich_ioc, isolate_host, block_ip,
        create_jira_ticket, escalate_severity, run_python_script
    )

    HANDLERS = {
        "notify_slack": notify_slack.execute,
        "enrich_ioc": enrich_ioc.execute,
        "isolate_host": isolate_host.execute,
        "block_ip": block_ip.execute,
        "create_jira_ticket": create_jira_ticket.execute,
        "escalate_severity": escalate_severity.execute,
        "run_python_script": run_python_script.execute,
    }

    results = []
    try:
        actions = yaml.safe_load(actions_yaml) or []
    except Exception as e:
        return [{"action": "parse_error", "status": "error", "message": str(e)}]

    for action_def in actions:
        action_name = action_def.get("action", "unknown")
        handler = HANDLERS.get(action_name)
        if not handler:
            results.append({"action": action_name, "status": "skipped", "message": "unknown action"})
            continue
        try:
            # Template-substitute context values into action params
            params = {k: v for k, v in action_def.items() if k != "action"}
            params = _substitute_context(params, context)
            result = handler(params, context)
            results.append({"action": action_name, "status": "success", "result": result})
        except Exception as e:
            logger.error("Action %s failed: %s", action_name, e)
            results.append({"action": action_name, "status": "error", "message": str(e)})
    return results

def _substitute_context(params: dict, context: dict) -> dict:
    """Replace {key} placeholders in string param values with context values."""
    result = {}
    for k, v in params.items():
        if isinstance(v, str):
            try:
                result[k] = v.format(
                    alert_title=context.get("title", ""),
                    alert_severity=context.get("severity", ""),
                    alert_source_ip=context.get("source_ip", ""),
                    alert_affected_system=context.get("affected_system", ""),
                    alert_mitre=context.get("mitre_techniques", ""),
                )
            except (KeyError, ValueError):
                result[k] = v
        else:
            result[k] = v
    return result
