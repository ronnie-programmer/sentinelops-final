import yaml
from playbooks.engine import evaluate_trigger, execute_actions

def test_trigger_always():
    trigger_yaml = yaml.dump({"type": "always"})
    assert evaluate_trigger(trigger_yaml, {}) is True

def test_trigger_severity_critical_matches():
    trigger_yaml = yaml.dump({"type": "alert_severity_gte", "severity": "CRITICAL"})
    assert evaluate_trigger(trigger_yaml, {"severity": "CRITICAL"}) is True

def test_trigger_severity_low_does_not_match_critical():
    trigger_yaml = yaml.dump({"type": "alert_severity_gte", "severity": "CRITICAL"})
    assert evaluate_trigger(trigger_yaml, {"severity": "LOW"}) is False

def test_trigger_mitre_technique_matches():
    trigger_yaml = yaml.dump({"type": "mitre_technique_in", "techniques": ["T1078"]})
    assert evaluate_trigger(trigger_yaml, {"mitre_techniques": "T1078, T1059"}) is True

def test_trigger_mitre_technique_no_match():
    trigger_yaml = yaml.dump({"type": "mitre_technique_in", "techniques": ["T1566"]})
    assert evaluate_trigger(trigger_yaml, {"mitre_techniques": "T1078"}) is False

def test_execute_unknown_action():
    actions_yaml = yaml.dump([{"action": "unknown_action"}])
    results = execute_actions(actions_yaml, {})
    assert results[0]["status"] == "skipped"

def test_execute_enrich_ioc_stub():
    actions_yaml = yaml.dump([{"action": "enrich_ioc", "ioc_value": "1.2.3.4", "ioc_type": "ip"}])
    results = execute_actions(actions_yaml, {})
    assert results[0]["status"] == "success"

def test_loader_reads_definitions():
    from playbooks.loader import get_builtin_definitions
    defs = get_builtin_definitions()
    assert len(defs) >= 3
    names = [d["name"] for d in defs]
    assert "Critical Ransomware Response" in names
