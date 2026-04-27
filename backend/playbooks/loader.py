"""Load prebuilt playbook YAML definitions and seed them into DB if not present."""
import os, yaml
from pathlib import Path

DEFINITIONS_DIR = Path(__file__).parent / "definitions"

def get_builtin_definitions() -> list[dict]:
    defs = []
    for yaml_file in DEFINITIONS_DIR.glob("*.yaml"):
        with open(yaml_file) as f:
            data = yaml.safe_load(f)
            defs.append(data)
    return defs

def seed_builtin_playbooks(db):
    from models import Playbook
    import yaml as _yaml
    for defn in get_builtin_definitions():
        existing = db.query(Playbook).filter(Playbook.name == defn["name"]).first()
        if not existing:
            trigger_data = defn.get("trigger", {"type": "always"})
            actions_data = defn.get("actions", [])
            pb = Playbook(
                name=defn["name"],
                description=defn.get("description", ""),
                enabled=1 if defn.get("enabled", True) else 0,
                trigger_yaml=_yaml.dump(trigger_data),
                actions_yaml=_yaml.dump(actions_data),
                is_builtin=1 if defn.get("is_builtin", False) else 0,
            )
            db.add(pb)
    db.commit()
