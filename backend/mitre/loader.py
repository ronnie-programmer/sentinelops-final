import json
import os
from functools import lru_cache

DATA_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "mitre_techniques.json")

@lru_cache(maxsize=1)
def load_techniques() -> dict:
    with open(DATA_FILE, "r") as f:
        data = json.load(f)
    return {t["id"]: t for t in data["techniques"]}


def get_technique(technique_id: str) -> dict | None:
    return load_techniques().get(technique_id)


def get_all_techniques() -> list:
    return list(load_techniques().values())


def get_tactics() -> list:
    seen = {}
    for t in load_techniques().values():
        tactic_id = t["tactic_id"]
        if tactic_id not in seen:
            seen[tactic_id] = {"id": tactic_id, "name": t["tactic"]}
    return sorted(seen.values(), key=lambda x: x["id"])
