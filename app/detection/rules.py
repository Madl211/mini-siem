from dataclasses import dataclass
from typing import Literal

import yaml
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Rule as RuleModel

RuleType = Literal["threshold_count", "unique_count", "time_window", "immediate"]


# detection rule from config.yaml
@dataclass
class Rule:

    name: str
    type: RuleType
    event_type: str
    alert_type: str
    severity: str
    enabled: bool = True
    threshold: int = 1
    window_seconds: int = 60
    start_hour: int = 0
    end_hour: int = 5
    unique_field: str = "path"


# load detection rules from a yaml file; unknown or invalid entries are skipped
def load_rules(path: str) -> list[Rule]:
    
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    rules: list[Rule] = []
    for entry in data.get("rules", []):
        try:
            rules.append(
                Rule(
                    name=entry["name"],
                    type=entry["type"],
                    event_type=entry["event_type"],
                    alert_type=entry["alert_type"],
                    severity=entry["severity"],
                    enabled=entry.get("enabled", True),
                    threshold=entry.get("threshold", 1),
                    window_seconds=entry.get("window_seconds", 60),
                    start_hour=entry.get("start_hour", 0),
                    end_hour=entry.get("end_hour", 5),
                    unique_field=entry.get("unique_field", "path"),
                )
            )
        except KeyError:
            continue
    return rules


# synchronize loaded rules to the database
def sync_rules_to_db(db: Session, rules: list[Rule]) -> None:

    for rule in rules:
        existing = db.execute(
            select(RuleModel).where(RuleModel.name == rule.name)
        ).scalar_one_or_none()
        if existing is None:
            existing = RuleModel(name=rule.name)
            db.add(existing)
        existing.event_type = rule.event_type
        existing.threshold = rule.threshold
        existing.window_seconds = rule.window_seconds
        existing.severity = rule.severity
        existing.alert_type = rule.alert_type
        existing.enabled = rule.enabled
    db.commit()