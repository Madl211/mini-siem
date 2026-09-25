from dataclasses import dataclass
from typing import Literal

import yaml
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Rule as RuleModel

RuleType = Literal["threshold_count", "unique_count", "time_window", "immediate"]


@dataclass
class Rule:
    """Eine geladene Detection-Regel (aus config.yaml). Rein-Python, keine DB-Abhaengigkeit."""

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


def load_rules(path: str) -> list[Rule]:
    """Laedt Regeln aus einer YAML-Datei. Unbekannte/fehlerhafte Eintraege werden uebersprungen, nicht die ganze Anwendung zum Absturz gebracht."""
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
            # Pflichtfeld fehlt - diese Regel ignorieren statt die App abstuerzen zu lassen
            continue
    return rules


def sync_rules_to_db(db: Session, rules: list[Rule]) -> None:
    """Spiegelt die geladenen Regeln in die 'rules'-Tabelle, damit sie dort einsehbar sind."""
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