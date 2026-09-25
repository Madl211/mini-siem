import json
from datetime import datetime, timezone
from typing import Callable

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.detection.rules import Rule
from app.models import Alert, AlertEvent, Event


def _find_breaches(
    events: list[Event],
    threshold: int,
    window_seconds: int,
    value_fn: Callable[[Event], object] | None = None,
) -> list[list[Event]]: # returns a list of event groups that breach the threshold within the time window
    breaches: list[list[Event]] = []
    n = len(events)
    i = 0
    while i < n:
        j = i
        seen: set[object] = set()
        while j < n and (events[j].timestamp - events[i].timestamp).total_seconds() <= window_seconds:
            if value_fn is not None:
                seen.add(value_fn(events[j]))
            j += 1
        count = len(seen) if value_fn is not None else (j - i)
        if count >= threshold:
            breaches.append(events[i:j])
            i = j   # skip to the end of the current breach to avoid counting overlapping groups
        else:
            i += 1
    return breaches


def _already_alerted_event_ids(db: Session, alert_type: str) -> set[int]:
    rows = db.execute(
        select(AlertEvent.event_id)
        .join(Alert, Alert.id == AlertEvent.alert_id)
        .where(Alert.alert_type == alert_type)
    ).scalars()
    return set(rows)


def _create_alert(
    db: Session,
    rule: Rule,
    source_ip: str,
    title: str,
    description: str,
    events: list[Event],
    extra_info: dict | None = None,
) -> None:
    alert = Alert(
        alert_type=rule.alert_type,
        title=title,
        description=description,
        severity=rule.severity,
        source_ip=source_ip,
        status="OPEN",
        extra_info=json.dumps(extra_info) if extra_info else None,
    )
    db.add(alert)
    db.flush()  # ensure alert.id is assigned before creating AlertEvent rows
    for event in events:
        db.add(AlertEvent(alert_id=alert.id, event_id=event.id))


def _apply_grouped_by_ip(
    db: Session, rule: Rule, value_fn: Callable[[Event], object] | None
) -> int:
    events = list(
        db.execute(
            select(Event)
            .where(Event.event_type == rule.event_type)
            .order_by(Event.source_ip, Event.timestamp)
        ).scalars()
    )
    if not events:
        return 0

    already_alerted = _already_alerted_event_ids(db, rule.alert_type)

    by_ip: dict[str, list[Event]] = {}
    for event in events:
        by_ip.setdefault(event.source_ip, []).append(event)

    created = 0
    for source_ip, ip_events in by_ip.items():
        breaches = _find_breaches(ip_events, rule.threshold, rule.window_seconds, value_fn)
        for breach in breaches:
            if all(e.id in already_alerted for e in breach):
                continue
            metric = "unterschiedliche Pfade" if value_fn else "Events"
            count = len({value_fn(e) for e in breach}) if value_fn else len(breach)
            _create_alert(
                db,
                rule,
                source_ip,
                title=f"{rule.name}: {source_ip}",
                description=(
                    f"{count} {metric} vom Typ '{rule.event_type}' innerhalb von "
                    f"{rule.window_seconds}s von {source_ip} erkannt."
                ),
                events=breach,
                extra_info={"count": count, "window_seconds": rule.window_seconds},
            )
            created += 1
    return created


def _apply_time_window(db: Session, rule: Rule) -> int:
    events = list(
        db.execute(
            select(Event).where(Event.event_type == rule.event_type)
        ).scalars()
    )
    already_alerted = _already_alerted_event_ids(db, rule.alert_type)

    created = 0
    for event in events:
        if event.id in already_alerted:
            continue
        if rule.start_hour <= event.timestamp.hour < rule.end_hour:
            _create_alert(
                db,
                rule,
                event.source_ip,
                title=f"{rule.name}: {event.source_ip}",
                description=(
                    f"Erfolgreicher Login von {event.source_ip} um "
                    f"{event.timestamp.strftime('%H:%M:%S')} Uhr (ausserhalb ueblicher Zeiten)."
                ),
                events=[event],
            )
            created += 1
    return created


def _apply_immediate(db: Session, rule: Rule) -> int:
    events = list(
        db.execute(
            select(Event).where(Event.event_type == rule.event_type)
        ).scalars()
    )
    already_alerted = _already_alerted_event_ids(db, rule.alert_type)

    created = 0
    for event in events:
        if event.id in already_alerted:
            continue
        _create_alert(
            db,
            rule,
            event.source_ip,
            title=f"{rule.name}: {event.source_ip}",
            description=(
                f"Verdaechtiges Event '{rule.event_type}' von {event.source_ip} erkannt "
                f"(User-Agent: {event.user_agent})."
            ),
            events=[event],
        )
        created += 1
    return created


def run_detection(db: Session, rules: list[Rule]) -> int:
    """Wendet alle aktiven Regeln auf die gespeicherten Events an und erzeugt neue Alerts.
    Gibt die Anzahl der neu erzeugten Alerts zurueck."""
    created = 0
    for rule in rules:
        if not rule.enabled:
            continue
        if rule.type == "threshold_count":
            created += _apply_grouped_by_ip(db, rule, value_fn=None)
        elif rule.type == "unique_count":
            created += _apply_grouped_by_ip(
                db, rule, value_fn=lambda e: getattr(e, rule.unique_field)
            )
        elif rule.type == "time_window":
            created += _apply_time_window(db, rule)
        elif rule.type == "immediate":
            created += _apply_immediate(db, rule)
    db.commit()
    return created