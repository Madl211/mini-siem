from datetime import datetime, timedelta

from app.detection.engine import run_detection
from app.detection.rules import load_rules
from app.models import Event

RULES_PATH = "app/detection/config.yaml"


def _add_events(db_session, events: list[Event]) -> None:
    for event in events:
        db_session.add(event)
    db_session.commit()


def _ssh_event(ts, ip, event_type, username=None, severity="LOW") -> Event:
    return Event(
        timestamp=ts,
        source_ip=ip,
        event_type=event_type,
        username=username,
        raw_message=f"fake ssh line for {ip}",
        severity=severity,
    )


def _http_event(ts, ip, event_type, path="/", status_code=200, user_agent="Mozilla/5.0", severity="LOW") -> Event:
    return Event(
        timestamp=ts,
        source_ip=ip,
        event_type=event_type,
        method="GET",
        path=path,
        status_code=status_code,
        user_agent=user_agent,
        raw_message=f"fake http line for {ip}",
        severity=severity,
    )


def test_ssh_brute_force_detected(db_session):
    base = datetime(2026, 1, 15, 12, 0, 0)
    events = [
        _ssh_event(base + timedelta(seconds=i * 5), "198.51.100.9", "ssh_login_failed", "root", "MEDIUM")
        for i in range(10)
    ]
    _add_events(db_session, events)

    rules = load_rules(RULES_PATH)
    created = run_detection(db_session, rules)

    assert created >= 1
    from app.models import Alert

    alert = db_session.query(Alert).filter_by(alert_type="SSH_BRUTE_FORCE").one()
    assert alert.severity == "HIGH"
    assert alert.source_ip == "198.51.100.9"
    assert len(alert.event_links) == 10


def test_ssh_brute_force_not_triggered_below_threshold(db_session):
    base = datetime(2026, 1, 15, 12, 0, 0)
    events = [
        _ssh_event(base + timedelta(seconds=i * 5), "198.51.100.9", "ssh_login_failed", "root", "MEDIUM")
        for i in range(5)
    ]
    _add_events(db_session, events)

    rules = load_rules(RULES_PATH)
    created = run_detection(db_session, rules)

    assert created == 0


def test_unusual_login_time_detected(db_session):
    night_login = _ssh_event(datetime(2026, 1, 15, 2, 30, 0), "10.0.0.5", "ssh_login_success", "deploy")
    day_login = _ssh_event(datetime(2026, 1, 15, 9, 0, 0), "10.0.0.6", "ssh_login_success", "alice")
    _add_events(db_session, [night_login, day_login])

    rules = load_rules(RULES_PATH)
    run_detection(db_session, rules)

    from app.models import Alert

    alerts = db_session.query(Alert).filter_by(alert_type="UNUSUAL_LOGIN_TIME").all()
    assert len(alerts) == 1
    assert alerts[0].source_ip == "10.0.0.5"
    assert alerts[0].severity == "MEDIUM"


def test_excessive_404_requests_detected(db_session):
    base = datetime(2026, 1, 15, 9, 0, 0)
    events = [
        _http_event(base + timedelta(seconds=i * 2), "203.0.113.50", "http_404", path=f"/missing{i}", status_code=404, severity="MEDIUM")
        for i in range(20)
    ]
    _add_events(db_session, events)

    rules = load_rules(RULES_PATH)
    run_detection(db_session, rules)

    from app.models import Alert

    alert = db_session.query(Alert).filter_by(alert_type="EXCESSIVE_404_REQUESTS").one()
    assert alert.severity == "MEDIUM"
    assert alert.source_ip == "203.0.113.50"


def test_excessive_500_errors_detected(db_session):
    base = datetime(2026, 1, 15, 9, 0, 0)
    events = [
        _http_event(base + timedelta(seconds=i * 2), "203.0.113.60", "http_500", path="/broken", status_code=500, severity="HIGH")
        for i in range(10)
    ]
    _add_events(db_session, events)

    rules = load_rules(RULES_PATH)
    run_detection(db_session, rules)

    from app.models import Alert

    alert = db_session.query(Alert).filter_by(alert_type="EXCESSIVE_500_ERRORS").one()
    assert alert.severity == "HIGH"


def test_suspicious_user_agent_detected(db_session):
    event = _http_event(
        datetime(2026, 1, 15, 9, 0, 0), "203.0.113.70", "suspicious_user_agent",
        path="/login.php", status_code=200, user_agent="sqlmap/1.6", severity="MEDIUM",
    )
    _add_events(db_session, [event])

    rules = load_rules(RULES_PATH)
    run_detection(db_session, rules)

    from app.models import Alert

    alert = db_session.query(Alert).filter_by(alert_type="SUSPICIOUS_USER_AGENT").one()
    assert alert.severity == "MEDIUM"
    assert alert.source_ip == "203.0.113.70"


def test_possible_port_scan_detected(db_session):
    base = datetime(2026, 1, 15, 9, 0, 0)
    events = [
        _http_event(base + timedelta(seconds=i), "203.0.113.80", "http_request", path=f"/scanpath{i}")
        for i in range(16)
    ]
    _add_events(db_session, events)

    rules = load_rules(RULES_PATH)
    run_detection(db_session, rules)

    from app.models import Alert

    alert = db_session.query(Alert).filter_by(alert_type="POSSIBLE_PORT_SCAN").one()
    assert alert.severity == "HIGH"
    assert alert.source_ip == "203.0.113.80"


def test_port_scan_not_triggered_for_same_path(db_session):
    # 16 Requests, aber immer derselbe Pfad -> keine unterschiedlichen Pfade -> kein Scan
    base = datetime(2026, 1, 15, 9, 0, 0)
    events = [
        _http_event(base + timedelta(seconds=i), "203.0.113.81", "http_request", path="/index.html")
        for i in range(16)
    ]
    _add_events(db_session, events)

    rules = load_rules(RULES_PATH)
    run_detection(db_session, rules)

    from app.models import Alert

    alerts = db_session.query(Alert).filter_by(alert_type="POSSIBLE_PORT_SCAN").all()
    assert len(alerts) == 0


def test_detection_does_not_create_duplicate_alerts_on_second_run(db_session):
    base = datetime(2026, 1, 15, 12, 0, 0)
    events = [
        _ssh_event(base + timedelta(seconds=i * 5), "198.51.100.9", "ssh_login_failed", "root", "MEDIUM")
        for i in range(10)
    ]
    _add_events(db_session, events)

    rules = load_rules(RULES_PATH)
    first_run = run_detection(db_session, rules)
    second_run = run_detection(db_session, rules)

    assert first_run == 1
    assert second_run == 0
