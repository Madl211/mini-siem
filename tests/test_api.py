import csv
import io
from datetime import datetime

from app.models import Alert, Event


def _make_event(db_session, **overrides) -> Event:
    defaults = dict(
        timestamp=datetime(2026, 1, 15, 9, 0, 0),
        source_ip="203.0.113.1",
        event_type="http_request",
        raw_message="fake log line",
        severity="LOW",
    )
    defaults.update(overrides)
    event = Event(**defaults)
    db_session.add(event)
    db_session.commit()
    db_session.refresh(event)
    return event


def _make_alert(db_session, **overrides) -> Alert:
    defaults = dict(
        alert_type="SSH_BRUTE_FORCE",
        title="Test Alert",
        description="Test description",
        severity="HIGH",
        source_ip="198.51.100.9",
        status="OPEN",
    )
    defaults.update(overrides)
    alert = Alert(**defaults)
    db_session.add(alert)
    db_session.commit()
    db_session.refresh(alert)
    return alert


def test_list_events_endpoint(client, db_session):
    _make_event(db_session, source_ip="192.168.1.42")
    _make_event(db_session, source_ip="10.0.0.1")

    res = client.get("/api/events")
    assert res.status_code == 200
    assert len(res.json()) == 2


def test_list_events_filters_by_source_ip(client, db_session):
    _make_event(db_session, source_ip="192.168.1.42")
    _make_event(db_session, source_ip="10.0.0.1")

    res = client.get("/api/events?source_ip=192.168.1.42")
    assert res.status_code == 200
    data = res.json()
    assert len(data) == 1
    assert data[0]["source_ip"] == "192.168.1.42"


def test_get_single_event(client, db_session):
    event = _make_event(db_session)

    res = client.get(f"/api/events/{event.id}")
    assert res.status_code == 200
    assert res.json()["id"] == event.id


def test_get_missing_event_returns_404(client):
    res = client.get("/api/events/999999")
    assert res.status_code == 404


def test_list_alerts_filters_by_severity_and_status(client, db_session):
    _make_alert(db_session, severity="HIGH", status="OPEN")
    _make_alert(db_session, severity="LOW", status="RESOLVED")

    res = client.get("/api/alerts?severity=HIGH&status=OPEN")
    assert res.status_code == 200
    data = res.json()
    assert len(data) == 1
    assert data[0]["severity"] == "HIGH"


def test_update_alert_status(client, db_session):
    alert = _make_alert(db_session, status="OPEN")

    res = client.patch(f"/api/alerts/{alert.id}", json={"status": "ACKNOWLEDGED"})
    assert res.status_code == 200
    assert res.json()["status"] == "ACKNOWLEDGED"

    res = client.get(f"/api/alerts/{alert.id}")
    assert res.json()["status"] == "ACKNOWLEDGED"


def test_update_alert_status_rejects_invalid_value(client, db_session):
    alert = _make_alert(db_session, status="OPEN")

    res = client.patch(f"/api/alerts/{alert.id}", json={"status": "DELETED"})
    assert res.status_code == 422


def test_update_missing_alert_returns_404(client):
    res = client.patch("/api/alerts/999999", json={"status": "RESOLVED"})
    assert res.status_code == 404


def test_upload_ssh_log(client):
    log_content = (
        "Jan 15 03:12:45 server sshd[1234]: Failed password for root from 192.168.1.100 port 51234 ssh2\n"
    )
    files = {"file": ("auth.log", log_content, "text/plain")}
    res = client.post("/api/logs/upload", data={"log_type": "ssh"}, files=files)

    assert res.status_code == 200
    body = res.json()
    assert body["log_type"] == "ssh"
    assert body["parsed_events"] == 1


def test_analyze_endpoint_runs_detection_on_existing_events(client, db_session):
    from datetime import timedelta

    base = datetime(2026, 1, 15, 12, 0, 0)
    for i in range(10):
        _make_event(
            db_session,
            timestamp=base + timedelta(seconds=i * 5),
            source_ip="198.51.100.9",
            event_type="ssh_login_failed",
            severity="MEDIUM",
        )

    res = client.post("/api/logs/analyze")
    assert res.status_code == 200
    assert res.json()["alerts_created"] == 1


def test_stats_endpoint(client, db_session):
    _make_event(db_session)
    _make_alert(db_session, status="OPEN", severity="CRITICAL")

    res = client.get("/api/stats")
    assert res.status_code == 200
    body = res.json()
    assert body["total_events"] == 1
    assert body["open_alerts"] == 1
    assert body["critical_alerts"] == 1


def test_export_alerts_json(client, db_session):
    _make_alert(db_session)

    res = client.get("/api/export/json?dataset=alerts")
    assert res.status_code == 200
    data = res.json()
    assert len(data) == 1
    assert data[0]["alert_type"] == "SSH_BRUTE_FORCE"


def test_export_events_csv(client, db_session):
    _make_event(db_session, source_ip="192.168.1.42")

    res = client.get("/api/export/csv?dataset=events")
    assert res.status_code == 200
    assert res.headers["content-type"].startswith("text/csv")

    rows = list(csv.reader(io.StringIO(res.text)))
    assert rows[0][0] == "id"
    assert rows[1][2] == "192.168.1.42"
