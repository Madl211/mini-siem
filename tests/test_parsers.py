from datetime import datetime

from app.parsers.http_parser import parse_http_line, parse_http_log
from app.parsers.ssh_parser import parse_ssh_line, parse_ssh_log

FIXED_NOW = datetime(2026, 1, 15)


def test_ssh_failed_login_is_parsed():
    line = "Jan 15 03:12:45 server sshd[1234]: Failed password for root from 192.168.1.100 port 51234 ssh2"
    event = parse_ssh_line(line, now=FIXED_NOW)

    assert event is not None
    assert event.event_type == "ssh_login_failed"
    assert event.source_ip == "192.168.1.100"
    assert event.username == "root"
    assert event.severity == "MEDIUM"


def test_ssh_invalid_user_is_parsed():
    line = "Jan 15 03:12:45 server sshd[1234]: Failed password for invalid user admin from 192.168.1.100 port 51234 ssh2"
    event = parse_ssh_line(line, now=FIXED_NOW)

    assert event is not None
    assert event.event_type == "ssh_invalid_user"
    assert event.username == "admin"


def test_ssh_successful_login_is_parsed():
    line = "Jan 15 08:22:10 server sshd[1234]: Accepted password for deploy from 10.0.0.5 port 51300 ssh2"
    event = parse_ssh_line(line, now=FIXED_NOW)

    assert event is not None
    assert event.event_type == "ssh_login_success"
    assert event.username == "deploy"
    assert event.severity == "LOW"


def test_ssh_privilege_escalation_is_parsed():
    line = "Jan 15 08:22:15 server sshd[1234]: pam_unix(sudo:session): session opened for user root by deploy(uid=1000)"
    event = parse_ssh_line(line, now=FIXED_NOW)

    assert event is not None
    assert event.event_type == "ssh_privilege_escalation"
    assert event.username == "deploy"
    assert event.severity == "HIGH"


def test_ssh_invalid_line_returns_none():
    assert parse_ssh_line("this is not a valid ssh log line", now=FIXED_NOW) is None
    assert parse_ssh_line("", now=FIXED_NOW) is None


def test_ssh_log_counts_unknown_lines():
    text = (
        "Jan 15 03:12:45 server sshd[1234]: Failed password for root from 192.168.1.100 port 51234 ssh2\n"
        "this is garbage\n"
        "Jan 15 08:22:10 server sshd[1234]: Accepted password for deploy from 10.0.0.5 port 51300 ssh2\n"
    )
    events, unknown = parse_ssh_log(text, now=FIXED_NOW)

    assert len(events) == 2
    assert unknown == 1


def test_http_request_is_parsed():
    line = '203.0.113.7 - - [15/Jan/2026:08:22:15 +0000] "GET /index.html HTTP/1.1" 200 1024 "-" "Mozilla/5.0"'
    event = parse_http_line(line)

    assert event is not None
    assert event.event_type == "http_request"
    assert event.source_ip == "203.0.113.7"
    assert event.method == "GET"
    assert event.path == "/index.html"
    assert event.status_code == 200
    assert event.severity == "LOW"


def test_http_404_is_parsed():
    line = '198.51.100.23 - - [15/Jan/2026:08:23:01 +0000] "GET /missing.html HTTP/1.1" 404 512 "-" "Mozilla/5.0"'
    event = parse_http_line(line)

    assert event is not None
    assert event.event_type == "http_404"
    assert event.status_code == 404
    assert event.severity == "MEDIUM"


def test_http_500_is_parsed():
    line = '198.51.100.23 - - [15/Jan/2026:08:23:01 +0000] "GET /broken HTTP/1.1" 500 512 "-" "Mozilla/5.0"'
    event = parse_http_line(line)

    assert event is not None
    assert event.event_type == "http_500"
    assert event.severity == "HIGH"


def test_http_suspicious_user_agent_overrides_status_based_type():
    line = '198.51.100.23 - - [15/Jan/2026:08:23:01 +0000] "GET /admin.php HTTP/1.1" 404 512 "-" "sqlmap/1.6"'
    event = parse_http_line(line)

    assert event is not None
    assert event.event_type == "suspicious_user_agent"
    assert event.severity == "MEDIUM"


def test_http_invalid_line_returns_none():
    assert parse_http_line("not a valid access log line") is None
    assert parse_http_line("") is None


def test_http_log_counts_unknown_lines():
    text = (
        '203.0.113.7 - - [15/Jan/2026:08:22:15 +0000] "GET /index.html HTTP/1.1" 200 1024 "-" "Mozilla/5.0"\n'
        "not a valid line\n"
    )
    events, unknown = parse_http_log(text)

    assert len(events) == 1
    assert unknown == 1
