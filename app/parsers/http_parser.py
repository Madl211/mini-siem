import re
from datetime import datetime

from app.parsers.ssh_parser import ParsedEvent

SUSPICIOUS_USER_AGENTS = (
    "sqlmap",
    "nikto",
    "nmap",
    "masscan",
    "zgrab",
    "curl",
    "python-requests",
)

# Combined Log Format
_COMBINED_LOG_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>\S+) \S+" '
    r'(?P<status>\d{3}) \S+ "[^"]*" "(?P<ua>[^"]*)"'
)


def _parse_apache_timestamp(raw: str) -> datetime | None:
    try:
        return datetime.strptime(raw.split(" ")[0], "%d/%b/%Y:%H:%M:%S")
    except ValueError:
        return None


def _is_suspicious_user_agent(user_agent: str) -> bool:
    ua_lower = user_agent.lower()
    return any(tool in ua_lower for tool in SUSPICIOUS_USER_AGENTS)


def parse_http_line(line: str) -> ParsedEvent | None:
    """Parst eine einzelne Zeile eines HTTP-Access-Logs. Gibt None zurueck, wenn die Zeile nicht erkannt wird."""
    line = line.strip()
    if not line:
        return None

    match = _COMBINED_LOG_RE.match(line)
    if not match:
        return None

    timestamp = _parse_apache_timestamp(match.group("ts"))
    if timestamp is None:
        return None

    status_code = int(match.group("status"))
    user_agent = match.group("ua")

    if status_code == 404:
        event_type = "http_404"
    elif status_code >= 500:
        event_type = "http_500"
    else:
        event_type = "http_request"

    severity = "LOW"
    if event_type == "http_500":
        severity = "HIGH"
    elif event_type == "http_404":
        severity = "MEDIUM"
    if _is_suspicious_user_agent(user_agent):
        event_type = "suspicious_user_agent"
        severity = "MEDIUM"

    return ParsedEvent(
        timestamp=timestamp,
        source_ip=match.group("ip"),
        event_type=event_type,
        method=match.group("method"),
        path=match.group("path"),
        status_code=status_code,
        user_agent=user_agent,
        raw_message=line,
        severity=severity,
    )


def parse_http_log(text: str) -> tuple[list[ParsedEvent], int]:
    """Parst mehrere Zeilen. Gibt (erkannte Events, Anzahl unbekannter Zeilen) zurueck."""
    events: list[ParsedEvent] = []
    unknown = 0
    for line in text.splitlines():
        if not line.strip():
            continue
        parsed = parse_http_line(line)
        if parsed is None:
            unknown += 1
        else:
            events.append(parsed)
    return events, unknown