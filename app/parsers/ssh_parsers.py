import re
from dataclasses import dataclass, field
from datetime import datetime


# independent class
@dataclass
class ParsedEvent:
    timestamp: datetime
    source_ip: str
    event_type: str
    raw_message: str
    username: str | None = None
    method: str | None = None
    path: str | None = None
    status_code: int | None = None
    user_agent: str | None = None
    severity: str = "LOW"


# syslog-timestaps have no year so we add it
_SYSLOG_TS_RE = re.compile(r"^(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})")

_FAILED_PASSWORD_RE = re.compile(
    r"Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+) port \d+"
)
_ACCEPTED_RE = re.compile(
    r"Accepted password for (?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+) port \d+"
)
_INVALID_USER_RE = re.compile(
    r"Invalid user (?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+)"
)
_SUDO_RE = re.compile(
    r"sudo:session\): session opened for user (?P<target>\S+) by (?P<actor>\S+)\("
)


def _parse_syslog_timestamp(line: str, now: datetime | None = None) -> datetime | None:
    match = _SYSLOG_TS_RE.match(line)
    if not match:
        return None
    year = (now or datetime.now()).year
    try:
        return datetime.strptime(f"{year} {match.group('ts')}", "%Y %b %d %H:%M:%S")
    except ValueError:
        return None


# parse a single line of SSH auth log and returns none if not recognized
def parse_ssh_line(line: str, now: datetime | None = None) -> ParsedEvent | None:
 
    line = line.strip()
    if not line:
        return None

    timestamp = _parse_syslog_timestamp(line, now)
    if timestamp is None:
        return None

    if match := _FAILED_PASSWORD_RE.search(line):
        is_invalid_user = "invalid user" in line
        return ParsedEvent(
            timestamp=timestamp,
            source_ip=match.group("ip"),
            event_type="ssh_invalid_user" if is_invalid_user else "ssh_login_failed",
            username=match.group("user"),
            raw_message=line,
            severity="MEDIUM",
        )

    if match := _ACCEPTED_RE.search(line):
        return ParsedEvent(
            timestamp=timestamp,
            source_ip=match.group("ip"),
            event_type="ssh_login_success",
            username=match.group("user"),
            raw_message=line,
            severity="LOW",
        )

    if match := _INVALID_USER_RE.search(line):
        return ParsedEvent(
            timestamp=timestamp,
            source_ip=match.group("ip"),
            event_type="ssh_invalid_user",
            username=match.group("user"),
            raw_message=line,
            severity="MEDIUM",
        )

    if match := _SUDO_RE.search(line):
        return ParsedEvent(
            timestamp=timestamp,
            source_ip="local",
            event_type="ssh_privilege_escalation",
            username=match.group("actor"),
            raw_message=line,
            severity="HIGH",
        )

    return None


# parse multiple lines of SSH auth log and returns recognized events and count of unknown lines
def parse_ssh_log(text: str, now: datetime | None = None) -> tuple[list[ParsedEvent], int]:
    
    events: list[ParsedEvent] = []
    unknown = 0
    for line in text.splitlines():
        if not line.strip():
            continue
        parsed = parse_ssh_line(line, now)
        if parsed is None:
            unknown += 1
        else:
            events.append(parsed)
    return events, unknown