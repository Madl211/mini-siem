from typing import Literal

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from sqlalchemy.orm import Session

from app.database import get_db
from app.detection.engine import run_detection
from app.detection.rules import load_rules
from app.models import Event
from app.parsers.http_parser import parse_http_log
from app.parsers.ssh_parser import ParsedEvent, parse_ssh_log
from app.schemas import LogUploadResult

router = APIRouter(tags=["logs"])

RULES_CONFIG_PATH = "app/detection/config.yaml"

LogType = Literal["ssh", "http", "auto"]


# heuristic to detect log type automatically
def _detect_log_type(text: str) -> Literal["ssh", "http"]:
    for line in text.splitlines():
        if not line.strip():
            continue
        if " - - [" in line:
            return "http"
        return "ssh"
    return "ssh"


def _parse(text: str, log_type: LogType) -> tuple[list[ParsedEvent], int, str]:
    if log_type == "auto":
        log_type = _detect_log_type(text)
    if log_type == "ssh":
        events, unknown = parse_ssh_log(text)
    else:
        events, unknown = parse_http_log(text)
    return events, unknown, log_type


def _save_events(db: Session, parsed_events: list[ParsedEvent]) -> None:
    for pe in parsed_events:
        db.add(
            Event(
                timestamp=pe.timestamp,
                source_ip=pe.source_ip,
                event_type=pe.event_type,
                username=pe.username,
                method=pe.method,
                path=pe.path,
                status_code=pe.status_code,
                user_agent=pe.user_agent,
                raw_message=pe.raw_message,
                severity=pe.severity,
            )
        )
    db.commit()


def _run_detection(db: Session) -> int:
    rules = load_rules(RULES_CONFIG_PATH)
    return run_detection(db, rules)


@router.post("/logs/upload", response_model=LogUploadResult)
async def upload_log(
    file: UploadFile = File(...),
    log_type: LogType = Form(default="auto"),
    db: Session = Depends(get_db),
) -> LogUploadResult:
    raw_bytes = await file.read()
    try:
        text = raw_bytes.decode("utf-8", errors="replace")
    except Exception:
        raise HTTPException(status_code=400, detail="Failed to decode log file as UTF-8 text")

    total_lines = len([line for line in text.splitlines() if line.strip()])
    parsed_events, unknown, resolved_type = _parse(text, log_type)

    _save_events(db, parsed_events)
    alerts_created = _run_detection(db)

    return LogUploadResult(
        filename=file.filename or "unknown",
        log_type=resolved_type,
        total_lines=total_lines,
        parsed_events=len(parsed_events),
        unknown_lines=unknown,
        alerts_created=alerts_created,
    )


# Endpoint to trigger detection on all stored events
@router.post("/logs/analyze")
def analyze_logs(db: Session = Depends(get_db)) -> dict[str, int]:
    alerts_created = _run_detection(db)
    return {"alerts_created": alerts_created}