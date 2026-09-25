from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict

Severity = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
AlertStatus = Literal["OPEN", "ACKNOWLEDGED", "RESOLVED"]


class EventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    timestamp: datetime
    source_ip: str
    event_type: str
    username: str | None
    method: str | None
    path: str | None
    status_code: int | None
    user_agent: str | None
    raw_message: str
    severity: Severity
    created_at: datetime


class AlertOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    alert_type: str
    title: str
    description: str
    severity: Severity
    source_ip: str
    status: AlertStatus
    extra_info: str | None
    created_at: datetime
    updated_at: datetime
    event_ids: list[int] = []


class AlertUpdate(BaseModel):
    status: AlertStatus


class LogUploadResult(BaseModel):
    filename: str
    log_type: str
    total_lines: int
    parsed_events: int
    unknown_lines: int
    alerts_created: int


class StatsOut(BaseModel):
    total_events: int
    open_alerts: int
    critical_alerts: int
    unique_source_ips: int
    top_alert_types: list[dict[str, int | str]]
    events_last_24h: int


class SampleLoadResult(BaseModel):
    files: list[LogUploadResult]
    alerts_created: int