import csv
import io
from datetime import datetime, timedelta, timezone
from typing import Literal

from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Alert, Event
from app.schemas import StatsOut

router = APIRouter(tags=["exports"])

ExportDataset = Literal["alerts", "events"]


@router.get("/stats", response_model=StatsOut)
def get_stats(db: Session = Depends(get_db)) -> StatsOut:
    total_events = db.execute(select(func.count(Event.id))).scalar_one()
    open_alerts = db.execute(
        select(func.count(Alert.id)).where(Alert.status == "OPEN")
    ).scalar_one()
    critical_alerts = db.execute(
        select(func.count(Alert.id)).where(Alert.severity == "CRITICAL")
    ).scalar_one()
    unique_source_ips = db.execute(
        select(func.count(func.distinct(Event.source_ip)))
    ).scalar_one()

    top_rows = db.execute(
        select(Alert.alert_type, func.count(Alert.id).label("count"))
        .group_by(Alert.alert_type)
        .order_by(func.count(Alert.id).desc())
        .limit(5)
    ).all()
    top_alert_types = [{"alert_type": row[0], "count": row[1]} for row in top_rows]

    cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=24)
    events_last_24h = db.execute(
        select(func.count(Event.id)).where(Event.timestamp >= cutoff)
    ).scalar_one()

    return StatsOut(
        total_events=total_events,
        open_alerts=open_alerts,
        critical_alerts=critical_alerts,
        unique_source_ips=unique_source_ips,
        top_alert_types=top_alert_types,
        events_last_24h=events_last_24h,
    )


def _fetch_rows(db: Session, dataset: ExportDataset) -> tuple[list[str], list[list[object]]]:
    if dataset == "alerts":
        columns = [
            "id", "alert_type", "title", "description", "severity",
            "source_ip", "status", "created_at", "updated_at",
        ]
        rows = db.execute(select(Alert).order_by(Alert.created_at.desc())).scalars()
        data = [
            [getattr(a, col) if col not in ("created_at", "updated_at") else getattr(a, col).isoformat() for col in columns]
            for a in rows
        ]
    else:
        columns = [
            "id", "timestamp", "source_ip", "event_type", "username",
            "method", "path", "status_code", "user_agent", "severity",
        ]
        rows = db.execute(select(Event).order_by(Event.timestamp.desc())).scalars()
        data = [
            [getattr(e, col) if col != "timestamp" else getattr(e, col).isoformat() for col in columns]
            for e in rows
        ]
    return columns, data


@router.get("/export/json")
def export_json(dataset: ExportDataset = Query(default="alerts"), db: Session = Depends(get_db)) -> list[dict]:
    columns, data = _fetch_rows(db, dataset)
    return [dict(zip(columns, row)) for row in data]


@router.get("/export/csv")
def export_csv(dataset: ExportDataset = Query(default="alerts"), db: Session = Depends(get_db)) -> StreamingResponse:
    columns, data = _fetch_rows(db, dataset)

    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(columns)
    writer.writerows(data)
    buffer.seek(0)

    return StreamingResponse(
        iter([buffer.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={dataset}.csv"},
    )