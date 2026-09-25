from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Alert
from app.schemas import AlertOut, AlertUpdate

router = APIRouter(tags=["alerts"])


def _to_alert_out(alert: Alert) -> AlertOut:
    out = AlertOut.model_validate(alert)
    out.event_ids = [link.event_id for link in alert.event_links]
    return out


@router.get("/alerts", response_model=list[AlertOut])
def list_alerts(
    db: Session = Depends(get_db),
    severity: str | None = Query(default=None),
    status: str | None = Query(default=None),
    alert_type: str | None = Query(default=None),
    source_ip: str | None = Query(default=None),
    since: datetime | None = Query(default=None),
    until: datetime | None = Query(default=None),
    q: str | None = Query(default=None, description="Search in title/description"),
    limit: int = Query(default=200, le=1000),
    offset: int = Query(default=0, ge=0),
) -> list[AlertOut]:
    stmt = select(Alert)

    if severity is not None:
        stmt = stmt.where(Alert.severity == severity)
    if status is not None:
        stmt = stmt.where(Alert.status == status)
    if alert_type is not None:
        stmt = stmt.where(Alert.alert_type == alert_type)
    if source_ip is not None:
        stmt = stmt.where(Alert.source_ip == source_ip)
    if since is not None:
        stmt = stmt.where(Alert.created_at >= since)
    if until is not None:
        stmt = stmt.where(Alert.created_at <= until)
    if q is not None:
        stmt = stmt.where(Alert.title.contains(q) | Alert.description.contains(q))

    stmt = stmt.order_by(Alert.created_at.desc()).offset(offset).limit(limit)
    alerts = db.execute(stmt).scalars()
    return [_to_alert_out(a) for a in alerts]


@router.get("/alerts/{alert_id}", response_model=AlertOut)
def get_alert(alert_id: int, db: Session = Depends(get_db)) -> AlertOut:
    alert = db.get(Alert, alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return _to_alert_out(alert)


@router.patch("/alerts/{alert_id}", response_model=AlertOut)
def update_alert(alert_id: int, payload: AlertUpdate, db: Session = Depends(get_db)) -> AlertOut:
    alert = db.get(Alert, alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.status = payload.status
    db.commit()
    db.refresh(alert)
    return _to_alert_out(alert)