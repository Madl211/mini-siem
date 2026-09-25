from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Event
from app.schemas import EventOut

router = APIRouter(tags=["events"])


@router.get("/events", response_model=list[EventOut])
def list_events(
    db: Session = Depends(get_db),
    source_ip: str | None = Query(default=None),
    event_type: str | None = Query(default=None),
    username: str | None = Query(default=None),
    path: str | None = Query(default=None),
    since: datetime | None = Query(default=None),
    until: datetime | None = Query(default=None),
    q: str | None = Query(default=None, description="Freitextsuche in der Rohzeile"),
    limit: int = Query(default=200, le=1000),
    offset: int = Query(default=0, ge=0),
) -> list[Event]:
    stmt = select(Event)

    if source_ip is not None:
        stmt = stmt.where(Event.source_ip == source_ip)
    if event_type is not None:
        stmt = stmt.where(Event.event_type == event_type)
    if username is not None:
        stmt = stmt.where(Event.username == username)
    if path is not None:
        stmt = stmt.where(Event.path.contains(path))
    if since is not None:
        stmt = stmt.where(Event.timestamp >= since)
    if until is not None:
        stmt = stmt.where(Event.timestamp <= until)
    if q is not None:
        stmt = stmt.where(Event.raw_message.contains(q))

    stmt = stmt.order_by(Event.timestamp.desc()).offset(offset).limit(limit)
    return list(db.execute(stmt).scalars())


@router.get("/events/{event_id}", response_model=EventOut)
def get_event(event_id: int, db: Session = Depends(get_db)) -> Event:
    event = db.get(Event, event_id)
    if event is None:
        raise HTTPException(status_code=404, detail="Event not found")
    return event