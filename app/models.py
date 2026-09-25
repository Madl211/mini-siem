from datetime import datetime, timezone

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import (
    Mapped,
    mapped_column,
    relationship,
)

from app.database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Event(Base):
    __tablename__ = "events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, index=True)
    source_ip: Mapped[str] = mapped_column(String(45), index=True)
    event_type: Mapped[str] = mapped_column(String(64), index=True)
    username: Mapped[str | None] = mapped_column(String(128), nullable=True)
    method: Mapped[str | None] = mapped_column(String(16), nullable=True)
    path: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(512), nullable=True)
    raw_message: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(16), default="LOW")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    alert_links: Mapped[list["AlertEvent"]] = relationship(
        back_populates="event", cascade="all, delete-orphan"
    )

    __table_args__ = (
        CheckConstraint(
            "severity in ('LOW','MEDIUM','HIGH','CRITICAL')", name="ck_event_severity"
        ),
    )


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    alert_type: Mapped[str] = mapped_column(String(64), index=True)
    title: Mapped[str] = mapped_column(String(256))
    description: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    source_ip: Mapped[str] = mapped_column(String(45), index=True)
    status: Mapped[str] = mapped_column(String(16), default="OPEN", index=True)
    extra_info: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=utcnow, onupdate=utcnow
    )

    event_links: Mapped[list["AlertEvent"]] = relationship(
        back_populates="alert", cascade="all, delete-orphan"
    )

    __table_args__ = (
        CheckConstraint(
            "severity in ('LOW','MEDIUM','HIGH','CRITICAL')", name="ck_alert_severity"
        ),
        CheckConstraint(
            "status in ('OPEN','ACKNOWLEDGED','RESOLVED')", name="ck_alert_status"
        ),
    )


class AlertEvent(Base):

    __tablename__ = "alert_events"

    alert_id: Mapped[int] = mapped_column(
        ForeignKey("alerts.id"), primary_key=True
    )
    event_id: Mapped[int] = mapped_column(
        ForeignKey("events.id"), primary_key=True
    )

    alert: Mapped["Alert"] = relationship(back_populates="event_links")
    event: Mapped["Event"] = relationship(back_populates="alert_links")


class Rule(Base):
    __tablename__ = "rules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(128), unique=True)
    event_type: Mapped[str] = mapped_column(String(64))
    threshold: Mapped[int] = mapped_column(Integer)
    window_seconds: Mapped[int] = mapped_column(Integer)
    severity: Mapped[str] = mapped_column(String(16))
    alert_type: Mapped[str] = mapped_column(String(64))
    enabled: Mapped[bool] = mapped_column(default=True)