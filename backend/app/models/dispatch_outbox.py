"""Durable Celery publication envelopes (ADR-0059)."""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import StrEnum

from sqlalchemy import Index, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base
from app.models.mixins import JSON_VARIANT, UtcDateTime, UuidPkMixin, utcnow


class DispatchOutboxState(StrEnum):
    PENDING = "pending"
    CLAIMED = "claimed"
    DISPATCHED = "dispatched"
    DEAD = "dead"


class DispatchOutbox(UuidPkMixin, Base):
    __tablename__ = "dispatch_outbox"
    __table_args__ = (
        UniqueConstraint(
            "aggregate_type",
            "aggregate_id",
            "task_name",
            name="uq_dispatch_outbox_aggregate_task",
        ),
        Index("ix_dispatch_outbox_relay", "state", "available_at", "created_at"),
    )

    aggregate_type: Mapped[str] = mapped_column(String(32), nullable=False)
    aggregate_id: Mapped[uuid.UUID] = mapped_column(nullable=False)
    task_name: Mapped[str] = mapped_column(String(128), nullable=False)
    queue: Mapped[str] = mapped_column(String(32), nullable=False)
    payload_json: Mapped[dict[str, str | None]] = mapped_column(JSON_VARIANT, nullable=False)
    state: Mapped[str] = mapped_column(
        String(16), nullable=False, default=DispatchOutboxState.PENDING.value
    )
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    available_at: Mapped[datetime] = mapped_column(UtcDateTime(), nullable=False, default=utcnow)
    claimed_at: Mapped[datetime | None] = mapped_column(UtcDateTime(), nullable=True)
    claim_owner: Mapped[str | None] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime(), nullable=False, default=utcnow)
    dispatched_at: Mapped[datetime | None] = mapped_column(UtcDateTime(), nullable=True)
    last_error_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
