"""Reusable ORM column infrastructure (REPO-STRUCTURE §4.2, P5).

``UuidPkMixin`` gives aggregates an app-side UUIDv4 primary key (ids exist
before the row hits the database — no sequence round-trip, safe for envelope
payloads and audit references). ``TimestampMixin`` adds tz-aware UTC
``created_at``/``updated_at`` columns, the latter refreshed on every UPDATE.

``UtcDateTime`` keeps datetimes aware-UTC across backends: PostgreSQL stores
``timestamptz`` natively; SQLite (the unit-test backend) returns naive values
which are re-tagged as UTC on the way out. Naive datetimes are rejected at
bind time so "naive local time" bugs cannot reach the database.

``JSON_VARIANT`` is the portable JSON column type: plain ``JSON`` everywhere,
``JSONB`` on PostgreSQL (D4 — JSONB is for raw/opaque payloads only).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import JSON, DateTime, TypeDecorator
from sqlalchemy.dialects import postgresql
from sqlalchemy.engine import Dialect
from sqlalchemy.orm import Mapped, mapped_column


def utcnow() -> datetime:
    """Return the current tz-aware UTC instant (column default helper)."""
    return datetime.now(UTC)


class UtcDateTime(TypeDecorator[datetime]):
    """tz-aware UTC datetime, portable across PostgreSQL and SQLite."""

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect: Dialect) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            raise ValueError("naive datetime not allowed; pass a tz-aware (UTC) datetime")
        return value.astimezone(UTC)

    def process_result_value(self, value: datetime | None, dialect: Dialect) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)


JSON_VARIANT = JSON().with_variant(postgresql.JSONB(), "postgresql")
"""Portable JSON column type: ``JSON`` generally, ``JSONB`` on PostgreSQL."""


class UuidPkMixin:
    """UUIDv4 primary key generated app-side (P5)."""

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)


class TimestampMixin:
    """tz-aware UTC ``created_at`` / ``updated_at``; the latter auto-refreshes."""

    created_at: Mapped[datetime] = mapped_column(UtcDateTime(), nullable=False, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        UtcDateTime(), nullable=False, default=utcnow, onupdate=utcnow
    )
