"""Append-only audit log (brief §7, ADR-0004, ADR-0011).

``audit_log`` is range-partitioned by ``created_at`` on PostgreSQL (the
partition option is ignored on SQLite), so the partition key must be part of
the primary key — hence the composite PK ``(id, created_at)``. Append-only
enforcement (INSERT/SELECT-only grants) is applied by migration, not here.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import String
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base
from app.models.mixins import JSON_VARIANT, UtcDateTime, utcnow


class AuditLog(Base):
    """One audited action: who (`actor`) did what (`action`) to which target."""

    __tablename__ = "audit_log"
    __table_args__ = {"postgresql_partition_by": "RANGE (created_at)"}

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime(), primary_key=True, default=utcnow)
    actor: Mapped[str] = mapped_column(String(255), nullable=False)
    action: Mapped[str] = mapped_column(String(128), nullable=False)
    target_type: Mapped[str] = mapped_column(String(128), nullable=False)
    target_id: Mapped[str | None] = mapped_column(String(255))
    detail: Mapped[dict[str, Any] | None] = mapped_column(JSON_VARIANT)
