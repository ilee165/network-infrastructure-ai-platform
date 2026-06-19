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
    """One audited action: who (`actor`) did what (`action`) to which target.

    ``reasoning_trace_id`` links an audited action back to the reasoning trace
    that produced it (brief §6). It is a plain indexed UUID with NO DB-level FK:
    ``reasoning_traces`` is range-partitioned, and PostgreSQL FKs to a
    partitioned table must include the partition key — the same design used for
    ``raw_artifact_id`` (see ``app.models.inventory``). Linkage integrity is
    enforced by tests, and the column is nullable for non-agent audit entries.

    ``request_id`` is the inbound request/correlation id of the call that
    produced the audited action (ADR-0020 §4 names ``request id`` as a required
    dimension of every transition audit entry). It is a plain indexed UUID with
    no FK — a free-standing correlation handle, captured at the route layer and
    threaded down to :func:`app.services.audit.record`. It is ``None`` for
    actions raised outside an HTTP request (e.g. background/agent-driven
    handoffs that carry no inbound correlation id).
    """

    __tablename__ = "audit_log"
    __table_args__ = {"postgresql_partition_by": "RANGE (created_at)"}

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime(), primary_key=True, default=utcnow)
    actor: Mapped[str] = mapped_column(String(255), nullable=False)
    action: Mapped[str] = mapped_column(String(128), nullable=False)
    target_type: Mapped[str] = mapped_column(String(128), nullable=False)
    target_id: Mapped[str | None] = mapped_column(String(255))
    detail: Mapped[dict[str, Any] | None] = mapped_column(JSON_VARIANT)
    reasoning_trace_id: Mapped[uuid.UUID | None] = mapped_column(index=True)
    request_id: Mapped[uuid.UUID | None] = mapped_column(index=True)
