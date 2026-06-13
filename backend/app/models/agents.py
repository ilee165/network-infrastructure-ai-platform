"""Agent-session + reasoning-trace persistence models (brief §5/§6, ADR-0003).

M3 makes "explain every AI decision" a durable artifact: each supervisor run
opens an :class:`AgentSession`, every specialist subgraph records a
:class:`ReasoningTraceRow`, and each reasoning step is a
:class:`ReasoningTraceStep`. The shapes mirror the in-process Pydantic models
in :mod:`app.agents.framework.traces` (``ReasoningTrace`` / ``TraceStep`` /
``EvidenceRef``) so the database-backed recorder persists them losslessly.

Partitioning (ADR-0011, D11): ``reasoning_traces`` and ``reasoning_trace_steps``
are range-partitioned by ``created_at`` on PostgreSQL (monthly), exactly like
``audit_log`` and ``raw_artifacts``. The partition key must be part of the
primary key, hence the composite PK ``(id, created_at)`` on both — these tables
deliberately do NOT use ``UuidPkMixin`` / ``TimestampMixin`` (which give an
id-only PK), following the ``AuditLog`` / ``RawArtifact`` precedent.

Design decision (fixed): rows that point at a partitioned table use a plain
indexed UUID with NO DB-level FK — PostgreSQL requires FKs to a partitioned
table to include the partition key, which is not worth it here. So
``reasoning_trace_steps.trace_id`` and ``audit_log.reasoning_trace_id`` carry
no FK; linkage integrity is enforced by tests (same as ``raw_artifact_id``,
M1-18). ``agent_sessions.user_id`` and ``reasoning_traces.session_id`` target
non-partitioned tables and so keep real foreign keys.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import Enum as SaEnum
from sqlalchemy import ForeignKey, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base
from app.models.mixins import JSON_VARIANT, TimestampMixin, UtcDateTime, UuidPkMixin, utcnow

__all__ = [
    "AgentSession",
    "AgentSessionStatus",
    "ReasoningTraceRow",
    "ReasoningTraceStep",
    "TraceStepKind",
]


class AgentSessionStatus(StrEnum):
    """Lifecycle of one agent (supervisor) run."""

    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class TraceStepKind(StrEnum):
    """What a persisted reasoning step represents.

    Wire values are identical to the in-process
    :class:`app.agents.framework.traces.TraceStepKind` so the database-backed
    recorder persists ``TraceStep.kind`` losslessly. Kept model-local (rather
    than imported from the agent framework) so the persistence layer does not
    depend on the agent package — the same way ``app.models.inventory`` owns
    its wire StrEnums.
    """

    PLAN = "plan"
    TOOL_CALL = "tool_call"
    OBSERVATION = "observation"
    CONCLUSION = "conclusion"


def _wire_enum(enum_cls: type[StrEnum], *, length: int = 32) -> SaEnum:
    """Portable enum column persisting StrEnum *values* as VARCHAR.

    ``native_enum=False`` keeps SQLite/Postgres DDL identical and avoids
    Postgres ``CREATE TYPE`` churn; values (not member names) go on the wire.
    Mirrors ``app.models.inventory._wire_enum``.
    """
    return SaEnum(
        enum_cls,
        native_enum=False,
        length=length,
        values_callable=lambda enum_type: [member.value for member in enum_type],
    )


class AgentSession(UuidPkMixin, TimestampMixin, Base):
    """One agent run: who invoked it, with which role, the intent, and outcome."""

    __tablename__ = "agent_sessions"

    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    invoking_role: Mapped[str] = mapped_column(String(64), nullable=False)
    intent: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[AgentSessionStatus] = mapped_column(
        _wire_enum(AgentSessionStatus), nullable=False, default=AgentSessionStatus.RUNNING
    )
    started_at: Mapped[datetime] = mapped_column(UtcDateTime(), nullable=False, default=utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(UtcDateTime())


class ReasoningTraceRow(Base):
    """The reasoning record of one agent's run inside a session.

    Range-partitioned by ``created_at`` on PostgreSQL (option ignored on
    SQLite), hence the composite PK ``(id, created_at)``. ``session_id`` keeps
    a real FK to the non-partitioned ``agent_sessions``; steps and audit rows
    point back here via plain indexed UUIDs (no FK — see module docstring).
    """

    __tablename__ = "reasoning_traces"
    __table_args__ = {"postgresql_partition_by": "RANGE (created_at)"}

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime(), primary_key=True, default=utcnow)
    session_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("agent_sessions.id"), nullable=False, index=True
    )
    agent_name: Mapped[str] = mapped_column(String(128), nullable=False)
    started_at: Mapped[datetime] = mapped_column(UtcDateTime(), nullable=False, default=utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(UtcDateTime())


class ReasoningTraceStep(Base):
    """One ordered step of a reasoning trace (mirrors ``traces.TraceStep``).

    Range-partitioned by ``created_at`` on PostgreSQL, hence the composite PK
    ``(id, created_at)``. ``trace_id`` is a plain indexed UUID (no FK) because
    ``reasoning_traces`` is partitioned — see the module docstring. ``evidence``
    holds a JSON list of ``EvidenceRef``-shaped objects.
    """

    __tablename__ = "reasoning_trace_steps"
    # PostgreSQL requires every unique constraint on a partitioned table to
    # include the partition key.  The composite (trace_id, ordinal, created_at)
    # enforces uniqueness of ordinals within a trace while satisfying that rule.
    # Without this constraint a recorder bug that emits two steps with the same
    # ordinal would silently corrupt the trace at the DB level.
    __table_args__ = (
        UniqueConstraint(
            "trace_id",
            "ordinal",
            "created_at",
            name="uq_reasoning_trace_steps_trace_ordinal",
        ),
        {"postgresql_partition_by": "RANGE (created_at)"},
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime(), primary_key=True, default=utcnow)
    trace_id: Mapped[uuid.UUID] = mapped_column(nullable=False, index=True)
    ordinal: Mapped[int] = mapped_column(nullable=False)
    kind: Mapped[TraceStepKind] = mapped_column(_wire_enum(TraceStepKind), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    detail: Mapped[str | None] = mapped_column(Text)
    tool_name: Mapped[str | None] = mapped_column(String(255))
    evidence: Mapped[list[dict[str, Any]]] = mapped_column(
        JSON_VARIANT, nullable=False, default=list
    )
    occurred_at: Mapped[datetime] = mapped_column(UtcDateTime(), nullable=False, default=utcnow)
