"""Compliance/audit report model (P4 W3-T1; ADR-0053 §1).

``report_runs`` + ``report_artifacts`` are a DEDICATED aggregate — deliberately
NOT the RAG-embedded ``documents`` table (ADR-0053 §1): ``documents`` rows are
chunked into the pgvector index and surfaced by agent retrieval to any user,
while reports are RBAC-scoped evidence (access review is admin-only). A separate
model makes the exclusion structural rather than a filter someone can forget;
``tests/engines/reports/test_boundary.py`` asserts generation never touches
``documents``.

Artifacts live in Postgres ``bytea`` (not disk/object storage): evidence files
are KB–low-MB, must survive DR, and ride the existing PG backup path (ADR-0030)
with zero new infrastructure. ``expires_at`` drives the scheduled retention
purge (``reports.purge_expired``, 7-year PROPOSED default, ADR-0053 §4).

``error_class`` is a TYPED token (``redaction_violation`` et al.) — never
free-form text that could carry secret material into the API or logs
(ADR-0053 §6 fail-closed contract).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Final

from sqlalchemy import BigInteger, ForeignKey, Index, LargeBinary, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base
from app.models.mixins import JSON_VARIANT, TimestampMixin, UtcDateTime, UuidPkMixin

#: Maximum reporting-period span (PR #166 F3). 400 days covers a full annual
#: report (366 leap-year days) plus fiscal-year-offset/grace slack. The report
#: builders materialize one tuple per period DAY (the compliance-posture daily
#: trend; audit-integrity additionally emits per-gap-day findings), so an
#: unbounded span — e.g. year 1 → today, ~739K days — is an unbounded-memory /
#: DoS vector on the worker. Enforced at BOTH generation entry points
#: (``app.schemas.reports_api`` for the API, ``read_facade
#: .report_generation_args`` for the agent path) — the worker executes
#: whatever those produce. Lives here (models layer) so both enforcers share
#: one constant without a layering violation.
MAX_REPORT_PERIOD_DAYS: Final = 400

#: Floor for ``period_start`` (PR #166 F3): well before the platform's first
#: deployable release (2026), so any legitimately reportable period is
#: representable while nonsense spans (year-1 timestamps) are refused outright.
REPORT_PERIOD_START_FLOOR: Final = datetime(2020, 1, 1, tzinfo=UTC)


class ReportKind(StrEnum):
    """The four PRODUCTION.md §7 report kinds (ADR-0053 §7)."""

    CHANGE = "change"
    COMPLIANCE_POSTURE = "compliance_posture"
    ACCESS_REVIEW = "access_review"
    AUDIT_INTEGRITY = "audit_integrity"


class ReportTrigger(StrEnum):
    """How a report run was requested (ADR-0053 §2)."""

    SCHEDULED = "scheduled"
    ON_DEMAND = "on_demand"


class ReportRunStatus(StrEnum):
    """Lifecycle of a report run (ADR-0053 §1)."""

    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"


class ReportFormat(StrEnum):
    """Artifact export formats (ADR-0053 §5)."""

    CSV = "csv"
    PDF = "pdf"


class ReportRun(UuidPkMixin, TimestampMixin, Base):
    """One report generation run for a ``(kind, period)`` (ADR-0053 §1).

    The primary key is the DETERMINISTIC claim UUID derived from
    ``(kind, period_start, period_end)`` (the ``_claim_backup_run`` precedent),
    so a beat delivery and an on-demand request for the same period collide on
    the PK/unique constraint instead of double-generating (ADR-0053 §2).
    """

    __tablename__ = "report_runs"
    __table_args__ = (
        # Idempotency per (kind, period): DB-level enforcement beneath the
        # deterministic-UUID claim (ADR-0053 §2).
        UniqueConstraint("kind", "period_start", "period_end", name="uq_report_runs_kind_period"),
        Index("ix_report_runs_kind_created", "kind", "created_at"),
    )

    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    trigger: Mapped[str] = mapped_column(String(16), nullable=False)
    #: Requesting user id for on-demand runs; NULL for beat-scheduled runs.
    #: Plain UUID (no FK) so evidence history survives user lifecycle changes,
    #: mirroring ``reasoning_trace_id`` on ``audit_log``.
    requested_by: Mapped[uuid.UUID | None] = mapped_column(nullable=True)
    period_start: Mapped[datetime] = mapped_column(UtcDateTime(), nullable=False)
    period_end: Mapped[datetime] = mapped_column(UtcDateTime(), nullable=False)
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default=ReportRunStatus.RUNNING.value
    )
    #: Typed failure class (``redaction_violation``, ``builder_error``,
    #: ``render_error``) — NEVER free-form text (no secret can leak through it).
    error_class: Mapped[str | None] = mapped_column(String(64), nullable=True)
    #: Regime control tags snapshotting the mapping in force at generation
    #: (ADR-0053 §8; SOC 2 CC-series PROPOSED default). Metadata only.
    regime_tags: Mapped[list[str]] = mapped_column(JSON_VARIANT, nullable=False, default=list)
    finished_at: Mapped[datetime | None] = mapped_column(UtcDateTime(), nullable=True)

    artifacts: Mapped[list[ReportArtifact]] = relationship(
        back_populates="run", cascade="all, delete-orphan"
    )


class ReportArtifact(UuidPkMixin, TimestampMixin, Base):
    """One rendered evidence artifact (CSV or PDF) of a report run (ADR-0053 §1)."""

    __tablename__ = "report_artifacts"
    __table_args__ = (
        # The retention purge scans by expiry (ADR-0053 §4).
        Index("ix_report_artifacts_expires_at", "expires_at"),
    )

    run_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("report_runs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    format: Mapped[str] = mapped_column(String(8), nullable=False)
    #: The artifact bytes themselves — PG ``bytea``, covered by the PG backup/DR
    #: path (ADR-0030); the MinIO object-store escalation is named, not built.
    #: DEFERRED (PR #166 F4): a plain (non-deferred) LargeBinary column loads
    #: EVERY sibling artifact's bytes on any query that selects the entity —
    #: metadata reads (``GET /reports/{run_id}``, the read facade) and even the
    #: download route's own ``ReportRun.artifacts`` selectinload only need
    #: ``sha256``/``size_bytes``/``format`` to answer, never the blob. Deferring
    #: keeps the column out of the default SELECT; the download route explicitly
    #: re-selects the ONE requested artifact's bytes with its own statement.
    #: ``deferred_raiseload=True`` turns any OTHER accidental touch of
    #: ``.content`` (e.g. via the audit-detail serializer) into an explicit,
    #: immediate ``InvalidRequestError`` instead of an implicit lazy-load —
    #: which, off the request's async greenlet, would surface as an opaque
    #: ``MissingGreenlet`` crash rather than a clear programming-error signal.
    content: Mapped[bytes] = mapped_column(
        LargeBinary(), nullable=False, deferred=True, deferred_raiseload=True
    )
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    size_bytes: Mapped[int] = mapped_column(BigInteger(), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(UtcDateTime(), nullable=False)

    run: Mapped[ReportRun] = relationship(back_populates="artifacts")
