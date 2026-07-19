"""API schemas for the compliance/audit report engine (P4 W3-T1; ADR-0053).

Metadata surfaces only: artifact CONTENT is served exclusively by the RBAC'd
download endpoint (never embedded in a JSON body), and ``error_class`` is the
typed token — no free-form failure text crosses the API (ADR-0053 §6).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

from app.models.reports import (
    MAX_REPORT_PERIOD_DAYS,
    REPORT_PERIOD_START_FLOOR,
    ReportKind,
)


class ReportGenerationRequest(BaseModel):
    """Body of ``POST /api/v1/reports`` — one on-demand ``(kind, period)``."""

    kind: ReportKind
    period_start: datetime
    period_end: datetime

    @field_validator("period_start", "period_end", mode="after")
    @classmethod
    def _pin_utc(cls, value: datetime) -> datetime:
        # Naive timestamps are pinned as UTC — NEVER host-local time — so the
        # run id derived here matches the worker's (``_parse_utc``) for the
        # same wall-clock period, and mixed naive/aware bodies stay comparable
        # in ``_period_ordered`` (422, not a TypeError 500). Duplicates
        # ``app.engines.reports.coerce_utc`` because schemas sit below engines
        # in the layers contract.
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def _period_ordered(self) -> ReportGenerationRequest:
        if self.period_end <= self.period_start:
            raise ValueError("period_end must be after period_start")
        if self.period_end > datetime.now(UTC):
            # A premature request would SUCCEED with partial data and the
            # claim-row guard would then block the completed period's scheduled
            # run forever ("skipped" for SUCCEEDED runs) — a silent compliance
            # gap. The period must be complete before generation.
            raise ValueError("period_end must not be in the future")
        if self.period_start < REPORT_PERIOD_START_FLOOR:
            # Platform-epoch floor (PR #166 F3): nothing reportable predates
            # the platform; a year-1 period_start is only ever a DoS probe.
            raise ValueError(
                f"period_start must not precede {REPORT_PERIOD_START_FLOOR.date().isoformat()}"
            )
        if self.period_end - self.period_start > timedelta(days=MAX_REPORT_PERIOD_DAYS):
            # Span cap (PR #166 F3): builders materialize one tuple per period
            # day, so an unbounded span is an unbounded-memory vector — 400
            # days covers an annual report plus fiscal-offset slack.
            raise ValueError(f"period span must not exceed {MAX_REPORT_PERIOD_DAYS} days")
        return self


class ReportGenerationQueued(BaseModel):
    """202 response: the deterministic run id for the requested period."""

    run_id: uuid.UUID
    status: str


class ReportArtifactRead(BaseModel):
    """Artifact metadata (bytes live behind the download endpoint only)."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    run_id: uuid.UUID
    format: str
    sha256: str
    size_bytes: int
    expires_at: datetime
    created_at: datetime


class ReportRunRead(BaseModel):
    """One report run's metadata."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    kind: str
    trigger: str
    requested_by: uuid.UUID | None
    period_start: datetime
    period_end: datetime
    status: str
    error_class: str | None
    regime_tags: list[str]
    finished_at: datetime | None
    created_at: datetime


class ReportRunDetail(ReportRunRead):
    """Run metadata plus its artifact metadata (still no content bytes)."""

    artifacts: list[ReportArtifactRead] = []


class ReportRunListResponse(BaseModel):
    """Paginated run listing (RBAC-scoped to kinds the caller may see)."""

    items: list[ReportRunRead]
    total: int
    limit: int
    offset: int
