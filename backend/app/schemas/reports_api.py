"""API schemas for the compliance/audit report engine (P4 W3-T1; ADR-0053).

Metadata surfaces only: artifact CONTENT is served exclusively by the RBAC'd
download endpoint (never embedded in a JSON body), and ``error_class`` is the
typed token — no free-form failure text crosses the API (ADR-0053 §6).
"""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, model_validator

from app.models.reports import ReportKind


class ReportGenerationRequest(BaseModel):
    """Body of ``POST /api/v1/reports`` — one on-demand ``(kind, period)``."""

    kind: ReportKind
    period_start: datetime
    period_end: datetime

    @model_validator(mode="after")
    def _period_ordered(self) -> ReportGenerationRequest:
        if self.period_end <= self.period_start:
            raise ValueError("period_end must be after period_start")
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
