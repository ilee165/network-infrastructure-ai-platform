"""Config-management + document API contracts (M4; T14).

Pure data (D2): validation only, no I/O.  ``from_attributes`` read models
mirror the ORM rows so endpoints can return ``model_validate(row)`` directly.

RBAC-sensitive rules (ADR-0017):
* ``ConfigSnapshotRead`` (list view) never includes ``content`` — only the
  content-addressed hash and metadata.  Content is returned ONLY by the
  ``GET /config-snapshots/{id}/content`` sub-resource and only to
  ``engineer+`` callers.
* ``DocumentRead`` exposes metadata and ``content``; documents do NOT contain
  secret material (they are agent-generated; A9 redaction applied at the LLM
  boundary before writing).  Viewer+ may list/download.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict

from app.engines.config_mgmt.compliance.engine import FindingStatus
from app.engines.config_mgmt.compliance.schema import Severity
from app.models.config_mgmt import (
    ConfigSource,
    DocumentFormat,
    DocumentKind,
)

__all__ = [
    "ComplianceRunResponse",
    "ConfigSnapshotContent",
    "ConfigSnapshotListResponse",
    "ConfigSnapshotRead",
    "DocumentDownload",
    "DocumentListResponse",
    "DocumentRead",
    "DriftResponse",
    "FindingRead",
]


# ---------------------------------------------------------------------------
# Config snapshot schemas
# ---------------------------------------------------------------------------


class ConfigSnapshotRead(BaseModel):
    """One config snapshot as returned in list views — no content field (ADR-0017)."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    device_id: uuid.UUID
    captured_at: datetime
    content_hash: str
    source: ConfigSource
    capture_run_id: uuid.UUID | None
    baseline: bool
    created_at: datetime
    updated_at: datetime


class ConfigSnapshotListResponse(BaseModel):
    """Paginated config-snapshot collection."""

    items: list[ConfigSnapshotRead]
    total: int
    limit: int
    offset: int


class ConfigSnapshotContent(BaseModel):
    """Raw (unredacted) snapshot content — engineer+ only (ADR-0017 §2).

    The ``content`` field is returned verbatim as stored.  The caller is
    responsible for ensuring this is never written to a log line, exception
    message, or API trace — it may contain credentials and keys.
    """

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    device_id: uuid.UUID
    content_hash: str
    content: str
    baseline: bool
    captured_at: datetime


# ---------------------------------------------------------------------------
# Drift schema
# ---------------------------------------------------------------------------


class DriftResponse(BaseModel):
    """Result of a drift check against the device's approved baseline."""

    device_id: uuid.UUID
    has_drift: bool
    diff: str
    hunks: list[str]
    baseline_hash: str
    current_hash: str


# ---------------------------------------------------------------------------
# Compliance schemas
# ---------------------------------------------------------------------------


class FindingRead(BaseModel):
    """One compliance finding from a policy evaluation (ADR-0018 §5).

    ``evidence`` may contain raw config snippets — callers must not expose it
    beyond the authenticated API surface.
    """

    device_id: uuid.UUID
    policy_id: str
    policy_version: int
    rule_id: str
    severity: Severity
    status: FindingStatus
    evidence: str


class ComplianceRunResponse(BaseModel):
    """Compliance evaluation result for one device against all active policies."""

    device_id: uuid.UUID
    policy_id: str
    policy_version: int
    findings: list[FindingRead]
    violation_count: int
    warn_count: int
    pass_count: int
    skipped_count: int


# ---------------------------------------------------------------------------
# Document schemas
# ---------------------------------------------------------------------------


class DocumentRead(BaseModel):
    """One generated document as returned in list/detail views.

    ``content`` is included — documents are agent-generated and have the A9
    redaction layer applied at write time (ADR-0019), so the content does not
    contain unredacted secret material.
    """

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    kind: DocumentKind
    title: str
    format: DocumentFormat
    content: str
    source_refs: dict[str, Any]
    generated_at: datetime
    generated_by_session_id: uuid.UUID | None
    created_at: datetime
    updated_at: datetime


class DocumentListResponse(BaseModel):
    """Paginated document collection."""

    items: list[DocumentRead]
    total: int
    limit: int
    offset: int


class DocumentDownload(BaseModel):
    """Download payload for a generated document (raw content + metadata)."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    title: str
    format: DocumentFormat
    content: str
    generated_at: datetime
