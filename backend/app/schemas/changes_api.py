"""ChangeRequest API contracts (M5-T15): request/response models for the
``/api/v1/agents/changes`` surface.

Pure data (D2): validation only, no I/O — these models import nothing from the
services or engines. They mirror the persisted
:class:`~app.models.change_requests.ChangeRequest` lifecycle row so the API can
surface "Human approval for changes" + "Audit everything" (CLAUDE.md) without
ever exposing the secret-bearing ``payload`` over the read surface.

Data minimization (ADR-0020 §4): a CR ``payload`` may carry a config diff or DDI
record body (secret-bearing), so :class:`ChangeRequestRead` deliberately surfaces
only lifecycle metadata + the **id-only** ``target_refs`` (which devices/DDI refs
the change touches) — never ``payload`` itself. The approver reviews the change
through the dedicated draft-authoring path, not by reading it back over the list
surface.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.models.change_requests import ChangeRequestKind, ChangeRequestState

__all__ = [
    "ChangeDecisionRequest",
    "ChangeRequestListResponse",
    "ChangeRequestRead",
]


class ChangeRequestRead(BaseModel):
    """One ChangeRequest as returned by the changes endpoints (no ``payload``).

    The secret-bearing ``payload`` (the exact diff / DDI body to apply) is never
    surfaced here (ADR-0020 §4 data minimization); only the lifecycle state, the
    requester, four-eyes posture, and the id-only ``target_refs`` ride out.
    """

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    state: ChangeRequestState
    kind: ChangeRequestKind
    requester_id: uuid.UUID
    four_eyes_required: bool
    target_refs: dict[str, Any] | None = None
    reasoning_trace_id: uuid.UUID | None = None
    created_at: datetime
    updated_at: datetime


class ChangeRequestListResponse(BaseModel):
    """Paginated list of ChangeRequests, newest first."""

    items: list[ChangeRequestRead]
    total: int
    limit: int
    offset: int


class ChangeDecisionRequest(BaseModel):
    """Body of the submit / approve / reject endpoints.

    Only an optional reviewer ``comment`` may accompany a decision — the
    approver and their RBAC role are taken from the authenticated principal
    (never the body), so the four-eyes ``approver != requester`` predicate
    cannot be spoofed through the request.
    """

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    comment: str | None = Field(default=None, max_length=2048)
