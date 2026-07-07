"""Manual application-tagging API contracts (P4 W2-T3, ADR-0052 §1/§7).

Pure data (D2): validation only, no I/O. Payloads are names, descriptions,
FQDNs, owner strings, and row references — no credential field exists on
either table (ADR-0052 §7 "no secret surface"), and every string is
length-capped here so the tagging surface cannot be used to stuff arbitrary
blobs into the graph or the audit trail.

``origin``/``source``/``target_kind`` reuse the :mod:`app.models.applications`
:class:`~enum.StrEnum` types, so the API vocabulary and the CHECK-constrained
column vocabulary can never drift. ``target_ref`` is accepted as a UUID (the
target row's PG id — by construction the projected node's ``pg_id`` key,
ADR-0052 §1) and canonicalized to its string form by the route.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, Field

from app.models.applications import ApplicationOrigin, DependencySource, DependencyTargetKind

__all__ = [
    "ApplicationCreate",
    "ApplicationDependencyCreate",
    "ApplicationDependencyRead",
    "ApplicationListResponse",
    "ApplicationRead",
    "ApplicationUpdate",
]

#: One FQDN the application answers on (ADR-0052 §1): bounded by the DNS
#: 253-octet name limit; content validation stays light — the DNS derivation
#: source reconciles, it does not trust.
Fqdn = Annotated[str, Field(min_length=1, max_length=253)]

#: Bound on the ``fqdns`` list — a tag payload is an annotation, not a zone dump.
MAX_FQDNS = 64


class ApplicationCreate(BaseModel):
    """Body of ``POST /applications`` — always creates a ``manual``-origin row.

    ``origin``/``origin_ref``/``created_by`` are server-assigned (ADR-0052 §7:
    the API creates user-owned rows only; ``derived`` rows are owned by the
    W2-T2 derivation lifecycle).
    """

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    name: str = Field(min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=4096)
    owner: str | None = Field(default=None, max_length=255)
    fqdns: list[Fqdn] = Field(default_factory=list, max_length=MAX_FQDNS)


class ApplicationUpdate(BaseModel):
    """Body of ``PATCH /applications/{id}`` — every field optional, unset = unchanged.

    A JSON ``null`` clears the nullable ``description``/``owner``; for the
    NOT NULL ``name``/``fqdns`` it means "leave unchanged" (the
    ``api/v1/devices.py`` PATCH-null precedent).
    """

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    name: str | None = Field(default=None, min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=4096)
    owner: str | None = Field(default=None, max_length=255)
    fqdns: list[Fqdn] | None = Field(default=None, max_length=MAX_FQDNS)


class ApplicationRead(BaseModel):
    """One application as returned by every application endpoint."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    description: str | None
    fqdns: list[str]
    origin: ApplicationOrigin
    origin_ref: str | None
    owner: str | None
    created_by: uuid.UUID | None
    created_at: datetime
    updated_at: datetime


class ApplicationListResponse(BaseModel):
    """Paginated application collection (``GET /applications``)."""

    items: list[ApplicationRead]
    total: int
    limit: int
    offset: int


class ApplicationDependencyCreate(BaseModel):
    """Body of ``POST /applications/{id}/dependencies`` — one manual tag.

    A manual tag IS one ``application_dependencies`` row (ADR-0052 §1 — no
    separate tag table): ``source``/``provenance``/``created_by``/``derived_at``
    are server-assigned (``source='manual'``, provenance the single
    ``{"kind": "user", "ref": <user_id>}`` step).
    """

    model_config = ConfigDict(extra="forbid")

    target_kind: DependencyTargetKind
    #: The target row's PG UUID: a ``devices.id`` for ``device``, the
    #: ``normalized_interfaces.id`` carrying the address for ``ip_address``
    #: (the ``IPAddress`` node key, ADR-0052 §1 / topology nodes contract).
    target_ref: uuid.UUID


class ApplicationDependencyRead(BaseModel):
    """One dependency row (any source) as returned by the dependency endpoints."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    application_id: uuid.UUID
    target_kind: DependencyTargetKind
    target_ref: str
    source: DependencySource
    provenance: list[dict[str, Any]]
    derived_at: datetime
    created_by: uuid.UUID | None
    created_at: datetime
