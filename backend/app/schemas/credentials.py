"""Credential API contracts (M1-15): the secret is strictly write-only.

``CredentialCreate``/``CredentialRotate`` carry the secret as a
:class:`~pydantic.SecretStr` so accidental ``repr``/logging shows ``'**********'``.
``CredentialRead`` exposes metadata only — id, name, kind, username, params,
kek_version, timestamps. There is deliberately no model that can serialize a
secret back out (ADR-0011: plaintext never leaves the vault boundary).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, SecretStr

from app.models.inventory import CredentialKind

__all__ = [
    "CredentialCreate",
    "CredentialListResponse",
    "CredentialRead",
    "CredentialRotate",
    "RotationStatusResponse",
]


class CredentialCreate(BaseModel):
    """Body of ``POST /credentials``.

    ``params`` is non-secret protocol metadata only (e.g. SNMPv3 protocol
    names) — it is persisted and audited verbatim, so never put key material
    in it; the secret belongs in ``secret`` exclusively.

    The three ``scope_*`` fields bind the credential to a least-privilege slice of
    the inventory (ADR-0040 §2 / ADR-0011). A NULL (omitted) dimension means
    "matches any"; a credential with all three NULL is UNSCOPED — it covers every
    device (the backward-compatible default for callers that omit scope). A SET
    dimension restricts the credential to devices whose corresponding attribute
    (``site`` / ``role`` / ``device_group``) equals it; the credentials service
    refuses, structurally, to open a session on a device the scope does not cover.
    NULL is therefore explicitly "unscoped/broad", NOT "deny" — least-privilege is
    OPT-IN here; an operator narrows a credential by setting one or more dimensions.
    """

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    name: str = Field(min_length=1, max_length=255)
    kind: CredentialKind
    username: str | None = Field(default=None, max_length=255)
    secret: SecretStr = Field(min_length=1)
    params: dict[str, Any] | None = None
    scope_site: str | None = Field(default=None, max_length=128)
    scope_role: str | None = Field(default=None, max_length=128)
    scope_device_group: str | None = Field(default=None, max_length=128)


class CredentialRotate(BaseModel):
    """Body of ``POST /credentials/{id}/rotate`` — the replacement secret."""

    model_config = ConfigDict(extra="forbid")

    secret: SecretStr = Field(min_length=1)


class CredentialRead(BaseModel):
    """Credential metadata — never any secret-bearing field.

    The ``scope_*`` fields expose the credential's least-privilege scope (ADR-0040
    §2); they are non-secret labels (NULL = unscoped/broad). No secret-bearing
    column is ever surfaced.
    """

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    kind: CredentialKind
    username: str | None
    params: dict[str, Any] | None
    scope_site: str | None
    scope_role: str | None
    scope_device_group: str | None
    kek_version: str
    disabled_at: datetime | None = None
    created_at: datetime
    updated_at: datetime


class CredentialListResponse(BaseModel):
    """Paginated credential collection (``GET /credentials``)."""

    items: list[CredentialRead]
    total: int
    limit: int
    offset: int


class RotationStatusResponse(BaseModel):
    """Master-key (KEK) rotation status — versions/counts only (ADR-0032 §6).

    Deliberately carries **no** blob: ``from_version`` is the oldest KEK version
    still referenced by an un-migrated credential (``None`` once the corpus is
    fully migrated to the active KEK), ``to_version`` is the active KEK, and
    ``rows_pending`` is how many credentials still await re-wrap. There is no
    field exposing ``wrapped_dek`` or a per-row ``kek_version``.
    """

    model_config = ConfigDict(from_attributes=True)

    from_version: str | None
    to_version: str
    rows_pending: int
