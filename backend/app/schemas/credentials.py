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
]


class CredentialCreate(BaseModel):
    """Body of ``POST /credentials``.

    ``params`` is non-secret protocol metadata only (e.g. SNMPv3 protocol
    names) — it is persisted and audited verbatim, so never put key material
    in it; the secret belongs in ``secret`` exclusively.
    """

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    name: str = Field(min_length=1, max_length=255)
    kind: CredentialKind
    username: str | None = Field(default=None, max_length=255)
    secret: SecretStr = Field(min_length=1)
    params: dict[str, Any] | None = None


class CredentialRotate(BaseModel):
    """Body of ``POST /credentials/{id}/rotate`` — the replacement secret."""

    model_config = ConfigDict(extra="forbid")

    secret: SecretStr = Field(min_length=1)


class CredentialRead(BaseModel):
    """Credential metadata — never any secret-bearing field."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    kind: CredentialKind
    username: str | None
    params: dict[str, Any] | None
    kek_version: str
    created_at: datetime
    updated_at: datetime


class CredentialListResponse(BaseModel):
    """Paginated credential collection (``GET /credentials``)."""

    items: list[CredentialRead]
    total: int
    limit: int
    offset: int
