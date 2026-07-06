"""ADC (F5 BIG-IP) inventory API contracts (W1-T3): read-only, no write path.

Mirrors :mod:`app.schemas.devices`: read models map straight off the
``Normalized*Row`` ORM rows in :mod:`app.models.adc` via ``from_attributes``.
``NormalizedPoolRow.members`` is a JSON list of plain dicts; Pydantic converts
each dict into :class:`PoolMemberRead` the same way ``from_attributes``
converts scalar columns — no extra glue needed.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict

from app.schemas.normalized import AdcAdminState, AdcAvailability, AdcProtocol

__all__ = [
    "PoolListResponse",
    "PoolMemberRead",
    "PoolRead",
    "VirtualServerListResponse",
    "VirtualServerRead",
]


class VirtualServerRead(BaseModel):
    """One ADC virtual server (``GET /adc/virtual-servers[/{id}]``)."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    device_id: uuid.UUID
    name: str
    vip_address: str | None
    port: int | None
    protocol: AdcProtocol
    vrf: str | None
    enabled: bool
    availability: AdcAvailability
    pool_name: str | None
    description: str | None
    collected_at: datetime
    source_vendor: str


class VirtualServerListResponse(BaseModel):
    """Paginated virtual-server collection (``GET /adc/virtual-servers``)."""

    items: list[VirtualServerRead]
    total: int
    limit: int
    offset: int


class PoolMemberRead(BaseModel):
    """One pool member, nested inside :class:`PoolRead` (ADR-0050 §4.3/§4.5)."""

    model_config = ConfigDict(from_attributes=True)

    name: str
    address: str | None
    fqdn: str | None
    port: int
    vrf: str | None
    admin_state: AdcAdminState
    availability: AdcAvailability


class PoolRead(BaseModel):
    """One ADC pool with nested members (``GET /adc/pools[/{id}]``)."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    device_id: uuid.UUID
    name: str
    monitors: list[str]
    availability: AdcAvailability
    members: list[PoolMemberRead]
    description: str | None
    collected_at: datetime
    source_vendor: str


class PoolListResponse(BaseModel):
    """Paginated pool collection (``GET /adc/pools``)."""

    items: list[PoolRead]
    total: int
    limit: int
    offset: int
