"""Device API contracts (M1-15): request/response models for ``/api/v1/devices``.

Pure data (D2): validation only, no I/O. ``mgmt_ip`` is canonicalized through
:mod:`ipaddress` so ``192.000.2.1``-style spellings cannot create duplicate
inventory rows. Read models mirror the ORM rows via ``from_attributes``; the
``''`` natural-key sentinel of normalized rows (see
:mod:`app.models.inventory`) maps back to ``None`` on the API surface.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from ipaddress import ip_address
from typing import Annotated

from pydantic import BaseModel, BeforeValidator, ConfigDict, Field

from app.models.inventory import DeviceStatus
from app.schemas.normalized import (
    InterfaceAdminStatus,
    InterfaceDuplex,
    InterfaceOperStatus,
    NeighborProtocol,
)

__all__ = [
    "DeviceCreate",
    "DeviceInterfaceRead",
    "DeviceListResponse",
    "DeviceNeighborRead",
    "DeviceRead",
    "DeviceUpdate",
]


def _canonical_ip(value: str) -> str:
    """Validate and canonicalize an IPv4/IPv6 management address."""
    return str(ip_address(value))


MgmtIp = Annotated[str, BeforeValidator(_canonical_ip)]
"""A management IP, canonicalized (``ValueError`` → 422 on bad input)."""


def _empty_to_none(value: object) -> object:
    """Map the ``''`` natural-key sentinel back to ``None`` (read direction)."""
    return None if value == "" else value


class DeviceCreate(BaseModel):
    """Body of ``POST /devices``."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    hostname: str = Field(min_length=1, max_length=255)
    mgmt_ip: MgmtIp
    vendor_id: str | None = Field(default=None, max_length=64)
    model: str | None = Field(default=None, max_length=128)
    os_version: str | None = Field(default=None, max_length=128)
    serial: str | None = Field(default=None, max_length=128)
    status: DeviceStatus = DeviceStatus.NEW
    credential_id: uuid.UUID | None = None


class DeviceUpdate(BaseModel):
    """Body of ``PATCH /devices/{id}`` — every field optional, unset = unchanged."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    hostname: str | None = Field(default=None, min_length=1, max_length=255)
    mgmt_ip: MgmtIp | None = None
    vendor_id: str | None = Field(default=None, max_length=64)
    model: str | None = Field(default=None, max_length=128)
    os_version: str | None = Field(default=None, max_length=128)
    serial: str | None = Field(default=None, max_length=128)
    status: DeviceStatus | None = None
    credential_id: uuid.UUID | None = None


class DeviceRead(BaseModel):
    """One inventory device as returned by every device endpoint."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    hostname: str
    mgmt_ip: str
    vendor_id: str | None
    model: str | None
    os_version: str | None
    serial: str | None
    status: DeviceStatus
    credential_id: uuid.UUID | None
    last_discovered_at: datetime | None
    created_at: datetime
    updated_at: datetime


class DeviceListResponse(BaseModel):
    """Paginated device collection (``GET /devices``)."""

    items: list[DeviceRead]
    total: int
    limit: int
    offset: int


class DeviceInterfaceRead(BaseModel):
    """One normalized interface (``GET /devices/{id}/interfaces``)."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    description: str | None
    admin_status: InterfaceAdminStatus
    oper_status: InterfaceOperStatus
    mac_address: str | None
    ip_address: str | None
    mtu: int | None
    speed_mbps: int | None
    duplex: InterfaceDuplex | None
    vlan_id: int | None
    input_errors: int | None
    output_errors: int | None
    collected_at: datetime
    source_vendor: str


class DeviceNeighborRead(BaseModel):
    """One normalized LLDP/CDP neighbor (``GET /devices/{id}/neighbors``)."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    protocol: NeighborProtocol
    local_interface: str
    neighbor_name: str
    neighbor_interface: Annotated[str | None, BeforeValidator(_empty_to_none)]
    neighbor_platform: str | None
    neighbor_address: str | None
    neighbor_capabilities: list[str]
    collected_at: datetime
    source_vendor: str
