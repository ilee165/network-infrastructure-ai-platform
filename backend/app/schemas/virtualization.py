"""Virtualization (VMware) inventory API contracts (W1-T3): read-only, no write path.

Mirrors :mod:`app.schemas.devices`: read models map straight off the
``Normalized*Row`` ORM rows in :mod:`app.models.virtualization` via
``from_attributes``. Nested ``nics``/``pnics`` are JSON lists of plain dicts;
Pydantic converts each dict into :class:`VirtualNicRead`/:class:`PhysicalNicRead`
the same way ``from_attributes`` converts scalar columns.

Port groups store the optional natural-key columns (``datacenter``,
``host_name``, ``moref``) as the ``''`` sentinel at the DB layer (NULL would
silently disable the unique constraint — see ``app.models.inventory`` module
docstring); :func:`_empty_to_none` maps ``''`` back to ``None`` on the read
side, the same pattern as ``DeviceNeighborRead.neighbor_interface``.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated

from pydantic import BaseModel, BeforeValidator, ConfigDict

from app.schemas.normalized import HostConnectionState, VirtualSwitchType, VmPowerState

__all__ = [
    "ComputeClusterListResponse",
    "ComputeClusterRead",
    "HypervisorHostListResponse",
    "HypervisorHostRead",
    "PhysicalNicRead",
    "PortGroupListResponse",
    "PortGroupRead",
    "VirtualMachineListResponse",
    "VirtualMachineRead",
    "VirtualNicRead",
]


def _empty_to_none(value: object) -> object:
    """Map the ``''`` natural-key sentinel back to ``None`` (read direction)."""
    return None if value == "" else value


EmptyToNone = Annotated[str | None, BeforeValidator(_empty_to_none)]


class VirtualNicRead(BaseModel):
    """One VM vNIC, nested inside :class:`VirtualMachineRead` (ADR-0051 §5.3)."""

    model_config = ConfigDict(from_attributes=True)

    label: str
    mac_address: str
    port_group_name: str | None
    switch_type: VirtualSwitchType | None
    connected: bool
    ip_addresses: list[str]


class VirtualMachineRead(BaseModel):
    """One virtual machine (``GET /virtualization/vms[/{id}]``)."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    device_id: uuid.UUID
    name: str
    moref: str
    instance_uuid: str | None
    is_template: bool
    power_state: VmPowerState
    guest_hostname: str | None
    guest_ip_addresses: list[str]
    host_name: str | None
    cluster_name: str | None
    datacenter: str | None
    nics: list[VirtualNicRead]
    description: str | None
    collected_at: datetime
    source_vendor: str


class VirtualMachineListResponse(BaseModel):
    """Paginated VM collection (``GET /virtualization/vms``)."""

    items: list[VirtualMachineRead]
    total: int
    limit: int
    offset: int


class PhysicalNicRead(BaseModel):
    """One host pNIC, nested inside :class:`HypervisorHostRead` (ADR-0051 §5.3)."""

    model_config = ConfigDict(from_attributes=True)

    name: str
    mac_address: str
    link_speed_mbps: int | None


class HypervisorHostRead(BaseModel):
    """One hypervisor host (``GET /virtualization/hosts[/{id}]``)."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    device_id: uuid.UUID
    name: str
    moref: str
    cluster_name: str | None
    datacenter: str | None
    vendor: str | None
    model: str | None
    hypervisor_version: str | None
    connection_state: HostConnectionState
    in_maintenance_mode: bool
    management_ip: str | None
    pnics: list[PhysicalNicRead]
    collected_at: datetime
    source_vendor: str


class HypervisorHostListResponse(BaseModel):
    """Paginated host collection (``GET /virtualization/hosts``)."""

    items: list[HypervisorHostRead]
    total: int
    limit: int
    offset: int


class ComputeClusterRead(BaseModel):
    """One compute cluster (``GET /virtualization/clusters[/{id}]``)."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    device_id: uuid.UUID
    name: str
    moref: str
    datacenter: str | None
    drs_enabled: bool | None
    ha_enabled: bool | None
    collected_at: datetime
    source_vendor: str


class ComputeClusterListResponse(BaseModel):
    """Paginated cluster collection (``GET /virtualization/clusters``)."""

    items: list[ComputeClusterRead]
    total: int
    limit: int
    offset: int


class PortGroupRead(BaseModel):
    """One port group (``GET /virtualization/port-groups[/{id}]``).

    ``datacenter``/``host_name``/``moref`` map the ``''`` sentinel back to
    ``None`` (standard port groups have no ``moref``; distributed port groups
    have no ``host_name``).
    """

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    device_id: uuid.UUID
    name: str
    switch_name: str
    switch_type: VirtualSwitchType
    datacenter: EmptyToNone
    host_name: EmptyToNone
    vlan_id: int | None
    moref: EmptyToNone
    uplink_pnic_names: list[str]
    collected_at: datetime
    source_vendor: str


class PortGroupListResponse(BaseModel):
    """Paginated port-group collection (``GET /virtualization/port-groups``)."""

    items: list[PortGroupRead]
    total: int
    limit: int
    offset: int
