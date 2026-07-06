"""Virtualization (VMware) inventory rows: VM/host/cluster/port-group (ADR-0051 §5, W1-T3).

Relational projections of the Pydantic models in :mod:`app.schemas.normalized`
(:class:`~app.schemas.normalized.NormalizedVirtualMachine` /
:class:`~app.schemas.normalized.NormalizedHypervisorHost` /
:class:`~app.schemas.normalized.NormalizedComputeCluster` /
:class:`~app.schemas.normalized.NormalizedPortGroup`), mirroring the
``Normalized*Row`` pattern in :mod:`app.models.inventory` field-for-field.
VMs/hosts/clusters/port-groups are flat top-level collections joined by name
(ADR-0051 §5.5/§5.6) — no nesting between them; only their own vNICs/pNICs
nest (as JSON, the ``NormalizedPoolRow.members`` precedent, ADR-0050 §4.5).

Identity keys per ADR-0051 §5.5: VMs/hosts/clusters key on
``(device_id, moref)``. Port groups are trickier — distributed groups key on
``(device_id, moref)``, standard groups (no moref) key on
``(device_id, datacenter, host_name, name)`` — so the unique constraint spans
all four optional-key columns with the inventory module's ``''``-sentinel
convention (NULL would silently disable the constraint, see
``app.models.inventory`` module docstring): ``moref``/``datacenter``/
``host_name`` are NOT NULL with ``''`` meaning "absent".

Read-only surfacing (W1-T3): see the module docstring in
:mod:`app.models.adc` for the same named deferral (no upsert/collection
pipeline yet — ``VIRTUALIZATION_INVENTORY`` is a pyVmomi capability, not
SSH/SNMP-collectible by the existing ``collect_device`` dispatch).
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base
from app.models.inventory import _ProvenanceMixin, _wire_enum
from app.models.mixins import JSON_VARIANT, TimestampMixin, UuidPkMixin
from app.schemas.normalized import HostConnectionState, VirtualSwitchType, VmPowerState

__all__ = [
    "NormalizedComputeClusterRow",
    "NormalizedHypervisorHostRow",
    "NormalizedPortGroupRow",
    "NormalizedVirtualMachineRow",
]


class NormalizedVirtualMachineRow(UuidPkMixin, TimestampMixin, _ProvenanceMixin, Base):
    """Relational projection of :class:`app.schemas.normalized.NormalizedVirtualMachine`.

    ``nics`` is the JSON-encoded ``tuple[NormalizedVirtualNic, ...]`` (dicts
    with ``label``/``mac_address``/``port_group_name``/``switch_type``/
    ``connected``/``ip_addresses`` keys).
    """

    __tablename__ = "virt_machines"
    __table_args__ = (UniqueConstraint("device_id", "moref"),)

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    moref: Mapped[str] = mapped_column(String(64), nullable=False)
    instance_uuid: Mapped[str | None] = mapped_column(String(64))
    is_template: Mapped[bool] = mapped_column(nullable=False)
    power_state: Mapped[VmPowerState] = mapped_column(_wire_enum(VmPowerState), nullable=False)
    guest_hostname: Mapped[str | None] = mapped_column(String(255))
    guest_ip_addresses: Mapped[list[str]] = mapped_column(
        JSON_VARIANT, nullable=False, default=list
    )
    host_name: Mapped[str | None] = mapped_column(String(255))
    cluster_name: Mapped[str | None] = mapped_column(String(255))
    datacenter: Mapped[str | None] = mapped_column(String(255))
    nics: Mapped[list[dict[str, Any]]] = mapped_column(JSON_VARIANT, nullable=False, default=list)
    description: Mapped[str | None] = mapped_column(String(1024))


class NormalizedHypervisorHostRow(UuidPkMixin, TimestampMixin, _ProvenanceMixin, Base):
    """Relational projection of :class:`app.schemas.normalized.NormalizedHypervisorHost`.

    ``pnics`` is the JSON-encoded ``tuple[NormalizedPhysicalNic, ...]`` (dicts
    with ``name``/``mac_address``/``link_speed_mbps`` keys).
    """

    __tablename__ = "virt_hosts"
    __table_args__ = (UniqueConstraint("device_id", "moref"),)

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    moref: Mapped[str] = mapped_column(String(64), nullable=False)
    cluster_name: Mapped[str | None] = mapped_column(String(255))
    datacenter: Mapped[str | None] = mapped_column(String(255))
    vendor: Mapped[str | None] = mapped_column(String(128))
    model: Mapped[str | None] = mapped_column(String(128))
    hypervisor_version: Mapped[str | None] = mapped_column(String(255))
    connection_state: Mapped[HostConnectionState] = mapped_column(
        _wire_enum(HostConnectionState), nullable=False
    )
    in_maintenance_mode: Mapped[bool] = mapped_column(nullable=False)
    management_ip: Mapped[str | None] = mapped_column(String(64))
    pnics: Mapped[list[dict[str, Any]]] = mapped_column(JSON_VARIANT, nullable=False, default=list)


class NormalizedComputeClusterRow(UuidPkMixin, TimestampMixin, _ProvenanceMixin, Base):
    """Relational projection of :class:`app.schemas.normalized.NormalizedComputeCluster`."""

    __tablename__ = "virt_clusters"
    __table_args__ = (UniqueConstraint("device_id", "moref"),)

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    moref: Mapped[str] = mapped_column(String(64), nullable=False)
    datacenter: Mapped[str | None] = mapped_column(String(255))
    drs_enabled: Mapped[bool | None]
    ha_enabled: Mapped[bool | None]


class NormalizedPortGroupRow(UuidPkMixin, TimestampMixin, _ProvenanceMixin, Base):
    """Relational projection of :class:`app.schemas.normalized.NormalizedPortGroup`.

    ``moref``/``datacenter``/``host_name`` are NOT NULL with the ``''``
    sentinel for "absent" (see module docstring) so the natural-key unique
    constraint stays effective for both standard and distributed groups.
    """

    __tablename__ = "virt_port_groups"
    __table_args__ = (UniqueConstraint("device_id", "moref", "datacenter", "host_name", "name"),)

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    switch_name: Mapped[str] = mapped_column(String(255), nullable=False)
    switch_type: Mapped[VirtualSwitchType] = mapped_column(
        _wire_enum(VirtualSwitchType), nullable=False
    )
    datacenter: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    host_name: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    vlan_id: Mapped[int | None]
    moref: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    uplink_pnic_names: Mapped[list[str]] = mapped_column(JSON_VARIANT, nullable=False, default=list)
