"""Read-only persistence and knowledge access for specialist agents."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Any
from uuid import UUID

if TYPE_CHECKING:
    from app.models import Device, NormalizedNeighborRow, NormalizedRouteRow


class UnknownDeviceStatus(ValueError):
    """A requested inventory status is not one of the persisted wire values."""

    def __init__(self, status: str, valid_values: tuple[str, ...]) -> None:
        self.status = status
        self.valid_values = valid_values
        super().__init__(f"unknown status {status!r}; valid values: {list(valid_values)}")


@dataclass(frozen=True, slots=True)
class DeviceSnapshot:
    """Immutable plain-data projection of an inventory device."""

    id: UUID
    hostname: str
    mgmt_ip: str
    vendor_id: str | None
    model: str | None
    os_version: str | None
    serial: str | None
    status: str
    site: str | None
    role: str | None
    device_group: str | None
    credential_id: UUID | None
    last_discovered_at: datetime | None
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True, slots=True)
class NeighborSnapshot:
    """Immutable plain-data projection of a normalized neighbor row."""

    id: UUID
    protocol: str
    local_interface: str
    neighbor_name: str
    neighbor_interface: str
    neighbor_platform: str | None
    neighbor_address: str | None
    neighbor_capabilities: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class RouteSnapshot:
    """Immutable plain-data projection of a normalized route row."""

    id: UUID
    prefix: str
    protocol: str
    next_hop: str
    interface: str
    vrf: str
    distance: int | None
    metric: int | None


@dataclass(frozen=True, slots=True)
class LiveReadTarget:
    """Non-secret inventory facts needed before audited credential access."""

    id: UUID
    host: str
    vendor_id: str | None
    credential_id: UUID | None


def _device_snapshot(row: Device) -> DeviceSnapshot:
    return DeviceSnapshot(
        id=row.id,
        hostname=row.hostname,
        mgmt_ip=row.mgmt_ip,
        vendor_id=row.vendor_id,
        model=row.model,
        os_version=row.os_version,
        serial=row.serial,
        status=row.status.value,
        site=row.site,
        role=row.role,
        device_group=row.device_group,
        credential_id=row.credential_id,
        last_discovered_at=row.last_discovered_at,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


def _neighbor_snapshot(row: NormalizedNeighborRow) -> NeighborSnapshot:
    return NeighborSnapshot(
        id=row.id,
        protocol=row.protocol.value,
        local_interface=row.local_interface,
        neighbor_name=row.neighbor_name,
        neighbor_interface=row.neighbor_interface,
        neighbor_platform=row.neighbor_platform,
        neighbor_address=row.neighbor_address,
        neighbor_capabilities=tuple(row.neighbor_capabilities),
    )


def _route_snapshot(row: NormalizedRouteRow) -> RouteSnapshot:
    return RouteSnapshot(
        id=row.id,
        prefix=row.prefix,
        protocol=row.protocol.value,
        next_hop=row.next_hop,
        interface=row.interface,
        vrf=row.vrf,
        distance=row.distance,
        metric=row.metric,
    )


async def list_devices(
    *,
    status_filter: str | None,
    vendor_id: str | None,
    limit: int,
    offset: int,
) -> tuple[int, list[DeviceSnapshot]]:
    """Return an immutable inventory page or raise a typed filter error."""
    from sqlalchemy import Select, func, select

    import app.db as db
    from app.models import Device, DeviceStatus

    async with db.get_sessionmaker()() as session:
        query: Select[tuple[Device]] = select(Device)
        if status_filter is not None:
            try:
                status = DeviceStatus(status_filter)
            except ValueError as exc:
                valid_values = tuple(candidate.value for candidate in DeviceStatus)
                raise UnknownDeviceStatus(status_filter, valid_values) from exc
            query = query.where(Device.status == status)
        if vendor_id is not None:
            query = query.where(Device.vendor_id == vendor_id)
        count_query = select(func.count()).select_from(query.subquery())
        total = (await session.execute(count_query)).scalar_one()
        rows = list(
            (
                await session.execute(
                    query.order_by(Device.hostname, Device.id).limit(limit).offset(offset)
                )
            )
            .scalars()
            .all()
        )
        snapshots = [_device_snapshot(row) for row in rows]
    return total, snapshots


async def get_device(device_id: UUID) -> DeviceSnapshot | None:
    """Return one inventory device without mutating it."""
    import app.db as db
    from app.models import Device

    async with db.get_sessionmaker()() as session:
        row = await session.get(Device, device_id)
        return _device_snapshot(row) if row is not None else None


async def list_neighbors(
    device_id: UUID,
) -> tuple[DeviceSnapshot | None, list[NeighborSnapshot]]:
    """Return a device and its normalized neighbors."""
    from sqlalchemy import select

    import app.db as db
    from app.models import Device, NormalizedNeighborRow

    async with db.get_sessionmaker()() as session:
        device = await session.get(Device, device_id)
        if device is None:
            return None, []
        rows = list(
            (
                await session.execute(
                    select(NormalizedNeighborRow)
                    .where(NormalizedNeighborRow.device_id == device_id)
                    .order_by(
                        NormalizedNeighborRow.local_interface,
                        NormalizedNeighborRow.neighbor_name,
                    )
                )
            )
            .scalars()
            .all()
        )
        device_snapshot = _device_snapshot(device)
        neighbor_snapshots = [_neighbor_snapshot(row) for row in rows]
    return device_snapshot, neighbor_snapshots


async def list_routes(device_id: UUID, *, prefix: str | None) -> list[RouteSnapshot]:
    """Return normalized routes for one device."""
    from sqlalchemy import select

    import app.db as db
    from app.models import NormalizedRouteRow

    async with db.get_sessionmaker()() as session:
        query = select(NormalizedRouteRow).where(NormalizedRouteRow.device_id == device_id)
        if prefix is not None:
            query = query.where(NormalizedRouteRow.prefix == prefix)
        rows = list(
            (await session.execute(query.order_by(NormalizedRouteRow.prefix))).scalars().all()
        )
        snapshots = [_route_snapshot(row) for row in rows]
    return snapshots


async def get_live_read_target(device_id: UUID) -> LiveReadTarget | None:
    """Return the non-secret inventory projection used for capability selection."""
    device = await get_device(device_id)
    if device is None:
        return None
    return LiveReadTarget(
        id=device.id,
        host=device.mgmt_ip,
        vendor_id=device.vendor_id,
        credential_id=device.credential_id,
    )


def knowledge_client() -> Any:
    """Return the process-wide graph read client."""
    from app.knowledge import get_client

    return get_client()


async def application_impact(client: Any, *, kind: str, ref: str, depth: int) -> dict[str, Any]:
    """Read application impact for a validated target kind and reference."""
    from app.knowledge.schema import (
        LABEL_APPLICATION,
        LABEL_DEVICE,
        LABEL_INTERFACE,
        LABEL_IPADDRESS,
        LABEL_SUBNET,
    )
    from app.knowledge.topology_read import fetch_impact

    labels = {
        "device": LABEL_DEVICE,
        "ip_address": LABEL_IPADDRESS,
        "interface": LABEL_INTERFACE,
        "subnet": LABEL_SUBNET,
        "application": LABEL_APPLICATION,
    }
    return await fetch_impact(
        client,
        target_label=labels[kind],
        target_key=ref,
        depth=depth,
    )


APPLICATION_IMPACT_KINDS = frozenset({"device", "ip_address", "interface", "subnet", "application"})
