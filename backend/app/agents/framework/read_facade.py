"""Read-only persistence and knowledge access for specialist agents."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from uuid import UUID


@dataclass(frozen=True, slots=True)
class LiveReadTarget:
    """Non-secret inventory facts needed before audited credential access."""

    id: UUID
    host: str
    vendor_id: str | None
    credential_id: UUID | None


async def list_devices(
    *,
    status_filter: str | None,
    vendor_id: str | None,
    limit: int,
    offset: int,
) -> tuple[int, list[Any]] | list[str]:
    """Return an inventory page, or valid status values for an invalid filter."""
    from sqlalchemy import Select, func, select

    import app.db as db
    from app.models import Device, DeviceStatus

    async with db.get_sessionmaker()() as session:
        query: Select[tuple[Device]] = select(Device)
        if status_filter is not None:
            try:
                status = DeviceStatus(status_filter)
            except ValueError:
                return [candidate.value for candidate in DeviceStatus]
            query = query.where(Device.status == status)
        if vendor_id is not None:
            query = query.where(Device.vendor_id == vendor_id)
        count_query = select(func.count()).select_from(query.subquery())
        total = (await session.execute(count_query)).scalar_one()
        rows = (
            (
                await session.execute(
                    query.order_by(Device.hostname, Device.id).limit(limit).offset(offset)
                )
            )
            .scalars()
            .all()
        )
    return total, list(rows)


async def get_device(device_id: UUID) -> Any | None:
    """Return one inventory device without mutating it."""
    import app.db as db
    from app.models import Device

    async with db.get_sessionmaker()() as session:
        return await session.get(Device, device_id)


async def list_neighbors(device_id: UUID) -> tuple[Any | None, list[Any]]:
    """Return a device and its normalized neighbors."""
    from sqlalchemy import select

    import app.db as db
    from app.models import Device, NormalizedNeighborRow

    async with db.get_sessionmaker()() as session:
        device = await session.get(Device, device_id)
        if device is None:
            return None, []
        rows = (
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
    return device, list(rows)


async def list_routes(device_id: UUID, *, prefix: str | None) -> list[Any]:
    """Return normalized routes for one device."""
    from sqlalchemy import select

    import app.db as db
    from app.models import NormalizedRouteRow

    async with db.get_sessionmaker()() as session:
        query = select(NormalizedRouteRow).where(NormalizedRouteRow.device_id == device_id)
        if prefix is not None:
            query = query.where(NormalizedRouteRow.prefix == prefix)
        rows = (await session.execute(query.order_by(NormalizedRouteRow.prefix))).scalars().all()
    return list(rows)


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
