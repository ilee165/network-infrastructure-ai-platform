"""Discovery persistence: raw artifacts + idempotent normalized upserts (M1-13).

Takes one :class:`~app.engines.discovery.engine.DeviceCollectionResult` and
writes it down in evidence-first order (D11):

1. the device row is upserted by its natural key ``mgmt_ip`` (status
   transitions to ``reachable`` — this function is only called after a
   successful collection),
2. one append-only :class:`~app.models.RawArtifact` is stored per executed
   command (verbatim output, never rewritten),
3. normalized rows are upserted under their natural-key unique constraints,
   each carrying the ``raw_artifact_id`` of the artifact whose command
   produced it.

PORTABILITY DECISION (fixed): upserts are select-by-natural-key then
update-or-insert in Python — no dialect-specific ``ON CONFLICT`` — so the
same code runs on aiosqlite in unit tests and PostgreSQL in production;
volumes are modest at MVP. Optional natural-key components map Pydantic
``None`` → ``''`` sentinel (see :mod:`app.models.inventory` docstring).
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any
from uuid import UUID

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.engines.discovery.engine import DeviceCollectionResult
from app.models import (
    Device,
    DeviceStatus,
    DiscoveryRun,
    NormalizedInterfaceRow,
    NormalizedNeighborRow,
    NormalizedRouteRow,
    RawArtifact,
)
from app.models.base import Base
from app.models.mixins import utcnow
from app.schemas.discovery import DeviceFacts
from app.schemas.normalized import (
    NeighborProtocol,
    NormalizedInterface,
    NormalizedNeighbor,
    NormalizedRoute,
)

__all__ = [
    "UpsertCounts",
    "persist_device_result",
    "store_artifact",
    "upsert_device",
    "upsert_interfaces",
    "upsert_neighbors",
    "upsert_routes",
]

logger = structlog.get_logger(__name__)

UpsertCounts = dict[str, int]
"""``{"inserted": n, "updated": m}`` for one upsert pass."""


async def store_artifact(
    session: AsyncSession,
    *,
    device_id: UUID,
    run_id: UUID | None,
    command: str,
    raw_text: str,
    parsed: dict[str, Any] | list[dict[str, Any]] | None = None,
) -> RawArtifact:
    """Append one verbatim command output as evidence (never updated)."""
    artifact = RawArtifact(
        device_id=device_id,
        run_id=run_id,
        command=command,
        raw_text=raw_text,
        parsed=parsed,
    )
    session.add(artifact)
    await session.flush()
    return artifact


async def upsert_device(
    session: AsyncSession,
    *,
    facts: DeviceFacts,
    mgmt_ip: str,
    credential_id: UUID | None,
) -> Device:
    """Insert or update the device identified by natural key ``mgmt_ip``.

    Called only after a successful collection, so the status transitions to
    ``reachable`` (``new`` → ``reachable`` on first contact) and
    ``last_discovered_at`` is stamped.
    """
    device = (
        await session.execute(select(Device).where(Device.mgmt_ip == mgmt_ip))
    ).scalar_one_or_none()
    if device is None:
        device = Device(mgmt_ip=mgmt_ip, hostname=facts.hostname)
        session.add(device)
    device.hostname = facts.hostname
    device.vendor_id = facts.vendor_id
    device.model = facts.model
    device.os_version = facts.os_version
    device.serial = facts.serial
    device.status = DeviceStatus.REACHABLE
    device.credential_id = credential_id
    device.last_discovered_at = utcnow()
    await session.flush()
    return device


# ---------------------------------------------------------------------------
# Normalized upserts (select-by-natural-key, then update-or-insert)
# ---------------------------------------------------------------------------


async def _upsert_rows(
    session: AsyncSession,
    orm_cls: type[Base],
    device: Device,
    key_fields: tuple[str, ...],
    items: dict[tuple[Any, ...], dict[str, Any]],
) -> UpsertCounts:
    """Generic natural-key upsert: one SELECT per pass, then per-row merge.

    ``items`` maps the natural-key tuple (excluding ``device_id``) to the
    non-key column values; duplicate keys in the input were already collapsed
    (last one wins) so a single pass can never violate the unique constraint.
    """
    existing_rows = (
        await session.execute(select(orm_cls).where(orm_cls.device_id == device.id))  # type: ignore[attr-defined]
    ).scalars()
    existing = {tuple(getattr(row, field) for field in key_fields): row for row in existing_rows}

    counts: UpsertCounts = {"inserted": 0, "updated": 0}
    for key, values in items.items():
        row = existing.get(key)
        if row is None:
            key_values = dict(zip(key_fields, key, strict=True))
            session.add(orm_cls(device_id=device.id, **key_values, **values))
            counts["inserted"] += 1
        else:
            for column, value in values.items():
                setattr(row, column, value)
            counts["updated"] += 1
    await session.flush()
    return counts


def _provenance(
    record: NormalizedInterface | NormalizedRoute | NormalizedNeighbor,
    raw_artifact_id: UUID,
) -> dict[str, Any]:
    return {
        "raw_artifact_id": raw_artifact_id,
        "collected_at": record.collected_at,
        "source_vendor": record.source_vendor,
    }


async def upsert_interfaces(
    session: AsyncSession,
    device: Device,
    rows: Sequence[NormalizedInterface],
    raw_artifact_id: UUID,
) -> UpsertCounts:
    """Upsert interfaces under natural key ``(device_id, name)``."""
    items: dict[tuple[Any, ...], dict[str, Any]] = {}
    for row in rows:
        items[(row.name,)] = {
            **_provenance(row, raw_artifact_id),
            "description": row.description,
            "admin_status": row.admin_status,
            "oper_status": row.oper_status,
            "mac_address": row.mac_address,
            "ip_address": str(row.ip_address) if row.ip_address is not None else None,
            "mtu": row.mtu,
            "speed_mbps": row.speed_mbps,
            "duplex": row.duplex,
            "vlan_id": row.vlan_id,
            "input_errors": row.input_errors,
            "output_errors": row.output_errors,
        }
    return await _upsert_rows(session, NormalizedInterfaceRow, device, ("name",), items)


async def upsert_routes(
    session: AsyncSession,
    device: Device,
    rows: Sequence[NormalizedRoute],
    raw_artifact_id: UUID,
) -> UpsertCounts:
    """Upsert routes under ``(device_id, vrf, prefix, protocol, next_hop, interface)``.

    Optional key parts (``vrf``/``next_hop``/``interface``) map ``None`` →
    ``''`` so the unique constraint stays effective (NULLS DISTINCT).
    """
    items: dict[tuple[Any, ...], dict[str, Any]] = {}
    for row in rows:
        key = (
            row.vrf or "",
            str(row.destination),
            row.protocol,
            str(row.next_hop) if row.next_hop is not None else "",
            row.interface or "",
        )
        items[key] = {
            **_provenance(row, raw_artifact_id),
            "distance": row.distance,
            "metric": row.metric,
        }
    return await _upsert_rows(
        session,
        NormalizedRouteRow,
        device,
        ("vrf", "prefix", "protocol", "next_hop", "interface"),
        items,
    )


async def upsert_neighbors(
    session: AsyncSession,
    device: Device,
    rows: Sequence[NormalizedNeighbor],
    raw_artifact_id: UUID,
) -> UpsertCounts:
    """Upsert neighbors under their protocol/interface/name natural key.

    ``neighbor_interface`` maps ``None`` → ``''`` (sentinel, see module
    docstring).
    """
    items: dict[tuple[Any, ...], dict[str, Any]] = {}
    for row in rows:
        key = (
            row.protocol,
            row.local_interface,
            row.neighbor_name,
            row.neighbor_interface or "",
        )
        items[key] = {
            **_provenance(row, raw_artifact_id),
            "neighbor_platform": row.neighbor_platform,
            "neighbor_address": (
                str(row.neighbor_address) if row.neighbor_address is not None else None
            ),
            "neighbor_capabilities": list(row.neighbor_capabilities),
        }
    return await _upsert_rows(
        session,
        NormalizedNeighborRow,
        device,
        ("protocol", "local_interface", "neighbor_name", "neighbor_interface"),
        items,
    )


# ---------------------------------------------------------------------------
# One-device persistence entry point
# ---------------------------------------------------------------------------

#: Tokens used to pick which stored artifact backs each normalized type.
#: First command containing a token wins; falls back to the first artifact.
_ARTIFACT_TOKENS: dict[str, tuple[str, ...]] = {
    "interfaces": ("interface",),
    "routes": ("route",),
    "neighbors_lldp": ("lldp",),
    "neighbors_cdp": ("cdp",),
}


def _pick_artifact(artifacts: dict[str, RawArtifact], kind: str) -> RawArtifact:
    """Pick the artifact backing rows of *kind* by command-text token match."""
    if not artifacts:
        raise ValueError(f"no raw artifacts available to back normalized {kind!r} rows")
    for command, artifact in artifacts.items():
        lowered = command.lower()
        if any(token in lowered for token in _ARTIFACT_TOKENS[kind]):
            return artifact
    return next(iter(artifacts.values()))


async def persist_device_result(
    session: AsyncSession,
    *,
    run: DiscoveryRun,
    device_result: DeviceCollectionResult,
    mgmt_ip: str,
    credential_id: UUID | None,
) -> dict[str, UpsertCounts]:
    """Persist one device's collection: device + artifacts + normalized rows.

    Requires ``device_result.facts`` (the device contact succeeded); stores
    one artifact per collected command, then upserts the device and each
    normalized type, returning per-type ``{"inserted", "updated"}`` counts.
    """
    if device_result.facts is None:
        raise ValueError("device_result has no facts; nothing to persist for an unreached device")

    device = await upsert_device(
        session, facts=device_result.facts, mgmt_ip=mgmt_ip, credential_id=credential_id
    )

    artifacts: dict[str, RawArtifact] = {}
    for command, raw_text in device_result.raw_outputs.items():
        artifacts[command] = await store_artifact(
            session,
            device_id=device.id,
            run_id=run.id,
            command=command,
            raw_text=raw_text,
            parsed=None,
        )

    counts: dict[str, UpsertCounts] = {
        "interfaces": {"inserted": 0, "updated": 0},
        "routes": {"inserted": 0, "updated": 0},
        "neighbors": {"inserted": 0, "updated": 0},
    }
    if device_result.interfaces:
        counts["interfaces"] = await upsert_interfaces(
            session, device, device_result.interfaces, _pick_artifact(artifacts, "interfaces").id
        )
    if device_result.routes:
        counts["routes"] = await upsert_routes(
            session, device, device_result.routes, _pick_artifact(artifacts, "routes").id
        )
    for protocol, kind in (
        (NeighborProtocol.LLDP, "neighbors_lldp"),
        (NeighborProtocol.CDP, "neighbors_cdp"),
    ):
        rows = [n for n in device_result.neighbors if n.protocol is protocol]
        if rows:
            partial = await upsert_neighbors(
                session, device, rows, _pick_artifact(artifacts, kind).id
            )
            counts["neighbors"]["inserted"] += partial["inserted"]
            counts["neighbors"]["updated"] += partial["updated"]

    logger.info(
        "discovery.persisted",
        device_id=str(device.id),
        run_id=str(run.id),
        artifacts=len(artifacts),
        counts=counts,
    )
    return counts
