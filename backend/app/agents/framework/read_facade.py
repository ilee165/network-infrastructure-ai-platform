"""Read-only persistence and knowledge access for specialist agents."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Any
from uuid import UUID

if TYPE_CHECKING:
    from app.core.security import Role
    from app.models import Device, NormalizedNeighborRow, NormalizedRouteRow
    from app.models.reports import ReportKind


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


# ---------------------------------------------------------------------------
# Compliance/audit report engine (P4 W3-T1, ADR-0053 §1 "Documentation Agent
# alignment"): typed read access + the per-kind RBAC floor, enforced against
# the INVOKING user's bound role. The agent triggers and cites reports; it
# never authors artifact content (artifact bytes are NOT exposed here — only
# metadata incl. sha256 for citation).
# ---------------------------------------------------------------------------


class ReportAccessDeniedError(PermissionError):
    """The invoking user's role is below the report kind's ADR-0053 §3 floor."""

    def __init__(self, kind: str, required: str) -> None:
        self.kind = kind
        self.required = required
        super().__init__(
            f"the {kind!r} report requires the {required!r} role or higher (ADR-0053 §3)"
        )


class UnknownReportKind(ValueError):
    """A requested report kind is not one of the four ADR-0053 kinds."""

    def __init__(self, kind: str, valid_values: tuple[str, ...]) -> None:
        self.kind = kind
        self.valid_values = valid_values
        super().__init__(f"unknown report kind {kind!r}; valid values: {list(valid_values)}")


@dataclass(frozen=True, slots=True)
class ReportArtifactSnapshot:
    """Immutable artifact metadata (sha256 for citation; never content bytes)."""

    id: UUID
    format: str
    sha256: str
    size_bytes: int
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class ReportRunSnapshot:
    """Immutable plain-data projection of one report run."""

    id: UUID
    kind: str
    trigger: str
    period_start: datetime
    period_end: datetime
    status: str
    error_class: str | None
    regime_tags: tuple[str, ...]
    finished_at: datetime | None
    artifacts: tuple[ReportArtifactSnapshot, ...]


def _resolve_report_kind(kind: str) -> ReportKind:
    from app.models.reports import ReportKind

    try:
        return ReportKind(kind)
    except ValueError as exc:
        raise UnknownReportKind(kind, tuple(k.value for k in ReportKind)) from exc


def ensure_report_access(role: Role | None, kind: str) -> None:
    """Raise unless *role* (a :class:`~app.core.security.Role` or ``None``)
    meets the ADR-0053 §3 floor for *kind* (deny-by-default on ``None``)."""
    from app.engines.reports import required_role, role_meets_floor

    resolved = _resolve_report_kind(kind)
    if not role_meets_floor(role, resolved):
        raise ReportAccessDeniedError(resolved.value, required_role(resolved).value)


def _run_snapshot(row: Any, artifacts: list[Any]) -> ReportRunSnapshot:
    return ReportRunSnapshot(
        id=row.id,
        kind=row.kind,
        trigger=row.trigger,
        period_start=row.period_start,
        period_end=row.period_end,
        status=row.status,
        error_class=row.error_class,
        regime_tags=tuple(row.regime_tags),
        finished_at=row.finished_at,
        artifacts=tuple(
            ReportArtifactSnapshot(
                id=a.id,
                format=a.format,
                sha256=a.sha256,
                size_bytes=a.size_bytes,
                expires_at=a.expires_at,
            )
            for a in artifacts
        ),
    )


async def list_report_runs(
    *, role: Role | None, kind: str | None, limit: int
) -> list[ReportRunSnapshot]:
    """List report runs (newest first) scoped to kinds *role* may see.

    With an explicit *kind* the floor is enforced (raises
    :class:`ReportAccessDeniedError`); without one, kinds above the invoking
    role's floor are silently excluded (the run's existence is itself
    RBAC-scoped metadata, ADR-0053 §3).
    """
    from sqlalchemy import select

    import app.db as db
    from app.engines.reports import kinds_visible_to
    from app.models.reports import ReportArtifact, ReportRun

    if kind is not None:
        ensure_report_access(role, kind)
        kinds = [_resolve_report_kind(kind).value]
    else:
        kinds = sorted(k.value for k in kinds_visible_to(role))
    if not kinds:
        return []
    async with db.get_sessionmaker()() as session:
        rows = (
            (
                await session.execute(
                    select(ReportRun)
                    .where(ReportRun.kind.in_(kinds))
                    .order_by(ReportRun.created_at.desc(), ReportRun.id)
                    .limit(limit)
                )
            )
            .scalars()
            .all()
        )
        # Two plain SELECTs instead of a relationship eager-load: the facade's
        # AST purity guard permits only bare ``select`` from SQLAlchemy.
        artifacts_by_run: dict[UUID, list[Any]] = {}
        if rows:
            artifact_rows = (
                (
                    await session.execute(
                        select(ReportArtifact).where(
                            ReportArtifact.run_id.in_([row.id for row in rows])
                        )
                    )
                )
                .scalars()
                .all()
            )
            for artifact in artifact_rows:
                artifacts_by_run.setdefault(artifact.run_id, []).append(artifact)
        return [_run_snapshot(row, artifacts_by_run.get(row.id, [])) for row in rows]


async def get_report_run(*, role: Role | None, run_id: UUID) -> ReportRunSnapshot | None:
    """One run's metadata + artifact metadata; per-kind floor enforced.

    Raises :class:`ReportAccessDeniedError` when the run exists but its kind is
    above the invoking role's floor.
    """
    from sqlalchemy import select

    import app.db as db
    from app.models.reports import ReportArtifact, ReportRun

    async with db.get_sessionmaker()() as session:
        row = (
            await session.execute(select(ReportRun).where(ReportRun.id == run_id))
        ).scalar_one_or_none()
        if row is None:
            return None
        ensure_report_access(role, row.kind)
        artifact_rows = (
            (await session.execute(select(ReportArtifact).where(ReportArtifact.run_id == row.id)))
            .scalars()
            .all()
        )
        return _run_snapshot(row, list(artifact_rows))


def report_generation_args(
    *, kind: str, period_start: datetime, period_end: datetime
) -> tuple[UUID, list[str]]:
    """Validate a generation request and return ``(run_id, task args)``.

    The deterministic run id + the exact ``reports.generate`` Celery argument
    vector (kind, period ISO strings, trigger) — the tool layer appends the
    invoking user id and enqueues (it owns the Celery seam; ADR-0053 §2).
    """
    from app.engines.reports import deterministic_run_id

    resolved = _resolve_report_kind(kind)
    if period_end <= period_start:
        raise ValueError("period_end must be after period_start")
    run_id = deterministic_run_id(resolved, period_start, period_end)
    return run_id, [
        resolved.value,
        period_start.isoformat(),
        period_end.isoformat(),
        "on_demand",
    ]
