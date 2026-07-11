"""Device inventory routes (M1-15): list/detail/subresources + engineer CRUD.

Reads require any authenticated user (``viewer`` rank); mutations require
``engineer`` (ADR-0010) and write a ``device.created`` / ``device.updated`` /
``device.deleted`` audit row that commits atomically with the change.
Duplicate ``mgmt_ip`` and FK-protected deletes surface as 409 conflicts;
unknown ids as 404 problem details.
"""

from __future__ import annotations

import uuid
from typing import Annotated, Final

from fastapi import APIRouter, Depends, Query, Response
from sqlalchemy import Select, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, require_role
from app.core.errors import ConflictError, NotFoundError
from app.models import (
    Device,
    DeviceCredential,
    DeviceStatus,
    NormalizedInterfaceRow,
    NormalizedNeighborRow,
    User,
)
from app.schemas.devices import (
    DeviceCreate,
    DeviceInterfaceRead,
    DeviceListResponse,
    DeviceNeighborRead,
    DeviceRead,
    DeviceUpdate,
)
from app.services import audit

router = APIRouter(prefix="/devices", tags=["devices"])

DbSession = Annotated[AsyncSession, Depends(get_db)]
Viewer = Annotated[User, Depends(require_role("viewer"))]
Engineer = Annotated[User, Depends(require_role("engineer"))]

_TARGET_TYPE: Final = "device"

#: PATCH fields that may not be nulled — a JSON ``null`` for these means
#: "leave unchanged", matching the NOT NULL columns they map onto.
_NON_NULLABLE_FIELDS: Final = frozenset({"hostname", "mgmt_ip", "status"})


def _is_mgmt_ip_unique_violation(exc: IntegrityError) -> bool:
    """True when *exc* is the devices.mgmt_ip unique constraint (not an FK, etc.).

    Matches PostgreSQL ``uq_devices_mgmt_ip`` / unique index names and SQLite's
    ``UNIQUE constraint failed: devices.mgmt_ip`` so we never mis-map a concurrent
    credential FK failure to a bogus "mgmt_ip already exists" 409.
    """
    parts = [str(exc.orig) if exc.orig is not None else "", *(str(a) for a in exc.args)]
    text = " ".join(parts).lower()
    return "mgmt_ip" in text or "uq_devices_mgmt_ip" in text


def _actor(user: User) -> str:
    return f"user:{user.username}"


async def _get_device_or_404(session: AsyncSession, device_id: uuid.UUID) -> Device:
    device = await session.get(Device, device_id)
    if device is None:
        raise NotFoundError(f"device {device_id} does not exist")
    return device


async def _ensure_mgmt_ip_free(
    session: AsyncSession, mgmt_ip: str, *, exclude_id: uuid.UUID | None = None
) -> None:
    query = select(Device.id).where(Device.mgmt_ip == mgmt_ip)
    if exclude_id is not None:
        query = query.where(Device.id != exclude_id)
    if (await session.execute(query)).scalar_one_or_none() is not None:
        raise ConflictError(f"a device with mgmt_ip {mgmt_ip} already exists")


async def _ensure_credential_exists(session: AsyncSession, credential_id: uuid.UUID) -> None:
    if await session.get(DeviceCredential, credential_id) is None:
        raise NotFoundError(f"credential {credential_id} does not exist")


@router.get("", response_model=DeviceListResponse)
async def list_devices(
    session: DbSession,
    _user: Viewer,
    status: Annotated[DeviceStatus | None, Query()] = None,
    vendor_id: Annotated[str | None, Query(max_length=64)] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> DeviceListResponse:
    """List inventory devices, filterable by status/vendor, paginated."""
    query: Select[tuple[Device]] = select(Device)
    if status is not None:
        query = query.where(Device.status == status)
    if vendor_id is not None:
        query = query.where(Device.vendor_id == vendor_id)
    total = (await session.execute(select(func.count()).select_from(query.subquery()))).scalar_one()
    rows = (
        (
            await session.execute(
                query.order_by(Device.hostname, Device.id).limit(limit).offset(offset)
            )
        )
        .scalars()
        .all()
    )
    return DeviceListResponse(
        items=[DeviceRead.model_validate(row) for row in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/{device_id}", response_model=DeviceRead)
async def get_device(device_id: uuid.UUID, session: DbSession, _user: Viewer) -> DeviceRead:
    """One device by id (404 problem details when unknown)."""
    return DeviceRead.model_validate(await _get_device_or_404(session, device_id))


@router.get("/{device_id}/interfaces", response_model=list[DeviceInterfaceRead])
async def list_device_interfaces(
    device_id: uuid.UUID, session: DbSession, _user: Viewer
) -> list[DeviceInterfaceRead]:
    """Normalized interfaces of one device."""
    await _get_device_or_404(session, device_id)
    rows = (
        (
            await session.execute(
                select(NormalizedInterfaceRow)
                .where(NormalizedInterfaceRow.device_id == device_id)
                .order_by(NormalizedInterfaceRow.name)
            )
        )
        .scalars()
        .all()
    )
    return [DeviceInterfaceRead.model_validate(row) for row in rows]


@router.get("/{device_id}/neighbors", response_model=list[DeviceNeighborRead])
async def list_device_neighbors(
    device_id: uuid.UUID, session: DbSession, _user: Viewer
) -> list[DeviceNeighborRead]:
    """Normalized LLDP/CDP neighbors of one device."""
    await _get_device_or_404(session, device_id)
    rows = (
        (
            await session.execute(
                select(NormalizedNeighborRow)
                .where(NormalizedNeighborRow.device_id == device_id)
                .order_by(
                    NormalizedNeighborRow.local_interface, NormalizedNeighborRow.neighbor_name
                )
            )
        )
        .scalars()
        .all()
    )
    return [DeviceNeighborRead.model_validate(row) for row in rows]


@router.post("", response_model=DeviceRead, status_code=201)
async def create_device(body: DeviceCreate, session: DbSession, user: Engineer) -> DeviceRead:
    """Create one inventory device; audits ``device.created``."""
    await _ensure_mgmt_ip_free(session, body.mgmt_ip)
    if body.credential_id is not None:
        await _ensure_credential_exists(session, body.credential_id)
    device = Device(**body.model_dump())
    session.add(device)
    try:
        await session.flush()
    except IntegrityError as exc:  # concurrent duplicate slipping past the pre-check
        await session.rollback()
        if not _is_mgmt_ip_unique_violation(exc):
            raise
        raise ConflictError(f"a device with mgmt_ip {body.mgmt_ip} already exists") from exc
    await audit.record(
        session,
        actor=_actor(user),
        action=audit.DEVICE_CREATED,
        target_type=_TARGET_TYPE,
        target_id=str(device.id),
        detail={"hostname": device.hostname, "mgmt_ip": device.mgmt_ip},
    )
    response = DeviceRead.model_validate(device)
    await session.commit()
    return response


@router.patch("/{device_id}", response_model=DeviceRead)
async def update_device(
    device_id: uuid.UUID, body: DeviceUpdate, session: DbSession, user: Engineer
) -> DeviceRead:
    """Partially update one device; audits ``device.updated`` with field names."""
    device = await _get_device_or_404(session, device_id)
    updates = {
        field: value
        for field, value in body.model_dump(exclude_unset=True).items()
        if not (value is None and field in _NON_NULLABLE_FIELDS)
    }
    if "mgmt_ip" in updates and updates["mgmt_ip"] != device.mgmt_ip:
        await _ensure_mgmt_ip_free(session, updates["mgmt_ip"], exclude_id=device.id)
    if updates.get("credential_id") is not None:
        await _ensure_credential_exists(session, updates["credential_id"])
    # Snapshot before flush: after rollback the ORM instance is expired and
    # lazy-loading ``device.mgmt_ip`` can raise MissingGreenlet on async sessions.
    prior_mgmt_ip = device.mgmt_ip
    for field, value in updates.items():
        setattr(device, field, value)
    try:
        await session.flush()
    except IntegrityError as exc:  # concurrent rename slipping past the pre-check
        await session.rollback()
        if not _is_mgmt_ip_unique_violation(exc):
            raise
        mgmt_ip = updates.get("mgmt_ip", prior_mgmt_ip)
        raise ConflictError(f"a device with mgmt_ip {mgmt_ip} already exists") from exc
    await audit.record(
        session,
        actor=_actor(user),
        action=audit.DEVICE_UPDATED,
        target_type=_TARGET_TYPE,
        target_id=str(device.id),
        detail={"fields": sorted(updates)},
    )
    response = DeviceRead.model_validate(device)
    await session.commit()
    return response


@router.delete("/{device_id}", status_code=204)
async def delete_device(device_id: uuid.UUID, session: DbSession, user: Engineer) -> Response:
    """Delete one device; audits ``device.deleted``.

    409 when dependent rows (raw artifacts, FK-protected children) still
    reference the device — evidence is never silently cascaded away.
    """
    device = await _get_device_or_404(session, device_id)
    detail = {"hostname": device.hostname, "mgmt_ip": device.mgmt_ip}
    await session.delete(device)
    try:
        await session.flush()
    except IntegrityError as exc:
        raise ConflictError(
            f"device {device_id} still has dependent records and cannot be deleted"
        ) from exc
    await audit.record(
        session,
        actor=_actor(user),
        action=audit.DEVICE_DELETED,
        target_type=_TARGET_TYPE,
        target_id=str(device_id),
        detail=detail,
    )
    await session.commit()
    return Response(status_code=204)
