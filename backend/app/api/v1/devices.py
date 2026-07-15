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
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, require_role
from app.core.actors import AuthenticatedActor
from app.schemas.devices import (
    DeviceCreate,
    DeviceInterfaceRead,
    DeviceListResponse,
    DeviceNeighborRead,
    DeviceRead,
    DeviceStatus,
    DeviceUpdate,
)
from app.services.devices import DeviceService

router = APIRouter(prefix="/devices", tags=["devices"])

Viewer = Annotated[AuthenticatedActor, Depends(require_role("viewer"))]
Engineer = Annotated[AuthenticatedActor, Depends(require_role("engineer"))]

#: PATCH fields that may not be nulled — a JSON ``null`` for these means
#: "leave unchanged", matching the NOT NULL columns they map onto.
_NON_NULLABLE_FIELDS: Final = frozenset({"hostname", "mgmt_ip", "status"})


def get_device_service(session: Annotated[AsyncSession, Depends(get_db)]) -> DeviceService:
    """Bind the service to the request's overridable persistence lifecycle."""
    return DeviceService(session)


Service = Annotated[DeviceService, Depends(get_device_service)]


@router.get("", response_model=DeviceListResponse)
async def list_devices(
    service: Service,
    _user: Viewer,
    status: Annotated[DeviceStatus | None, Query()] = None,
    vendor_id: Annotated[str | None, Query(max_length=64)] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> DeviceListResponse:
    """List inventory devices, filterable by status/vendor, paginated."""
    page = await service.list_devices(
        status=status, vendor_id=vendor_id, limit=limit, offset=offset
    )
    return DeviceListResponse(
        items=[DeviceRead.model_validate(row) for row in page.items],
        total=page.total,
        limit=limit,
        offset=offset,
    )


@router.get("/{device_id}", response_model=DeviceRead)
async def get_device(device_id: uuid.UUID, service: Service, _user: Viewer) -> DeviceRead:
    """One device by id (404 problem details when unknown)."""
    return DeviceRead.model_validate(await service.get(device_id))


@router.get("/{device_id}/interfaces", response_model=list[DeviceInterfaceRead])
async def list_device_interfaces(
    device_id: uuid.UUID, service: Service, _user: Viewer
) -> list[DeviceInterfaceRead]:
    """Normalized interfaces of one device."""
    rows = await service.list_interfaces(device_id)
    return [DeviceInterfaceRead.model_validate(row) for row in rows]


@router.get("/{device_id}/neighbors", response_model=list[DeviceNeighborRead])
async def list_device_neighbors(
    device_id: uuid.UUID, service: Service, _user: Viewer
) -> list[DeviceNeighborRead]:
    """Normalized LLDP/CDP neighbors of one device."""
    rows = await service.list_neighbors(device_id)
    return [DeviceNeighborRead.model_validate(row) for row in rows]


@router.post("", response_model=DeviceRead, status_code=201)
async def create_device(body: DeviceCreate, service: Service, user: Engineer) -> DeviceRead:
    """Create one inventory device; audits ``device.created``."""
    return DeviceRead.model_validate(await service.create(body, user))


@router.patch("/{device_id}", response_model=DeviceRead)
async def update_device(
    device_id: uuid.UUID, body: DeviceUpdate, service: Service, user: Engineer
) -> DeviceRead:
    """Partially update one device; audits ``device.updated`` with field names."""
    updates = {
        field: value
        for field, value in body.model_dump(exclude_unset=True).items()
        if not (value is None and field in _NON_NULLABLE_FIELDS)
    }
    return DeviceRead.model_validate(await service.update(device_id, updates, user))


@router.delete("/{device_id}", status_code=204)
async def delete_device(device_id: uuid.UUID, service: Service, user: Engineer) -> Response:
    """Delete one device; audits ``device.deleted``.

    409 when dependent rows (raw artifacts, FK-protected children) still
    reference the device — evidence is never silently cascaded away.
    """
    await service.delete(device_id, user)
    return Response(status_code=204)
