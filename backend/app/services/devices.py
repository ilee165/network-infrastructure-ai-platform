"""Persistence and audit service for device inventory routes."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any, Final

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.actors import AuthenticatedActor
from app.core.errors import ConflictError, NotFoundError
from app.models import (
    Device,
    DeviceCredential,
    DeviceStatus,
    NormalizedInterfaceRow,
    NormalizedNeighborRow,
)
from app.schemas.devices import DeviceCreate
from app.services import audit
from app.services.integrity import integrity_sqlstate, unique_constraint_name

_TARGET_TYPE: Final = "device"


@dataclass(frozen=True, slots=True)
class DevicePage:
    items: list[Device]
    total: int


def _actor(user: AuthenticatedActor) -> str:
    return f"user:{user.username}"


def _is_mgmt_ip_unique_violation(exc: IntegrityError) -> bool:
    """Return whether an integrity failure names the management-IP constraint."""
    orig = exc.orig
    if orig is None:
        return False

    sqlstate = integrity_sqlstate(exc)
    if sqlstate is not None:
        return sqlstate == "23505" and unique_constraint_name(exc) == "uq_devices_mgmt_ip"

    # SQLite exposes neither SQLSTATE nor structured constraint metadata.
    # Its driver message identifies the violated table/column directly.
    message = str(orig).lower()
    return "unique constraint failed: devices.mgmt_ip" in message


class DeviceService:
    """Own relational reads, writes, transactions, and audits for devices."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def _get(self, device_id: uuid.UUID) -> Device:
        row = await self._session.get(Device, device_id)
        if row is None:
            raise NotFoundError(f"device {device_id} does not exist")
        return row

    async def _ensure_mgmt_ip_free(
        self, mgmt_ip: str, *, exclude_id: uuid.UUID | None = None
    ) -> None:
        query = select(Device.id).where(Device.mgmt_ip == mgmt_ip)
        if exclude_id is not None:
            query = query.where(Device.id != exclude_id)
        if (await self._session.execute(query)).scalar_one_or_none() is not None:
            raise ConflictError(f"a device with mgmt_ip {mgmt_ip} already exists")

    async def _ensure_credential_exists(self, credential_id: uuid.UUID) -> None:
        if await self._session.get(DeviceCredential, credential_id) is None:
            raise NotFoundError(f"credential {credential_id} does not exist")

    async def list_devices(
        self,
        *,
        status: DeviceStatus | None,
        vendor_id: str | None,
        limit: int,
        offset: int,
    ) -> DevicePage:
        query = select(Device)
        if status is not None:
            query = query.where(Device.status == status)
        if vendor_id is not None:
            query = query.where(Device.vendor_id == vendor_id)
        total = (
            await self._session.execute(select(func.count()).select_from(query.subquery()))
        ).scalar_one()
        rows = list(
            (
                await self._session.execute(
                    query.order_by(Device.hostname, Device.id).limit(limit).offset(offset)
                )
            )
            .scalars()
            .all()
        )
        return DevicePage(items=rows, total=total)

    async def get(self, device_id: uuid.UUID) -> Device:
        return await self._get(device_id)

    async def list_interfaces(self, device_id: uuid.UUID) -> list[NormalizedInterfaceRow]:
        await self._get(device_id)
        return list(
            (
                await self._session.execute(
                    select(NormalizedInterfaceRow)
                    .where(NormalizedInterfaceRow.device_id == device_id)
                    .order_by(NormalizedInterfaceRow.name)
                )
            )
            .scalars()
            .all()
        )

    async def list_neighbors(self, device_id: uuid.UUID) -> list[NormalizedNeighborRow]:
        await self._get(device_id)
        return list(
            (
                await self._session.execute(
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

    async def create(self, body: DeviceCreate, user: AuthenticatedActor) -> Device:
        await self._ensure_mgmt_ip_free(body.mgmt_ip)
        if body.credential_id is not None:
            await self._ensure_credential_exists(body.credential_id)
        row = Device(**body.model_dump())
        self._session.add(row)
        try:
            await self._session.flush()
        except IntegrityError as exc:
            await self._session.rollback()
            if not _is_mgmt_ip_unique_violation(exc):
                raise
            raise ConflictError(f"a device with mgmt_ip {body.mgmt_ip} already exists") from exc
        await audit.record(
            self._session,
            actor=_actor(user),
            action=audit.DEVICE_CREATED,
            target_type=_TARGET_TYPE,
            target_id=str(row.id),
            detail={"hostname": row.hostname, "mgmt_ip": row.mgmt_ip},
        )
        await self._session.commit()
        return row

    async def update(
        self,
        device_id: uuid.UUID,
        updates: dict[str, Any],
        user: AuthenticatedActor,
    ) -> Device:
        row = await self._get(device_id)
        if "mgmt_ip" in updates and updates["mgmt_ip"] != row.mgmt_ip:
            await self._ensure_mgmt_ip_free(updates["mgmt_ip"], exclude_id=row.id)
        if updates.get("credential_id") is not None:
            await self._ensure_credential_exists(updates["credential_id"])
        prior_mgmt_ip = row.mgmt_ip
        for field, value in updates.items():
            setattr(row, field, value)
        try:
            await self._session.flush()
        except IntegrityError as exc:
            await self._session.rollback()
            if not _is_mgmt_ip_unique_violation(exc):
                raise
            mgmt_ip = updates.get("mgmt_ip", prior_mgmt_ip)
            raise ConflictError(f"a device with mgmt_ip {mgmt_ip} already exists") from exc
        await audit.record(
            self._session,
            actor=_actor(user),
            action=audit.DEVICE_UPDATED,
            target_type=_TARGET_TYPE,
            target_id=str(row.id),
            detail={"fields": sorted(updates)},
        )
        await self._session.commit()
        return row

    async def delete(self, device_id: uuid.UUID, user: AuthenticatedActor) -> None:
        row = await self._get(device_id)
        detail = {"hostname": row.hostname, "mgmt_ip": row.mgmt_ip}
        await self._session.delete(row)
        try:
            await self._session.flush()
        except IntegrityError as exc:
            raise ConflictError(
                f"device {device_id} still has dependent records and cannot be deleted"
            ) from exc
        await audit.record(
            self._session,
            actor=_actor(user),
            action=audit.DEVICE_DELETED,
            target_type=_TARGET_TYPE,
            target_id=str(device_id),
            detail=detail,
        )
        await self._session.commit()
