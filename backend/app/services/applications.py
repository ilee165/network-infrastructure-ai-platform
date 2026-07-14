"""Persistence and audit service for manual application tagging."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Final

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import ConflictError, NotFoundError, StalePreconditionError
from app.models import Application, ApplicationDependency, Device, NormalizedInterfaceRow, User
from app.models.applications import ApplicationOrigin, DependencySource, DependencyTargetKind
from app.models.mixins import utcnow
from app.schemas.applications import (
    ApplicationCreate,
    ApplicationDependencyCreate,
    ApplicationUpdate,
)
from app.services import audit

_TARGET_TYPE_APPLICATION: Final = "application"
_TARGET_TYPE_DEPENDENCY: Final = "application_dependency"
_NON_NULLABLE_FIELDS: Final = frozenset({"name", "fqdns"})


@dataclass(frozen=True, slots=True)
class ApplicationPage:
    items: list[Application]
    total: int


def _actor(user: User) -> str:
    return f"user:{user.username}"


def _application_state(application: Application) -> dict[str, Any]:
    return {
        "name": application.name,
        "description": application.description,
        "owner": application.owner,
        "fqdns": list(application.fqdns),
        "origin": str(application.origin),
        "origin_ref": application.origin_ref,
    }


def _dependency_state(dependency: ApplicationDependency) -> dict[str, Any]:
    return {
        "application_id": str(dependency.application_id),
        "target_kind": str(dependency.target_kind),
        "target_ref": dependency.target_ref,
        "source": str(dependency.source),
        "provenance": list(dependency.provenance),
        "derived_at": dependency.derived_at.isoformat(),
    }


class ApplicationService:
    """Own all relational reads, writes, transactions, and audits for applications."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def _get(self, application_id: uuid.UUID, *, for_update: bool = False) -> Application:
        row = await self._session.get(Application, application_id, with_for_update=for_update)
        if row is None:
            raise NotFoundError(f"application {application_id} does not exist")
        return row

    async def _ensure_name_free(
        self, name: str, *, exclude_id: uuid.UUID | None = None
    ) -> None:
        query = select(Application.id).where(func.lower(Application.name) == name.lower())
        if exclude_id is not None:
            query = query.where(Application.id != exclude_id)
        if (await self._session.execute(query)).scalar_one_or_none() is not None:
            raise ConflictError(
                f"an application named {name!r} already exists (names are case-insensitive)"
            )

    async def _ensure_target_exists(
        self, target_kind: DependencyTargetKind, target_ref: uuid.UUID
    ) -> None:
        if target_kind is DependencyTargetKind.DEVICE:
            if await self._session.get(Device, target_ref) is None:
                raise NotFoundError(f"device {target_ref} does not exist")
            return
        interface = await self._session.get(NormalizedInterfaceRow, target_ref)
        if interface is None or not interface.ip_address:
            raise NotFoundError(f"no IP address endpoint exists at interface row {target_ref}")

    async def list(
        self, *, origin: ApplicationOrigin | None, q: str | None, limit: int, offset: int
    ) -> ApplicationPage:
        query = select(Application)
        if origin is not None:
            query = query.where(Application.origin == origin)
        if q is not None:
            query = query.where(Application.name.icontains(q, autoescape=True))
        total = (
            await self._session.execute(select(func.count()).select_from(query.subquery()))
        ).scalar_one()
        rows = list(
            (
                await self._session.execute(
                    query.order_by(Application.name, Application.id).limit(limit).offset(offset)
                )
            )
            .scalars()
            .all()
        )
        return ApplicationPage(items=rows, total=total)

    async def get(self, application_id: uuid.UUID) -> Application:
        return await self._get(application_id)

    async def list_dependencies(self, application_id: uuid.UUID) -> list[ApplicationDependency]:
        await self._get(application_id)
        return list(
            (
                await self._session.execute(
                    select(ApplicationDependency)
                    .where(ApplicationDependency.application_id == application_id)
                    .order_by(
                        ApplicationDependency.target_kind,
                        ApplicationDependency.target_ref,
                        ApplicationDependency.source,
                    )
                )
            )
            .scalars()
            .all()
        )

    async def create(self, body: ApplicationCreate, user: User) -> Application:
        await self._ensure_name_free(body.name)
        row = Application(
            name=body.name,
            description=body.description,
            owner=body.owner,
            fqdns=body.fqdns,
            origin=ApplicationOrigin.MANUAL,
            created_by=user.id,
        )
        self._session.add(row)
        try:
            await self._session.flush()
        except IntegrityError as exc:
            await self._session.rollback()
            raise ConflictError(f"an application named {body.name!r} already exists") from exc
        await audit.record(
            self._session,
            actor=_actor(user),
            action=audit.APPLICATION_CREATE,
            target_type=_TARGET_TYPE_APPLICATION,
            target_id=str(row.id),
            detail={"after": _application_state(row)},
        )
        await self._session.commit()
        return row

    async def prepare_update(self, application_id: uuid.UUID) -> Application:
        """Load and lock the update target before HTTP precondition parsing."""
        return await self._get(application_id, for_update=True)

    async def apply_update(
        self,
        row: Application,
        body: ApplicationUpdate,
        user: User,
        expected: datetime,
    ) -> Application:
        if row.updated_at != expected:
            raise StalePreconditionError(
                f"application {row.id} was modified by another writer since you "
                "last read it; reload and retry"
            )
        before = _application_state(row)
        updates = {
            field: value
            for field, value in body.model_dump(exclude_unset=True).items()
            if not (value is None and field in _NON_NULLABLE_FIELDS)
        }
        if "name" in updates:
            await self._ensure_name_free(updates["name"], exclude_id=row.id)
        for field, value in updates.items():
            setattr(row, field, value)
        try:
            await self._session.flush()
        except IntegrityError as exc:
            await self._session.rollback()
            name = updates.get("name", row.name)
            raise ConflictError(f"an application named {name!r} already exists") from exc
        await audit.record(
            self._session,
            actor=_actor(user),
            action=audit.APPLICATION_UPDATE,
            target_type=_TARGET_TYPE_APPLICATION,
            target_id=str(row.id),
            detail={
                "before": before,
                "after": _application_state(row),
                "fields": sorted(updates),
            },
        )
        await self._session.commit()
        return row

    async def delete(
        self, application_id: uuid.UUID, user: User, expected: datetime | None
    ) -> None:
        row = await self._get(application_id, for_update=True)
        if ApplicationOrigin(row.origin) is ApplicationOrigin.DERIVED:
            raise ConflictError(
                f"application {application_id} is derived and lifecycle-owned by derivation; "
                "it disappears when its source object disappears, not by user delete"
            )
        if expected is not None and row.updated_at != expected:
            raise StalePreconditionError(
                f"application {application_id} was modified by another writer since you "
                "last read it; reload and retry"
            )
        dependencies = await self.list_dependencies(application_id)
        detail = {
            "before": _application_state(row),
            "cascaded_dependencies": [
                {"id": str(dependency.id), **_dependency_state(dependency)}
                for dependency in dependencies
            ],
        }
        await self._session.delete(row)
        await self._session.flush()
        await audit.record(
            self._session,
            actor=_actor(user),
            action=audit.APPLICATION_DELETE,
            target_type=_TARGET_TYPE_APPLICATION,
            target_id=str(application_id),
            detail=detail,
        )
        await self._session.commit()
    async def create_dependency(
        self, application_id: uuid.UUID, body: ApplicationDependencyCreate, user: User
    ) -> ApplicationDependency:
        application = await self._get(application_id)
        await self._ensure_target_exists(body.target_kind, body.target_ref)
        target_ref = str(body.target_ref)
        duplicate = (
            await self._session.execute(
                select(ApplicationDependency.id).where(
                    ApplicationDependency.application_id == application.id,
                    ApplicationDependency.target_kind == body.target_kind,
                    ApplicationDependency.target_ref == target_ref,
                    ApplicationDependency.source == DependencySource.MANUAL,
                )
            )
        ).scalar_one_or_none()
        if duplicate is not None:
            raise ConflictError(
                f"a manual dependency on {body.target_kind}:{target_ref} already exists "
                f"for application {application_id}"
            )
        row = ApplicationDependency(
            application_id=application.id,
            target_kind=body.target_kind,
            target_ref=target_ref,
            source=DependencySource.MANUAL,
            provenance=[{"kind": "user", "ref": str(user.id)}],
            derived_at=utcnow(),
            created_by=user.id,
        )
        self._session.add(row)
        try:
            await self._session.flush()
        except IntegrityError as exc:
            await self._session.rollback()
            raise ConflictError(
                f"a manual dependency on {body.target_kind}:{target_ref} already exists "
                f"for application {application_id}"
            ) from exc
        await audit.record(
            self._session,
            actor=_actor(user),
            action=audit.APPLICATION_DEPENDENCY_CREATE,
            target_type=_TARGET_TYPE_DEPENDENCY,
            target_id=str(row.id),
            detail={"after": _dependency_state(row)},
        )
        await self._session.commit()
        return row

    async def delete_dependency(
        self, application_id: uuid.UUID, dependency_id: uuid.UUID, user: User
    ) -> None:
        row = await self._session.get(ApplicationDependency, dependency_id)
        if row is None or row.application_id != application_id:
            raise NotFoundError(
                f"dependency {dependency_id} does not exist on application {application_id}"
            )
        if DependencySource(row.source) is not DependencySource.MANUAL:
            raise ConflictError(
                f"dependency {dependency_id} is owned by the {row.source!s} derivation "
                "source; it retracts when that source stops asserting it, not by user delete"
            )
        detail = {"before": _dependency_state(row)}
        await self._session.delete(row)
        await self._session.flush()
        await audit.record(
            self._session,
            actor=_actor(user),
            action=audit.APPLICATION_DEPENDENCY_DELETE,
            target_type=_TARGET_TYPE_DEPENDENCY,
            target_id=str(dependency_id),
            detail=detail,
        )
        await self._session.commit()
