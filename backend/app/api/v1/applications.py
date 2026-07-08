"""Manual application-tagging routes (P4 W2-T3): direct write under RBAC, full audit.

Implements the decided ADR-0052 §7 write path — the exact ``api/v1/devices.py``
precedent: reads require any authenticated user (``viewer`` rank); mutations
require ``engineer`` (ADR-0010, enforced via the single
:func:`app.api.deps.require_role` check-site) and each write a hash-chained
``application.*`` / ``application_dependency.*`` audit entry (ADR-0038) that
commits atomically with the change, carrying actor, target ids, and
before/after state. CR-gating was considered and DECLINED (user decision
2026-07-05) — tags never touch a device; this module implements the decision.

Hard edges (ADR-0052 §3.3/§7):

- ``POST /applications`` creates ``manual``-origin rows only; ``origin`` /
  ``origin_ref`` are never caller-settable.
- ``DELETE /applications/{id}`` REFUSES ``derived`` rows (409): they are
  lifecycle-owned by derivation and a user delete would silently resurrect on
  re-derivation (§3.3.5). Manual deletes cascade their dependency rows
  (``ON DELETE CASCADE``), and the audit entry records every cascaded row.
- ``PATCH /applications/{id}`` is allowed on BOTH origins — user curation of a
  derived application (rename/attach, §3.3.4 consequence) is the point of the
  §3.3.3 manual-wins rule: the house ``onupdate`` moves ``updated_at`` while
  ``derived_watermark`` stays, permanently handing attribute ownership to the
  user. Lifecycle columns are untouched.
- Dependency rows are only ever written with ``source='manual'``,
  ``created_by`` stamped, and provenance the single
  ``{"kind": "user", "ref": <user_id>}`` step; removing a derivation-owned row
  is refused (409) — it retracts when its source stops asserting (§3.3.2).
- Targets are the two rebuild-safe kinds only (§2.3), and must exist:
  ``device`` → a ``devices`` row; ``ip_address`` → a ``normalized_interfaces``
  row carrying an address (the ``IPAddress`` node's ``pg_id``).

No agent-facing tagging tool exists (§7: a future one is STATE_CHANGING and
CR-gated); the standard per-principal API rate limit is applied at router
registration (``app.api.v1.__init__``), bounding bulk tagging (§7 abuse
containment).
"""

from __future__ import annotations

import uuid
from typing import Annotated, Any, Final

from fastapi import APIRouter, Depends, Query, Response
from sqlalchemy import Select, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, require_role
from app.core.errors import ConflictError, NotFoundError
from app.models import (
    Application,
    ApplicationDependency,
    Device,
    NormalizedInterfaceRow,
    User,
)
from app.models.applications import ApplicationOrigin, DependencySource, DependencyTargetKind
from app.models.mixins import utcnow
from app.schemas.applications import (
    ApplicationCreate,
    ApplicationDependencyCreate,
    ApplicationDependencyRead,
    ApplicationListResponse,
    ApplicationRead,
    ApplicationUpdate,
)
from app.services import audit

router = APIRouter(prefix="/applications", tags=["applications"])

DbSession = Annotated[AsyncSession, Depends(get_db)]
Viewer = Annotated[User, Depends(require_role("viewer"))]
Engineer = Annotated[User, Depends(require_role("engineer"))]

_TARGET_TYPE_APPLICATION: Final = "application"
_TARGET_TYPE_DEPENDENCY: Final = "application_dependency"

#: PATCH fields that may not be nulled — a JSON ``null`` for these means
#: "leave unchanged", matching the NOT NULL columns they map onto (the
#: ``api/v1/devices.py`` precedent).
_NON_NULLABLE_FIELDS: Final = frozenset({"name", "fqdns"})


def _actor(user: User) -> str:
    return f"user:{user.username}"


def _application_state(application: Application) -> dict[str, Any]:
    """JSON-safe before/after snapshot for ``application.*`` audit entries.

    Names/FQDNs/owner strings and lifecycle columns only — the full ADR-0052 §7
    accountability payload; no credential field exists on the row.
    """
    return {
        "name": application.name,
        "description": application.description,
        "owner": application.owner,
        "fqdns": list(application.fqdns),
        "origin": str(application.origin),
        "origin_ref": application.origin_ref,
    }


def _dependency_state(dependency: ApplicationDependency) -> dict[str, Any]:
    """JSON-safe before/after snapshot for ``application_dependency.*`` entries."""
    return {
        "application_id": str(dependency.application_id),
        "target_kind": str(dependency.target_kind),
        "target_ref": dependency.target_ref,
        "source": str(dependency.source),
        "provenance": list(dependency.provenance),
        "derived_at": dependency.derived_at.isoformat(),
    }


async def _get_application_or_404(session: AsyncSession, application_id: uuid.UUID) -> Application:
    application = await session.get(Application, application_id)
    if application is None:
        raise NotFoundError(f"application {application_id} does not exist")
    return application


async def _ensure_name_free(
    session: AsyncSession, name: str, *, exclude_id: uuid.UUID | None = None
) -> None:
    """409 when *name* is taken case-insensitively (the ``lower(name)`` unique index).

    The §3.3.4 collision rule makes same-name applications the SAME application —
    the API refuses the duplicate instead of silently attaching (the user should
    tag the existing row).
    """
    query = select(Application.id).where(func.lower(Application.name) == name.lower())
    if exclude_id is not None:
        query = query.where(Application.id != exclude_id)
    if (await session.execute(query)).scalar_one_or_none() is not None:
        raise ConflictError(
            f"an application named {name!r} already exists (names are case-insensitive)"
        )


async def _ensure_target_exists(
    session: AsyncSession, target_kind: DependencyTargetKind, target_ref: uuid.UUID
) -> None:
    """404 unless the rebuild-safe target row exists (ADR-0052 §2.3).

    ``device`` → a ``devices`` row; ``ip_address`` → a ``normalized_interfaces``
    row that carries an address (an address-less interface row never projects an
    ``IPAddress`` node, so an edge to it could never resolve).
    """
    if target_kind is DependencyTargetKind.DEVICE:
        if await session.get(Device, target_ref) is None:
            raise NotFoundError(f"device {target_ref} does not exist")
        return
    interface = await session.get(NormalizedInterfaceRow, target_ref)
    if interface is None or not interface.ip_address:
        raise NotFoundError(f"no IP address endpoint exists at interface row {target_ref}")


# ---------------------------------------------------------------------------
# Reads — viewer+ (like the rest of the topology surface, ADR-0052 §7)
# ---------------------------------------------------------------------------


@router.get("", response_model=ApplicationListResponse)
async def list_applications(
    session: DbSession,
    _user: Viewer,
    origin: Annotated[ApplicationOrigin | None, Query()] = None,
    q: Annotated[str | None, Query(min_length=1, max_length=255)] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> ApplicationListResponse:
    """List applications, filterable by origin and (case-insensitive) name substring."""
    query: Select[tuple[Application]] = select(Application)
    if origin is not None:
        query = query.where(Application.origin == origin)
    if q is not None:
        query = query.where(Application.name.icontains(q, autoescape=True))
    total = (await session.execute(select(func.count()).select_from(query.subquery()))).scalar_one()
    rows = (
        (
            await session.execute(
                query.order_by(Application.name, Application.id).limit(limit).offset(offset)
            )
        )
        .scalars()
        .all()
    )
    return ApplicationListResponse(
        items=[ApplicationRead.model_validate(row) for row in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/{application_id}", response_model=ApplicationRead)
async def get_application(
    application_id: uuid.UUID, session: DbSession, _user: Viewer
) -> ApplicationRead:
    """One application by id (404 problem details when unknown)."""
    return ApplicationRead.model_validate(await _get_application_or_404(session, application_id))


@router.get("/{application_id}/dependencies", response_model=list[ApplicationDependencyRead])
async def list_application_dependencies(
    application_id: uuid.UUID, session: DbSession, _user: Viewer
) -> list[ApplicationDependencyRead]:
    """Every dependency row of one application — all four sources, per-source rows."""
    await _get_application_or_404(session, application_id)
    rows = (
        (
            await session.execute(
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
    return [ApplicationDependencyRead.model_validate(row) for row in rows]


# ---------------------------------------------------------------------------
# Mutations — engineer+ (ADR-0052 §7), one audit entry per mutation
# ---------------------------------------------------------------------------


@router.post("", response_model=ApplicationRead, status_code=201)
async def create_application(
    body: ApplicationCreate, session: DbSession, user: Engineer
) -> ApplicationRead:
    """Create one ``manual``-origin application; audits ``application.create``."""
    await _ensure_name_free(session, body.name)
    application = Application(
        name=body.name,
        description=body.description,
        owner=body.owner,
        fqdns=body.fqdns,
        origin=ApplicationOrigin.MANUAL,
        created_by=user.id,
    )
    session.add(application)
    try:
        await session.flush()
    except IntegrityError as exc:  # concurrent duplicate slipping past the pre-check
        await session.rollback()
        raise ConflictError(f"an application named {body.name!r} already exists") from exc
    await audit.record(
        session,
        actor=_actor(user),
        action=audit.APPLICATION_CREATE,
        target_type=_TARGET_TYPE_APPLICATION,
        target_id=str(application.id),
        detail={"after": _application_state(application)},
    )
    response = ApplicationRead.model_validate(application)
    await session.commit()
    return response


@router.patch("/{application_id}", response_model=ApplicationRead)
async def update_application(
    application_id: uuid.UUID, body: ApplicationUpdate, session: DbSession, user: Engineer
) -> ApplicationRead:
    """Update attributes; audits ``application.update`` with before/after state.

    Allowed on both origins: editing a ``derived`` row's attributes is the
    §3.3.3 manual-wins handoff — ``updated_at`` moves (house ``onupdate``)
    while ``derived_watermark`` stays, so no derivation pass may overwrite the
    user's curation again. ``origin``/``origin_ref`` are not editable.
    """
    application = await _get_application_or_404(session, application_id)
    before = _application_state(application)
    updates = {
        field: value
        for field, value in body.model_dump(exclude_unset=True).items()
        if not (value is None and field in _NON_NULLABLE_FIELDS)
    }
    if "name" in updates:
        await _ensure_name_free(session, updates["name"], exclude_id=application.id)
    for field, value in updates.items():
        setattr(application, field, value)
    try:
        await session.flush()
    except IntegrityError as exc:  # concurrent rename slipping past the pre-check
        await session.rollback()
        name = updates.get("name", application.name)
        raise ConflictError(f"an application named {name!r} already exists") from exc
    await audit.record(
        session,
        actor=_actor(user),
        action=audit.APPLICATION_UPDATE,
        target_type=_TARGET_TYPE_APPLICATION,
        target_id=str(application.id),
        detail={
            "before": before,
            "after": _application_state(application),
            "fields": sorted(updates),
        },
    )
    response = ApplicationRead.model_validate(application)
    await session.commit()
    return response


@router.delete("/{application_id}", status_code=204)
async def delete_application(
    application_id: uuid.UUID, session: DbSession, user: Engineer
) -> Response:
    """Delete one ``manual`` application; audits ``application.delete``.

    409 for ``derived`` rows — they are lifecycle-owned by derivation and would
    silently resurrect on the next pass (ADR-0052 §3.3.5). The cascade-deleted
    dependency rows (``ON DELETE CASCADE``) are recorded in the audit entry so
    every retracted edge stays answerable from the trail.
    """
    application = await _get_application_or_404(session, application_id)
    if ApplicationOrigin(application.origin) is ApplicationOrigin.DERIVED:
        raise ConflictError(
            f"application {application_id} is derived and lifecycle-owned by derivation; "
            "it disappears when its source object disappears, not by user delete"
        )
    dependencies = (
        (
            await session.execute(
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
    detail = {
        "before": _application_state(application),
        "cascaded_dependencies": [
            {"id": str(row.id), **_dependency_state(row)} for row in dependencies
        ],
    }
    await session.delete(application)
    await session.flush()
    await audit.record(
        session,
        actor=_actor(user),
        action=audit.APPLICATION_DELETE,
        target_type=_TARGET_TYPE_APPLICATION,
        target_id=str(application_id),
        detail=detail,
    )
    await session.commit()
    return Response(status_code=204)


@router.post(
    "/{application_id}/dependencies", response_model=ApplicationDependencyRead, status_code=201
)
async def create_application_dependency(
    application_id: uuid.UUID,
    body: ApplicationDependencyCreate,
    session: DbSession,
    user: Engineer,
) -> ApplicationDependencyRead:
    """Tag one object into an application (ONE ``source='manual'`` row);
    audits ``application_dependency.create``."""
    application = await _get_application_or_404(session, application_id)
    await _ensure_target_exists(session, body.target_kind, body.target_ref)
    target_ref = str(body.target_ref)
    duplicate = (
        await session.execute(
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
    dependency = ApplicationDependency(
        application_id=application.id,
        target_kind=body.target_kind,
        target_ref=target_ref,
        source=DependencySource.MANUAL,
        # Manual provenance is the single user step (ADR-0052 §2 source 4/§7).
        provenance=[{"kind": "user", "ref": str(user.id)}],
        derived_at=utcnow(),
        created_by=user.id,
    )
    session.add(dependency)
    try:
        await session.flush()
    except IntegrityError as exc:  # concurrent duplicate slipping past the pre-check
        await session.rollback()
        raise ConflictError(
            f"a manual dependency on {body.target_kind}:{target_ref} already exists "
            f"for application {application_id}"
        ) from exc
    await audit.record(
        session,
        actor=_actor(user),
        action=audit.APPLICATION_DEPENDENCY_CREATE,
        target_type=_TARGET_TYPE_DEPENDENCY,
        target_id=str(dependency.id),
        detail={"after": _dependency_state(dependency)},
    )
    response = ApplicationDependencyRead.model_validate(dependency)
    await session.commit()
    return response


@router.delete("/{application_id}/dependencies/{dependency_id}", status_code=204)
async def delete_application_dependency(
    application_id: uuid.UUID, dependency_id: uuid.UUID, session: DbSession, user: Engineer
) -> Response:
    """Remove one ``manual`` dependency row; audits ``application_dependency.delete``.

    409 for derivation-owned rows (``source != 'manual'``): they are retracted
    by their source's next derivation pass, never by user delete (ADR-0052
    §3.3.1/§3.3.2 row ownership).
    """
    dependency = await session.get(ApplicationDependency, dependency_id)
    if dependency is None or dependency.application_id != application_id:
        raise NotFoundError(
            f"dependency {dependency_id} does not exist on application {application_id}"
        )
    if DependencySource(dependency.source) is not DependencySource.MANUAL:
        raise ConflictError(
            f"dependency {dependency_id} is owned by the {dependency.source!s} derivation "
            "source; it retracts when that source stops asserting it, not by user delete"
        )
    detail = {"before": _dependency_state(dependency)}
    await session.delete(dependency)
    await session.flush()
    await audit.record(
        session,
        actor=_actor(user),
        action=audit.APPLICATION_DEPENDENCY_DELETE,
        target_type=_TARGET_TYPE_DEPENDENCY,
        target_id=str(dependency_id),
        detail=detail,
    )
    await session.commit()
    return Response(status_code=204)
