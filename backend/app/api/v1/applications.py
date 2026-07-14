"""HTTP routes for manual application tagging (ADR-0052 §7)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Annotated, Protocol

from fastapi import APIRouter, Depends, Header, Query, Response
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, require_role
from app.core.actors import AuthenticatedActor
from app.core.errors import BadRequestError, PreconditionRequiredError
from app.schemas.applications import (
    ApplicationCreate,
    ApplicationDependencyCreate,
    ApplicationDependencyRead,
    ApplicationListResponse,
    ApplicationRead,
    ApplicationUpdate,
)
from app.services.applications import ApplicationOrigin, ApplicationService

router = APIRouter(prefix="/applications", tags=["applications"])

Viewer = Annotated[AuthenticatedActor, Depends(require_role("viewer"))]
Engineer = Annotated[AuthenticatedActor, Depends(require_role("engineer"))]


def get_application_service(
    session: Annotated[AsyncSession, Depends(get_db)],
) -> ApplicationService:
    """Bind the service to the request's overridable persistence lifecycle."""
    return ApplicationService(session)


Service = Annotated[ApplicationService, Depends(get_application_service)]


class _VersionedApplication(Protocol):
    @property
    def updated_at(self) -> datetime: ...


def _etag(application: _VersionedApplication) -> str:
    return f'"{application.updated_at.isoformat()}"'


def _parse_if_match(raw: str | None) -> datetime:
    if raw is None:
        raise PreconditionRequiredError(
            "this endpoint requires an If-Match precondition header carrying the "
            "application's current updated_at ETag"
        )
    token = raw.strip()
    if token.startswith("W/"):
        token = token[2:].strip()
    token = token.strip('"')
    try:
        parsed = datetime.fromisoformat(token)
    except ValueError as exc:
        raise BadRequestError(
            "malformed If-Match token; expected a double-quoted ISO-8601 updated_at"
        ) from exc
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


@router.get("", response_model=ApplicationListResponse)
async def list_applications(
    service: Service,
    _user: Viewer,
    origin: Annotated[ApplicationOrigin | None, Query()] = None,
    q: Annotated[str | None, Query(min_length=1, max_length=255)] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> ApplicationListResponse:
    """List applications, filterable by origin and (case-insensitive) name substring."""
    page = await service.list_applications(origin=origin, q=q, limit=limit, offset=offset)
    return ApplicationListResponse(
        items=[ApplicationRead.model_validate(row) for row in page.items],
        total=page.total,
        limit=limit,
        offset=offset,
    )


@router.get("/{application_id}", response_model=ApplicationRead)
async def get_application(
    application_id: uuid.UUID, service: Service, _user: Viewer, http_response: Response
) -> ApplicationRead:
    """One application by id (404 problem details when unknown).

    Emits the row's ``ETag`` so a client can read the token here and echo it in
    the ``If-Match`` of a later conditional PATCH/DELETE (N1).
    """
    row = await service.get(application_id)
    http_response.headers["ETag"] = _etag(row)
    return ApplicationRead.model_validate(row)


@router.get("/{application_id}/dependencies", response_model=list[ApplicationDependencyRead])
async def list_application_dependencies(
    application_id: uuid.UUID, service: Service, _user: Viewer
) -> list[ApplicationDependencyRead]:
    """Every dependency row of one application — all four sources, per-source rows."""
    rows = await service.list_dependencies(application_id)
    return [ApplicationDependencyRead.model_validate(row) for row in rows]


@router.post("", response_model=ApplicationRead, status_code=201)
async def create_application(
    body: ApplicationCreate, service: Service, user: Engineer, http_response: Response
) -> ApplicationRead:
    """Create one ``manual``-origin application; audits ``application.create``.

    The 201 carries the new row's ``ETag`` so a client can precondition a
    follow-up edit without a round-trip GET (N1).
    """
    row = await service.create(body, user)
    http_response.headers["ETag"] = _etag(row)
    return ApplicationRead.model_validate(row)


@router.patch("/{application_id}", response_model=ApplicationRead)
async def update_application(
    application_id: uuid.UUID,
    body: ApplicationUpdate,
    service: Service,
    user: Engineer,
    http_response: Response,
    if_match: Annotated[str | None, Header(alias="If-Match")] = None,
) -> ApplicationRead:
    """Update attributes; audits ``application.update`` with before/after state.

    Optimistic concurrency (N1): the PATCH is mandatory-conditional. The caller
    MUST send ``If-Match`` carrying the ``updated_at`` ETag it last read; a
    missing header is 428, a malformed one 400, and a token that no longer
    matches the current row is 409 ``stale-precondition`` — so two engineers
    editing the same application from stale modal state cannot silently clobber
    each other (a lost update). The row is locked ``FOR UPDATE`` for the read so
    the compare-then-write cannot race on PostgreSQL. A rejected precondition
    raises BEFORE any state snapshot, mutation, flush, or audit, so the failed
    attempt leaves no ``application.update`` entry and mutates nothing.

    Allowed on both origins: editing a ``derived`` row's attributes is the
    §3.3.3 manual-wins handoff — ``updated_at`` moves (house ``onupdate``)
    while ``derived_watermark`` stays, so no derivation pass may overwrite the
    user's curation again. ``origin``/``origin_ref`` are not editable.
    """
    row = await service.prepare_update(application_id)
    row = await service.apply_update(row, body, user, _parse_if_match(if_match))
    http_response.headers["ETag"] = _etag(row)
    return ApplicationRead.model_validate(row)


@router.delete("/{application_id}", status_code=204)
async def delete_application(
    application_id: uuid.UUID,
    service: Service,
    user: Engineer,
    if_match: Annotated[str | None, Header(alias="If-Match")] = None,
) -> Response:
    """Delete one ``manual`` application; audits ``application.delete``.

    409 for ``derived`` rows — they are lifecycle-owned by derivation and would
    silently resurrect on the next pass (ADR-0052 §3.3.5). The cascade-deleted
    dependency rows (``ON DELETE CASCADE``) are recorded in the audit entry so
    every retracted edge stays answerable from the trail.

    ``If-Match`` is OPTIONAL here (unlike the PATCH): a token-less delete still
    succeeds, but when the caller DOES send one it is enforced — a stale token
    is 409 ``stale-precondition`` (a malformed one 400), so a delete issued from
    a view the user edited elsewhere cannot destroy a row that changed under
    them. The row is locked ``FOR UPDATE`` for the read.
    """
    row = await service.prepare_delete(application_id)
    expected = _parse_if_match(if_match) if if_match is not None else None
    await service.apply_delete(row, user, expected)
    return Response(status_code=204)


@router.post(
    "/{application_id}/dependencies", response_model=ApplicationDependencyRead, status_code=201
)
async def create_application_dependency(
    application_id: uuid.UUID,
    body: ApplicationDependencyCreate,
    service: Service,
    user: Engineer,
) -> ApplicationDependencyRead:
    """Tag one object into an application (ONE ``source='manual'`` row);
    audits ``application_dependency.create``."""
    row = await service.create_dependency(application_id, body, user)
    return ApplicationDependencyRead.model_validate(row)


@router.delete("/{application_id}/dependencies/{dependency_id}", status_code=204)
async def delete_application_dependency(
    application_id: uuid.UUID,
    dependency_id: uuid.UUID,
    service: Service,
    user: Engineer,
) -> Response:
    """Remove one ``manual`` dependency row; audits ``application_dependency.delete``.

    409 for derivation-owned rows (``source != 'manual'``): they are retracted
    by their source's next derivation pass, never by user delete (ADR-0052
    §3.3.1/§3.3.2 row ownership).
    """
    await service.delete_dependency(application_id, dependency_id, user)
    return Response(status_code=204)
