"""HTTP routes for manual application tagging (ADR-0052 §7)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Header, Query, Response

from app.api.deps import get_db, require_role
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

Viewer = Annotated[Any, Depends(require_role("viewer"))]
Engineer = Annotated[Any, Depends(require_role("engineer"))]


def get_application_service(session: Annotated[Any, Depends(get_db)]) -> ApplicationService:
    """Bind the service to the request's overridable persistence lifecycle."""
    return ApplicationService(session)


Service = Annotated[ApplicationService, Depends(get_application_service)]


def _etag(application: Any) -> str:
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
    row = await service.get(application_id)
    http_response.headers["ETag"] = _etag(row)
    return ApplicationRead.model_validate(row)


@router.get("/{application_id}/dependencies", response_model=list[ApplicationDependencyRead])
async def list_application_dependencies(
    application_id: uuid.UUID, service: Service, _user: Viewer
) -> list[ApplicationDependencyRead]:
    rows = await service.list_dependencies(application_id)
    return [ApplicationDependencyRead.model_validate(row) for row in rows]


@router.post("", response_model=ApplicationRead, status_code=201)
async def create_application(
    body: ApplicationCreate, service: Service, user: Engineer, http_response: Response
) -> ApplicationRead:
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
    expected = _parse_if_match(if_match) if if_match is not None else None
    await service.delete(application_id, user, expected)
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
    row = await service.create_dependency(application_id, body, user)
    return ApplicationDependencyRead.model_validate(row)


@router.delete("/{application_id}/dependencies/{dependency_id}", status_code=204)
async def delete_application_dependency(
    application_id: uuid.UUID,
    dependency_id: uuid.UUID,
    service: Service,
    user: Engineer,
) -> Response:
    await service.delete_dependency(application_id, dependency_id, user)
    return Response(status_code=204)
