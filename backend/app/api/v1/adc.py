"""ADC (F5 BIG-IP) inventory routes (W1-T3): read-only list/detail, viewer+ floor.

Mirrors ``app/api/v1/devices.py`` (M1-15) one-for-one: viewer+ RBAC floor,
paginated/filterable list endpoints, 404 problem details on an unknown id.
**No write path** — these tables are populated the same way the existing
``Normalized*Row`` fixtures are (direct ORM inserts today; a future task wires
a live F5 collection pass into an upsert pipeline, ADR-0050 §4.7).

Availability and admin-state are surfaced as **separate dimensions** (ADR-0050
§4.4): the API never collapses a pool member's ``admin_state`` into its
``availability``, or vice versa.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy import Select, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, require_role
from app.core.errors import NotFoundError
from app.models import NormalizedPoolRow, NormalizedVirtualServerRow, User
from app.schemas.adc import (
    PoolListResponse,
    PoolRead,
    VirtualServerListResponse,
    VirtualServerRead,
)
from app.schemas.normalized import AdcAvailability

router = APIRouter(prefix="/adc", tags=["adc"])

DbSession = Annotated[AsyncSession, Depends(get_db)]
Viewer = Annotated[User, Depends(require_role("viewer"))]


@router.get("/virtual-servers", response_model=VirtualServerListResponse)
async def list_virtual_servers(
    session: DbSession,
    _user: Viewer,
    device_id: Annotated[uuid.UUID | None, Query()] = None,
    availability: Annotated[AdcAvailability | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> VirtualServerListResponse:
    """List ADC virtual servers, filterable by device/availability, paginated."""
    query: Select[tuple[NormalizedVirtualServerRow]] = select(NormalizedVirtualServerRow)
    if device_id is not None:
        query = query.where(NormalizedVirtualServerRow.device_id == device_id)
    if availability is not None:
        query = query.where(NormalizedVirtualServerRow.availability == availability)
    total = (await session.execute(select(func.count()).select_from(query.subquery()))).scalar_one()
    rows = (
        (
            await session.execute(
                query.order_by(NormalizedVirtualServerRow.name, NormalizedVirtualServerRow.id)
                .limit(limit)
                .offset(offset)
            )
        )
        .scalars()
        .all()
    )
    return VirtualServerListResponse(
        items=[VirtualServerRead.model_validate(row) for row in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/virtual-servers/{virtual_server_id}", response_model=VirtualServerRead)
async def get_virtual_server(
    virtual_server_id: uuid.UUID, session: DbSession, _user: Viewer
) -> VirtualServerRead:
    """One ADC virtual server by id (404 problem details when unknown)."""
    row = await session.get(NormalizedVirtualServerRow, virtual_server_id)
    if row is None:
        raise NotFoundError(f"virtual server {virtual_server_id} does not exist")
    return VirtualServerRead.model_validate(row)


@router.get("/pools", response_model=PoolListResponse)
async def list_pools(
    session: DbSession,
    _user: Viewer,
    device_id: Annotated[uuid.UUID | None, Query()] = None,
    availability: Annotated[AdcAvailability | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> PoolListResponse:
    """List ADC pools (with nested members), filterable by device/availability."""
    query: Select[tuple[NormalizedPoolRow]] = select(NormalizedPoolRow)
    if device_id is not None:
        query = query.where(NormalizedPoolRow.device_id == device_id)
    if availability is not None:
        query = query.where(NormalizedPoolRow.availability == availability)
    total = (await session.execute(select(func.count()).select_from(query.subquery()))).scalar_one()
    rows = (
        (
            await session.execute(
                query.order_by(NormalizedPoolRow.name, NormalizedPoolRow.id)
                .limit(limit)
                .offset(offset)
            )
        )
        .scalars()
        .all()
    )
    return PoolListResponse(
        items=[PoolRead.model_validate(row) for row in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/pools/{pool_id}", response_model=PoolRead)
async def get_pool(pool_id: uuid.UUID, session: DbSession, _user: Viewer) -> PoolRead:
    """One ADC pool with nested members by id (404 problem details when unknown)."""
    row = await session.get(NormalizedPoolRow, pool_id)
    if row is None:
        raise NotFoundError(f"pool {pool_id} does not exist")
    return PoolRead.model_validate(row)
