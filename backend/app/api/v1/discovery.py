"""Discovery run routes (M1-16): start a run, list runs, status, results.

Starting a run requires ``engineer`` (ADR-0010): the request is validated
through :class:`~app.engines.discovery.planner.DiscoveryPlan` (422 on
anything the engine would reject), the run row is created ``pending``, a
``discovery.run_started`` audit entry commits atomically with it, and only
after the commit is the ``discovery.run`` Celery task enqueued — the worker
always finds the row. Reads require any authenticated user (``viewer``).

Results are aggregated from the normalized tables, scoped to the devices the
run touched: a device was "touched" when the run wrote at least one raw
artifact for it (normalized rows themselves carry no ``run_id`` — they are
the device's latest state, upserted idempotently).
"""

from __future__ import annotations

import uuid
from typing import Annotated, Final

from fastapi import APIRouter, Depends, Query
from sqlalchemy import Select, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, require_role
from app.core.errors import NotFoundError
from app.models import (
    Device,
    DiscoveryRun,
    NormalizedInterfaceRow,
    NormalizedNeighborRow,
    NormalizedRouteRow,
    RawArtifact,
    User,
)
from app.schemas.discovery_api import (
    DiscoveredDeviceSummary,
    RunListResponse,
    RunResults,
    RunStatus,
    StartRunRequest,
)
from app.services import audit
from app.workers.celery_app import QUEUE_DISCOVERY
from app.workers.dispatch import durable_dispatch

router = APIRouter(prefix="/discovery", tags=["discovery"])

DbSession = Annotated[AsyncSession, Depends(get_db)]
Viewer = Annotated[User, Depends(require_role("viewer"))]
Engineer = Annotated[User, Depends(require_role("engineer"))]

_TARGET_TYPE: Final = "discovery_run"
#: Celery task name of the run orchestrator (app/workers/tasks/discovery.py).
RUN_TASK_NAME: Final = "discovery.run"


async def _get_run_or_404(session: AsyncSession, run_id: uuid.UUID) -> DiscoveryRun:
    run = await session.get(DiscoveryRun, run_id)
    if run is None:
        raise NotFoundError(f"discovery run {run_id} does not exist")
    return run


@router.post("/runs", response_model=RunStatus, status_code=202)
async def start_run(body: StartRunRequest, session: DbSession, user: Engineer) -> RunStatus:
    """Create a ``pending`` run and enqueue ``discovery.run``; audits the start.

    202: the work happens asynchronously on the ``discovery`` queue — poll
    ``GET /discovery/runs/{id}`` for lifecycle progress.
    """
    plan = body.to_plan()
    run = DiscoveryRun(
        seeds=list(plan.seeds),
        hop_limit=plan.hop_limit,
        allowlist=list(plan.allowlist),
        credential_names=list(plan.credential_names),
    )
    session.add(run)
    await session.flush()
    await audit.record(
        session,
        actor=f"user:{user.username}",
        action=audit.DISCOVERY_RUN_STARTED,
        target_type=_TARGET_TYPE,
        target_id=str(run.id),
        detail={
            "seeds": list(plan.seeds),
            "hop_limit": plan.hop_limit,
            "allowlist": list(plan.allowlist),
            # Credential *names* are vault references, never secret material;
            # still, only the count is needed for the trail.
            "credential_count": len(plan.credential_names),
        },
    )
    response = RunStatus.model_validate(run)
    await session.commit()
    durable_dispatch(task_name=RUN_TASK_NAME, args=[str(run.id)], queue=QUEUE_DISCOVERY)
    return response


@router.get("/runs", response_model=RunListResponse)
async def list_runs(
    session: DbSession,
    _user: Viewer,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> RunListResponse:
    """List discovery runs, newest first, paginated."""
    total = (await session.execute(select(func.count()).select_from(DiscoveryRun))).scalar_one()
    rows = (
        (
            await session.execute(
                select(DiscoveryRun)
                .order_by(DiscoveryRun.created_at.desc(), DiscoveryRun.id.desc())
                .limit(limit)
                .offset(offset)
            )
        )
        .scalars()
        .all()
    )
    return RunListResponse(
        items=[RunStatus.model_validate(row) for row in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/runs/{run_id}", response_model=RunStatus)
async def get_run(run_id: uuid.UUID, session: DbSession, _user: Viewer) -> RunStatus:
    """One run's lifecycle status (404 problem details when unknown)."""
    return RunStatus.model_validate(await _get_run_or_404(session, run_id))


@router.get("/runs/{run_id}/results", response_model=RunResults)
async def get_run_results(run_id: uuid.UUID, session: DbSession, _user: Viewer) -> RunResults:
    """Aggregated counts + device summaries for the devices the run touched."""
    run = await _get_run_or_404(session, run_id)
    touched_ids: Select[tuple[uuid.UUID]] = (
        select(RawArtifact.device_id).where(RawArtifact.run_id == run_id).distinct()
    )

    async def _count(query: Select[tuple[int]]) -> int:
        count: int = (await session.execute(query)).scalar_one()
        return count

    device_count = await _count(select(func.count()).select_from(touched_ids.subquery()))
    interface_count = await _count(
        select(func.count())
        .select_from(NormalizedInterfaceRow)
        .where(NormalizedInterfaceRow.device_id.in_(touched_ids))
    )
    route_count = await _count(
        select(func.count())
        .select_from(NormalizedRouteRow)
        .where(NormalizedRouteRow.device_id.in_(touched_ids))
    )
    neighbor_count = await _count(
        select(func.count())
        .select_from(NormalizedNeighborRow)
        .where(NormalizedNeighborRow.device_id.in_(touched_ids))
    )
    devices = (
        (
            await session.execute(
                select(Device)
                .where(Device.id.in_(touched_ids))
                .order_by(Device.hostname, Device.id)
            )
        )
        .scalars()
        .all()
    )
    return RunResults(
        run_id=run.id,
        status=run.status,
        device_count=device_count,
        interface_count=interface_count,
        route_count=route_count,
        neighbor_count=neighbor_count,
        devices=[DiscoveredDeviceSummary.model_validate(device) for device in devices],
    )
