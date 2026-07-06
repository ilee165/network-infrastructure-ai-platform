"""Virtualization (VMware) inventory routes (W1-T3): read-only list/detail, viewer+ floor.

Mirrors ``app/api/v1/devices.py`` (M1-15) one-for-one: viewer+ RBAC floor,
paginated/filterable list endpoints, 404 problem details on an unknown id.
**No write path** — see the module docstring in ``app/api/v1/adc.py`` for the
same named deferral on live-collection wiring.

Power state / template, and connection state / maintenance mode, are each
surfaced as **separate dimensions** (ADR-0051 §5.4) — the API never collapses
one into the other. Tools-less VMs (``guest_ip_addresses=[]``), standalone
hosts (``cluster_name=None``), and empty pools render as data, not errors
(empty-state honesty).
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy import Select, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, require_role
from app.core.errors import NotFoundError
from app.models import (
    NormalizedComputeClusterRow,
    NormalizedHypervisorHostRow,
    NormalizedPortGroupRow,
    NormalizedVirtualMachineRow,
    User,
)
from app.schemas.normalized import HostConnectionState, VirtualSwitchType, VmPowerState
from app.schemas.virtualization import (
    ComputeClusterListResponse,
    ComputeClusterRead,
    HypervisorHostListResponse,
    HypervisorHostRead,
    PortGroupListResponse,
    PortGroupRead,
    VirtualMachineListResponse,
    VirtualMachineRead,
)

router = APIRouter(prefix="/virtualization", tags=["virtualization"])

DbSession = Annotated[AsyncSession, Depends(get_db)]
Viewer = Annotated[User, Depends(require_role("viewer"))]


@router.get("/vms", response_model=VirtualMachineListResponse)
async def list_virtual_machines(
    session: DbSession,
    _user: Viewer,
    device_id: Annotated[uuid.UUID | None, Query()] = None,
    power_state: Annotated[VmPowerState | None, Query()] = None,
    cluster_name: Annotated[str | None, Query(max_length=255)] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> VirtualMachineListResponse:
    """List virtual machines, filterable by device/power state/cluster, paginated."""
    query: Select[tuple[NormalizedVirtualMachineRow]] = select(NormalizedVirtualMachineRow)
    if device_id is not None:
        query = query.where(NormalizedVirtualMachineRow.device_id == device_id)
    if power_state is not None:
        query = query.where(NormalizedVirtualMachineRow.power_state == power_state)
    if cluster_name is not None:
        query = query.where(NormalizedVirtualMachineRow.cluster_name == cluster_name)
    total = (await session.execute(select(func.count()).select_from(query.subquery()))).scalar_one()
    rows = (
        (
            await session.execute(
                query.order_by(NormalizedVirtualMachineRow.name, NormalizedVirtualMachineRow.id)
                .limit(limit)
                .offset(offset)
            )
        )
        .scalars()
        .all()
    )
    return VirtualMachineListResponse(
        items=[VirtualMachineRead.model_validate(row) for row in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/vms/{vm_id}", response_model=VirtualMachineRead)
async def get_virtual_machine(
    vm_id: uuid.UUID, session: DbSession, _user: Viewer
) -> VirtualMachineRead:
    """One virtual machine by id (404 problem details when unknown)."""
    row = await session.get(NormalizedVirtualMachineRow, vm_id)
    if row is None:
        raise NotFoundError(f"virtual machine {vm_id} does not exist")
    return VirtualMachineRead.model_validate(row)


@router.get("/hosts", response_model=HypervisorHostListResponse)
async def list_hypervisor_hosts(
    session: DbSession,
    _user: Viewer,
    device_id: Annotated[uuid.UUID | None, Query()] = None,
    connection_state: Annotated[HostConnectionState | None, Query()] = None,
    cluster_name: Annotated[str | None, Query(max_length=255)] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> HypervisorHostListResponse:
    """List hypervisor hosts, filterable by device/connection state/cluster."""
    query: Select[tuple[NormalizedHypervisorHostRow]] = select(NormalizedHypervisorHostRow)
    if device_id is not None:
        query = query.where(NormalizedHypervisorHostRow.device_id == device_id)
    if connection_state is not None:
        query = query.where(NormalizedHypervisorHostRow.connection_state == connection_state)
    if cluster_name is not None:
        query = query.where(NormalizedHypervisorHostRow.cluster_name == cluster_name)
    total = (await session.execute(select(func.count()).select_from(query.subquery()))).scalar_one()
    rows = (
        (
            await session.execute(
                query.order_by(NormalizedHypervisorHostRow.name, NormalizedHypervisorHostRow.id)
                .limit(limit)
                .offset(offset)
            )
        )
        .scalars()
        .all()
    )
    return HypervisorHostListResponse(
        items=[HypervisorHostRead.model_validate(row) for row in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/hosts/{host_id}", response_model=HypervisorHostRead)
async def get_hypervisor_host(
    host_id: uuid.UUID, session: DbSession, _user: Viewer
) -> HypervisorHostRead:
    """One hypervisor host by id (404 problem details when unknown)."""
    row = await session.get(NormalizedHypervisorHostRow, host_id)
    if row is None:
        raise NotFoundError(f"hypervisor host {host_id} does not exist")
    return HypervisorHostRead.model_validate(row)


@router.get("/clusters", response_model=ComputeClusterListResponse)
async def list_compute_clusters(
    session: DbSession,
    _user: Viewer,
    device_id: Annotated[uuid.UUID | None, Query()] = None,
    datacenter: Annotated[str | None, Query(max_length=255)] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> ComputeClusterListResponse:
    """List compute clusters, filterable by device/datacenter."""
    query: Select[tuple[NormalizedComputeClusterRow]] = select(NormalizedComputeClusterRow)
    if device_id is not None:
        query = query.where(NormalizedComputeClusterRow.device_id == device_id)
    if datacenter is not None:
        query = query.where(NormalizedComputeClusterRow.datacenter == datacenter)
    total = (await session.execute(select(func.count()).select_from(query.subquery()))).scalar_one()
    rows = (
        (
            await session.execute(
                query.order_by(NormalizedComputeClusterRow.name, NormalizedComputeClusterRow.id)
                .limit(limit)
                .offset(offset)
            )
        )
        .scalars()
        .all()
    )
    return ComputeClusterListResponse(
        items=[ComputeClusterRead.model_validate(row) for row in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/clusters/{cluster_id}", response_model=ComputeClusterRead)
async def get_compute_cluster(
    cluster_id: uuid.UUID, session: DbSession, _user: Viewer
) -> ComputeClusterRead:
    """One compute cluster by id (404 problem details when unknown)."""
    row = await session.get(NormalizedComputeClusterRow, cluster_id)
    if row is None:
        raise NotFoundError(f"compute cluster {cluster_id} does not exist")
    return ComputeClusterRead.model_validate(row)


@router.get("/port-groups", response_model=PortGroupListResponse)
async def list_port_groups(
    session: DbSession,
    _user: Viewer,
    device_id: Annotated[uuid.UUID | None, Query()] = None,
    switch_type: Annotated[VirtualSwitchType | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> PortGroupListResponse:
    """List standard + distributed port groups, filterable by device/switch type."""
    query: Select[tuple[NormalizedPortGroupRow]] = select(NormalizedPortGroupRow)
    if device_id is not None:
        query = query.where(NormalizedPortGroupRow.device_id == device_id)
    if switch_type is not None:
        query = query.where(NormalizedPortGroupRow.switch_type == switch_type)
    total = (await session.execute(select(func.count()).select_from(query.subquery()))).scalar_one()
    rows = (
        (
            await session.execute(
                query.order_by(NormalizedPortGroupRow.name, NormalizedPortGroupRow.id)
                .limit(limit)
                .offset(offset)
            )
        )
        .scalars()
        .all()
    )
    return PortGroupListResponse(
        items=[PortGroupRead.model_validate(row) for row in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/port-groups/{port_group_id}", response_model=PortGroupRead)
async def get_port_group(
    port_group_id: uuid.UUID, session: DbSession, _user: Viewer
) -> PortGroupRead:
    """One port group by id (404 problem details when unknown)."""
    row = await session.get(NormalizedPortGroupRow, port_group_id)
    if row is None:
        raise NotFoundError(f"port group {port_group_id} does not exist")
    return PortGroupRead.model_validate(row)
