"""Celery topology task (M2-09): project one discovery run into Neo4j.

``topology.sync_after_run`` is triggered automatically when a
``discovery.run`` finishes with devices discovered (see
:func:`app.workers.tasks.discovery.run_discovery`).  It is the bridge between
the Postgres ``normalized_*`` tables and the Neo4j projection (ADR-0005): it

1. loads the devices + normalized interface/route/neighbor rows from Postgres,
2. derives the typed node/edge sets (:func:`app.engines.topology.sync`),
3. ensures the graph uniqueness constraints,
4. runs one *incremental* projection pass
   (:func:`app.engines.topology.projector.project`), and
5. writes the per-run ``topology_snapshot`` (the diff foundation).

Failure isolation (ADR-0005 / M2 plan): the discovery run is already finished
and committed before this task runs.  A projection failure here must therefore
**never** be allowed to surface as a discovery failure — the task swallows the
exception, logs it, and records a ``topology_sync`` block in ``run.stats`` so
the outcome is observable without touching the run's terminal status.

Async DB / Neo4j from sync Celery: like the discovery tasks, each invocation
opens a fresh engine + event loop via ``asyncio.run``.  Module-level seams
(``_make_engine``, ``_neo4j_client``) let unit tests run everything eagerly
with fakes.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any
from uuid import UUID

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

from app import db
from app.core.config import get_settings
from app.engines.topology.projector import project
from app.engines.topology.snapshots import upsert_snapshot
from app.engines.topology.sync import derive_topology, snapshot_lists
from app.knowledge.neo4j_client import Neo4jClient, get_client
from app.knowledge.schema import ensure_constraints
from app.models import DiscoveryRun
from app.models.inventory import (
    Device,
    NormalizedInterfaceRow,
    NormalizedNeighborRow,
    NormalizedRouteRow,
)
from app.models.mixins import utcnow
from app.workers.celery_app import celery_app

__all__ = ["sync_after_run"]

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Seams (monkeypatched by unit tests)
# ---------------------------------------------------------------------------


def _make_engine() -> AsyncEngine:
    """New async engine for one task phase (loop-scoped, disposed after use)."""
    return db.create_engine(get_settings())


def _neo4j_client() -> Neo4jClient:
    """The process-wide Neo4j client used for the projection writes."""
    return get_client()


@asynccontextmanager
async def _session() -> AsyncIterator[AsyncSession]:
    """One AsyncSession on a fresh engine, disposed when the phase ends."""
    engine = _make_engine()
    try:
        async with db.create_sessionmaker(engine)() as session:
            yield session
    finally:
        await engine.dispose()


# ---------------------------------------------------------------------------
# Inventory loading
# ---------------------------------------------------------------------------


class _Inventory:
    """The four row sets a projection pass derives from."""

    __slots__ = ("devices", "interfaces", "neighbors", "routes")

    def __init__(
        self,
        devices: list[Device],
        interfaces: list[NormalizedInterfaceRow],
        routes: list[NormalizedRouteRow],
        neighbors: list[NormalizedNeighborRow],
    ) -> None:
        self.devices = devices
        self.interfaces = interfaces
        self.routes = routes
        self.neighbors = neighbors


async def _load_inventory(session: AsyncSession) -> _Inventory:
    """Load every device + normalized row (whole-inventory projection)."""
    devices = list((await session.execute(select(Device))).scalars())
    interfaces = list((await session.execute(select(NormalizedInterfaceRow))).scalars())
    routes = list((await session.execute(select(NormalizedRouteRow))).scalars())
    neighbors = list((await session.execute(select(NormalizedNeighborRow))).scalars())
    return _Inventory(devices, interfaces, routes, neighbors)


# ---------------------------------------------------------------------------
# Projection pass
# ---------------------------------------------------------------------------


async def _project_run(run_id: UUID) -> dict[str, Any]:
    """Derive, project incrementally, and snapshot the whole inventory.

    Returns a JSON-safe stats block describing what was projected. Raised
    exceptions propagate to :func:`sync_after_run`, which isolates them from
    the discovery run's status.
    """
    projected_at = utcnow()
    async with _session() as session:
        inventory = await _load_inventory(session)
        derived = derive_topology(
            inventory.devices,
            inventory.interfaces,
            inventory.routes,
            inventory.neighbors,
        )
        node_list, edge_list = snapshot_lists(derived.nodes, derived.edges)

        client = _neo4j_client()
        await ensure_constraints(client)
        await project(client, derived.nodes, derived.edges, projected_at)

        await upsert_snapshot(session, run_id=run_id, nodes=node_list, edges=edge_list)
        await session.commit()

    return {
        "ok": True,
        "projected_at": projected_at.isoformat(),
        "nodes": len(node_list),
        "edges": len(edge_list),
        "unresolved_neighbors": derived.l2_report.unresolved_neighbors,
    }


async def _record_sync_stats(run_id: UUID, sync_stats: dict[str, Any]) -> None:
    """Merge a ``topology_sync`` block into the run's stats (best-effort).

    Never raises for a missing run: the run is the parent FK of any snapshot,
    but recording is purely observational and must not mask the sync outcome.
    """
    async with _session() as session:
        run = await session.get(DiscoveryRun, run_id)
        if run is None:
            logger.warning("topology.sync_run_missing", run_id=str(run_id))
            return
        stats = dict(run.stats or {})
        stats["topology_sync"] = sync_stats
        run.stats = stats
        await session.commit()


# ---------------------------------------------------------------------------
# Task: topology.sync_after_run
# ---------------------------------------------------------------------------


@celery_app.task(name="topology.sync_after_run")
def sync_after_run(run_id: str) -> dict[str, Any]:
    """Project the current inventory into Neo4j and snapshot it for *run_id*.

    Always returns a JSON-safe summary and never re-raises: a projection
    failure is logged and recorded in ``run.stats['topology_sync']`` with
    ``ok=False`` so the already-finished discovery run is never degraded by a
    graph-side problem (ADR-0005 failure isolation).
    """
    run_uuid = uuid.UUID(run_id)
    try:
        sync_stats = asyncio.run(_project_run(run_uuid))
        logger.info(
            "topology.sync_complete",
            run_id=run_id,
            nodes=sync_stats["nodes"],
            edges=sync_stats["edges"],
        )
    except Exception as exc:  # projection must not fail the discovery run
        sync_stats = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
        logger.warning(
            "topology.sync_failed",
            run_id=run_id,
            error_type=type(exc).__name__,
        )

    try:
        asyncio.run(_record_sync_stats(run_uuid, sync_stats))
    except Exception:  # stat recording is best-effort, never fatal
        logger.warning("topology.sync_stats_unrecorded", run_id=run_id)

    return {"run_id": run_id, **sync_stats}
