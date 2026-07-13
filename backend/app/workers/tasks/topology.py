"""Celery topology task (M2-09): project one discovery run into Neo4j.

``topology.sync_after_run`` is triggered automatically when a
``discovery.run`` finishes with devices discovered (see
:func:`app.workers.tasks.discovery.run_discovery`).  It is the bridge between
the Postgres ``normalized_*`` tables and the Neo4j projection (ADR-0005): it

0. runs the **application-dependency derivation pass** (ADR-0052 §2/§5 —
   the post-discovery-run trigger for sources 1-3): loads the persisted ADC
   (W1-T1) and virtualization (W1-T2) rows plus inventory and the current
   application tables, fetches the DDI record set for source 3 through the
   :func:`_fetch_dns_records` seam (``None`` = skip, preserving persisted
   source-3 rows), computes the pure
   :func:`~app.engines.topology.app_derivation.derive_application_dependencies`
   plan, and persists it in one transaction via
   :func:`~app.engines.topology.app_derivation_store.apply_derivation_plan`.
   Derivation only WRITES the PG tables — it never projects (writes flow one
   way, ADR-0005 §5) — and a derivation failure never blocks the projection
   (the pass then projects the previous rows),
1. loads the devices + normalized interface/route/neighbor rows AND the
   application-dependency rows (``applications`` + ``application_dependencies``,
   ADR-0052 §5 — the layer is part of EVERY projection pass) from Postgres,
2. derives the typed node/edge/application sets (:func:`app.engines.topology.sync`),
3. ensures the graph uniqueness constraints,
4. runs one *incremental* projection pass
   (:func:`app.engines.topology.projector.project`), and
5. writes the per-run ``topology_snapshot`` (the diff foundation).

Failure isolation (ADR-0005 / M2 plan): the discovery run is already finished
and committed before this task runs.  A projection failure here must therefore
**never** be allowed to surface as a discovery failure — the task swallows the
exception, logs it, and records a ``topology_sync`` block in ``run.stats`` so
the outcome is observable without touching the run's terminal status.  The
derivation step is isolated the same way, under its own
``application_derivation`` stats block.

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
from app.engines.topology.app_derivation import derive_application_dependencies
from app.engines.topology.app_derivation_store import apply_derivation_plan
from app.engines.topology.inventory_load import (
    InventoryBundle,
    filter_derived_for_scope,
    interface_ids_for_scope,
    load_inventory,
    run_touched_device_ids,
)
from app.engines.topology.projector import project
from app.engines.topology.snapshots import upsert_snapshot
from app.engines.topology.sync import derive_topology, snapshot_lists
from app.knowledge.neo4j_client import Neo4jClient, create_client
from app.knowledge.schema import ensure_constraints
from app.models import DiscoveryRun
from app.models.adc import NormalizedPoolRow, NormalizedVirtualServerRow
from app.models.applications import Application, ApplicationDependency
from app.models.inventory import (
    Device,
    NormalizedInterfaceRow,
)
from app.models.mixins import utcnow
from app.models.virtualization import NormalizedHypervisorHostRow, NormalizedVirtualMachineRow
from app.schemas.normalized import NormalizedDnsRecord
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
    """Create a fresh Neo4j client for one task invocation (loop-scoped)."""
    return create_client(get_settings())


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
# Inventory loading (shared with rebuild — Wave 5 T4)
# ---------------------------------------------------------------------------


async def _load_inventory(session: AsyncSession) -> InventoryBundle:
    """Load the full inventory (write-set scoping happens post-derivation)."""
    return await load_inventory(session)


# ---------------------------------------------------------------------------
# Application-dependency derivation pass (ADR-0052 §2/§5 — step 0)
# ---------------------------------------------------------------------------


def _fetch_dns_records() -> list[NormalizedDnsRecord] | None:
    """Caller-side DDI fetch for source 3 (the ADR-0052 §2 input-side exception).

    Returns the full DDI-normalized record set, or ``None`` when no DDI read
    is available — the derivation then SKIPS the dns pass, preserving the
    persisted source-3 rows (an outage must never read as "no DNS evidence"
    and delete results the rebuild contract depends on).

    No worker-side DDI REST read path exists yet: it is the same W1-T3 named
    deferral that leaves the ``adc_*``/``virt_*`` tables to a future
    collection task (the SSH/SNMP-only ``collect_device`` dispatch covers
    neither, see :mod:`app.models.adc`). Until that collection pass lands,
    the production default is ``None``; tests (and a future composition
    root) monkeypatch/override this seam — the derivation and diff-replace
    of source 3 are fully exercised against fixture records either way.
    """
    return None


async def _derive_applications() -> dict[str, Any]:
    """Run the pre-projection derivation for sources 1-3 and persist it.

    Loads every input on this side (the derivation function is pure: no
    session, no plugin, no DDI call inside), applies the plan in ONE
    transaction, and returns a JSON-safe stats block (planned counters per
    source + rows actually written). Raised exceptions propagate to
    :func:`sync_after_run`, which isolates them from the projection and the
    discovery run.
    """
    dns_records = _fetch_dns_records()
    async with _session() as session:
        virtual_servers = list(
            (await session.execute(select(NormalizedVirtualServerRow))).scalars()
        )
        pools = list((await session.execute(select(NormalizedPoolRow))).scalars())
        virtual_machines = list(
            (await session.execute(select(NormalizedVirtualMachineRow))).scalars()
        )
        hypervisor_hosts = list(
            (await session.execute(select(NormalizedHypervisorHostRow))).scalars()
        )
        devices = list((await session.execute(select(Device))).scalars())
        interfaces = list((await session.execute(select(NormalizedInterfaceRow))).scalars())
        applications = list((await session.execute(select(Application))).scalars())
        dependencies = list((await session.execute(select(ApplicationDependency))).scalars())

        plan = derive_application_dependencies(
            virtual_servers=virtual_servers,
            pools=pools,
            virtual_machines=virtual_machines,
            hypervisor_hosts=hypervisor_hosts,
            devices=devices,
            interfaces=interfaces,
            applications=applications,
            dependencies=dependencies,
            dns_records=dns_records,
        )
        applied = await apply_derivation_plan(session, plan)
        await session.commit()

    return {
        "ok": True,
        "dns_pass_ran": plan.dns_pass_ran,
        "planned": plan.stats.model_dump(),
        "applied": applied.model_dump(),
    }


# ---------------------------------------------------------------------------
# Projection pass
# ---------------------------------------------------------------------------


async def _project_run(run_id: UUID) -> dict[str, Any]:
    """Derive, project (delta when possible), and snapshot.

    Wave 5 / perf #9: when the discovery run touched a subset of devices
    (``raw_artifacts`` for *run_id*), **Neo4j writes** are filtered to that
    touch-set — shared Subnet/Vlan/VRF/Site nodes referenced-only, PR #161
    review — with ``stale_sweep=False`` so untouched estate nodes are not
    deleted. Full rebuild remains the GC path.

    Derivation and the run snapshot always use the FULL inventory: a scoped
    derivation cannot see cross-scope subnet/neighbor joins (missing
    ``L3_ADJACENT`` edges, device-level ``CONNECTED_TO`` fallbacks), and a
    scope-truncated snapshot makes the run-to-run diff report every untouched
    device as removed. The delta win is the write path, not the row load.

    Returns a JSON-safe stats block describing what was projected. Raised
    exceptions propagate to :func:`sync_after_run`, which isolates them from
    the discovery run's status.
    """
    projected_at = utcnow()
    client = _neo4j_client()
    stats: dict[str, Any] = {"ok": True, "projected_at": projected_at.isoformat()}
    try:
        async with _session() as session:
            touched = await run_touched_device_ids(session, run_id)
            # Non-empty touch set scopes the Neo4j WRITE set below; the load
            # and the snapshot stay estate-wide (correct diffs + cross-scope
            # edges). Empty touch set (no artifacts) means a full pass.
            scope = touched if touched else None
            inventory = await _load_inventory(session)
            derived = derive_topology(
                inventory.devices,
                inventory.interfaces,
                inventory.routes,
                inventory.neighbors,
                inventory.applications,
                inventory.application_dependencies,
            )
            node_list, edge_list = snapshot_lists(
                derived.nodes, derived.edges, derived.applications
            )

            proj_nodes = derived.nodes
            proj_edges = derived.edges
            proj_apps = derived.applications
            delta = False
            if scope is not None:
                iface_ids = interface_ids_for_scope(inventory.interfaces, scope)
                proj_nodes, proj_edges, proj_apps = filter_derived_for_scope(
                    nodes=derived.nodes,
                    edges=derived.edges,
                    applications=derived.applications,
                    scope_device_ids=scope,
                    scope_interface_ids=iface_ids,
                    interfaces=inventory.interfaces,
                )
                delta = True

            await ensure_constraints(client)
            await project(
                client,
                proj_nodes,
                proj_edges,
                projected_at,
                applications=proj_apps,
                # Delta path: upsert only; no estate-wide stale sweep (Option B).
                stale_sweep=not delta,
            )

            await upsert_snapshot(session, run_id=run_id, nodes=node_list, edges=edge_list)
            await session.commit()

            stats.update(
                {
                    "nodes": len(node_list),
                    "edges": len(edge_list),
                    "nodes_written": (
                        len(proj_nodes.devices)
                        + len(proj_nodes.interfaces)
                        + len(proj_nodes.ip_addresses)
                        + len(proj_nodes.subnets)
                        + len(proj_nodes.vlans)
                        + len(proj_nodes.vrfs)
                        + len(proj_nodes.sites)
                    ),
                    "delta": delta,
                    "scope_devices": len(scope) if scope is not None else None,
                    "unresolved_neighbors": derived.l2_report.unresolved_neighbors,
                }
            )
    finally:
        await client.close()

    return stats


async def _record_sync_stats(
    run_id: UUID, sync_stats: dict[str, Any], derivation_stats: dict[str, Any]
) -> None:
    """Merge the ``topology_sync`` + ``application_derivation`` blocks into
    the run's stats (best-effort).

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
        stats["application_derivation"] = derivation_stats
        run.stats = stats
        await session.commit()


# ---------------------------------------------------------------------------
# Task: topology.sync_after_run
# ---------------------------------------------------------------------------


@celery_app.task(name="topology.sync_after_run")
def sync_after_run(run_id: str) -> dict[str, Any]:
    """Derive application dependencies, project the inventory, snapshot it.

    Always returns a JSON-safe summary and never re-raises: a derivation or
    projection failure is logged and recorded in the run's
    ``application_derivation`` / ``topology_sync`` stats blocks with
    ``ok=False`` so the already-finished discovery run is never degraded by a
    graph-side problem (ADR-0005 failure isolation).
    """
    run_uuid = uuid.UUID(run_id)

    # Step 0 — the post-discovery-run derivation trigger for sources 1-3
    # (ADR-0052 §5). Isolated exactly like the projection: a derivation
    # failure only means this pass projects the previous rows.
    try:
        derivation_stats = asyncio.run(_derive_applications())
        logger.info(
            "topology.derivation_complete",
            run_id=run_id,
            planned=derivation_stats["planned"],
            applied=derivation_stats["applied"],
        )
    except Exception as exc:  # derivation must not fail the sync or the run
        derivation_stats = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
        logger.warning(
            "topology.derivation_failed",
            run_id=run_id,
            error_type=type(exc).__name__,
        )

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
        asyncio.run(_record_sync_stats(run_uuid, sync_stats, derivation_stats))
    except Exception:  # stat recording is best-effort, never fatal
        logger.warning("topology.sync_stats_unrecorded", run_id=run_id)

    return {"run_id": run_id, "application_derivation": derivation_stats, **sync_stats}
