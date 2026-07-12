"""Operator full-rebuild entrypoint for the Neo4j topology projection (M2-09).

Run as a module::

    python -m app.engines.topology.rebuild

It drops every projected node label, re-asserts the uniqueness constraints and
re-projects the *entire* current Postgres inventory into Neo4j
(:func:`app.engines.topology.projector.full_rebuild`), then writes a
``topology_snapshot`` for the run id supplied via ``--run-id`` (when given).

The full rebuild is the ADR-0005 recovery path: Neo4j is a pure projection of
Postgres, so a drop-and-reproject must always reconstruct the graph from the
relational source of truth alone.  Unlike the per-run
``topology.sync_after_run`` task, failures here are **not** isolated — the
command exits non-zero so an operator (or CI/automation) sees the error.

``--run-id`` is optional: when omitted no snapshot is written (a bare rebuild
of the graph), which is the common "the graph drifted, reproject it" case.
"""

from __future__ import annotations

import argparse
import asyncio
from typing import Any
from uuid import UUID

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app import db
from app.core.config import get_settings
from app.engines.topology.projector import full_rebuild
from app.engines.topology.snapshots import upsert_snapshot
from app.engines.topology.sync import derive_topology, snapshot_lists
from app.knowledge.neo4j_client import create_client
from app.models.applications import Application, ApplicationDependency
from app.models.inventory import (
    Device,
    NormalizedInterfaceRow,
    NormalizedNeighborRow,
    NormalizedRouteRow,
)
from app.models.mixins import utcnow

logger = structlog.get_logger(__name__)

__all__ = ["main", "rebuild"]


async def rebuild(run_id: UUID | None = None) -> dict[str, Any]:
    """Drop and re-project the whole topology subgraph from Postgres.

    Loads every device + normalized row, derives the node/edge sets, runs
    :func:`app.engines.topology.projector.full_rebuild` (wipe + constraints +
    project), and — when *run_id* is given — writes that run's
    ``topology_snapshot``.  Returns a JSON-safe summary of what was projected.
    """
    settings = get_settings()
    engine = db.create_engine(settings)
    client = create_client(settings)
    projected_at = utcnow()
    try:
        async with db.create_sessionmaker(engine)() as session:
            (
                devices,
                interfaces,
                routes,
                neighbors,
                applications,
                dependencies,
            ) = await _load_inventory(session)
            derived = derive_topology(
                devices, interfaces, routes, neighbors, applications, dependencies
            )
            node_list, edge_list = snapshot_lists(
                derived.nodes, derived.edges, derived.applications
            )

            await full_rebuild(
                client,
                derived.nodes,
                derived.edges,
                projected_at,
                applications=derived.applications,
            )

            if run_id is not None:
                await upsert_snapshot(session, run_id=run_id, nodes=node_list, edges=edge_list)
                await session.commit()
    finally:
        await client.close()
        await engine.dispose()

    summary = {
        "ok": True,
        "projected_at": projected_at.isoformat(),
        "nodes": len(node_list),
        "edges": len(edge_list),
        "run_id": str(run_id) if run_id is not None else None,
    }
    logger.info(
        "topology.full_rebuild_complete",
        nodes=summary["nodes"],
        edges=summary["edges"],
        run_id=summary["run_id"],
    )
    return summary


async def _load_inventory(
    session: AsyncSession,
) -> tuple[
    list[Device],
    list[NormalizedInterfaceRow],
    list[NormalizedRouteRow],
    list[NormalizedNeighborRow],
    list[Application],
    list[ApplicationDependency],
]:
    """Load every device + normalized row + application row (whole inventory).

    Delegates to the shared Wave 5 loader so rebuild and discovery-sync cannot
    drift. The application layer is part of EVERY projection pass (ADR-0052 §5).
    """
    from app.engines.topology.inventory_load import load_inventory

    bundle = await load_inventory(session, device_ids=None)
    return (
        bundle.devices,
        bundle.interfaces,
        bundle.routes,
        bundle.neighbors,
        bundle.applications,
        bundle.application_dependencies,
    )


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="python -m app.engines.topology.rebuild",
        description="Drop and re-project the whole Neo4j topology from Postgres.",
    )
    parser.add_argument(
        "--run-id",
        type=UUID,
        default=None,
        help="discovery run id to write the topology snapshot for (optional).",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """CLI entry: parse args, run the rebuild, return a process exit code."""
    args = _parse_args(argv)
    try:
        asyncio.run(rebuild(args.run_id))
    except Exception as exc:
        logger.error("topology.rebuild_failed", error=str(exc))
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover - module execution shim
    raise SystemExit(main())
