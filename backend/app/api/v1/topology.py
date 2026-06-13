"""Topology REST API (M2-10, ADR-0005): read the projection, diff two runs.

Two read endpoints, both ``viewer``-and-above (reads never mutate the graph):

``GET /topology/graph``
    Returns the projected Neo4j subgraph (``nodes`` / ``edges`` /
    ``projected_at``) via :mod:`app.knowledge` — the only package that talks to
    Neo4j.  ``site`` / ``vrf`` scope the subgraph; ``layer`` (``l2`` / ``l3`` /
    ``all``) selects which relationship families are returned.  ``projected_at``
    surfaces the projection pass these answers are "as of" (ADR-0005).

``GET /topology/diff``
    Loads the two ``topology_snapshots`` rows for ``from_run`` / ``to_run`` from
    Postgres and returns the M2-08 diff (added/removed node & edge multisets).
    The diff is computed *within Postgres* from the canonical snapshots — never
    a live graph-vs-graph query.  A missing snapshot for either run is a 404
    RFC 7807 problem; invalid query params are rejected as 422 by FastAPI.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, get_knowledge_client, require_role
from app.core.errors import NotFoundError
from app.engines.topology.diff import diff_snapshots
from app.engines.topology.snapshots import SnapshotData
from app.knowledge import Neo4jClient, fetch_graph
from app.knowledge.topology_read import LAYER_ALL, LAYERS
from app.models import TopologySnapshot, User
from app.schemas.topology import GraphResponse, TopologyDiffResponse

router = APIRouter(prefix="/topology", tags=["topology"])

DbSession = Annotated[AsyncSession, Depends(get_db)]
KnowledgeClient = Annotated[Neo4jClient, Depends(get_knowledge_client)]
Viewer = Annotated[User, Depends(require_role("viewer"))]


async def _snapshot_or_404(session: AsyncSession, run_id: uuid.UUID) -> TopologySnapshot:
    """Load the canonical snapshot for *run_id* or raise a 404 problem."""
    snapshot = (
        await session.execute(select(TopologySnapshot).where(TopologySnapshot.run_id == run_id))
    ).scalar_one_or_none()
    if snapshot is None:
        raise NotFoundError(f"no topology snapshot exists for run {run_id}")
    return snapshot


def _snapshot_data(snapshot: TopologySnapshot) -> SnapshotData:
    """Coerce a stored snapshot row into the diff engine's canonical dict."""
    return {"nodes": snapshot.nodes or [], "edges": snapshot.edges or []}


@router.get("/graph", response_model=GraphResponse, summary="Read the projected topology graph")
async def get_graph(
    client: KnowledgeClient,
    _user: Viewer,
    site: Annotated[str | None, Query(max_length=255)] = None,
    vrf: Annotated[str | None, Query(max_length=255)] = None,
    layer: Annotated[str, Query(pattern="^(l2|l3|all)$")] = LAYER_ALL,
) -> GraphResponse:
    """Return the projected subgraph as of the latest projection pass.

    ``site`` / ``vrf`` scope the subgraph; ``layer`` selects the relationship
    families (``l2`` neighbors, ``l3`` adjacency/routing, or ``all``).
    ``projected_at`` is the most recent ``last_projected_at`` across the
    returned nodes (``null`` when the filtered subgraph is empty).
    """
    # ``layer`` is constrained by the pattern above; this guards the contract.
    if layer not in LAYERS:  # pragma: no cover - pattern enforces the set
        raise NotFoundError(f"unknown topology layer {layer!r}")
    graph = await fetch_graph(client, layer=layer, site=site, vrf=vrf)
    return GraphResponse.model_validate(graph)


@router.get("/diff", response_model=TopologyDiffResponse, summary="Diff two topology snapshots")
async def get_diff(
    session: DbSession,
    _user: Viewer,
    from_run: Annotated[uuid.UUID, Query(description="Baseline (earlier) run id.")],
    to_run: Annotated[uuid.UUID, Query(description="Compared (later) run id.")],
) -> TopologyDiffResponse:
    """Diff the snapshots of two discovery runs (added/removed nodes & edges).

    404 (RFC 7807) when either run has no ``topology_snapshots`` row; 422 when a
    run id is not a valid UUID.  The diff is computed entirely from the stored
    Postgres snapshots (ADR-0005), never from a live Neo4j query.
    """
    older = await _snapshot_or_404(session, from_run)
    newer = await _snapshot_or_404(session, to_run)
    diff = diff_snapshots(_snapshot_data(older), _snapshot_data(newer))
    return TopologyDiffResponse(from_run=from_run, to_run=to_run, diff=diff)
