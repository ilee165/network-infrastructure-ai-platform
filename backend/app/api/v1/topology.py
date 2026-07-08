"""Topology REST API (M2-10, ADR-0005): read the projection, diff two runs.

Read endpoints, all ``viewer``-and-above (reads never mutate the graph):

``GET /topology/graph``
    Returns the projected Neo4j subgraph (``nodes`` / ``edges`` /
    ``projected_at``) via :mod:`app.knowledge` — the only package that talks to
    Neo4j.  ``site`` / ``vrf`` scope the subgraph; ``layer`` (``l2`` / ``l3`` /
    ``all``) selects which relationship families are returned.  ``projected_at``
    surfaces the projection pass these answers are "as of" (ADR-0005).

``GET /topology/graph/neighborhood``
    The scoped variant (audit Wave 5, ARCH_DEBT #7): the subgraph within
    ``depth`` hops of one device (``device`` = the projected ``Device`` key),
    same ``layer`` semantics and wire shape as ``/graph``.

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

from app.api.deps import get_app_settings, get_db, get_knowledge_client, require_role
from app.core.config import Settings
from app.core.errors import GraphTooLargeError, NotFoundError
from app.engines.topology.diff import diff_snapshots
from app.engines.topology.snapshots import SnapshotData
from app.knowledge import Neo4jClient, count_graph_nodes, fetch_graph, fetch_neighborhood
from app.knowledge.schema import (
    LABEL_APPLICATION,
    LABEL_DEVICE,
    LABEL_INTERFACE,
    LABEL_IPADDRESS,
    LABEL_SUBNET,
)
from app.knowledge.topology_read import LAYER_ALL, LAYERS, MAX_NEIGHBORHOOD_DEPTH, fetch_impact
from app.models import TopologySnapshot, User
from app.schemas.topology import GraphResponse, ImpactResponse, TopologyDiffResponse

#: Impact target-kind query value (lower-snake, ADR-0052 §1) -> projected label.
_IMPACT_KIND_TO_LABEL: dict[str, str] = {
    "device": LABEL_DEVICE,
    "ip_address": LABEL_IPADDRESS,
    "interface": LABEL_INTERFACE,
    "subnet": LABEL_SUBNET,
    "application": LABEL_APPLICATION,
}

router = APIRouter(prefix="/topology", tags=["topology"])

DbSession = Annotated[AsyncSession, Depends(get_db)]
KnowledgeClient = Annotated[Neo4jClient, Depends(get_knowledge_client)]
Viewer = Annotated[User, Depends(require_role("viewer"))]
AppSettings = Annotated[Settings, Depends(get_app_settings)]


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
    settings: AppSettings,
    _user: Viewer,
    site: Annotated[str | None, Query(max_length=255)] = None,
    vrf: Annotated[str | None, Query(max_length=255)] = None,
    layer: Annotated[str, Query(pattern="^(l2|l3|dns|app|all)$")] = LAYER_ALL,
) -> GraphResponse:
    """Return the projected subgraph as of the latest projection pass.

    ``site`` / ``vrf`` scope the subgraph; ``layer`` selects the relationship
    families (``l2`` neighbors, ``l3`` adjacency/routing, ``dns`` zone/record
    dependencies, or ``all``).  ``projected_at`` is the most recent
    ``last_projected_at`` across the returned nodes (``null`` when the filtered
    subgraph is empty).

    Over ``topology_max_nodes`` (audit Wave 5, G-SCA) the read is refused with
    a 413 problem — never a truncated or over-cap 200.  The count pre-check
    (same filters as the read) refuses cheaply before materializing the graph;
    a second guard on the materialized node set closes the pre-check's race
    with a concurrent projection pass — Neo4j read transactions are
    read-committed, not snapshot-isolated, so the graph can legitimately grow
    between the two statements no matter how they are batched.  The
    depth-bounded ``/graph/neighborhood`` endpoint is exempt by construction.
    """
    # ``layer`` is constrained by the pattern above; this guards the contract.
    if layer not in LAYERS:  # pragma: no cover - pattern enforces the set
        raise NotFoundError(f"unknown topology layer {layer!r}")
    max_nodes = settings.topology_max_nodes
    if max_nodes > 0:
        node_count = await count_graph_nodes(client, layer=layer, site=site, vrf=vrf)
        if node_count > max_nodes:
            raise _too_large(node_count, max_nodes)
    graph = await fetch_graph(client, layer=layer, site=site, vrf=vrf)
    if 0 < max_nodes < len(graph["nodes"]):
        raise _too_large(len(graph["nodes"]), max_nodes)
    return GraphResponse.model_validate(graph)


def _too_large(node_count: int, max_nodes: int) -> GraphTooLargeError:
    """The 413 problem for an over-cap graph read (count, limit, alternatives)."""
    return GraphTooLargeError(
        f"this subgraph has {node_count} nodes, over the {max_nodes}-node "
        "limit; narrow the read with ?site=<name> or "
        "GET /topology/graph/neighborhood, or raise NETOPS_TOPOLOGY_MAX_NODES"
    )


@router.get(
    "/graph/neighborhood",
    response_model=GraphResponse,
    summary="Read a device-centered neighborhood subgraph",
)
async def get_neighborhood(
    client: KnowledgeClient,
    _user: Viewer,
    device: Annotated[
        str,
        Query(min_length=1, max_length=255, description="Key (pg_id) of the center device."),
    ],
    depth: Annotated[
        int,
        Query(ge=1, le=MAX_NEIGHBORHOOD_DEPTH, description="Hop radius around the device."),
    ] = 2,
    layer: Annotated[str, Query(pattern="^(l2|l3|dns|app|all)$")] = LAYER_ALL,
) -> GraphResponse:
    """Return the subgraph within ``depth`` hops of one projected device.

    The scoped topology read (audit Wave 5, ARCH_DEBT #7): bounded by
    construction, so it stays usable where the full projection is not.  The
    traversal is undirected; ``layer`` selects the relationship families walked
    (same semantics as ``GET /topology/graph``).  The center device is always
    included, even when it has no edges in the selected layer.  404 (RFC 7807)
    when no projected device carries ``device`` as its key; out-of-range
    ``depth`` is rejected as 422 by FastAPI.
    """
    if layer not in LAYERS:  # pragma: no cover - pattern enforces the set
        raise NotFoundError(f"unknown topology layer {layer!r}")
    graph = await fetch_neighborhood(client, device=device, depth=depth, layer=layer)
    if graph is None:
        raise NotFoundError(f"no projected device with key {device!r}")
    return GraphResponse.model_validate(graph)


@router.get(
    "/impact",
    response_model=ImpactResponse,
    summary="What depends on a node (and, for an application, what it depends on)",
)
async def get_impact(
    client: KnowledgeClient,
    _user: Viewer,
    target_kind: Annotated[
        str,
        Query(
            pattern="^(device|ip_address|interface|subnet|application)$",
            description="Kind of the impact target node.",
        ),
    ],
    target_ref: Annotated[
        str,
        Query(min_length=1, max_length=255, description="The target node's key (pg_id / cidr)."),
    ],
    depth: Annotated[
        int,
        Query(ge=1, le=MAX_NEIGHBORHOOD_DEPTH, description="Physical-neighborhood hop bound."),
    ] = 2,
) -> ImpactResponse:
    """Answer "what depends on X" — and, for an ``Application`` target, "what
    does X depend on" — with per-edge provenance (ADR-0052 §8).

    The read is bounded by construction (a scoped ``MATCH`` from the target key,
    ``depth`` clamped to ``MAX_NEIGHBORHOOD_DEPTH``); every dependency claim
    cites the asserting source(s), a compact provenance summary, and the
    ``projected_at`` watermark it is "as of". A target absent from the
    projection is a 200 with empty ``dependents``/``dependencies`` (absence is an
    answer, not an error); an unknown ``target_kind`` or out-of-range ``depth``
    is rejected as 422 by FastAPI.
    """
    result = await fetch_impact(
        client,
        target_label=_IMPACT_KIND_TO_LABEL[target_kind],
        target_key=target_ref,
        depth=depth,
    )
    return ImpactResponse.model_validate(result)


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
