"""Topology snapshot builder and persistence helper (M2-07, ADR-0005).

The snapshot is the *diff foundation*: a deterministic, sorted multiset
summary of every node and edge projected in a single topology pass.  It is
stored in ``topology_snapshots`` (one row per discovery run) so that the diff
engine (M2-08) can compare successive runs entirely within Postgres — no
graph-vs-graph diff, no live Neo4j query.

Canonical form
--------------
- **nodes** — sorted, deduped list of ``[label, key]`` pairs.
- **edges** — sorted, deduped list of ``[rel_type, src_key, dst_key]`` triples.

Both are sorted lexicographically by their elements (label/type first, then
key/src/dst) so that the same logical topology always produces byte-identical
JSON regardless of the order in which the caller supplies the inputs.

Public API
----------
:func:`build_snapshot`
    Pure function — no I/O.  Takes raw ``[label, key]`` and
    ``[rel_type, src, dst]`` lists and returns the canonical ``{"nodes": ...,
    "edges": ...}`` dict ready for JSON storage.

:func:`upsert_snapshot`
    Async persistence helper.  Fetches the existing
    :class:`~app.models.topology.TopologySnapshot` for a run (if any) and
    updates it in place, or inserts a new row.  The unique constraint on
    ``run_id`` prevents duplicate rows; Python-level select-then-upsert matches
    the portability decision used everywhere in the discovery persistence layer
    (no dialect-specific ``ON CONFLICT``).
"""

from __future__ import annotations

from uuid import UUID

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.topology import TopologySnapshot

__all__ = [
    "SnapshotData",
    "build_snapshot",
    "upsert_snapshot",
]

logger = structlog.get_logger(__name__)

#: Type alias for the canonical snapshot dict returned by :func:`build_snapshot`.
SnapshotData = dict[str, list[list[str]]]


def build_snapshot(
    nodes: list[list[str]],
    edges: list[list[str]],
) -> SnapshotData:
    """Build a deterministic canonical snapshot from node/edge lists (pure).

    Args:
        nodes: Sequence of ``[label, key]`` pairs — order and duplicates are
               tolerated; the output is always deduped and sorted.
        edges: Sequence of ``[rel_type, src_key, dst_key]`` triples — same
               dedup/sort guarantee.

    Returns:
        ``{"nodes": [[label, key], ...], "edges": [[type, src, dst], ...]}``
        where both lists are sorted lexicographically and contain no duplicates.

    The function is a pure transformation: same logical inputs -> identical
    output regardless of caller-supplied ordering.
    """
    # Convert to tuples for set hashing, dedup, then sort and convert back.
    node_set: set[tuple[str, str]] = set()
    for pair in nodes:
        node_set.add((pair[0], pair[1]))

    edge_set: set[tuple[str, str, str]] = set()
    for triple in edges:
        edge_set.add((triple[0], triple[1], triple[2]))

    sorted_nodes: list[list[str]] = [list(pair) for pair in sorted(node_set)]
    sorted_edges: list[list[str]] = [list(triple) for triple in sorted(edge_set)]

    return {"nodes": sorted_nodes, "edges": sorted_edges}


async def upsert_snapshot(
    session: AsyncSession,
    *,
    run_id: UUID,
    nodes: list[list[str]],
    edges: list[list[str]],
) -> TopologySnapshot:
    """Upsert the topology snapshot for *run_id* (portable select-then-write).

    If a :class:`~app.models.topology.TopologySnapshot` row already exists for
    *run_id* it is updated in place; otherwise a new row is inserted.  The
    canonical form is computed via :func:`build_snapshot` before writing so the
    stored data is always sorted and deduped.

    Args:
        session: An open async SQLAlchemy session (caller owns transaction).
        run_id:  UUID of the parent :class:`~app.models.inventory.DiscoveryRun`.
        nodes:   Raw ``[label, key]`` pairs (may be unsorted / contain dups).
        edges:   Raw ``[rel_type, src, dst]`` triples (same tolerance).

    Returns:
        The created or updated :class:`~app.models.topology.TopologySnapshot`
        row (flushed, not yet committed).
    """
    snap = build_snapshot(nodes, edges)

    result = await session.execute(
        select(TopologySnapshot).where(TopologySnapshot.run_id == run_id)
    )
    row: TopologySnapshot | None = result.scalar_one_or_none()

    if row is None:
        row = TopologySnapshot(run_id=run_id, nodes=snap["nodes"], edges=snap["edges"])
        session.add(row)
        logger.debug("topology_snapshot.inserted", run_id=str(run_id))
    else:
        row.nodes = snap["nodes"]
        row.edges = snap["edges"]
        logger.debug("topology_snapshot.updated", run_id=str(run_id), snapshot_id=str(row.id))

    await session.flush()
    return row
