"""Topology diff engine (M2-08, ADR-0005).

The diff is computed *within Postgres* from two canonical topology snapshots
(per-run node/edge multisets stored in ``topology_snapshots``) — never as a
live graph-vs-graph query against Neo4j.  Given an ``older`` and a ``newer``
:data:`~app.engines.topology.snapshots.SnapshotData`, :func:`diff_snapshots`
reports what changed between the two projection passes as four
stable-sorted, deduped lists:

- ``nodes_added`` / ``edges_added`` — present in ``newer`` but not ``older``;
- ``nodes_removed`` / ``edges_removed`` — present in ``older`` but not ``newer``.

Because each snapshot is already the canonical *set* form (sorted, deduped
``[label, key]`` / ``[rel_type, src, dst]`` lists — see
:func:`app.engines.topology.snapshots.build_snapshot`), the diff is a plain
set difference.  The function is pure: no I/O, no input mutation, output fully
determined by input *content* and insensitive to input ordering.

:class:`TopologyDiff` is the pydantic result schema and becomes the API/diff
wire shape in M2-10.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from app.engines.topology.snapshots import SnapshotData

__all__ = [
    "TopologyDiff",
    "diff_snapshots",
]

#: A node element in a snapshot: ``[label, key]``.
NodeElement = list[str]
#: An edge element in a snapshot: ``[rel_type, src_key, dst_key]``.
EdgeElement = list[str]


class TopologyDiff(BaseModel):
    """The difference between two topology snapshots (older -> newer).

    Each field is a lexicographically sorted, deduped list in the same
    canonical element form used by the snapshot:

    - ``nodes_added`` / ``nodes_removed``: ``[[label, key], ...]``
    - ``edges_added`` / ``edges_removed``: ``[[rel_type, src_key, dst_key], ...]``

    "Added" means present in ``newer`` but not ``older``; "removed" means
    present in ``older`` but not ``newer``.  This model is the M2-10 wire shape.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    nodes_added: list[NodeElement] = Field(default_factory=list)
    nodes_removed: list[NodeElement] = Field(default_factory=list)
    edges_added: list[EdgeElement] = Field(default_factory=list)
    edges_removed: list[EdgeElement] = Field(default_factory=list)

    def is_empty(self) -> bool:
        """Return ``True`` when the two snapshots are identical (no changes)."""
        return not (
            self.nodes_added or self.nodes_removed or self.edges_added or self.edges_removed
        )


def _as_tuple_set(elements: list[list[str]] | None) -> set[tuple[str, ...]]:
    """Coerce a snapshot element list into a set of tuples for set algebra.

    Tolerates a missing/``None`` value (treated as the empty multiset) so a
    snapshot dict lacking a ``nodes`` or ``edges`` key diffs cleanly.
    """
    if not elements:
        return set()
    return {tuple(element) for element in elements}


def _sorted_lists(elements: set[tuple[str, ...]]) -> list[list[str]]:
    """Convert a set of element tuples back into stable-sorted nested lists."""
    return [list(element) for element in sorted(elements)]


def diff_snapshots(older: SnapshotData, newer: SnapshotData) -> TopologyDiff:
    """Compute the multiset difference between two canonical snapshots (pure).

    Args:
        older: The earlier snapshot (e.g. the previous discovery run).
        newer: The later snapshot (e.g. the current discovery run).

    Returns:
        A :class:`TopologyDiff` whose four lists are lexicographically sorted
        and deduped.  Identical snapshots yield an all-empty diff
        (:meth:`TopologyDiff.is_empty` returns ``True``).

    The snapshots are already canonical *set* forms, so the diff is a plain
    symmetric set difference computed per element category.  The result is
    insensitive to the ordering of elements within each input snapshot.
    """
    older_nodes = _as_tuple_set(older.get("nodes"))
    newer_nodes = _as_tuple_set(newer.get("nodes"))
    older_edges = _as_tuple_set(older.get("edges"))
    newer_edges = _as_tuple_set(newer.get("edges"))

    return TopologyDiff(
        nodes_added=_sorted_lists(newer_nodes - older_nodes),
        nodes_removed=_sorted_lists(older_nodes - newer_nodes),
        edges_added=_sorted_lists(newer_edges - older_edges),
        edges_removed=_sorted_lists(older_edges - newer_edges),
    )
