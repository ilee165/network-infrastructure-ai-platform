"""M2-08 topology diff engine: multiset diff of two canonical snapshots.

The diff engine compares two :data:`~app.engines.topology.snapshots.SnapshotData`
multisets (``older`` vs ``newer``) and reports, as stable-sorted lists:

- ``nodes_added`` / ``edges_added`` — present in ``newer``, absent from ``older``;
- ``nodes_removed`` / ``edges_removed`` — present in ``older``, absent from ``newer``.

All tests are pure (no DB, no Neo4j). The MVP exit criterion is the
single-CONNECTED_TO-edge case: two snapshots differing by exactly one
``CONNECTED_TO`` edge must produce a diff flagging exactly that edge as removed
and nothing else.
"""

from __future__ import annotations

import json

from app.engines.topology.diff import TopologyDiff, diff_snapshots
from app.engines.topology.snapshots import SnapshotData, build_snapshot

# ---------------------------------------------------------------------------
# Canonical form helpers
# ---------------------------------------------------------------------------


def _node(label: str, key: str) -> list[str]:
    return [label, key]


def _edge(rel_type: str, src: str, dst: str) -> list[str]:
    return [rel_type, src, dst]


def _snap(nodes: list[list[str]], edges: list[list[str]]) -> SnapshotData:
    """Build a canonical snapshot (sorted, deduped) from raw lists."""
    return build_snapshot(nodes, edges)


# ---------------------------------------------------------------------------
# MVP exit criterion: one CONNECTED_TO edge removed, nothing else flagged
# ---------------------------------------------------------------------------


class TestSingleConnectedToEdgeRemoved:
    """Exit criterion: a snapshot pair differing by exactly one L2 link."""

    _NODES = [
        _node("Device", "dev-a"),
        _node("Device", "dev-b"),
        _node("Interface", "if-a"),
        _node("Interface", "if-b"),
    ]
    _EDGES_WITH_LINK = [
        _edge("HAS_INTERFACE", "dev-a", "if-a"),
        _edge("HAS_INTERFACE", "dev-b", "if-b"),
        _edge("CONNECTED_TO", "if-a", "if-b"),
    ]
    _EDGES_WITHOUT_LINK = [
        _edge("HAS_INTERFACE", "dev-a", "if-a"),
        _edge("HAS_INTERFACE", "dev-b", "if-b"),
    ]

    def test_exactly_one_edge_removed(self) -> None:
        older = _snap(self._NODES, self._EDGES_WITH_LINK)
        newer = _snap(self._NODES, self._EDGES_WITHOUT_LINK)

        diff = diff_snapshots(older, newer)

        assert diff.edges_removed == [["CONNECTED_TO", "if-a", "if-b"]]
        assert diff.edges_added == []
        assert diff.nodes_added == []
        assert diff.nodes_removed == []

    def test_reverse_direction_flags_edge_added(self) -> None:
        # Swapping older/newer must flag the same edge as *added* instead.
        older = _snap(self._NODES, self._EDGES_WITHOUT_LINK)
        newer = _snap(self._NODES, self._EDGES_WITH_LINK)

        diff = diff_snapshots(older, newer)

        assert diff.edges_added == [["CONNECTED_TO", "if-a", "if-b"]]
        assert diff.edges_removed == []
        assert diff.nodes_added == []
        assert diff.nodes_removed == []


# ---------------------------------------------------------------------------
# Added / removed device cases
# ---------------------------------------------------------------------------


class TestDeviceAddedRemoved:
    """A device (and its interface + HAS_INTERFACE edge) appearing/leaving."""

    _BASE_NODES = [_node("Device", "dev-a"), _node("Interface", "if-a")]
    _BASE_EDGES = [_edge("HAS_INTERFACE", "dev-a", "if-a")]

    _GROWN_NODES = [
        _node("Device", "dev-a"),
        _node("Device", "dev-b"),
        _node("Interface", "if-a"),
        _node("Interface", "if-b"),
    ]
    _GROWN_EDGES = [
        _edge("HAS_INTERFACE", "dev-a", "if-a"),
        _edge("HAS_INTERFACE", "dev-b", "if-b"),
    ]

    def test_added_device(self) -> None:
        older = _snap(self._BASE_NODES, self._BASE_EDGES)
        newer = _snap(self._GROWN_NODES, self._GROWN_EDGES)

        diff = diff_snapshots(older, newer)

        assert diff.nodes_added == [
            ["Device", "dev-b"],
            ["Interface", "if-b"],
        ]
        assert diff.edges_added == [["HAS_INTERFACE", "dev-b", "if-b"]]
        assert diff.nodes_removed == []
        assert diff.edges_removed == []

    def test_removed_device(self) -> None:
        older = _snap(self._GROWN_NODES, self._GROWN_EDGES)
        newer = _snap(self._BASE_NODES, self._BASE_EDGES)

        diff = diff_snapshots(older, newer)

        assert diff.nodes_removed == [
            ["Device", "dev-b"],
            ["Interface", "if-b"],
        ]
        assert diff.edges_removed == [["HAS_INTERFACE", "dev-b", "if-b"]]
        assert diff.nodes_added == []
        assert diff.edges_added == []


# ---------------------------------------------------------------------------
# No-change case
# ---------------------------------------------------------------------------


class TestNoChange:
    """Identical snapshots produce an empty diff regardless of input order."""

    def test_identical_snapshots_empty_diff(self) -> None:
        nodes = [_node("Device", "dev-a"), _node("Interface", "if-a")]
        edges = [_edge("HAS_INTERFACE", "dev-a", "if-a")]
        older = _snap(nodes, edges)
        newer = _snap(nodes, edges)

        diff = diff_snapshots(older, newer)

        assert diff.nodes_added == []
        assert diff.nodes_removed == []
        assert diff.edges_added == []
        assert diff.edges_removed == []
        assert diff.is_empty() is True

    def test_same_content_different_input_order_empty_diff(self) -> None:
        older = _snap(
            [_node("Interface", "if-a"), _node("Device", "dev-a")],
            [_edge("HAS_INTERFACE", "dev-a", "if-a")],
        )
        newer = _snap(
            [_node("Device", "dev-a"), _node("Interface", "if-a")],
            [_edge("HAS_INTERFACE", "dev-a", "if-a")],
        )

        diff = diff_snapshots(older, newer)

        assert diff.is_empty() is True


# ---------------------------------------------------------------------------
# Stable sorted output + determinism
# ---------------------------------------------------------------------------


class TestStableSortedOutput:
    """Output lists are lexicographically sorted and order-insensitive."""

    def test_added_nodes_sorted(self) -> None:
        older: SnapshotData = {"nodes": [], "edges": []}
        newer = _snap(
            [
                _node("Subnet", "10.0.0.0/24"),
                _node("Device", "z-dev"),
                _node("Device", "a-dev"),
                _node("Vlan", "10"),
            ],
            [],
        )

        diff = diff_snapshots(older, newer)

        assert diff.nodes_added == sorted(diff.nodes_added)
        assert diff.nodes_added == [
            ["Device", "a-dev"],
            ["Device", "z-dev"],
            ["Subnet", "10.0.0.0/24"],
            ["Vlan", "10"],
        ]

    def test_added_edges_sorted(self) -> None:
        older: SnapshotData = {"nodes": [], "edges": []}
        newer = _snap(
            [],
            [
                _edge("ROUTES_TO", "dev-b", "10.0.0.0/8"),
                _edge("HAS_INTERFACE", "dev-a", "if-2"),
                _edge("HAS_INTERFACE", "dev-a", "if-1"),
            ],
        )

        diff = diff_snapshots(older, newer)

        assert diff.edges_added == sorted(diff.edges_added)
        assert diff.edges_added == [
            ["HAS_INTERFACE", "dev-a", "if-1"],
            ["HAS_INTERFACE", "dev-a", "if-2"],
            ["ROUTES_TO", "dev-b", "10.0.0.0/8"],
        ]

    def test_diff_independent_of_snapshot_list_order(self) -> None:
        # Same logical snapshots, different stored ordering -> same diff.
        older_a = _snap(
            [_node("Device", "a"), _node("Device", "b")],
            [_edge("CONNECTED_TO", "a", "b")],
        )
        # Manually mis-order the stored lists (canonical builder always sorts,
        # so construct directly to prove diff does not depend on input order).
        older_b: SnapshotData = {
            "nodes": [["Device", "b"], ["Device", "a"]],
            "edges": [["CONNECTED_TO", "a", "b"]],
        }
        newer = _snap([_node("Device", "a")], [])

        diff_a = diff_snapshots(older_a, newer)
        diff_b = diff_snapshots(older_b, newer)

        assert diff_a == diff_b


# ---------------------------------------------------------------------------
# Mixed add + remove + result schema
# ---------------------------------------------------------------------------


class TestMixedAndSchema:
    """Simultaneous add+remove, plus pydantic wire-shape sanity."""

    def test_simultaneous_add_and_remove(self) -> None:
        older = _snap(
            [_node("Device", "a"), _node("Device", "b")],
            [_edge("CONNECTED_TO", "a", "b")],
        )
        newer = _snap(
            [_node("Device", "a"), _node("Device", "c")],
            [_edge("CONNECTED_TO", "a", "c")],
        )

        diff = diff_snapshots(older, newer)

        assert diff.nodes_added == [["Device", "c"]]
        assert diff.nodes_removed == [["Device", "b"]]
        assert diff.edges_added == [["CONNECTED_TO", "a", "c"]]
        assert diff.edges_removed == [["CONNECTED_TO", "a", "b"]]
        assert diff.is_empty() is False

    def test_result_is_pydantic_and_json_serialisable(self) -> None:
        older = _snap([_node("Device", "a")], [])
        newer = _snap([_node("Device", "b")], [])

        diff = diff_snapshots(older, newer)

        assert isinstance(diff, TopologyDiff)
        # Round-trips through JSON (this is the M2-10 wire shape).
        payload = json.loads(diff.model_dump_json())
        assert payload == {
            "nodes_added": [["Device", "b"]],
            "nodes_removed": [["Device", "a"]],
            "edges_added": [],
            "edges_removed": [],
        }

    def test_missing_keys_treated_as_empty(self) -> None:
        # Defensive: a snapshot dict missing a key behaves as empty multiset.
        older: SnapshotData = {"nodes": [["Device", "a"]]}  # type: ignore[typeddict-item]
        newer: SnapshotData = {"edges": [["CONNECTED_TO", "a", "b"]]}  # type: ignore[typeddict-item]

        diff = diff_snapshots(older, newer)

        assert diff.nodes_removed == [["Device", "a"]]
        assert diff.edges_added == [["CONNECTED_TO", "a", "b"]]
        assert diff.nodes_added == []
        assert diff.edges_removed == []
