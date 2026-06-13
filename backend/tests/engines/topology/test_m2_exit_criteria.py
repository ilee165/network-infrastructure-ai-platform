"""M2 roadmap exit-criteria tests (docs/roadmap/MVP.md §4, M2-14).

Verifiable-without-the-lab criteria covered here (the unit-testable subset of
the MVP §4 list — isomorphism and traceability against a live graph live in
``test_rebuild_exit_criteria.py`` under ``@pytest.mark.integration``):

- "Disconnecting a lab link and re-discovering produces a diff that flags
  exactly that ``CONNECTED_TO`` edge as removed."
  → :class:`TestSingleLinkRemovalDiff` — exercised purely on fixtures: derive
  two snapshots that differ by one L2 link and assert the diff reports exactly
  one removed ``CONNECTED_TO`` edge and nothing else changed.
- Diff-foundation determinism (the property the §4 isomorphism criterion and
  the diff endpoint both rest on): the canonical snapshot and the diff are
  fully determined by input *content*, insensitive to input ordering.
  → :class:`TestSnapshotDiffDeterminism`.
- Projection-writer well-formedness (ADR-0005: "ALL nodes carry their key
  property and ``last_projected_at``"): every node row the writer would
  ``UNWIND`` into Neo4j carries a non-null key matching the schema key property
  and a tz-aware ``last_projected_at``.
  → :class:`TestProjectionWriterNodeWellFormedness`.

Lab-only §4 criteria (deliberately NOT covered here — they need the live lab
topology and are a manual pre-release gate per the roadmap backlog):

- Lab topology renders in the UI in <3 s for the full lab graph; L2 links match
  the cabling plan exactly.
- Incremental sync completes in <10% of full-rebuild time on the lab dataset.

These functions are pure (``derive_nodes`` / ``build_l2_edges`` /
``build_l3_edges`` / ``build_snapshot`` / ``diff_snapshots`` / the projector row
builders), so the whole module runs in the unit gate with no Postgres or Neo4j.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import pytest

from app.engines.topology.diff import diff_snapshots
from app.engines.topology.edges import build_l2_edges, build_l3_edges
from app.engines.topology.nodes import derive_nodes
from app.engines.topology.projector import (
    DerivedEdges,
    _node_rows,
    _node_sets,
)
from app.engines.topology.snapshots import SnapshotData, build_snapshot
from app.knowledge.schema import NODE_KEY_PROPERTY, REL_CONNECTED_TO
from app.models.inventory import (
    Device,
    NormalizedInterfaceRow,
    NormalizedNeighborRow,
    NormalizedRouteRow,
)
from app.schemas.normalized import (
    InterfaceAdminStatus,
    InterfaceOperStatus,
    NeighborProtocol,
    RouteProtocol,
)

# ---------------------------------------------------------------------------
# Fixed inventory: two devices, one L2 link, addressed interfaces, a route.
# Fixed UUIDs so the derived snapshot is byte-stable across runs.
# ---------------------------------------------------------------------------

COLLECTED_AT = datetime(2026, 6, 12, 12, 0, tzinfo=UTC)
PROJECTED_AT = datetime(2026, 6, 13, 1, 0, tzinfo=UTC)

DEV1 = UUID("00000000-0000-0000-0000-0000000000d1")
DEV2 = UUID("00000000-0000-0000-0000-0000000000d2")
IF1 = UUID("00000000-0000-0000-0000-0000000000a1")
IF2 = UUID("00000000-0000-0000-0000-0000000000a2")
RAW = UUID("00000000-0000-0000-0000-0000000000ff")


def _devices() -> list[Device]:
    return [
        Device(id=DEV1, hostname="core-1", mgmt_ip="10.20.0.1", vendor_id="cisco_ios", site="hq"),
        Device(id=DEV2, hostname="core-2", mgmt_ip="10.20.0.2", vendor_id="arista_eos"),
    ]


def _interfaces() -> list[NormalizedInterfaceRow]:
    common: dict[str, Any] = {
        "raw_artifact_id": RAW,
        "collected_at": COLLECTED_AT,
        "source_vendor": "cisco_ios",
        "admin_status": InterfaceAdminStatus.UP,
        "oper_status": InterfaceOperStatus.UP,
    }
    return [
        NormalizedInterfaceRow(
            id=IF1,
            device_id=DEV1,
            name="Ethernet1",
            ip_address="10.20.0.1/24",
            vlan_id=10,
            **common,
        ),
        NormalizedInterfaceRow(
            id=IF2,
            device_id=DEV2,
            name="Ethernet2",
            ip_address="10.20.0.2/24",
            vlan_id=10,
            **common,
        ),
    ]


def _routes() -> list[NormalizedRouteRow]:
    return [
        NormalizedRouteRow(
            device_id=DEV1,
            raw_artifact_id=RAW,
            collected_at=COLLECTED_AT,
            source_vendor="cisco_ios",
            prefix="10.30.0.0/24",
            protocol=RouteProtocol.STATIC,
            next_hop="10.20.0.254",
            interface="",
            vrf="prod",
        ),
    ]


def _l2_link() -> NormalizedNeighborRow:
    """The single L2 adjacency core-1:Ethernet1 <-> core-2:Ethernet2 (LLDP)."""
    return NormalizedNeighborRow(
        device_id=DEV1,
        raw_artifact_id=RAW,
        collected_at=COLLECTED_AT,
        source_vendor="cisco_ios",
        protocol=NeighborProtocol.LLDP,
        local_interface="Ethernet1",
        neighbor_name="core-2",
        neighbor_interface="Ethernet2",
        neighbor_address="10.20.0.2",
    )


def _snapshot_from_inventory(
    devices: list[Device],
    interfaces: list[NormalizedInterfaceRow],
    routes: list[NormalizedRouteRow],
    neighbors: list[NormalizedNeighborRow],
) -> SnapshotData:
    """Derive a canonical snapshot the way the projection pipeline does.

    Runs the same pure derivation the projector consumes (nodes + L2/L3 edges),
    flattens it into the ``[label, key]`` / ``[rel_type, src, dst]`` element
    form, and canonicalizes via :func:`build_snapshot`.
    """
    nodes = derive_nodes(devices, interfaces, routes)
    l2 = build_l2_edges(devices, interfaces, neighbors)
    l3 = build_l3_edges(devices, interfaces, routes)

    node_elements: list[list[str]] = []
    for label, node_set in _node_sets(nodes):
        key_property = NODE_KEY_PROPERTY[label]
        for node in node_set:
            node_elements.append([label, str(node.neo4j_properties(PROJECTED_AT)[key_property])])

    edge_elements: list[list[str]] = []
    for l2_edge in l2.edges:
        edge_elements.append([l2_edge.rel_type, l2_edge.a.key, l2_edge.b.key])
    for hi_edge in l3.has_interface:
        edge_elements.append([hi_edge.rel_type, hi_edge.device_pg_id, hi_edge.interface_pg_id])
    for sn_edge in l3.in_subnet:
        edge_elements.append([sn_edge.rel_type, sn_edge.interface_pg_id, sn_edge.cidr])
    for adj_edge in l3.l3_adjacent:
        edge_elements.append([adj_edge.rel_type, adj_edge.device_a_pg_id, adj_edge.device_b_pg_id])
    for rt_edge in l3.routes_to:
        edge_elements.append([rt_edge.rel_type, rt_edge.device_pg_id, rt_edge.cidr])

    return build_snapshot(node_elements, edge_elements)


# ---------------------------------------------------------------------------
# 1. Single-link removal diff
# ---------------------------------------------------------------------------


class TestSingleLinkRemovalDiff:
    """§4: disconnecting one link flags exactly that CONNECTED_TO edge removed."""

    def test_diff_reports_exactly_one_removed_connected_to_edge(self) -> None:
        # "Before": the lab has the single core-1 <-> core-2 link.
        before = _snapshot_from_inventory(_devices(), _interfaces(), _routes(), [_l2_link()])
        # "After": the link is disconnected; re-discovery reports no neighbor.
        after = _snapshot_from_inventory(_devices(), _interfaces(), _routes(), [])

        diff = diff_snapshots(before, after)

        # Exactly one edge removed, and it is the CONNECTED_TO link.
        assert len(diff.edges_removed) == 1, diff.edges_removed
        (removed,) = diff.edges_removed
        assert removed[0] == REL_CONNECTED_TO
        # Endpoints are the two interfaces that were cabled together.
        assert {removed[1], removed[2]} == {str(IF1), str(IF2)}

        # Nothing else moved: the L3 graph (interfaces, subnets, routes, VLAN,
        # VRF, site, HAS_INTERFACE/IN_SUBNET/L3_ADJACENT/ROUTES_TO) is identical.
        assert diff.edges_added == []
        assert diff.nodes_added == []
        assert diff.nodes_removed == []

    def test_reverse_diff_reports_the_link_added(self) -> None:
        # The inverse direction (link restored) must flag it as exactly one add.
        before = _snapshot_from_inventory(_devices(), _interfaces(), _routes(), [])
        after = _snapshot_from_inventory(_devices(), _interfaces(), _routes(), [_l2_link()])

        diff = diff_snapshots(before, after)

        assert len(diff.edges_added) == 1, diff.edges_added
        (added,) = diff.edges_added
        assert added[0] == REL_CONNECTED_TO
        assert {added[1], added[2]} == {str(IF1), str(IF2)}
        assert diff.edges_removed == []
        assert diff.nodes_added == []
        assert diff.nodes_removed == []

    def test_only_the_l2_link_distinguishes_the_two_snapshots(self) -> None:
        # Guards the fixture: the ONLY difference between the two inventories is
        # the neighbor row, so the link must be the sole edge present in one and
        # absent in the other — otherwise the "exactly that edge" claim is weak.
        with_link = _snapshot_from_inventory(_devices(), _interfaces(), _routes(), [_l2_link()])
        without_link = _snapshot_from_inventory(_devices(), _interfaces(), _routes(), [])

        only_with_link = [e for e in with_link["edges"] if e not in without_link["edges"]]
        assert only_with_link == [[REL_CONNECTED_TO, str(IF1), str(IF2)]]
        # Node sets are completely unaffected by the link change.
        assert with_link["nodes"] == without_link["nodes"]


# ---------------------------------------------------------------------------
# 2. Snapshot / diff determinism
# ---------------------------------------------------------------------------


class TestSnapshotDiffDeterminism:
    """The canonical snapshot and diff depend only on content, not order."""

    def test_snapshot_is_byte_identical_under_input_reordering(self) -> None:
        devices, interfaces, routes, neighbors = (
            _devices(),
            _interfaces(),
            _routes(),
            [_l2_link()],
        )
        forward = _snapshot_from_inventory(devices, interfaces, routes, neighbors)
        # Reverse every input sequence: a pure pipeline must be insensitive to it.
        reversed_ = _snapshot_from_inventory(
            list(reversed(devices)),
            list(reversed(interfaces)),
            list(reversed(routes)),
            list(reversed(neighbors)),
        )
        assert forward == reversed_

    def test_build_snapshot_dedups_and_sorts_regardless_of_order(self) -> None:
        a = build_snapshot(
            nodes=[["Device", "z"], ["Device", "a"], ["Device", "a"]],
            edges=[["CONNECTED_TO", "b", "a"], ["CONNECTED_TO", "b", "a"]],
        )
        b = build_snapshot(
            nodes=[["Device", "a"], ["Device", "z"]],
            edges=[["CONNECTED_TO", "b", "a"]],
        )
        assert a == b
        assert a["nodes"] == [["Device", "a"], ["Device", "z"]]
        assert a["edges"] == [["CONNECTED_TO", "b", "a"]]

    def test_diff_is_insensitive_to_element_ordering_within_snapshots(self) -> None:
        older: SnapshotData = {
            "nodes": [["Device", "a"], ["Device", "b"]],
            "edges": [["CONNECTED_TO", "a", "b"]],
        }
        # Same content, shuffled order, plus one extra node.
        newer: SnapshotData = {
            "nodes": [["Device", "b"], ["Device", "c"], ["Device", "a"]],
            "edges": [["CONNECTED_TO", "a", "b"]],
        }
        diff = diff_snapshots(older, newer)
        assert diff.nodes_added == [["Device", "c"]]
        assert diff.nodes_removed == []
        assert diff.edges_added == []
        assert diff.edges_removed == []

    def test_identical_snapshots_yield_empty_diff(self) -> None:
        snap = _snapshot_from_inventory(_devices(), _interfaces(), _routes(), [_l2_link()])
        diff = diff_snapshots(snap, snap)
        assert diff.is_empty()


# ---------------------------------------------------------------------------
# 3. Projection-writer node well-formedness
# ---------------------------------------------------------------------------


class TestProjectionWriterNodeWellFormedness:
    """ADR-0005: every projected node carries its key + last_projected_at."""

    def test_every_node_row_has_its_key_and_last_projected_at(self) -> None:
        nodes = derive_nodes(_devices(), _interfaces(), _routes())

        total_rows = 0
        for label, node_set in _node_sets(nodes):
            key_property = NODE_KEY_PROPERTY[label]
            rows = _node_rows(label, node_set, PROJECTED_AT)
            for row in rows:
                total_rows += 1
                # The MERGE key the writer UNWINDs must be present and non-null.
                assert row["key"] is not None, f"{label} row has a null MERGE key"
                props = row["props"]
                # ...and it must equal the schema key property in the prop map,
                # so MERGE (n:{label} {{key}}) SET n = row.props is consistent.
                assert props[key_property] == row["key"]
                assert props[key_property] is not None
                # Every node carries the tz-aware projection stamp (ADR-0005).
                stamp = props["last_projected_at"]
                assert stamp == PROJECTED_AT
                assert stamp.tzinfo is not None

        # The fixture is non-trivial: assert we actually exercised real rows
        # across multiple labels (a vacuous pass would be meaningless).
        assert total_rows >= 6  # 2 Device + 2 Interface + IPs + Subnets + VLAN + VRF + Site

    def test_no_node_row_omits_the_key_property_from_its_property_map(self) -> None:
        # The stale-sweep relies on last_projected_at on every node; the MERGE
        # relies on the key property. Assert no label slips through without both.
        nodes = derive_nodes(_devices(), _interfaces(), _routes())
        for label, node_set in _node_sets(nodes):
            key_property = NODE_KEY_PROPERTY[label]
            for row in _node_rows(label, node_set, PROJECTED_AT):
                assert key_property in row["props"]
                assert "last_projected_at" in row["props"]

    def test_writer_node_rows_require_timezone_aware_stamp(self) -> None:
        # neo4j_properties (called by _node_rows) rejects a naive datetime, so a
        # node can never be projected without a tz-aware last_projected_at.
        nodes = derive_nodes(_devices(), _interfaces(), _routes())
        label, node_set = _node_sets(nodes)[0]
        naive = datetime(2026, 6, 13, 1, 0)  # noqa: DTZ001 — intentionally naive
        with pytest.raises(ValueError, match="timezone-aware"):
            _node_rows(label, node_set, naive)

    def test_derived_edges_empty_default_is_constructible(self) -> None:
        # The projector wraps L2+L3 edges in DerivedEdges; an all-empty pass
        # (no edges derived) must still be a valid projection input so the stale
        # sweep can run. Guards the writer's empty-graph contract.
        empty = DerivedEdges()
        assert empty.connected_to == ()
        assert empty.has_interface == ()
        assert empty.in_subnet == ()
        assert empty.l3_adjacent == ()
        assert empty.routes_to == ()
