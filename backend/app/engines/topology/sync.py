"""Derivation + projection orchestration for one topology sync pass (M2-09).

This module is the pure glue between the three derivation builders
(:func:`app.engines.topology.nodes.derive_nodes`,
:func:`app.engines.topology.edges.build_l2_edges`,
:func:`app.engines.topology.edges.build_l3_edges`) and the projection writer
(:mod:`app.engines.topology.projector`).  It contains no I/O of its own:

- :func:`derive_topology` runs every builder on in-memory inventory rows and
  assembles the combined :class:`~app.engines.topology.nodes.DerivedNodes` /
  :class:`~app.engines.topology.projector.DerivedEdges` pair the projector
  consumes.  The L2 build report is returned alongside so callers can record
  unresolved-neighbor counts in run statistics.
- :func:`snapshot_lists` flattens those derived sets into the canonical
  ``[label, key]`` / ``[rel_type, src_key, dst_key]`` lists that
  :func:`app.engines.topology.snapshots.upsert_snapshot` stores per run.

Both functions are deterministic: identical inventory rows always produce
identical output (the builders already sort + dedupe their results).
"""

from __future__ import annotations

from collections.abc import Sequence

from app.engines.topology.edges import L2BuildReport, build_l2_edges, build_l3_edges
from app.engines.topology.nodes import DerivedNodes, derive_nodes
from app.engines.topology.projector import DerivedEdges
from app.models.inventory import (
    Device,
    NormalizedInterfaceRow,
    NormalizedNeighborRow,
    NormalizedRouteRow,
)

__all__ = [
    "DerivedTopology",
    "derive_topology",
    "snapshot_lists",
]


class DerivedTopology:
    """The combined output of one derivation pass plus the L2 build report."""

    __slots__ = ("edges", "l2_report", "nodes")

    def __init__(
        self,
        nodes: DerivedNodes,
        edges: DerivedEdges,
        l2_report: L2BuildReport,
    ) -> None:
        self.nodes = nodes
        self.edges = edges
        self.l2_report = l2_report


def derive_topology(
    devices: Sequence[Device],
    interfaces: Sequence[NormalizedInterfaceRow],
    routes: Sequence[NormalizedRouteRow],
    neighbors: Sequence[NormalizedNeighborRow],
) -> DerivedTopology:
    """Derive the full node + edge sets from inventory rows (pure).

    The seven node sets come from :func:`derive_nodes`; ``CONNECTED_TO`` edges
    come from the L2 builder and the four L3 relationship sets from the L3
    builder.  The two edge groups are merged into one
    :class:`~app.engines.topology.projector.DerivedEdges` the projector writes
    in a single pass.
    """
    nodes = derive_nodes(devices, interfaces, routes)
    l2 = build_l2_edges(devices, interfaces, neighbors)
    l3 = build_l3_edges(devices, interfaces, routes)
    edges = DerivedEdges(
        connected_to=l2.edges,
        has_interface=l3.has_interface,
        in_subnet=l3.in_subnet,
        l3_adjacent=l3.l3_adjacent,
        routes_to=l3.routes_to,
    )
    return DerivedTopology(nodes=nodes, edges=edges, l2_report=l2.report)


def snapshot_lists(
    nodes: DerivedNodes,
    edges: DerivedEdges,
) -> tuple[list[list[str]], list[list[str]]]:
    """Flatten derived sets into canonical snapshot ``[label, key]`` / triples.

    Returns ``(node_list, edge_list)`` where ``node_list`` holds ``[label,
    key]`` pairs and ``edge_list`` holds ``[rel_type, src_key, dst_key]``
    triples, both as plain strings (keys are stringified — VLAN ids become
    their decimal string).  Ordering/dedup is irrelevant here:
    :func:`app.engines.topology.snapshots.build_snapshot` canonicalises both
    lists before storage.
    """
    node_list: list[list[str]] = []
    for node_set in (
        nodes.devices,
        nodes.interfaces,
        nodes.ip_addresses,
        nodes.subnets,
        nodes.vlans,
        nodes.vrfs,
        nodes.sites,
    ):
        for node in node_set:
            node_list.append([node.label, str(node.key)])

    edge_list: list[list[str]] = []
    for edge in edges.connected_to:
        edge_list.append([edge.rel_type, edge.a.key, edge.b.key])
    for hi in edges.has_interface:
        edge_list.append([hi.rel_type, hi.device_pg_id, hi.interface_pg_id])
    for ins in edges.in_subnet:
        edge_list.append([ins.rel_type, ins.interface_pg_id, ins.cidr])
    for adj in edges.l3_adjacent:
        edge_list.append([adj.rel_type, adj.device_a_pg_id, adj.device_b_pg_id])
    for rt in edges.routes_to:
        edge_list.append([rt.rel_type, rt.device_pg_id, rt.cidr])

    return node_list, edge_list
