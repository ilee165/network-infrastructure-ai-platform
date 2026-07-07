"""Derivation + projection orchestration for one topology sync pass (M2-09).

This module is the pure glue between the derivation builders
(:func:`app.engines.topology.nodes.derive_nodes`,
:func:`app.engines.topology.edges.build_l2_edges`,
:func:`app.engines.topology.edges.build_l3_edges`,
:func:`app.engines.topology.applications.derive_applications`) and the
projection writer (:mod:`app.engines.topology.projector`).  It contains no I/O
of its own:

- :func:`derive_topology` runs every builder on in-memory inventory rows and
  assembles the combined :class:`~app.engines.topology.nodes.DerivedNodes` /
  :class:`~app.engines.topology.projector.DerivedEdges` /
  :class:`~app.engines.topology.applications.DerivedApplications` triple the
  projector consumes.  The application inputs are REQUIRED positional
  parameters (P4 W2, ADR-0052 §5): no derivation pass can omit the layer, so
  the projector's stale sweep can never silently destroy it (the optional
  ``dns=`` deletion hazard must not recur).  The L2 build report is returned
  alongside so callers can record unresolved-neighbor counts in run
  statistics.
- :func:`snapshot_lists` flattens those derived sets into the canonical
  ``[label, key]`` / ``[rel_type, src_key, dst_key]`` lists that
  :func:`app.engines.topology.snapshots.upsert_snapshot` stores per run — the
  application layer included, so the rebuild drill's source-of-record count
  (``topology_counts.py pg-source``) covers the new kinds (ADR-0052 §6.2).

Both functions are deterministic: identical inventory rows always produce
identical output (the builders already sort + dedupe their results).
"""

from __future__ import annotations

from collections.abc import Sequence

from app.engines.topology.applications import DerivedApplications, derive_applications
from app.engines.topology.edges import L2BuildReport, build_l2_edges, build_l3_edges
from app.engines.topology.nodes import DerivedNodes, derive_nodes
from app.engines.topology.projector import DerivedEdges
from app.knowledge.schema import LABEL_APPLICATION
from app.models.applications import Application, ApplicationDependency
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
    """The combined output of one derivation pass plus the L2 build report.

    ``applications`` is a REQUIRED component (ADR-0052 §5): every production
    projection pass (sync, rebuild, auto-rebuild) carries the application
    layer — there is no constructor default to fall back on.
    """

    __slots__ = ("applications", "edges", "l2_report", "nodes")

    def __init__(
        self,
        nodes: DerivedNodes,
        edges: DerivedEdges,
        applications: DerivedApplications,
        l2_report: L2BuildReport,
    ) -> None:
        self.nodes = nodes
        self.edges = edges
        self.applications = applications
        self.l2_report = l2_report


def derive_topology(
    devices: Sequence[Device],
    interfaces: Sequence[NormalizedInterfaceRow],
    routes: Sequence[NormalizedRouteRow],
    neighbors: Sequence[NormalizedNeighborRow],
    applications: Sequence[Application],
    application_dependencies: Sequence[ApplicationDependency],
) -> DerivedTopology:
    """Derive the full node + edge + application sets from PG rows (pure).

    The seven inventory node sets come from :func:`derive_nodes`;
    ``CONNECTED_TO`` edges come from the L2 builder and the four L3
    relationship sets from the L3 builder; the ``Application`` nodes and
    union ``DEPENDS_ON`` edges come from :func:`derive_applications`, keyed
    against the Device/IPAddress node keys of the SAME pass so no edge can
    reference an endpoint the projector will not project (no phantom
    endpoints, ADR-0052 §5).

    *applications* / *application_dependencies* are REQUIRED (no default):
    callers load BOTH tables or neither — a pass that loaded only one would
    sweep the other's valid graph elements (ADR-0052 §5, sweep-over-deletion
    hazard).
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
    app_layer = derive_applications(
        applications,
        application_dependencies,
        device_keys={str(node.pg_id) for node in nodes.devices},
        ip_address_keys={str(node.pg_id) for node in nodes.ip_addresses},
    )
    return DerivedTopology(nodes=nodes, edges=edges, applications=app_layer, l2_report=l2.report)


def snapshot_lists(
    nodes: DerivedNodes,
    edges: DerivedEdges,
    applications: DerivedApplications,
) -> tuple[list[list[str]], list[list[str]]]:
    """Flatten derived sets into canonical snapshot ``[label, key]`` / triples.

    Returns ``(node_list, edge_list)`` where ``node_list`` holds ``[label,
    key]`` pairs and ``edge_list`` holds ``[rel_type, src_key, dst_key]``
    triples, both as plain strings (keys are stringified — VLAN ids become
    their decimal string).  The application layer is a REQUIRED input
    (ADR-0052 §5/§6.2): its ``Application`` nodes and ``DEPENDS_ON`` edges
    join the canonical lists, so the per-run snapshot and the rebuild-drill
    source-of-record counts cover the new kinds.  Ordering/dedup is irrelevant
    here: :func:`app.engines.topology.snapshots.build_snapshot` canonicalises
    both lists before storage.
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
    for app_node in applications.applications:
        node_list.append([LABEL_APPLICATION, str(app_node.key)])

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
    for dep in applications.depends_on:
        edge_list.append([dep.rel_type, dep.application_pg_id, dep.target_key])

    return node_list, edge_list
