"""Projection writer: derived topology -> Neo4j (M2-06, ADR-0005).

Neo4j is a *pure projection* of Postgres: the node/edge derivation
(:mod:`app.engines.topology.nodes` / :mod:`app.engines.topology.edges`) is the
single source of truth and this module merely makes the graph converge to it.

:func:`project` performs one incremental sync pass:

1. **Upsert** every derived node — ``MERGE`` by ``(label, key property)`` from
   :data:`app.knowledge.schema.NODE_KEY_PROPERTY`, then ``SET n = row.props``
   so the whole property map (including ``last_projected_at``) is replaced and
   stale properties cannot linger.
2. **Upsert** every derived edge — endpoints are ``MATCH``-ed (never created:
   no phantom nodes), the relationship is ``MERGE``-d by endpoint keys + type,
   and ``SET r = row.props`` stamps ``last_projected_at`` on the edge too.
3. **Sweep stale elements** — any node of the 7 projected labels or edge of
   the 5 projected relationship types *not* stamped in this pass is deleted.
   The sweep is scoped strictly to the projected labels / types; everything
   else in the graph is never touched.

:func:`full_rebuild` is the drop-and-reproject path: ``DETACH DELETE`` every
node of the 7 projected labels, re-run
:func:`app.knowledge.schema.ensure_constraints`, then :func:`project`.

All writes are batched ``UNWIND`` statements — one round trip per
(label / relationship-group, batch) — never one per row.
"""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from datetime import datetime
from typing import Any

import structlog
from pydantic import BaseModel, ConfigDict

from app.engines.topology.dns import (
    DerivedDns,
    DnsRecordNode,
    DnsZoneNode,
)
from app.engines.topology.edges import (
    ConnectedToEdge,
    HasInterfaceEdge,
    InSubnetEdge,
    L3AdjacentEdge,
    RoutesToEdge,
)
from app.engines.topology.nodes import (
    DerivedNodes,
    DeviceNode,
    GraphNode,
    InterfaceNode,
    IPAddressNode,
    SiteNode,
    SubnetNode,
    VlanNode,
    VrfNode,
)
from app.knowledge.schema import (
    LABEL_DEVICE,
    LABEL_DNS_RECORD,
    LABEL_DNS_ZONE,
    LABEL_INTERFACE,
    LABEL_SUBNET,
    NODE_KEY_PROPERTY,
    REL_CONNECTED_TO,
    REL_HAS_INTERFACE,
    REL_IN_SUBNET,
    REL_IN_ZONE,
    REL_L3_ADJACENT,
    REL_RESOLVES_TO,
    REL_ROUTES_TO,
    ensure_constraints,
)

logger = structlog.get_logger(__name__)

__all__ = [
    "DEFAULT_BATCH_SIZE",
    "PROJECTED_NODE_LABELS",
    "PROJECTED_REL_TYPES",
    "DerivedEdges",
    "full_rebuild",
    "project",
]

#: The seven node labels this projector owns (and is allowed to delete from).
PROJECTED_NODE_LABELS: tuple[str, ...] = tuple(NODE_KEY_PROPERTY)

#: The relationship types this projector owns (M2 L2/L3 + M5 DNS-dependency).
PROJECTED_REL_TYPES: tuple[str, ...] = (
    REL_CONNECTED_TO,
    REL_HAS_INTERFACE,
    REL_IN_SUBNET,
    REL_L3_ADJACENT,
    REL_ROUTES_TO,
    REL_IN_ZONE,
    REL_RESOLVES_TO,
)

#: Rows per UNWIND statement; bounds transaction size on large inventories.
DEFAULT_BATCH_SIZE: int = 1000


class DerivedEdges(BaseModel):
    """The complete edge sets of one derivation pass (L2 + L3 + DNS combined)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    connected_to: tuple[ConnectedToEdge, ...] = ()
    has_interface: tuple[HasInterfaceEdge, ...] = ()
    in_subnet: tuple[InSubnetEdge, ...] = ()
    l3_adjacent: tuple[L3AdjacentEdge, ...] = ()
    routes_to: tuple[RoutesToEdge, ...] = ()


# ---------------------------------------------------------------------------
# Cypher builders
# ---------------------------------------------------------------------------


def _node_upsert_cypher(label: str) -> str:
    key = NODE_KEY_PROPERTY[label]
    return f"UNWIND $rows AS row MERGE (n:{label} {{{key}: row.key}}) SET n = row.props"


def _edge_upsert_cypher(rel_type: str, label_a: str, label_b: str) -> str:
    key_a = NODE_KEY_PROPERTY[label_a]
    key_b = NODE_KEY_PROPERTY[label_b]
    return (
        f"UNWIND $rows AS row "
        f"MATCH (a:{label_a} {{{key_a}: row.a_key}}) "
        f"MATCH (b:{label_b} {{{key_b}: row.b_key}}) "
        f"MERGE (a)-[r:{rel_type}]->(b) "
        f"SET r = row.props"
    )


def _stale_edge_sweep_cypher(rel_type: str) -> str:
    return (
        f"MATCH ()-[r:{rel_type}]->() "
        f"WHERE r.last_projected_at IS NULL OR r.last_projected_at <> $projected_at "
        f"DELETE r"
    )


def _stale_node_sweep_cypher(label: str) -> str:
    return (
        f"MATCH (n:{label}) "
        f"WHERE n.last_projected_at IS NULL OR n.last_projected_at <> $projected_at "
        f"DETACH DELETE n"
    )


def _wipe_label_cypher(label: str) -> str:
    return f"MATCH (n:{label}) DETACH DELETE n"


# ---------------------------------------------------------------------------
# Row builders
# ---------------------------------------------------------------------------


def _chunks(rows: list[dict[str, Any]], size: int) -> Iterator[list[dict[str, Any]]]:
    for start in range(0, len(rows), size):
        yield rows[start : start + size]


def _node_sets(
    nodes: DerivedNodes, dns: DerivedDns | None = None
) -> tuple[tuple[str, Sequence[GraphNode]], ...]:
    """The (label, node tuple) pairs in deterministic projection order.

    The seven M2 labels first, then the two DNS-dependency labels (M5 task #13)
    when *dns* is supplied — empty otherwise so a non-DNS pass is unchanged.
    """
    dns = dns or DerivedDns()
    return (
        (DeviceNode.label, nodes.devices),
        (InterfaceNode.label, nodes.interfaces),
        (IPAddressNode.label, nodes.ip_addresses),
        (SubnetNode.label, nodes.subnets),
        (VlanNode.label, nodes.vlans),
        (VrfNode.label, nodes.vrfs),
        (SiteNode.label, nodes.sites),
        (DnsZoneNode.label, dns.zones),
        (DnsRecordNode.label, dns.records),
    )


def _node_rows(
    label: str, node_set: Sequence[GraphNode], projected_at: datetime
) -> list[dict[str, Any]]:
    """``{key, props}`` rows; the MERGE key is the schema key property."""
    key_property = NODE_KEY_PROPERTY[label]
    rows: list[dict[str, Any]] = []
    for node in node_set:
        props = node.neo4j_properties(projected_at)
        rows.append({"key": props[key_property], "props": props})
    return rows


_EdgeGroup = tuple[str, str, str, list[dict[str, Any]]]


def _edge_groups(
    edges: DerivedEdges, dns: DerivedDns | None, projected_at: datetime
) -> Iterator[_EdgeGroup]:
    """Yield ``(rel_type, label_a, label_b, rows)`` upsert groups.

    ``CONNECTED_TO`` endpoints mix Device/Interface labels, so its edges are
    grouped per (label_a, label_b) pair — one UNWIND statement each. The four
    L3 types have fixed endpoint labels.  The DNS-dependency edges (M5 task #13)
    are appended when *dns* is supplied: ``IN_ZONE`` (DnsZone -> DnsRecord) and
    ``RESOLVES_TO`` (DnsRecord -> the reconciled IPAddress/Device endpoint, one
    UNWIND per target label; unreconciled records carry no edge).
    """
    connected_groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for edge in edges.connected_to:
        connected_groups.setdefault((edge.a.label, edge.b.label), []).append(
            {
                "a_key": edge.a.key,
                "b_key": edge.b.key,
                "props": {
                    "protocols": list(edge.protocols),
                    "interface_a": edge.interface_a,
                    "interface_b": edge.interface_b,
                    "last_projected_at": projected_at,
                },
            }
        )
    for (label_a, label_b), rows in sorted(connected_groups.items()):
        yield (REL_CONNECTED_TO, label_a, label_b, rows)

    yield (
        REL_HAS_INTERFACE,
        LABEL_DEVICE,
        LABEL_INTERFACE,
        [
            {
                "a_key": edge.device_pg_id,
                "b_key": edge.interface_pg_id,
                "props": {"last_projected_at": projected_at},
            }
            for edge in edges.has_interface
        ],
    )
    yield (
        REL_IN_SUBNET,
        LABEL_INTERFACE,
        LABEL_SUBNET,
        [
            {
                "a_key": edge.interface_pg_id,
                "b_key": edge.cidr,
                "props": {"last_projected_at": projected_at},
            }
            for edge in edges.in_subnet
        ],
    )
    yield (
        REL_L3_ADJACENT,
        LABEL_DEVICE,
        LABEL_DEVICE,
        [
            {
                "a_key": edge.device_a_pg_id,
                "b_key": edge.device_b_pg_id,
                "props": {"cidrs": list(edge.cidrs), "last_projected_at": projected_at},
            }
            for edge in edges.l3_adjacent
        ],
    )
    yield (
        REL_ROUTES_TO,
        LABEL_DEVICE,
        LABEL_SUBNET,
        [
            {
                "a_key": edge.device_pg_id,
                "b_key": edge.cidr,
                "props": {
                    "protocol": edge.protocol,
                    "next_hop": edge.next_hop,
                    "vrf": edge.vrf,
                    "metric": edge.metric,
                    "distance": edge.distance,
                    "last_projected_at": projected_at,
                },
            }
            for edge in edges.routes_to
        ],
    )

    if dns is None:
        return

    yield (
        REL_IN_ZONE,
        LABEL_DNS_ZONE,
        LABEL_DNS_RECORD,
        [
            {
                "a_key": edge.zone_fqdn,
                "b_key": edge.record_key,
                "props": {"last_projected_at": projected_at},
            }
            for edge in dns.in_zone
        ],
    )

    # RESOLVES_TO endpoints land on either IPAddress or Device (the reconciled
    # node), so — like CONNECTED_TO — group per target label, one UNWIND each.
    # Unreconciled records (target_label is None) carry no edge: a RESOLVES_TO
    # endpoint must be a real projected node (no-phantom-nodes invariant).
    resolves_groups: dict[str, list[dict[str, Any]]] = {}
    for rte in dns.resolves_to:
        if rte.target_label is None or rte.target_key is None:
            continue
        resolves_groups.setdefault(rte.target_label, []).append(
            {
                "a_key": rte.record_key,
                "b_key": rte.target_key,
                "props": {"value": rte.value, "last_projected_at": projected_at},
            }
        )
    for target_label, rows in sorted(resolves_groups.items()):
        yield (REL_RESOLVES_TO, LABEL_DNS_RECORD, target_label, rows)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


async def project(
    client: Any,
    nodes: DerivedNodes,
    edges: DerivedEdges,
    projected_at: datetime,
    *,
    dns: DerivedDns | None = None,
    batch_size: int = DEFAULT_BATCH_SIZE,
) -> None:
    """Make the graph converge to one derivation pass (incremental sync).

    Upserts every derived node and edge stamped with *projected_at*, then
    deletes every node/edge of the projected labels / relationship types that
    was *not* stamped in this pass (its key is absent from the derivation).
    Elements outside the projected labels and types are never touched.

    Parameters
    ----------
    client:
        Any object exposing a ``.session()`` async context manager whose body
        yields an object with an async ``.run(cypher, **params)`` method — in
        production :class:`app.knowledge.neo4j_client.Neo4jClient`.
    nodes / edges:
        Output of one derivation pass (``derive_nodes`` / edge builders).
    projected_at:
        tz-aware UTC instant stamped as ``last_projected_at`` on every
        upserted element; also the staleness watermark for the sweep.
    dns:
        Optional DNS-dependency derivation (``derive_dns``, M5 task #13).  When
        supplied its ``DnsZone``/``DnsRecord`` nodes and ``IN_ZONE``/``RESOLVES_TO``
        edges are projected too; when ``None`` the DNS layer is swept clean (no
        DNS elements are stamped this pass) like any other empty derivation.
    batch_size:
        Rows per ``UNWIND`` statement (bounds memory per round trip).
    """
    if projected_at.tzinfo is None:
        raise ValueError("projected_at must be timezone-aware")
    if batch_size < 1:
        raise ValueError("batch_size must be >= 1")

    node_count = 0
    edge_count = 0
    async with client.session() as session:
        for label, node_set in _node_sets(nodes, dns):
            rows = _node_rows(label, node_set, projected_at)
            node_count += len(rows)
            cypher = _node_upsert_cypher(label)
            for batch in _chunks(rows, batch_size):
                await session.run(cypher, rows=batch)

        for rel_type, label_a, label_b, rows in _edge_groups(edges, dns, projected_at):
            edge_count += len(rows)
            cypher = _edge_upsert_cypher(rel_type, label_a, label_b)
            for batch in _chunks(rows, batch_size):
                await session.run(cypher, rows=batch)

        # Stale sweep: every projected type/label, even ones derived empty —
        # an element can only survive by being re-stamped above.
        for rel_type in PROJECTED_REL_TYPES:
            await session.run(_stale_edge_sweep_cypher(rel_type), projected_at=projected_at)
        for label in PROJECTED_NODE_LABELS:
            await session.run(_stale_node_sweep_cypher(label), projected_at=projected_at)

    logger.info(
        "topology_projection_complete",
        nodes_upserted=node_count,
        edges_upserted=edge_count,
        projected_at=projected_at.isoformat(),
    )


async def full_rebuild(
    client: Any,
    nodes: DerivedNodes,
    edges: DerivedEdges,
    projected_at: datetime,
    *,
    dns: DerivedDns | None = None,
    batch_size: int = DEFAULT_BATCH_SIZE,
) -> None:
    """Drop and re-project the whole topology subgraph (ADR-0005 invariant).

    ``DETACH DELETE`` every node of the projected labels (their edges go with
    them), re-assert the uniqueness constraints, then run a normal
    :func:`project` pass. Labels outside the projection are never touched.
    """
    async with client.session() as session:
        for label in PROJECTED_NODE_LABELS:
            await session.run(_wipe_label_cypher(label))
    logger.info("topology_projection_wiped", labels=list(PROJECTED_NODE_LABELS))
    await ensure_constraints(client)
    await project(client, nodes, edges, projected_at, dns=dns, batch_size=batch_size)
