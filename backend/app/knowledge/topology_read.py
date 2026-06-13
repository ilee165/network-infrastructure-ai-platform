"""Read-side topology queries against the Neo4j projection (M2-10, ADR-0005).

``app.knowledge`` is the only package that talks to Neo4j, so the Cypher that
answers the topology REST API lives here rather than in the API layer.  These
are *read-only* queries — the projection writer
(:mod:`app.engines.topology.projector`) remains the sole writer.

:func:`fetch_graph` returns the projected subgraph as plain, JSON-safe dicts
(``nodes`` / ``edges`` / ``projected_at``) so the API layer can validate them
into its response schema without importing the driver's record types:

- each node carries ``label``, ``key`` (the value of the label's key property),
  and a flat ``properties`` map;
- each edge carries ``type``, ``source``/``target`` (the endpoint key values),
  and a flat ``properties`` map;
- ``projected_at`` is the most recent ``last_projected_at`` stamp across the
  returned nodes (ADR-0005: answers are "as of run X") or ``None`` when the
  subgraph is empty.

Filtering
---------
``site`` scopes the subgraph to devices assigned that ``Device.site`` value
(and the interfaces/addresses/subnets reachable from them); ``vrf`` scopes it
to the subnet endpoints of ``ROUTES_TO`` edges in that VRF.  ``layer`` selects
which relationship families are returned (``l2`` → ``CONNECTED_TO``; ``l3`` →
the four L3 types; ``all`` → every projected type).  The node set is always the
union of every endpoint that survives the active filters, so the returned
subgraph is internally consistent (no dangling edges).
"""

from __future__ import annotations

from typing import Any

from neo4j import AsyncManagedTransaction

from app.knowledge.neo4j_client import Neo4jClient
from app.knowledge.schema import (
    NODE_KEY_PROPERTY,
    REL_CONNECTED_TO,
    REL_HAS_INTERFACE,
    REL_IN_SUBNET,
    REL_L3_ADJACENT,
    REL_ROUTES_TO,
)

__all__ = [
    "GraphData",
    "LAYER_ALL",
    "LAYER_L2",
    "LAYER_L3",
    "LAYERS",
    "fetch_graph",
    "rel_types_for_layer",
]

#: ``layer`` query-parameter values.
LAYER_L2 = "l2"
LAYER_L3 = "l3"
LAYER_ALL = "all"
LAYERS: tuple[str, ...] = (LAYER_L2, LAYER_L3, LAYER_ALL)

#: The L3 relationship family (everything that is not the single L2 type).
_L3_REL_TYPES: tuple[str, ...] = (
    REL_HAS_INTERFACE,
    REL_IN_SUBNET,
    REL_L3_ADJACENT,
    REL_ROUTES_TO,
)

#: Property name every projected element carries (the projection watermark).
_PROJECTED_AT_PROP = "last_projected_at"

#: A node label is unknown to the projection unless it is one of these seven.
_KNOWN_LABELS = frozenset(NODE_KEY_PROPERTY)

#: The wire shape :func:`fetch_graph` returns (JSON-safe, no driver types).
GraphData = dict[str, Any]


def rel_types_for_layer(layer: str) -> tuple[str, ...]:
    """Relationship types selected by *layer* (``l2`` / ``l3`` / ``all``)."""
    if layer == LAYER_L2:
        return (REL_CONNECTED_TO,)
    if layer == LAYER_L3:
        return _L3_REL_TYPES
    return (REL_CONNECTED_TO, *_L3_REL_TYPES)


def _node_key(label: str, properties: dict[str, Any]) -> Any:
    """The value of *label*'s key property within *properties*."""
    key_property = NODE_KEY_PROPERTY.get(label)
    if key_property is None:
        return None
    return properties.get(key_property)


def _coerce(value: Any) -> Any:
    """Make a single driver property value JSON-safe.

    The Bolt driver returns temporals as :class:`neo4j.time.DateTime`; everything
    we project is otherwise a primitive / list of primitives.  We stringify any
    object exposing ``isoformat`` (driver ``DateTime`` and stdlib ``datetime``)
    so the API layer never has to know about driver types.
    """
    isoformat = getattr(value, "isoformat", None)
    if callable(isoformat):
        return isoformat()
    return value


def _node_payload(label: str, raw_props: dict[str, Any]) -> dict[str, Any]:
    properties = {name: _coerce(val) for name, val in raw_props.items()}
    return {
        "label": label,
        "key": _node_key(label, properties),
        "properties": properties,
    }


def _projected_at(nodes: list[dict[str, Any]]) -> str | None:
    """Most recent ``last_projected_at`` across *nodes* (ISO-8601) or ``None``."""
    stamps = [
        stamp for node in nodes if (stamp := node["properties"].get(_PROJECTED_AT_PROP)) is not None
    ]
    if not stamps:
        return None
    return max(stamps)


def _primary_label(labels: list[str] | tuple[str, ...]) -> str | None:
    """The single projected label of a node (ignoring any extra labels)."""
    for label in labels:
        if label in _KNOWN_LABELS:
            return label
    return None


async def _read_graph(
    tx: AsyncManagedTransaction,
    *,
    rel_types: tuple[str, ...],
    site: str | None,
    vrf: str | None,
) -> dict[str, Any]:
    """Collect the projected subgraph in one transaction (driver-typed records).

    Edges are matched by the selected relationship types; the node set is the
    union of every surviving endpoint, so the result is always self-consistent.
    Filters are applied as endpoint predicates and bound as parameters (never
    string-interpolated) so untrusted ``site`` / ``vrf`` values cannot inject
    Cypher.
    """
    # Relationship types are validated module constants — safe to interpolate
    # into the type pattern (the driver cannot parameterize a rel-type literal).
    rel_pattern = "|".join(rel_types)
    cypher = (
        f"MATCH (a)-[r:{rel_pattern}]->(b) "
        "WHERE ($site IS NULL OR a.site = $site OR b.site = $site) "
        "  AND ($vrf IS NULL OR r.vrf = $vrf OR NOT type(r) = 'ROUTES_TO') "
        "RETURN labels(a) AS a_labels, properties(a) AS a_props, "
        "       labels(b) AS b_labels, properties(b) AS b_props, "
        "       type(r) AS rel_type, properties(r) AS rel_props"
    )
    result = await tx.run(cypher, site=site, vrf=vrf)

    nodes: dict[tuple[str, Any], dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []

    def _register(labels: list[str], props: dict[str, Any]) -> Any:
        label = _primary_label(labels)
        if label is None:
            return None
        payload = _node_payload(label, props)
        nodes[(label, payload["key"])] = payload
        return payload["key"]

    async for record in result:
        a_key = _register(record["a_labels"], record["a_props"])
        b_key = _register(record["b_labels"], record["b_props"])
        if a_key is None or b_key is None:
            continue
        edges.append(
            {
                "type": record["rel_type"],
                "source": a_key,
                "target": b_key,
                "properties": {name: _coerce(val) for name, val in record["rel_props"].items()},
            }
        )

    return {"nodes": list(nodes.values()), "edges": edges}


async def fetch_graph(
    client: Neo4jClient,
    *,
    layer: str,
    site: str | None = None,
    vrf: str | None = None,
) -> GraphData:
    """Read the projected topology subgraph as JSON-safe dicts.

    Args:
        client: The Neo4j access wrapper (:class:`Neo4jClient`).
        layer:  ``l2`` / ``l3`` / ``all`` — which relationship families to return.
        site:   Optional ``Device.site`` filter; ``None`` returns every site.
        vrf:    Optional VRF filter for ``ROUTES_TO`` edges; ``None`` returns all.

    Returns:
        ``{"nodes": [...], "edges": [...], "projected_at": <iso8601|None>}``
        where each node has ``label``/``key``/``properties`` and each edge has
        ``type``/``source``/``target``/``properties``.  ``projected_at`` is the
        most recent ``last_projected_at`` across the returned nodes.
    """
    rel_types = rel_types_for_layer(layer)
    graph = await client.execute_read(_read_graph, rel_types=rel_types, site=site, vrf=vrf)
    graph["projected_at"] = _projected_at(graph["nodes"])
    return graph
