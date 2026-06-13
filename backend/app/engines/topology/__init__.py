"""Topology engine (M2, ADR-0005): Postgres -> Neo4j projection layer.

Neo4j is a pure projection of the Postgres ``normalized_*`` tables; this
package derives the typed graph nodes (and, in later tasks, relationships
and projection plumbing) from inventory rows.
"""

from app.engines.topology.edges import (
    ConnectedToEdge,
    EdgeEndpoint,
    L2BuildReport,
    L2BuildResult,
    build_l2_edges,
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
    derive_nodes,
)

__all__ = [
    "ConnectedToEdge",
    "DerivedNodes",
    "DeviceNode",
    "EdgeEndpoint",
    "GraphNode",
    "IPAddressNode",
    "InterfaceNode",
    "L2BuildReport",
    "L2BuildResult",
    "SiteNode",
    "SubnetNode",
    "VlanNode",
    "VrfNode",
    "build_l2_edges",
    "derive_nodes",
]
