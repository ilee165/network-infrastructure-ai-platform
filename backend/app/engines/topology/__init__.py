"""Topology engine (M2, ADR-0005): Postgres -> Neo4j projection layer.

Neo4j is a pure projection of the Postgres ``normalized_*`` tables; this
package derives the typed graph nodes (and, in later tasks, relationships
and projection plumbing) from inventory rows.
"""

from app.engines.topology.edges import (
    ConnectedToEdge,
    DerivedL3Edges,
    EdgeEndpoint,
    HasInterfaceEdge,
    InSubnetEdge,
    L2BuildReport,
    L2BuildResult,
    L3AdjacentEdge,
    RoutesToEdge,
    build_l2_edges,
    build_l3_edges,
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
    "DerivedL3Edges",
    "DerivedNodes",
    "DeviceNode",
    "EdgeEndpoint",
    "GraphNode",
    "HasInterfaceEdge",
    "IPAddressNode",
    "InSubnetEdge",
    "InterfaceNode",
    "L2BuildReport",
    "L2BuildResult",
    "L3AdjacentEdge",
    "RoutesToEdge",
    "SiteNode",
    "SubnetNode",
    "VlanNode",
    "VrfNode",
    "build_l2_edges",
    "build_l3_edges",
    "derive_nodes",
]
