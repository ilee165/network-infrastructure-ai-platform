"""Topology engine (M2, ADR-0005): Postgres -> Neo4j projection layer.

Neo4j is a pure projection of the Postgres ``normalized_*`` tables; this
package derives the typed graph nodes (and, in later tasks, relationships
and projection plumbing) from inventory rows.
"""

from app.engines.topology.app_derivation import (
    DerivationPlan,
    DerivationStats,
    PlannedApplication,
    PlannedDependency,
    ProvenanceStep,
    derive_application_dependencies,
)
from app.engines.topology.app_derivation_store import (
    DerivationApplyStats,
    SourceApplyStats,
    apply_derivation_plan,
)
from app.engines.topology.applications import (
    ApplicationNode,
    DependsOnEdge,
    DerivedApplications,
    derive_applications,
)
from app.engines.topology.diff import (
    TopologyDiff,
    diff_snapshots,
)
from app.engines.topology.dns import (
    DerivedDns,
    DnsRecordNode,
    DnsZoneNode,
    InZoneEdge,
    ResolvesToEdge,
    derive_dns,
    dns_record_key,
)
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
from app.engines.topology.projector import (
    DEFAULT_BATCH_SIZE,
    PROJECTED_NODE_LABELS,
    PROJECTED_REL_TYPES,
    DerivedEdges,
    full_rebuild,
    project,
)
from app.engines.topology.snapshots import (
    SnapshotData,
    build_snapshot,
    upsert_snapshot,
)
from app.engines.topology.sync import (
    DerivedTopology,
    derive_topology,
    snapshot_lists,
)

__all__ = [
    "DEFAULT_BATCH_SIZE",
    "PROJECTED_NODE_LABELS",
    "PROJECTED_REL_TYPES",
    "ApplicationNode",
    "ConnectedToEdge",
    "DependsOnEdge",
    "DerivationApplyStats",
    "DerivationPlan",
    "DerivationStats",
    "DerivedApplications",
    "DerivedDns",
    "DerivedEdges",
    "DerivedL3Edges",
    "DerivedNodes",
    "DerivedTopology",
    "DeviceNode",
    "DnsRecordNode",
    "DnsZoneNode",
    "EdgeEndpoint",
    "GraphNode",
    "HasInterfaceEdge",
    "IPAddressNode",
    "InSubnetEdge",
    "InZoneEdge",
    "InterfaceNode",
    "L2BuildReport",
    "L2BuildResult",
    "L3AdjacentEdge",
    "PlannedApplication",
    "PlannedDependency",
    "ProvenanceStep",
    "ResolvesToEdge",
    "RoutesToEdge",
    "SiteNode",
    "SnapshotData",
    "SourceApplyStats",
    "SubnetNode",
    "TopologyDiff",
    "VlanNode",
    "VrfNode",
    "apply_derivation_plan",
    "build_l2_edges",
    "build_l3_edges",
    "build_snapshot",
    "derive_application_dependencies",
    "derive_applications",
    "derive_dns",
    "derive_nodes",
    "derive_topology",
    "diff_snapshots",
    "dns_record_key",
    "full_rebuild",
    "project",
    "snapshot_lists",
    "upsert_snapshot",
]
