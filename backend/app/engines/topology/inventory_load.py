"""Shared inventory loader for topology projection / rebuild (Wave 5 T4).

Both the discovery-sync worker path and the manual full-rebuild CLI load the
same Postgres inventory shape. A optional *device_ids* filter scopes
interface/route/neighbor rows to run-touched devices while always loading the
full application layer (ADR-0052 §5 — both tables or neither).
"""

from __future__ import annotations

from collections.abc import Collection, Sequence
from dataclasses import dataclass
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.applications import Application, ApplicationDependency
from app.models.inventory import (
    Device,
    NormalizedInterfaceRow,
    NormalizedNeighborRow,
    NormalizedRouteRow,
    RawArtifact,
)

__all__ = [
    "InventoryBundle",
    "load_inventory",
    "run_touched_device_ids",
]


@dataclass(frozen=True, slots=True)
class InventoryBundle:
    """Row sets one topology derivation/projection pass reads."""

    devices: list[Device]
    interfaces: list[NormalizedInterfaceRow]
    routes: list[NormalizedRouteRow]
    neighbors: list[NormalizedNeighborRow]
    applications: list[Application]
    application_dependencies: list[ApplicationDependency]
    #: When set, Neo4j writes should be limited to this device set (Wave 5 T4).
    scope_device_ids: frozenset[UUID] | None = None


async def run_touched_device_ids(session: AsyncSession, run_id: UUID) -> frozenset[UUID]:
    """Device ids that produced raw artifacts in *run_id* (discovery-touched)."""
    rows = (
        await session.execute(
            select(RawArtifact.device_id).where(RawArtifact.run_id == run_id).distinct()
        )
    ).all()
    return frozenset(row[0] for row in rows if row[0] is not None)


async def load_inventory(
    session: AsyncSession,
    *,
    device_ids: Collection[UUID] | None = None,
) -> InventoryBundle:
    """Load inventory (+ application layer) for a projection pass.

    Parameters
    ----------
    device_ids:
        When provided, only load interfaces/routes/neighbors for those devices.
        **All** devices are still loaded so L2 neighbor resolution can match
        peer hostnames/mgmt_ips outside the touch set. Applications are always
        loaded fully (ADR-0052 §5).
    """
    devices = list((await session.execute(select(Device))).scalars())
    applications = list((await session.execute(select(Application))).scalars())
    dependencies = list((await session.execute(select(ApplicationDependency))).scalars())

    if device_ids is None:
        interfaces = list((await session.execute(select(NormalizedInterfaceRow))).scalars())
        routes = list((await session.execute(select(NormalizedRouteRow))).scalars())
        neighbors = list((await session.execute(select(NormalizedNeighborRow))).scalars())
        scope: frozenset[UUID] | None = None
    else:
        scope = frozenset(device_ids)
        if not scope:
            interfaces, routes, neighbors = [], [], []
        else:
            interfaces = list(
                (
                    await session.execute(
                        select(NormalizedInterfaceRow).where(
                            NormalizedInterfaceRow.device_id.in_(scope)
                        )
                    )
                ).scalars()
            )
            routes = list(
                (
                    await session.execute(
                        select(NormalizedRouteRow).where(NormalizedRouteRow.device_id.in_(scope))
                    )
                ).scalars()
            )
            neighbors = list(
                (
                    await session.execute(
                        select(NormalizedNeighborRow).where(
                            NormalizedNeighborRow.device_id.in_(scope)
                        )
                    )
                ).scalars()
            )

    return InventoryBundle(
        devices=devices,
        interfaces=interfaces,
        routes=routes,
        neighbors=neighbors,
        applications=applications,
        application_dependencies=dependencies,
        scope_device_ids=scope,
    )


def interface_ids_for_scope(
    interfaces: Sequence[NormalizedInterfaceRow],
    scope: Collection[UUID],
) -> frozenset[UUID]:
    """Interface row ids owned by devices in *scope*."""
    return frozenset(row.id for row in interfaces if row.device_id in scope)


def filter_derived_for_scope(
    *,
    nodes: Any,
    edges: Any,
    applications: Any,
    scope_device_ids: Collection[UUID],
    scope_interface_ids: Collection[UUID],
) -> tuple[Any, Any, Any]:
    """Keep derived elements owned by the discovery touch-set (Wave 5 T4).

    - Device / Interface / IPAddress nodes filtered by scope ids.
    - Shared Subnet/Vlan/Vrf/Site nodes retained (cheap MERGEs; required as
      endpoints of scoped edges).
    - Edges kept when either endpoint key is a scoped device or interface.
    - Applications pass through unchanged (ADR-0052 §5).
    """
    from app.engines.topology.nodes import DerivedNodes
    from app.engines.topology.projector import DerivedEdges

    device_keys = {str(i) for i in scope_device_ids}
    iface_keys = {str(i) for i in scope_interface_ids}
    endpoint_keys = device_keys | iface_keys

    def _edge_in_scope(edge: Any) -> bool:
        # CONNECTED_TO
        if hasattr(edge, "a") and hasattr(edge, "b"):
            return edge.a.key in endpoint_keys or edge.b.key in endpoint_keys
        # HAS_INTERFACE / ROUTES_TO / L3_ADJACENT / IN_SUBNET
        for attr in (
            "device_pg_id",
            "interface_pg_id",
            "device_a_pg_id",
            "device_b_pg_id",
        ):
            val = getattr(edge, attr, None)
            if val is not None and str(val) in endpoint_keys:
                return True
        return False

    scoped_nodes = DerivedNodes(
        devices=tuple(n for n in nodes.devices if str(n.pg_id) in device_keys),
        interfaces=tuple(n for n in nodes.interfaces if str(n.pg_id) in iface_keys),
        ip_addresses=tuple(n for n in nodes.ip_addresses if str(n.pg_id) in iface_keys),
        subnets=nodes.subnets,
        vlans=nodes.vlans,
        vrfs=nodes.vrfs,
        sites=nodes.sites,
    )
    scoped_edges = DerivedEdges(
        connected_to=tuple(e for e in edges.connected_to if _edge_in_scope(e)),
        has_interface=tuple(e for e in edges.has_interface if _edge_in_scope(e)),
        in_subnet=tuple(e for e in edges.in_subnet if _edge_in_scope(e)),
        l3_adjacent=tuple(e for e in edges.l3_adjacent if _edge_in_scope(e)),
        routes_to=tuple(e for e in edges.routes_to if _edge_in_scope(e)),
    )
    return scoped_nodes, scoped_edges, applications
