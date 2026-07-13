"""Shared inventory loader for topology projection / rebuild (Wave 5 T4).

Both the discovery-sync worker path and the manual full-rebuild CLI load the
same Postgres inventory shape — always estate-wide, application layer
included (ADR-0052 §5 — both tables or neither). Delta passes scope only the
Neo4j WRITE set via :func:`filter_derived_for_scope`, never the load.
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


async def run_touched_device_ids(session: AsyncSession, run_id: UUID) -> frozenset[UUID]:
    """Device ids that produced raw artifacts in *run_id* (discovery-touched)."""
    rows = (
        await session.execute(
            select(RawArtifact.device_id).where(RawArtifact.run_id == run_id).distinct()
        )
    ).all()
    return frozenset(row[0] for row in rows if row[0] is not None)


async def load_inventory(session: AsyncSession) -> InventoryBundle:
    """Load the full inventory (+ application layer) for a projection pass.

    Always estate-wide: derivation needs cross-device joins and the run
    snapshot must be estate-complete (see the warning on
    :func:`filter_derived_for_scope`). The former scoped-load branch had no
    live caller and was removed (PR #161 review).
    """
    devices = list((await session.execute(select(Device))).scalars())
    applications = list((await session.execute(select(Application))).scalars())
    dependencies = list((await session.execute(select(ApplicationDependency))).scalars())
    interfaces = list((await session.execute(select(NormalizedInterfaceRow))).scalars())
    routes = list((await session.execute(select(NormalizedRouteRow))).scalars())
    neighbors = list((await session.execute(select(NormalizedNeighborRow))).scalars())

    return InventoryBundle(
        devices=devices,
        interfaces=interfaces,
        routes=routes,
        neighbors=neighbors,
        applications=applications,
        application_dependencies=dependencies,
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
    interfaces: Sequence[NormalizedInterfaceRow],
) -> tuple[Any, Any, Any]:
    """Keep derived elements owned by the discovery touch-set (Wave 5 T4).

    - Device / Interface / IPAddress nodes filtered by scope ids.
    - Edges kept when either endpoint key is a scoped device or interface.
    - Pass-through families are written REFERENCED-ONLY (PR #161 review — the
      wholesale pass-through re-MERGEd O(estate) route-prefix Subnets on every
      1-device delta): a Subnet iff its cidr rides a kept ``IN_SUBNET``/
      ``ROUTES_TO`` edge or a kept ``L3_ADJACENT`` edge's ``cidrs``; a Vlan iff
      a scoped *interfaces* row carries its ``vlan_id``; a VRF iff a kept
      ``ROUTES_TO`` edge names it; a Site iff a kept Device node sits in it.
      Every kept edge's Subnet endpoint stays writable — the projector MATCHes
      endpoints and silently drops the edge otherwise — while endpoints on
      untouched devices are NOT written (they exist from prior estate passes).
    - Applications pass through unchanged (ADR-0052 §5).

    .. warning:: Scope only the WRITE set, never the load/derivation: a scoped
       derivation cannot see cross-scope subnet/neighbor joins (missing
       ``L3_ADJACENT`` edges, device-level ``CONNECTED_TO`` fallbacks) and a
       scope-truncated ``snapshot_lists`` makes the run-to-run diff report
       every untouched device as removed.
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

    scoped_edges = DerivedEdges(
        connected_to=tuple(e for e in edges.connected_to if _edge_in_scope(e)),
        has_interface=tuple(e for e in edges.has_interface if _edge_in_scope(e)),
        in_subnet=tuple(e for e in edges.in_subnet if _edge_in_scope(e)),
        l3_adjacent=tuple(e for e in edges.l3_adjacent if _edge_in_scope(e)),
        routes_to=tuple(e for e in edges.routes_to if _edge_in_scope(e)),
    )

    # Reference rules mirror how the derivation produces each family (see
    # nodes.derive_nodes): kept-edge cidrs -> Subnet, scoped interface-row
    # vlan_id -> Vlan, kept routes_to vrf -> VRF, kept device site -> Site.
    referenced_cidrs = (
        {e.cidr for e in scoped_edges.in_subnet}
        | {e.cidr for e in scoped_edges.routes_to}
        | {cidr for e in scoped_edges.l3_adjacent for cidr in e.cidrs}
    )
    referenced_vlans = {
        row.vlan_id for row in interfaces if row.vlan_id is not None and str(row.id) in iface_keys
    }
    referenced_vrfs = {e.vrf.strip() for e in scoped_edges.routes_to if e.vrf.strip()}
    scoped_devices = tuple(n for n in nodes.devices if str(n.pg_id) in device_keys)
    referenced_sites = {n.site for n in scoped_devices if n.site}

    scoped_nodes = DerivedNodes(
        devices=scoped_devices,
        interfaces=tuple(n for n in nodes.interfaces if str(n.pg_id) in iface_keys),
        ip_addresses=tuple(n for n in nodes.ip_addresses if str(n.pg_id) in iface_keys),
        subnets=tuple(n for n in nodes.subnets if n.cidr in referenced_cidrs),
        vlans=tuple(n for n in nodes.vlans if n.vlan_id in referenced_vlans),
        vrfs=tuple(n for n in nodes.vrfs if n.name in referenced_vrfs),
        sites=tuple(n for n in nodes.sites if n.name in referenced_sites),
    )
    return scoped_nodes, scoped_edges, applications
