"""Graph-node derivation for the topology projection (M2-04, ADR-0005).

Neo4j is a *pure projection* of the Postgres ``devices`` /
``normalized_interfaces`` / ``normalized_routes`` tables: this module turns
those rows into typed, frozen node records for the seven M2 labels —
``Device``, ``Interface``, ``IPAddress``, ``Subnet``, ``Vlan``, ``VRF``,
``Site`` — without touching either database. :func:`derive_nodes` is a pure
function: deterministic ordering, dedup by key, no input mutation.

Derivation rules (approved M2 plan):

- ``Device`` / ``Interface`` map 1:1 from rows and carry ``pg_id`` (the UUID
  of the source Postgres row).
- ``Subnet`` comes from each interface ``ip_address`` *network* AND from
  each route ``prefix`` (M2-05: every ``ROUTES_TO`` edge needs a real
  projected Subnet endpoint).
- ``IPAddress`` comes from each interface ``ip_address`` *host*, deduped by
  address (lowest interface ``pg_id`` wins, deterministically).
- ``Vlan`` from distinct interface ``vlan_id``; ``VRF`` from distinct
  non-empty route ``vrf`` (``''`` sentinel = global table, ADR-0004 natural
  keys); ``Site`` from distinct non-empty ``Device.site``.

Every record renders a Neo4j-ready property map via
:meth:`GraphNode.neo4j_properties`, which stamps ``last_projected_at``
(tz-aware UTC of the projection pass) onto every node.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from datetime import datetime
from enum import StrEnum
from ipaddress import (
    IPv4Address,
    IPv4Network,
    IPv6Address,
    IPv6Network,
    ip_address,
    ip_interface,
    ip_network,
)
from typing import Any, ClassVar, TypeVar
from uuid import UUID

from pydantic import BaseModel, ConfigDict

from app.models.inventory import Device, NormalizedInterfaceRow, NormalizedRouteRow
from app.schemas.normalized import InterfaceAdminStatus, InterfaceOperStatus

__all__ = [
    "DerivedNodes",
    "DeviceNode",
    "GraphNode",
    "IPAddressNode",
    "InterfaceNode",
    "SiteNode",
    "SubnetNode",
    "VlanNode",
    "VrfNode",
    "derive_nodes",
]


# ---------------------------------------------------------------------------
# Typed node records (frozen — they are projection inputs, not scratch space)
# ---------------------------------------------------------------------------


class GraphNode(BaseModel):
    """Base for projected graph nodes: label, key property, Neo4j payload."""

    model_config = ConfigDict(frozen=True, extra="forbid", str_strip_whitespace=True)

    label: ClassVar[str]
    """Neo4j node label this record projects to."""

    key_property: ClassVar[str]
    """Name of the property MERGE keys on (``pg_id`` or the natural key)."""

    @property
    def key(self) -> Any:
        """Value of :attr:`key_property` for this record."""
        return getattr(self, self.key_property)

    def neo4j_properties(self, last_projected_at: datetime) -> dict[str, Any]:
        """Flat Neo4j property map: driver-safe values + projection stamp.

        UUIDs become strings (the Bolt protocol has no UUID type) and
        StrEnums collapse to their wire values. *last_projected_at* must be
        timezone-aware (ADR-0005: every projected node carries the tz-aware
        UTC instant of the projection pass).
        """
        if last_projected_at.tzinfo is None:
            raise ValueError("last_projected_at must be timezone-aware")
        props: dict[str, Any] = {}
        for field_name in type(self).model_fields:
            value = getattr(self, field_name)
            if isinstance(value, UUID):
                value = str(value)
            elif isinstance(value, StrEnum):
                value = str(value.value)
            props[field_name] = value
        props["last_projected_at"] = last_projected_at
        return props


class DeviceNode(GraphNode):
    """A managed device (1:1 with a ``devices`` row)."""

    label: ClassVar[str] = "Device"
    key_property: ClassVar[str] = "pg_id"

    pg_id: UUID
    hostname: str
    mgmt_ip: str
    vendor_id: str | None
    model: str | None
    site: str | None


class InterfaceNode(GraphNode):
    """A device interface (1:1 with a ``normalized_interfaces`` row)."""

    label: ClassVar[str] = "Interface"
    key_property: ClassVar[str] = "pg_id"

    pg_id: UUID
    name: str
    admin_status: InterfaceAdminStatus
    oper_status: InterfaceOperStatus
    mac_address: str | None


class IPAddressNode(GraphNode):
    """A host address from an interface ``ip_address``; keyed by address.

    ``pg_id`` is the ``normalized_interfaces`` row the address was derived
    from (lowest row UUID when several interfaces share the address).
    """

    label: ClassVar[str] = "IPAddress"
    key_property: ClassVar[str] = "address"

    pg_id: UUID
    address: str


class SubnetNode(GraphNode):
    """A subnet derived from an interface ``ip_address`` network."""

    label: ClassVar[str] = "Subnet"
    key_property: ClassVar[str] = "cidr"

    cidr: str


class VlanNode(GraphNode):
    """A VLAN derived from distinct interface ``vlan_id`` values."""

    label: ClassVar[str] = "Vlan"
    key_property: ClassVar[str] = "vlan_id"

    vlan_id: int


class VrfNode(GraphNode):
    """A VRF derived from distinct non-empty route ``vrf`` values."""

    label: ClassVar[str] = "VRF"
    key_property: ClassVar[str] = "name"

    name: str


class SiteNode(GraphNode):
    """A site derived from distinct non-empty ``Device.site`` values."""

    label: ClassVar[str] = "Site"
    key_property: ClassVar[str] = "name"

    name: str


class DerivedNodes(BaseModel):
    """The complete node sets of one derivation pass, per label."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    devices: tuple[DeviceNode, ...] = ()
    interfaces: tuple[InterfaceNode, ...] = ()
    ip_addresses: tuple[IPAddressNode, ...] = ()
    subnets: tuple[SubnetNode, ...] = ()
    vlans: tuple[VlanNode, ...] = ()
    vrfs: tuple[VrfNode, ...] = ()
    sites: tuple[SiteNode, ...] = ()


# ---------------------------------------------------------------------------
# Derivation
# ---------------------------------------------------------------------------

_NodeT = TypeVar("_NodeT", bound=GraphNode)


def _dedupe_sorted(nodes: Iterable[_NodeT]) -> tuple[_NodeT, ...]:
    """Drop key-duplicates from already-sorted *nodes*, keeping the first."""
    out: list[_NodeT] = []
    seen: set[Any] = set()
    for node in nodes:
        if node.key in seen:
            continue
        seen.add(node.key)
        out.append(node)
    return tuple(out)


def _addr_sort_key(address: IPv4Address | IPv6Address) -> tuple[int, int]:
    """Total order over mixed v4/v6 addresses: version first, then value."""
    return (address.version, int(address))


def route_prefix_network(prefix: str) -> IPv4Network | IPv6Network:
    """Canonical network of a route ``prefix`` (host bits tolerated).

    Shared by Subnet-node derivation and the ``ROUTES_TO`` edge builder
    (M2-05) so route edges always key the exact CIDR string their Subnet
    endpoint was projected under.
    """
    return ip_network(prefix, strict=False)


def derive_nodes(
    devices: Sequence[Device],
    interfaces: Sequence[NormalizedInterfaceRow],
    routes: Sequence[NormalizedRouteRow],
) -> DerivedNodes:
    """Derive the seven node sets from inventory rows (pure, deterministic).

    Inputs are plain in-memory ORM rows — no session, no I/O. Output ordering
    and dedup are independent of input order: row-backed nodes sort by their
    display name then ``pg_id``; derived nodes sort by natural key.
    """
    device_nodes = _dedupe_sorted(
        sorted(
            (
                DeviceNode(
                    pg_id=device.id,
                    hostname=device.hostname,
                    mgmt_ip=device.mgmt_ip,
                    vendor_id=device.vendor_id,
                    model=device.model,
                    site=device.site,
                )
                for device in devices
            ),
            key=lambda node: (node.hostname, str(node.pg_id)),
        )
    )

    interface_nodes = _dedupe_sorted(
        sorted(
            (
                InterfaceNode(
                    pg_id=row.id,
                    name=row.name,
                    admin_status=row.admin_status,
                    oper_status=row.oper_status,
                    mac_address=row.mac_address,
                )
                for row in interfaces
            ),
            key=lambda node: (node.name, str(node.pg_id)),
        )
    )

    addressed = [(ip_interface(row.ip_address), row) for row in interfaces if row.ip_address]

    ip_nodes = _dedupe_sorted(
        sorted(
            (IPAddressNode(pg_id=row.id, address=str(iface.ip)) for iface, row in addressed),
            key=lambda node: (*_addr_sort_key(ip_address(node.address)), str(node.pg_id)),
        )
    )

    # Route prefixes are projected Subnet nodes too (M2-05): every ROUTES_TO
    # edge must land on a real endpoint.
    subnet_networks = {iface.network for iface, _ in addressed} | {
        route_prefix_network(row.prefix) for row in routes
    }
    subnet_nodes = tuple(
        SubnetNode(cidr=str(network))
        for network in sorted(
            subnet_networks,
            key=lambda net: (net.version, int(net.network_address), net.prefixlen),
        )
    )

    vlan_nodes = tuple(
        VlanNode(vlan_id=vlan_id)
        for vlan_id in sorted({row.vlan_id for row in interfaces if row.vlan_id is not None})
    )

    _vrf_names: set[str] = {row.vrf.strip() for row in routes if row.vrf.strip()}
    vrf_nodes = tuple(VrfNode(name=name) for name in sorted(_vrf_names))

    _site_names: set[str] = {s for device in devices if (s := (device.site or "").strip())}
    site_nodes = tuple(SiteNode(name=name) for name in sorted(_site_names))

    return DerivedNodes(
        devices=device_nodes,
        interfaces=interface_nodes,
        ip_addresses=ip_nodes,
        subnets=subnet_nodes,
        vlans=vlan_nodes,
        vrfs=vrf_nodes,
        sites=site_nodes,
    )
