"""Edge builders for the topology projection (M2-05, ADR-0005).

L2: ``normalized_neighbors`` rows become ``CONNECTED_TO`` edges between
``Interface`` endpoints, falling back to the owning ``Device`` endpoint when
an interface cannot be resolved. Neo4j stays a pure subset of Postgres:
neighbors whose remote device cannot be matched to a ``devices`` row are
*skipped* (never phantom nodes) and counted in the returned
:class:`L2BuildReport`.

Neighbor resolution order (approved M2 plan):

1. ``neighbor_name`` vs ``devices.hostname``, case-insensitive exact match;
2. bare-label match (``name.split('.')[0]``) tolerating bare-name vs FQDN
   mismatch in either direction — skipped when the bare label is ambiguous
   across devices;
3. ``neighbor_address`` vs ``devices.mgmt_ip``.

Bidirectional dedup: an adjacency observed from both ends collapses to ONE
edge keyed by the canonical sorted endpoint tuple; protocols are unioned and
interface names kept per endpoint.

L3: ``HAS_INTERFACE`` (Device -> Interface), ``IN_SUBNET`` (Interface ->
Subnet, from the interface ``ip_address`` network), ``L3_ADJACENT``
(device pairs sharing a subnet — derived, deduped to one edge per pair
carrying every shared CIDR, self-pairs excluded) and ``ROUTES_TO``
(Device -> Subnet from ``normalized_routes``; route-prefix subnets are
projected nodes, see :func:`app.engines.topology.nodes.derive_nodes`).
Rows referencing a device absent from *devices* are skipped — the same
no-phantom-nodes invariant as L2.

All builders are pure functions: no I/O, no input mutation, output fully
determined by input *content* (insensitive to input ordering). Edge records
carry node keys as strings (``pg_id`` UUIDs stringified — the same form the
Neo4j ``MERGE`` keys use, see ``app.knowledge.schema``).
"""

from __future__ import annotations

from collections.abc import Sequence
from ipaddress import ip_interface
from typing import ClassVar
from uuid import UUID

from pydantic import BaseModel, ConfigDict

from app.engines.topology.nodes import route_prefix_network
from app.knowledge.schema import (
    LABEL_DEVICE,
    LABEL_INTERFACE,
    REL_CONNECTED_TO,
    REL_HAS_INTERFACE,
    REL_IN_SUBNET,
    REL_L3_ADJACENT,
    REL_ROUTES_TO,
)
from app.models.inventory import (
    Device,
    NormalizedInterfaceRow,
    NormalizedNeighborRow,
    NormalizedRouteRow,
)

__all__ = [
    "ConnectedToEdge",
    "DerivedL3Edges",
    "EdgeEndpoint",
    "HasInterfaceEdge",
    "InSubnetEdge",
    "L2BuildReport",
    "L2BuildResult",
    "L3AdjacentEdge",
    "RoutesToEdge",
    "build_l2_edges",
    "build_l3_edges",
]


# ---------------------------------------------------------------------------
# Typed edge records (frozen — projection inputs, not scratch space)
# ---------------------------------------------------------------------------


class EdgeEndpoint(BaseModel):
    """One end of a projected edge: node label + MERGE-key value (string)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    label: str
    key: str

    @property
    def sort_key(self) -> tuple[str, str]:
        """Total order used for canonical endpoint pairing."""
        return (self.label, self.key)


class ConnectedToEdge(BaseModel):
    """An L2 adjacency; endpoints are canonically sorted (``a`` <= ``b``).

    ``interface_a`` / ``interface_b`` are the *observed* interface names on
    each side ('' when the protocol did not report one); they are carried as
    edge properties even when an endpoint fell back to the Device level.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    rel_type: ClassVar[str] = REL_CONNECTED_TO

    a: EdgeEndpoint
    b: EdgeEndpoint
    protocols: tuple[str, ...]
    interface_a: str = ""
    interface_b: str = ""


class L2BuildReport(BaseModel):
    """Outcome counts of one L2 build pass (deterministic)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    neighbor_rows: int
    edges_built: int
    unresolved_neighbors: int
    unresolved_neighbor_names: tuple[str, ...] = ()


class L2BuildResult(BaseModel):
    """Edges plus the build report of one L2 pass."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    edges: tuple[ConnectedToEdge, ...] = ()
    report: L2BuildReport


# ---------------------------------------------------------------------------
# Neighbor -> device resolution
# ---------------------------------------------------------------------------


def _bare(name: str) -> str:
    """Lower-cased bare label of a (possibly fully qualified) host name."""
    return name.split(".", 1)[0].strip().lower()


class _DeviceIndex:
    """Lookup tables for resolving a neighbor row to a known device."""

    def __init__(self, devices: Sequence[Device]) -> None:
        self.by_id: dict[UUID, Device] = {device.id: device for device in devices}
        ordered = sorted(self.by_id.values(), key=lambda d: (d.hostname.lower(), str(d.id)))
        self._exact: dict[str, Device | None] = {}
        self._bare: dict[str, Device | None] = {}
        self._by_mgmt_ip: dict[str, Device] = {}
        for device in ordered:
            self._claim(self._exact, device.hostname.strip().lower(), device)
            self._claim(self._bare, _bare(device.hostname), device)
            self._by_mgmt_ip.setdefault(device.mgmt_ip, device)

    @staticmethod
    def _claim(table: dict[str, Device | None], key: str, device: Device) -> None:
        """Register *key*; a second distinct claimant marks it ambiguous."""
        if not key:
            return
        if key in table and table[key] is not device:
            table[key] = None  # ambiguous — name matching must not guess
        else:
            table.setdefault(key, device)

    def resolve(self, row: NormalizedNeighborRow) -> Device | None:
        """Match a neighbor row to a device, or ``None`` when unresolved."""
        name = row.neighbor_name.strip().lower()
        device = self._exact.get(name) or self._bare.get(_bare(row.neighbor_name))
        if device is None and row.neighbor_address:
            device = self._by_mgmt_ip.get(row.neighbor_address)
        return device


# ---------------------------------------------------------------------------
# L2 builder
# ---------------------------------------------------------------------------


def _endpoint(
    device: Device,
    interface_name: str,
    interfaces_by_name: dict[tuple[UUID, str], NormalizedInterfaceRow],
) -> EdgeEndpoint:
    """Interface endpoint when resolvable on *device*, else Device endpoint."""
    row = interfaces_by_name.get((device.id, interface_name.strip().lower()))
    if row is not None:
        return EdgeEndpoint(label=LABEL_INTERFACE, key=str(row.id))
    return EdgeEndpoint(label=LABEL_DEVICE, key=str(device.id))


def build_l2_edges(
    devices: Sequence[Device],
    interfaces: Sequence[NormalizedInterfaceRow],
    neighbors: Sequence[NormalizedNeighborRow],
) -> L2BuildResult:
    """Build deduped ``CONNECTED_TO`` edges from neighbor rows (pure).

    A row contributes an edge only when both its reporting device and its
    remote neighbor resolve to known ``devices`` rows; otherwise it is
    skipped and counted (Neo4j-subset-of-Postgres invariant — no phantom
    nodes). Endpoints prefer the matching ``normalized_interfaces`` row
    (case-insensitive name match) and fall back to the owning device.
    """
    index = _DeviceIndex(devices)
    interfaces_by_name: dict[tuple[UUID, str], NormalizedInterfaceRow] = {}
    for iface in sorted(interfaces, key=lambda r: (r.name.lower(), str(r.id))):
        interfaces_by_name.setdefault((iface.device_id, iface.name.strip().lower()), iface)

    # Deterministic processing order, independent of caller ordering: sort by
    # the rows' natural-key tuple (their unique constraint).
    ordered_rows = sorted(
        neighbors,
        key=lambda r: (
            str(r.device_id),
            str(r.protocol),
            r.local_interface,
            r.neighbor_name,
            r.neighbor_interface,
        ),
    )

    merged: dict[tuple[EdgeEndpoint, EdgeEndpoint], tuple[set[str], dict[EdgeEndpoint, str]]] = {}
    unresolved_names: set[str] = set()
    phantom_local_ids: set[str] = set()
    unresolved = 0

    for row in ordered_rows:
        local_device = index.by_id.get(row.device_id)
        remote_device = index.resolve(row)
        if local_device is None or remote_device is None:
            unresolved += 1
            if local_device is None:
                # The reporting device is not in the supplied devices list.
                # The neighbor name itself may be perfectly resolvable, so it
                # must NOT be added to unresolved_names.
                phantom_local_ids.add(str(row.device_id))
            else:
                # Remote neighbor could not be matched — this is the true
                # "unresolved neighbor" case the field name describes.
                unresolved_names.add(row.neighbor_name)
            continue

        local = _endpoint(local_device, row.local_interface, interfaces_by_name)
        remote = _endpoint(remote_device, row.neighbor_interface, interfaces_by_name)
        names = {local: row.local_interface, remote: row.neighbor_interface}
        if local == remote:  # degenerate self-pair: order the names themselves
            names = {local: min(row.local_interface, row.neighbor_interface)}
        a, b = sorted((local, remote), key=lambda e: e.sort_key)

        protocols, endpoint_names = merged.setdefault((a, b), (set(), {}))
        protocols.add(str(row.protocol))
        for endpoint, name in names.items():
            if name and not endpoint_names.get(endpoint):
                endpoint_names[endpoint] = name

    edges = tuple(
        ConnectedToEdge(
            a=a,
            b=b,
            protocols=tuple(sorted(protocols)),
            interface_a=endpoint_names.get(a, ""),
            interface_b=endpoint_names.get(b, ""),
        )
        for (a, b), (protocols, endpoint_names) in sorted(
            merged.items(), key=lambda item: (item[0][0].sort_key, item[0][1].sort_key)
        )
    )
    return L2BuildResult(
        edges=edges,
        report=L2BuildReport(
            neighbor_rows=len(neighbors),
            edges_built=len(edges),
            unresolved_neighbors=unresolved,
            unresolved_neighbor_names=tuple(sorted(unresolved_names)),
        ),
    )


# ---------------------------------------------------------------------------
# L3 typed edge records
# ---------------------------------------------------------------------------


class HasInterfaceEdge(BaseModel):
    """Device owns an interface (1:1 with a ``normalized_interfaces`` row)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    rel_type: ClassVar[str] = REL_HAS_INTERFACE

    device_pg_id: str
    interface_pg_id: str


class InSubnetEdge(BaseModel):
    """Interface participates in the subnet of its ``ip_address`` network."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    rel_type: ClassVar[str] = REL_IN_SUBNET

    interface_pg_id: str
    cidr: str


class L3AdjacentEdge(BaseModel):
    """Two devices share >=1 subnet; one edge per pair, canonically sorted.

    ``cidrs`` lists every shared subnet CIDR (sorted) as an edge property.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    rel_type: ClassVar[str] = REL_L3_ADJACENT

    device_a_pg_id: str
    device_b_pg_id: str
    cidrs: tuple[str, ...]


class RoutesToEdge(BaseModel):
    """Device routes toward a subnet (one edge per distinct route row tuple).

    ``next_hop`` / ``vrf`` keep the ``''`` sentinel of ``normalized_routes``
    (absent / global table, ADR-0004 natural keys).
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    rel_type: ClassVar[str] = REL_ROUTES_TO

    device_pg_id: str
    cidr: str
    protocol: str
    next_hop: str = ""
    vrf: str = ""
    metric: int | None = None
    distance: int | None = None


class DerivedL3Edges(BaseModel):
    """The complete L3 edge sets of one build pass, per relationship type."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    has_interface: tuple[HasInterfaceEdge, ...] = ()
    in_subnet: tuple[InSubnetEdge, ...] = ()
    l3_adjacent: tuple[L3AdjacentEdge, ...] = ()
    routes_to: tuple[RoutesToEdge, ...] = ()


# ---------------------------------------------------------------------------
# L3 builder
# ---------------------------------------------------------------------------


def build_l3_edges(
    devices: Sequence[Device],
    interfaces: Sequence[NormalizedInterfaceRow],
    routes: Sequence[NormalizedRouteRow],
) -> DerivedL3Edges:
    """Build the four L3 edge sets from inventory rows (pure, deterministic).

    Interface/route rows whose ``device_id`` is not among *devices* are
    skipped: a Device edge endpoint must always be a projected node
    (Neo4j-subset-of-Postgres invariant). ``IN_SUBNET`` needs no such filter
    — both of its endpoints derive from the interface row itself.
    """
    known_devices = {device.id for device in devices}

    has_interface = tuple(
        HasInterfaceEdge(device_pg_id=str(row.device_id), interface_pg_id=str(row.id))
        for row in sorted(interfaces, key=lambda r: (str(r.device_id), r.name, str(r.id)))
        if row.device_id in known_devices
    )

    addressed = [(ip_interface(row.ip_address), row) for row in interfaces if row.ip_address]

    in_subnet = tuple(
        InSubnetEdge(interface_pg_id=str(row.id), cidr=str(iface.network))
        for iface, row in sorted(
            addressed, key=lambda pair: (str(pair[1].id), str(pair[0].network))
        )
    )

    # L3_ADJACENT: device pairs sharing a subnet, one edge per pair with all
    # shared CIDRs; self-pairs excluded.
    devices_by_subnet: dict[str, set[str]] = {}
    for iface, row in addressed:
        if row.device_id in known_devices:
            devices_by_subnet.setdefault(str(iface.network), set()).add(str(row.device_id))
    pair_cidrs: dict[tuple[str, str], set[str]] = {}
    for cidr, members in devices_by_subnet.items():
        ordered = sorted(members)
        for i, device_a in enumerate(ordered):
            for device_b in ordered[i + 1 :]:
                pair_cidrs.setdefault((device_a, device_b), set()).add(cidr)
    l3_adjacent = tuple(
        L3AdjacentEdge(device_a_pg_id=a, device_b_pg_id=b, cidrs=tuple(sorted(cidrs)))
        for (a, b), cidrs in sorted(pair_cidrs.items())
    )

    routes_to = tuple(
        sorted(
            {
                RoutesToEdge(
                    device_pg_id=str(row.device_id),
                    cidr=str(route_prefix_network(row.prefix)),
                    protocol=str(row.protocol),
                    next_hop=row.next_hop,
                    vrf=row.vrf,
                    metric=row.metric,
                    distance=row.distance,
                )
                for row in routes
                if row.device_id in known_devices
            },
            key=lambda edge: (
                edge.device_pg_id,
                edge.cidr,
                edge.protocol,
                edge.vrf,
                edge.next_hop,
                edge.metric is None,
                edge.metric or 0,
                edge.distance is None,
                edge.distance or 0,
            ),
        )
    )

    return DerivedL3Edges(
        has_interface=has_interface,
        in_subnet=in_subnet,
        l3_adjacent=l3_adjacent,
        routes_to=routes_to,
    )
