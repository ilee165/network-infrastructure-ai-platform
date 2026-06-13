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

All builders are pure functions: no I/O, no input mutation, output fully
determined by input *content* (insensitive to input ordering). Edge records
carry node keys as strings (``pg_id`` UUIDs stringified — the same form the
Neo4j ``MERGE`` keys use, see ``app.knowledge.schema``).
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import ClassVar
from uuid import UUID

from pydantic import BaseModel, ConfigDict

from app.knowledge.schema import LABEL_DEVICE, LABEL_INTERFACE, REL_CONNECTED_TO
from app.models.inventory import Device, NormalizedInterfaceRow, NormalizedNeighborRow

__all__ = [
    "ConnectedToEdge",
    "EdgeEndpoint",
    "L2BuildReport",
    "L2BuildResult",
    "build_l2_edges",
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
    unresolved = 0

    for row in ordered_rows:
        local_device = index.by_id.get(row.device_id)
        remote_device = index.resolve(row)
        if local_device is None or remote_device is None:
            unresolved += 1
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
