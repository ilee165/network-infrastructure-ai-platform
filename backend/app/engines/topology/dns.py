"""DNS-dependency layer derivation (M5 task #13, ADR-0022).

The DNS-dependency layer is a *pure projection* of the normalized Infoblox DDI
currency (:class:`~app.schemas.normalized.NormalizedDnsRecord` + the zone FQDN
list from ``DdiDnsCapability.get_zones``) onto two new Neo4j labels and two
relationship types, mirroring the M2 L2/L3 derivation:

- ``DnsZone``   — one per distinct authoritative zone FQDN (from the zone list
  AND from every record's ``zone`` field, so a record never dangles).
- ``DnsRecord`` — one per distinct ``(name, record_type, value)`` triple; the
  natural key is the composite ``name|type|value`` because a single host name
  carries many records.
- ``IN_ZONE``     — ``DnsZone`` -> ``DnsRecord`` containment (structural glue so
  the layer is a connected, queryable subgraph; the analog of ``HAS_INTERFACE``).
- ``RESOLVES_TO`` — ``DnsRecord`` -> the projected node its value resolves to.

Reconciliation (the heart of task #13): an ``A``/``AAAA`` record whose value is a
known device interface address resolves to that **projected** ``IPAddress`` node
(keyed by the interface ``pg_id`` — the same key the M2 ``IPAddressNode`` uses);
failing that, a value equal to a device ``mgmt_ip`` resolves to that ``Device``
node.  An interface-IP match always wins over an mgmt-IP match.  A record that
reconciles to nothing known points at **no** node (the Neo4j-subset-of-Postgres
invariant — no phantom nodes) but keeps its literal value on the edge so the
dependency is still visible.

:func:`derive_dns` is pure: deterministic ordering, dedup by key, no I/O, output
fully determined by input *content* and insensitive to input ordering.
"""

from __future__ import annotations

from collections.abc import Sequence
from ipaddress import ip_address, ip_interface
from typing import ClassVar

from pydantic import BaseModel, ConfigDict

from app.engines.topology.nodes import GraphNode
from app.knowledge.schema import (
    LABEL_DEVICE,
    LABEL_DNS_RECORD,
    LABEL_DNS_ZONE,
    LABEL_IPADDRESS,
    REL_IN_ZONE,
    REL_RESOLVES_TO,
)
from app.models.inventory import Device, NormalizedInterfaceRow
from app.schemas.normalized import DnsRecordType, NormalizedDnsRecord

__all__ = [
    "DerivedDns",
    "DnsRecordNode",
    "DnsZoneNode",
    "InZoneEdge",
    "ResolvesToEdge",
    "derive_dns",
    "dns_record_key",
]

#: Record types whose value is an IP literal eligible for IPAddress/Device
#: reconciliation.  Everything else (CNAME/MX/TXT/...) keeps a literal target.
_ADDRESS_RECORD_TYPES: frozenset[DnsRecordType] = frozenset({DnsRecordType.A, DnsRecordType.AAAA})


def dns_record_key(name: str, record_type: DnsRecordType, value: str) -> str:
    """Composite natural key of a DNS record (``name|type|value``).

    A host name alone is not unique (it carries many record types/values), so the
    DnsRecord MERGE key is this triple, mirroring how routes key on their full
    natural tuple.
    """
    return f"{name}|{record_type.value}|{value}"


# ---------------------------------------------------------------------------
# Typed node records (frozen — projection inputs, not scratch space)
# ---------------------------------------------------------------------------


class DnsZoneNode(GraphNode):
    """An authoritative DNS zone (keyed by its FQDN)."""

    label: ClassVar[str] = LABEL_DNS_ZONE
    key_property: ClassVar[str] = "fqdn"

    fqdn: str


class DnsRecordNode(GraphNode):
    """A DNS resource record (keyed by the composite ``name|type|value``).

    The MERGE key property is ``record_key`` (not ``name`` — a host carries many
    records).  ``node.key`` (the inherited :attr:`GraphNode.key`) returns the same
    ``record_key`` value, so edge builders and the projector agree on the key.
    """

    label: ClassVar[str] = LABEL_DNS_RECORD
    key_property: ClassVar[str] = "record_key"

    record_key: str
    name: str
    record_type: DnsRecordType
    value: str
    zone: str | None
    ttl: int | None = None


# ---------------------------------------------------------------------------
# Typed edge records
# ---------------------------------------------------------------------------


class InZoneEdge(BaseModel):
    """A ``DnsZone`` contains a ``DnsRecord`` (zone -> record)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    rel_type: ClassVar[str] = REL_IN_ZONE

    zone_fqdn: str
    record_key: str


class ResolvesToEdge(BaseModel):
    """A ``DnsRecord`` resolves toward a target.

    ``target_label`` / ``target_key`` identify the projected node the record
    reconciled to (``IPAddress`` keyed by interface ``pg_id``, or ``Device`` keyed
    by ``pg_id``); both are ``None`` when nothing known matched.  ``value`` always
    carries the record's literal right-hand side so the edge is meaningful even
    unreconciled; ``reconciled`` is the explicit boolean for callers/UI.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    rel_type: ClassVar[str] = REL_RESOLVES_TO

    record_key: str
    value: str
    reconciled: bool
    target_label: str | None = None
    target_key: str | None = None


class DerivedDns(BaseModel):
    """The complete DNS-layer node + edge sets of one derivation pass."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    zones: tuple[DnsZoneNode, ...] = ()
    records: tuple[DnsRecordNode, ...] = ()
    in_zone: tuple[InZoneEdge, ...] = ()
    resolves_to: tuple[ResolvesToEdge, ...] = ()


# ---------------------------------------------------------------------------
# Reconciliation index
# ---------------------------------------------------------------------------


def _normalize_ip(value: str) -> str | None:
    """Canonical string form of an IP literal, or ``None`` if not an address."""
    try:
        return str(ip_address(value.strip()))
    except ValueError:
        return None


class _AddressIndex:
    """Maps an IP literal to the projected node (IPAddress / Device) it belongs to.

    Built once per derivation.  Interface addresses win over device ``mgmt_ip``:
    the IPAddress node is the more specific endpoint and the address it carries is
    the same canonical host string the M2 projection keys on.
    """

    def __init__(
        self, devices: Sequence[Device], interfaces: Sequence[NormalizedInterfaceRow]
    ) -> None:
        # Device mgmt_ip layer first (lowest priority), so interface entries below
        # overwrite it for any collision.
        self._by_ip: dict[str, tuple[str, str]] = {}
        for device in sorted(devices, key=lambda d: str(d.id)):
            canonical = _normalize_ip(device.mgmt_ip)
            if canonical is not None:
                self._by_ip.setdefault(canonical, (LABEL_DEVICE, str(device.id)))

        # Interface addresses: lowest interface pg_id wins per address, matching
        # the M2 IPAddressNode dedup, then it shadows any mgmt_ip entry.
        addressed: dict[str, str] = {}
        for row in sorted(interfaces, key=lambda r: str(r.id)):
            if not row.ip_address:
                continue
            try:
                host = str(ip_interface(row.ip_address).ip)
            except ValueError:
                continue
            addressed.setdefault(host, str(row.id))
        for host, pg_id in addressed.items():
            self._by_ip[host] = (LABEL_IPADDRESS, pg_id)

    def resolve(self, value: str) -> tuple[str, str] | None:
        """Projected ``(label, key)`` for *value*, or ``None`` when unknown."""
        canonical = _normalize_ip(value)
        if canonical is None:
            return None
        return self._by_ip.get(canonical)


# ---------------------------------------------------------------------------
# Derivation
# ---------------------------------------------------------------------------


def derive_dns(
    records: Sequence[NormalizedDnsRecord],
    zones: Sequence[str],
    devices: Sequence[Device],
    interfaces: Sequence[NormalizedInterfaceRow],
) -> DerivedDns:
    """Derive the DNS-dependency node + edge sets (pure, deterministic).

    *records* / *zones* are the normalized Infoblox DDI currency (records from
    ``DdiDnsCapability.get_records`` and FQDNs from ``get_zones``); *devices* /
    *interfaces* are the existing inventory rows the ``RESOLVES_TO`` reconciliation
    matches against.  Output ordering/dedup are independent of input order.
    """
    # Dedup records by their composite key, deterministically.
    record_by_key: dict[str, DnsRecordNode] = {}
    for rec in records:
        key = dns_record_key(rec.name, rec.record_type, rec.value)
        record_by_key.setdefault(
            key,
            DnsRecordNode(
                record_key=key,
                name=rec.name,
                record_type=rec.record_type,
                value=rec.value,
                zone=rec.zone,
                ttl=rec.ttl,
            ),
        )
    record_nodes = tuple(sorted(record_by_key.values(), key=lambda node: node.record_key))

    # Zones come from the explicit list AND from every record's zone field, so a
    # record's IN_ZONE edge always lands on a projected DnsZone node.
    zone_fqdns: set[str] = {z.strip() for z in zones if z and z.strip()}
    zone_fqdns |= {
        node.zone.strip() for node in record_nodes if node.zone is not None and node.zone.strip()
    }
    zone_nodes = tuple(DnsZoneNode(fqdn=fqdn) for fqdn in sorted(zone_fqdns))

    in_zone = tuple(
        InZoneEdge(zone_fqdn=node.zone.strip(), record_key=node.record_key)
        for node in record_nodes
        if node.zone is not None and node.zone.strip()
    )

    index = _AddressIndex(devices, interfaces)
    resolves_to_list: list[ResolvesToEdge] = []
    for node in record_nodes:
        target: tuple[str, str] | None = None
        if node.record_type in _ADDRESS_RECORD_TYPES:
            target = index.resolve(node.value)
        if target is None:
            resolves_to_list.append(
                ResolvesToEdge(record_key=node.record_key, value=node.value, reconciled=False)
            )
        else:
            label, key = target
            resolves_to_list.append(
                ResolvesToEdge(
                    record_key=node.record_key,
                    value=node.value,
                    reconciled=True,
                    target_label=label,
                    target_key=key,
                )
            )
    resolves_to = tuple(sorted(resolves_to_list, key=lambda edge: edge.record_key))

    return DerivedDns(
        zones=zone_nodes,
        records=record_nodes,
        in_zone=in_zone,
        resolves_to=resolves_to,
    )
