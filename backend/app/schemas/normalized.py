"""Vendor-agnostic normalized network models (brief §4, ADR-0006, ADR-0007).

These Pydantic models are the *only* currency vendor plugins may return:
engines and agents consume ``Normalized*`` records and never see vendor
syntax. Every record carries the provenance triple ``device_id`` /
``collected_at`` / ``source_vendor`` so each normalized row is joinable to
the device inventory and re-derivable from the verbatim raw artifact stored
before parsing (auditability, D11).

Conventions:

- IPs use :mod:`ipaddress` types (validated/coerced by Pydantic).
- States are :class:`~enum.StrEnum` members (wire values, REPO-STRUCTURE §4.1).
- MAC addresses normalize to lowercase colon-separated octets.
- Models are frozen and reject unknown fields — they are evidence, not
  scratch space.
"""

from __future__ import annotations

import re
from enum import StrEnum
from ipaddress import (
    IPv4Address,
    IPv4Interface,
    IPv4Network,
    IPv6Address,
    IPv6Interface,
    IPv6Network,
)
from typing import Annotated
from uuid import UUID

from pydantic import AfterValidator, AwareDatetime, BaseModel, ConfigDict, Field

__all__ = [
    "AclAction",
    "BgpPeerState",
    "DhcpLeaseState",
    "DiscoveredObjectKind",
    "DnsRecordType",
    "FirewallAction",
    "HaPeerRole",
    "HaPeerLinkState",
    "InterfaceAdminStatus",
    "InterfaceDuplex",
    "InterfaceOperStatus",
    "MacAddress",
    "NatType",
    "NeighborProtocol",
    "NormalizedAclEntry",
    "NormalizedArpEntry",
    "NormalizedBgpPeer",
    "NormalizedDhcpLease",
    "NormalizedDhcpRange",
    "NormalizedDiscoveredObject",
    "NormalizedDnsRecord",
    "NormalizedFirewallRule",
    "NormalizedHaStatus",
    "NormalizedInterface",
    "NormalizedNatRule",
    "NormalizedNetwork",
    "NormalizedNeighbor",
    "NormalizedOspfNeighbor",
    "NormalizedRecord",
    "NormalizedRoute",
    "NormalizedVlan",
    "OspfNeighborState",
    "RouteProtocol",
    "VlanId",
    "VlanStatus",
    "normalize_mac",
]

_MAC_HEX_RE = re.compile(r"^[0-9a-f]{12}$")


def normalize_mac(value: str) -> str:
    """Normalize a MAC address to lowercase colon-separated octets.

    Accepts the common vendor formats (``fa16.3e11.2233``,
    ``FA:16:3E:11:22:33``, ``fa-16-3e-11-22-33``, bare hex) and raises
    :class:`ValueError` for anything that is not exactly 12 hex digits.
    """
    cleaned = re.sub(r"[^0-9a-fA-F]", "", value).lower()
    if not _MAC_HEX_RE.match(cleaned):
        raise ValueError(f"invalid MAC address: {value!r}")
    return ":".join(cleaned[i : i + 2] for i in range(0, 12, 2))


MacAddress = Annotated[str, AfterValidator(normalize_mac)]
"""A MAC address, normalized to ``aa:bb:cc:dd:ee:ff`` form on validation."""

VlanId = Annotated[int, Field(ge=1, le=4094)]
"""An IEEE 802.1Q VLAN ID (1–4094)."""


# ---------------------------------------------------------------------------
# State enums (StrEnum wire values, REPO-STRUCTURE §4.1)
# ---------------------------------------------------------------------------


class InterfaceAdminStatus(StrEnum):
    """Configured (administrative) interface state."""

    UP = "up"
    DOWN = "down"


class InterfaceOperStatus(StrEnum):
    """Observed (operational / line-protocol) interface state."""

    UP = "up"
    DOWN = "down"
    UNKNOWN = "unknown"


class InterfaceDuplex(StrEnum):
    """Interface duplex mode."""

    FULL = "full"
    HALF = "half"
    AUTO = "auto"


class RouteProtocol(StrEnum):
    """Routing-table entry origin, unified across vendors."""

    CONNECTED = "connected"
    LOCAL = "local"
    STATIC = "static"
    RIP = "rip"
    OSPF = "ospf"
    EIGRP = "eigrp"
    BGP = "bgp"
    ISIS = "isis"
    OTHER = "other"


class NeighborProtocol(StrEnum):
    """Discovery protocol a neighbor adjacency was learned from."""

    LLDP = "lldp"
    CDP = "cdp"


class BgpPeerState(StrEnum):
    """BGP finite-state-machine state (RFC 4271 §8)."""

    IDLE = "idle"
    CONNECT = "connect"
    ACTIVE = "active"
    OPEN_SENT = "open_sent"
    OPEN_CONFIRM = "open_confirm"
    ESTABLISHED = "established"


class OspfNeighborState(StrEnum):
    """OSPF neighbor state machine (RFC 2328 §10.1)."""

    DOWN = "down"
    ATTEMPT = "attempt"
    INIT = "init"
    TWO_WAY = "two_way"
    EXSTART = "exstart"
    EXCHANGE = "exchange"
    LOADING = "loading"
    FULL = "full"


class AclAction(StrEnum):
    """Action taken by an ACL entry on matching traffic."""

    PERMIT = "permit"
    DENY = "deny"


class FirewallAction(StrEnum):
    """Action a firewall/security policy rule takes on matching traffic (ADR-0034 §4).

    Lowest common denominator across PAN-OS (``allow``/``deny``/``drop``/``reset``)
    and FortiOS (``accept``/``deny``); the plugin maps its vendor verbs onto this
    set (``reset`` → ``reject``, ``accept`` → ``allow``).
    """

    ALLOW = "allow"
    DENY = "deny"
    DROP = "drop"
    REJECT = "reject"


class NatType(StrEnum):
    """Kind of address translation a NAT policy rule performs (ADR-0034 §4)."""

    SOURCE = "source"
    DESTINATION = "destination"
    STATIC = "static"


class VlanStatus(StrEnum):
    """Operational status of a VLAN."""

    ACTIVE = "active"
    SUSPENDED = "suspended"
    SHUTDOWN = "shutdown"
    UNKNOWN = "unknown"


class DnsRecordType(StrEnum):
    """Common DNS resource-record types; ``OTHER`` covers the long tail."""

    A = "a"
    AAAA = "aaaa"
    CNAME = "cname"
    MX = "mx"
    NS = "ns"
    PTR = "ptr"
    SOA = "soa"
    SRV = "srv"
    TXT = "txt"
    OTHER = "other"


class DhcpLeaseState(StrEnum):
    """Lifecycle state of a DHCP lease, unified across DDI platforms."""

    ACTIVE = "active"
    FREE = "free"
    EXPIRED = "expired"
    ABANDONED = "abandoned"
    OFFERED = "offered"
    STATIC = "static"
    BACKUP = "backup"
    OTHER = "other"


class HaPeerRole(StrEnum):
    """Role of this device in a high-availability pair (vPC/FHRP/active-standby).

    Vendor-neutral: vPC uses ``PRIMARY``/``SECONDARY``; active/standby HA
    platforms (PAN-OS, FortiOS, F5) use ``ACTIVE``/``STANDBY``.
    ``UNKNOWN`` is the safe default when the device does not report a role.
    """

    PRIMARY = "primary"
    SECONDARY = "secondary"
    ACTIVE = "active"
    STANDBY = "standby"
    UNKNOWN = "unknown"


class HaPeerLinkState(StrEnum):
    """Operational state of the HA peer-link or keepalive channel."""

    UP = "up"
    DOWN = "down"
    UNKNOWN = "unknown"


class DiscoveredObjectKind(StrEnum):
    """Kind of object returned by an API-based discovery pass (ADR-0022 §2).

    The categories an appliance/cloud discovery surfaces — networks, DNS
    zones, and infrastructure members (grid members, appliances) — feeding the
    discovery engine. ``OTHER`` covers the long tail so a new WAPI object type
    never breaks normalization.
    """

    NETWORK = "network"
    DNS_ZONE = "dns_zone"
    MEMBER = "member"
    OTHER = "other"


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


class NormalizedRecord(BaseModel):
    """Base for all normalized records: immutable + provenance triple.

    ``device_id`` is the Postgres UUID of the source device (``devices.id``),
    ``collected_at`` is the timezone-aware collection instant, and
    ``source_vendor`` is the ``vendor_id`` of the plugin that produced the
    record (e.g. ``"cisco_ios"``).
    """

    model_config = ConfigDict(frozen=True, extra="forbid", str_strip_whitespace=True)

    device_id: UUID
    collected_at: AwareDatetime
    source_vendor: str = Field(min_length=1)


class NormalizedInterface(NormalizedRecord):
    """A device interface: identity, state, addressing, and error metrics."""

    name: str = Field(min_length=1)
    description: str | None = None
    admin_status: InterfaceAdminStatus
    oper_status: InterfaceOperStatus
    mac_address: MacAddress | None = None
    ip_address: IPv4Interface | IPv6Interface | None = None
    mtu: int | None = Field(default=None, ge=1)
    speed_mbps: int | None = Field(default=None, ge=0)
    duplex: InterfaceDuplex | None = None
    vlan_id: VlanId | None = None
    input_errors: int | None = Field(default=None, ge=0)
    output_errors: int | None = Field(default=None, ge=0)


class NormalizedRoute(NormalizedRecord):
    """A routing-table entry. ``vrf=None`` means the global routing table."""

    destination: IPv4Network | IPv6Network
    protocol: RouteProtocol
    next_hop: IPv4Address | IPv6Address | None = None
    interface: str | None = None
    vrf: str | None = None
    distance: int | None = Field(default=None, ge=0, le=255)
    metric: int | None = Field(default=None, ge=0)


class NormalizedNeighbor(NormalizedRecord):
    """An LLDP/CDP adjacency, unified across both discovery protocols."""

    protocol: NeighborProtocol
    local_interface: str = Field(min_length=1)
    neighbor_name: str = Field(min_length=1)
    neighbor_interface: str | None = None
    neighbor_platform: str | None = None
    neighbor_address: IPv4Address | IPv6Address | None = None
    neighbor_capabilities: tuple[str, ...] = ()


class NormalizedBgpPeer(NormalizedRecord):
    """A BGP peering session and its observed FSM state."""

    peer_address: IPv4Address | IPv6Address
    remote_as: int = Field(ge=0, le=4_294_967_295)
    local_as: int | None = Field(default=None, ge=0, le=4_294_967_295)
    state: BgpPeerState
    vrf: str | None = None
    address_family: str | None = None
    prefixes_received: int | None = Field(default=None, ge=0)
    uptime_seconds: int | None = Field(default=None, ge=0)


class NormalizedOspfNeighbor(NormalizedRecord):
    """An OSPF neighbor adjacency."""

    neighbor_id: IPv4Address
    interface: str = Field(min_length=1)
    state: OspfNeighborState
    neighbor_address: IPv4Address | IPv6Address | None = None
    area: str | None = None
    priority: int | None = Field(default=None, ge=0, le=255)
    dead_time_seconds: int | None = Field(default=None, ge=0)
    vrf: str | None = None


class NormalizedAclEntry(NormalizedRecord):
    """A single ACL rule. ``source``/``destination`` of ``None`` mean *any*."""

    acl_name: str = Field(min_length=1)
    action: AclAction
    protocol: str = "ip"
    sequence: int | None = Field(default=None, ge=0)
    source: IPv4Network | IPv6Network | None = None
    source_port: str | None = None
    destination: IPv4Network | IPv6Network | None = None
    destination_port: str | None = None
    hits: int | None = Field(default=None, ge=0)


class NormalizedFirewallRule(NormalizedRecord):
    """A zone/application-aware firewall (security) policy rule (ADR-0034 §2).

    Distinct from :class:`NormalizedAclEntry` (an interface-bound L3/L4 ACL):
    a firewall rule matches on source/destination **zones**, named **address
    objects**, and **application/service** identity. Addresses are strings
    (object names *or* CIDR/IP literals — ADR-0034 §5), and an empty tuple means
    *any* (firewall convention). Vendor-unique richness (security profiles, rule
    UUIDs, schedules) does not enter this model; it lives only in the verbatim
    raw artifact (ADR-0034 §6). No field carries a secret — policy is config
    metadata.
    """

    name: str = Field(min_length=1)
    position: int | None = Field(default=None, ge=0)
    enabled: bool
    action: FirewallAction
    source_zones: tuple[str, ...] = ()
    destination_zones: tuple[str, ...] = ()
    source_addresses: tuple[str, ...] = ()
    destination_addresses: tuple[str, ...] = ()
    applications: tuple[str, ...] = ()
    services: tuple[str, ...] = ()
    logging: bool | None = None
    hit_count: int | None = Field(default=None, ge=0)
    description: str | None = None


class NormalizedNatRule(NormalizedRecord):
    """A NAT policy rule (source/destination/static) (ADR-0034 §3).

    Original/translated endpoints are strings (object names *or* literals,
    ADR-0034 §5); an empty tuple means *any*. Secret-free config metadata.
    """

    name: str = Field(min_length=1)
    nat_type: NatType
    enabled: bool
    source_zones: tuple[str, ...] = ()
    destination_zones: tuple[str, ...] = ()
    original_source: tuple[str, ...] = ()
    original_destination: tuple[str, ...] = ()
    original_service: str | None = None
    translated_source: tuple[str, ...] = ()
    translated_destination: tuple[str, ...] = ()
    translated_service: str | None = None


class NormalizedVlan(NormalizedRecord):
    """A VLAN and the interfaces assigned to it."""

    vlan_id: VlanId
    name: str | None = None
    status: VlanStatus = VlanStatus.UNKNOWN
    interfaces: tuple[str, ...] = ()


class NormalizedArpEntry(NormalizedRecord):
    """An ARP/ND cache entry. ``vrf=None`` means the global table."""

    ip_address: IPv4Address | IPv6Address
    mac_address: MacAddress
    interface: str | None = None
    vrf: str | None = None
    age_minutes: float | None = Field(default=None, ge=0)


class NormalizedDnsRecord(NormalizedRecord):
    """A DNS resource record as reported by a DDI platform or zone export."""

    name: str = Field(min_length=1)
    record_type: DnsRecordType
    value: str = Field(min_length=1)
    ttl: int | None = Field(default=None, ge=0)
    zone: str | None = None
    object_ref: str | None = Field(
        default=None,
        description="Opaque DDI handle (Infoblox WAPI _ref) identifying the source object; "
        "carried through so a later mutation targets the exact record (ADR-0022 §1). "
        "Never a secret.",
    )


class NormalizedDhcpLease(NormalizedRecord):
    """A DHCP lease as reported by a DDI/DHCP platform (ADR-0022 §2)."""

    ip_address: IPv4Address | IPv6Address
    state: DhcpLeaseState
    mac_address: MacAddress | None = None
    hostname: str | None = None
    network: IPv4Network | IPv6Network | None = None
    starts_at: AwareDatetime | None = None
    ends_at: AwareDatetime | None = None
    object_ref: str | None = Field(
        default=None,
        description="Opaque DDI handle (Infoblox WAPI _ref) for the source lease object. "
        "Never a secret.",
    )


class NormalizedDhcpRange(NormalizedRecord):
    """A DHCP range (address pool) within a network (ADR-0022 §2)."""

    start_address: IPv4Address | IPv6Address
    end_address: IPv4Address | IPv6Address
    network: IPv4Network | IPv6Network | None = None
    name: str | None = None
    member: str | None = Field(
        default=None, description="Serving DHCP member/server, when reported."
    )
    object_ref: str | None = Field(
        default=None,
        description="Opaque DDI handle (Infoblox WAPI _ref) for the source range object. "
        "Never a secret.",
    )


class NormalizedNetwork(NormalizedRecord):
    """An IPAM network/subnet with utilization, as reported by a DDI platform.

    The IPAM currency (ADR-0022 §2): ``DDI_IPAM`` read methods return these and
    ``DISCOVERY_API`` surfaces the same subnets as discovered objects.
    """

    network: IPv4Network | IPv6Network
    comment: str | None = None
    network_view: str | None = Field(
        default=None, description="Infoblox network view (default view when None)."
    )
    utilization_percent: float | None = Field(default=None, ge=0, le=100)
    object_ref: str | None = Field(
        default=None,
        description="Opaque DDI handle (Infoblox WAPI _ref) for the source network object. "
        "Never a secret.",
    )


class NormalizedDiscoveredObject(NormalizedRecord):
    """An object surfaced by an API-based discovery pass (ADR-0022 §2).

    The first API-based discovery currency: ``DISCOVERY_API`` returns these
    (networks, DNS zones, grid members) so the discovery engine stays
    vendor-agnostic. ``identifier`` is the object's natural key (the network
    CIDR, the zone FQDN, the member hostname); ``attributes`` carries a flat,
    secret-free map of extra fields for engines that want them.
    """

    kind: DiscoveredObjectKind
    identifier: str = Field(min_length=1)
    display_name: str | None = None
    attributes: tuple[tuple[str, str], ...] = ()
    object_ref: str | None = Field(
        default=None,
        description="Opaque DDI handle (Infoblox WAPI _ref) for the source object. Never a secret.",
    )


class NormalizedHaStatus(NormalizedRecord):
    """High-availability peer state for a device (vPC, FHRP, active/standby).

    Lowest-common-denominator HA model covering vPC (NX-OS), PAN-OS HA,
    FortiOS HA, and F5 DSC (ADR-0025 §8). ``peer_role`` is the role this
    device holds in the HA pair; ``peer_link_state`` is the operational
    state of the control-plane peer-link or keepalive channel. For vPC on
    NX-OS these correspond to the vPC domain role and the peer-link/keepalive
    status reported by ``show vpc``. ``consistency_check_ok`` reflects the
    vendor's consistency-parameter agreement state; ``None`` means the
    platform does not report it.
    """

    ha_domain: str | None = Field(
        default=None,
        description="HA domain identifier (vPC domain ID, HA group, etc.). Never a secret.",
    )
    peer_role: HaPeerRole = HaPeerRole.UNKNOWN
    peer_link_state: HaPeerLinkState = HaPeerLinkState.UNKNOWN
    keepalive_state: HaPeerLinkState = HaPeerLinkState.UNKNOWN
    consistency_check_ok: bool | None = Field(
        default=None,
        description="Whether the HA consistency parameters agree across peers; None if unreported.",
    )
    peer_address: IPv4Address | IPv6Address | None = None
