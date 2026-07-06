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

from pydantic import AfterValidator, AwareDatetime, BaseModel, ConfigDict, Field, model_validator

__all__ = [
    "AclAction",
    "AdcAdminState",
    "AdcAvailability",
    "AdcProtocol",
    "BgpPeerState",
    "DhcpLeaseState",
    "DiscoveredObjectKind",
    "DnsRecordType",
    "FirewallAction",
    "HaPeerRole",
    "HaPeerLinkState",
    "HostConnectionState",
    "InterfaceAdminStatus",
    "InterfaceDuplex",
    "InterfaceOperStatus",
    "MacAddress",
    "NatType",
    "NeighborProtocol",
    "NormalizedAclEntry",
    "NormalizedArpEntry",
    "NormalizedBgpPeer",
    "NormalizedComputeCluster",
    "NormalizedDhcpLease",
    "NormalizedDhcpRange",
    "NormalizedDiscoveredObject",
    "NormalizedDnsRecord",
    "NormalizedFirewallRule",
    "NormalizedHaStatus",
    "NormalizedHypervisorHost",
    "NormalizedInterface",
    "NormalizedNatRule",
    "NormalizedNetwork",
    "NormalizedNeighbor",
    "NormalizedOspfNeighbor",
    "NormalizedPhysicalNic",
    "NormalizedPool",
    "NormalizedPoolMember",
    "NormalizedPortGroup",
    "NormalizedRecord",
    "NormalizedRoute",
    "NormalizedVirtualMachine",
    "NormalizedVirtualNic",
    "NormalizedVirtualServer",
    "NormalizedVlan",
    "OspfNeighborState",
    "RouteProtocol",
    "VirtualSwitchType",
    "VlanId",
    "VlanStatus",
    "VmPowerState",
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


class AdcProtocol(StrEnum):
    """L4 protocol of an ADC virtual server (ADR-0050 §4.4).

    F5 ``ipProtocol`` values map directly; ``OTHER`` covers the long tail so an
    exotic protocol never breaks normalization (the ``DiscoveredObjectKind.OTHER``
    pattern).
    """

    TCP = "tcp"
    UDP = "udp"
    SCTP = "sctp"
    ANY = "any"
    OTHER = "other"


class AdcAvailability(StrEnum):
    """Monitor-reported availability of an ADC object (ADR-0050 §4.4).

    Maps F5 ``status.availabilityState`` (plus ``enabledState`` for ``disabled``);
    ``UNKNOWN`` is the safe default (an unmonitored object reports the F5 "blue"
    unknown state).
    """

    AVAILABLE = "available"
    OFFLINE = "offline"
    DISABLED = "disabled"
    UNKNOWN = "unknown"


class AdcAdminState(StrEnum):
    """Administrative session state of an ADC pool member (ADR-0050 §4.4).

    F5's three member session states map 1:1; a future ADC-style source without a
    forced-offline concept uses only the first two. Kept **separate** from
    :class:`AdcAvailability` on purpose (ADR-0050 §4.4): a member can be
    admin-enabled yet monitor-down, or admin-disabled yet monitor-up.
    """

    ENABLED = "enabled"
    DISABLED = "disabled"
    FORCED_OFFLINE = "forced_offline"


class VmPowerState(StrEnum):
    """Runtime power state of a virtual machine (ADR-0051 §5.4).

    vSphere's three runtime power states map 1:1; ``UNKNOWN`` is the safe
    default for unreachable/inconsistent state (the
    :class:`DiscoveredObjectKind.OTHER` pattern). ``power_state`` is a separate
    dimension from ``is_template`` on purpose — a template is always powered
    off, but a powered-off VM is usually not a template.
    """

    POWERED_ON = "powered_on"
    POWERED_OFF = "powered_off"
    SUSPENDED = "suspended"
    UNKNOWN = "unknown"


class HostConnectionState(StrEnum):
    """vCenter-reported connection state of a hypervisor host (ADR-0051 §5.4).

    Kept separate from ``in_maintenance_mode`` (a drained host is not a failed
    host): the W2 derivation needs each distinction to decide whether an edge
    represents a live workload path.
    """

    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    NOT_RESPONDING = "not_responding"
    UNKNOWN = "unknown"


class VirtualSwitchType(StrEnum):
    """Kind of virtual switch a port group belongs to (ADR-0051 §5.4).

    ``standard`` port groups exist per host (a name may repeat across hosts);
    ``distributed`` port groups are vCenter-wide and keyed by a moref. The type
    disambiguates the vNIC → port-group join scope (§5.5).
    """

    STANDARD = "standard"
    DISTRIBUTED = "distributed"


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
    """A single ACL rule.

    A ``None`` ``source``/``destination`` is **ambiguous** on its own: it means
    either a literal *any* or a named address-group the normalized model cannot
    represent (a vendor object-group/address-set/field-set that collapses to
    ``None`` at parse time — e.g. cisco_nxos ``addrgroup``). The ``*_is_any``
    flags disambiguate: a parser sets them ``True`` **only** for an explicit
    literal-any token, never for a collapsed group. Consumers therefore read
    ``source is None and source_is_any`` as a definite *any*, and ``source is
    None and not source_is_any`` as an unresolved group (advisory only).
    """

    acl_name: str = Field(min_length=1)
    action: AclAction
    protocol: str = "ip"
    sequence: int | None = Field(default=None, ge=0)
    source: IPv4Network | IPv6Network | None = None
    source_is_any: bool = False
    source_port: str | None = None
    destination: IPv4Network | IPv6Network | None = None
    destination_is_any: bool = False
    destination_port: str | None = None
    hits: int | None = Field(default=None, ge=0)

    @model_validator(mode="after")
    def _is_any_requires_unscoped_endpoint(self) -> NormalizedAclEntry:
        """An endpoint flagged *any* must be unscoped (``None``).

        ``source_is_any`` / ``destination_is_any`` mean "this endpoint is a literal
        *any*"; that is contradictory with a concrete network. Enforcing it
        structurally keeps the flag's documented meaning trustworthy for every
        consumer (e.g. the security posture engine), not just by parser convention.
        """
        if self.source_is_any and self.source is not None:
            raise ValueError("source_is_any=True requires source=None (a literal 'any')")
        if self.destination_is_any and self.destination is not None:
            raise ValueError("destination_is_any=True requires destination=None (a literal 'any')")
        return self


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


class NormalizedPoolMember(BaseModel):
    """A pool member (real server) nested inside a :class:`NormalizedPool` (ADR-0050 §4.3/§4.5).

    Not a :class:`NormalizedRecord`: members inherit their pool's provenance
    triple, and F5 returns them as a subcollection of the pool — nesting keeps
    the W2 derivation's VIP->pool->member chain traversable with no string
    re-join (ADR-0050 §4.5). No field carries a secret (ADR-0050 §4.3).
    """

    model_config = ConfigDict(frozen=True, extra="forbid", str_strip_whitespace=True)

    name: str = Field(min_length=1, description="Full-path member name (e.g. /Common/web01:80).")
    address: IPv4Address | IPv6Address | None = Field(
        default=None,
        description="Member address, route-domain suffix stripped (§5); None only for an "
        "unresolved FQDN node.",
    )
    fqdn: str | None = Field(
        default=None, description="FQDN for FQDN-type nodes — the W2 DNS-dependency bridge."
    )
    port: int = Field(ge=0, le=65535, description="Service port; 0 = any.")
    vrf: str | None = Field(default=None, description="Route domain of the member address (§5).")
    admin_state: AdcAdminState
    availability: AdcAvailability


class NormalizedVirtualServer(NormalizedRecord):
    """An ADC virtual server (VIP) (ADR-0050 §4.3).

    The primary input to the W2 application-dependency derivation (ADR-0052):
    VIP address, port, protocol, and the ``pool_name`` join key. Names carry the
    F5 full-path, partition-qualified form (``/Common/vs_web``) verbatim. No
    field carries a secret — this is config/state metadata (ADR-0050 §4.3).
    """

    name: str = Field(min_length=1, description="Full-path virtual-server name.")
    vip_address: IPv4Address | IPv6Address | None = Field(
        default=None,
        description="Destination address, route-domain suffix stripped (§5); None when the "
        "destination is non-literal (e.g. an address list).",
    )
    port: int | None = Field(
        default=None, ge=0, le=65535, description="Service port; None = any (F5 0/any -> None)."
    )
    protocol: AdcProtocol
    vrf: str | None = Field(default=None, description="F5 route domain (§5); reuses the house vrf.")
    enabled: bool = Field(description="Disabled virtual servers are collected, not dropped.")
    availability: AdcAvailability
    pool_name: str | None = Field(
        default=None,
        description="Full-path default-pool name — the VIP->pool join key; None when the VS "
        "has no default pool (iRule/policy-only).",
    )
    description: str | None = None


class NormalizedPool(NormalizedRecord):
    """An ADC pool with nested members (ADR-0050 §4.3/§4.5).

    ``name`` is the join target of :attr:`NormalizedVirtualServer.pool_name`.
    ``members`` nests :class:`NormalizedPoolMember` sub-models (F5's own
    pool->member subcollection shape). No field carries a secret (ADR-0050 §4.3).
    """

    name: str = Field(min_length=1, description="Full-path pool name.")
    monitors: tuple[str, ...] = Field(default=(), description="Health-monitor names; () = none.")
    availability: AdcAvailability
    members: tuple[NormalizedPoolMember, ...] = Field(
        default=(), description="Nested members (§4.5); () = empty pool."
    )
    description: str | None = None


# ---------------------------------------------------------------------------
# Virtualization inventory (ADR-0051): VM / host / cluster / port-group models.
# vNICs / pNICs are nested frozen sub-models (not NormalizedRecords) — they
# inherit their parent record's provenance and are intrinsically hierarchical
# (the NormalizedPoolMember precedent, ADR-0050 §4.2/§4.5).
# ---------------------------------------------------------------------------


class NormalizedVirtualNic(BaseModel):
    """A VM virtual NIC nested inside a :class:`NormalizedVirtualMachine` (ADR-0051 §5.3).

    ``mac_address`` is the physical-L2 join key (switch MAC/forwarding tables).
    ``port_group_name`` joins :attr:`NormalizedPortGroup.name`; distributed
    portgroup keys are resolved to names at collection time so consumers join
    on one field. ``switch_type`` disambiguates that join's scope (§5.5): a
    ``standard`` name scopes to the VM's host, a ``distributed`` name is
    vCenter-wide. No field carries a secret.
    """

    model_config = ConfigDict(frozen=True, extra="forbid", str_strip_whitespace=True)

    label: str = Field(min_length=1, description="Device label (e.g. 'Network adapter 1').")
    mac_address: MacAddress = Field(description="House-canonical MAC — the physical-L2 join key.")
    port_group_name: str | None = Field(
        default=None,
        description="Join to NormalizedPortGroup.name; None when the backing is unresolvable.",
    )
    switch_type: VirtualSwitchType | None = Field(
        default=None, description="Disambiguates the port-group join scope (§5.5)."
    )
    connected: bool = Field(description="vNIC link state.")
    ip_addresses: tuple[IPv4Address | IPv6Address, ...] = Field(
        default=(), description="Per-NIC Tools-reported IPs; () when unreported."
    )


class NormalizedPhysicalNic(BaseModel):
    """A host physical NIC nested inside a :class:`NormalizedHypervisorHost` (ADR-0051 §5.3).

    ``name`` (e.g. ``vmnic0``) is the join target of
    :attr:`NormalizedPortGroup.uplink_pnic_names`; ``mac_address`` is the MAC a
    physical switch sees. No field carries a secret.
    """

    model_config = ConfigDict(frozen=True, extra="forbid", str_strip_whitespace=True)

    name: str = Field(min_length=1, description="Physical adapter name (e.g. 'vmnic0').")
    mac_address: MacAddress = Field(description="House-canonical MAC — the physical-L2 join key.")
    link_speed_mbps: int | None = Field(
        default=None, ge=0, description="Link speed in Mbps; None = link down or unreported."
    )


class NormalizedVirtualMachine(NormalizedRecord):
    """A virtual machine with placement + vNICs (ADR-0051 §5.3).

    Identity is ``moref`` (names collide across folders); the derivation's VM
    node key is ``(device_id, moref)``. ``host_name`` / ``cluster_name`` are the
    placement join keys (scoped by ``datacenter``, §5.5). ``guest_hostname`` /
    ``guest_ip_addresses`` bridge to the DNS-dependency layer and to F5 pool
    members (the VIP→pool→member→VM chain). No field carries a secret — guest
    credentials and certificate material are never collected (§5.3).
    """

    name: str = Field(min_length=1, description="VM display name — not unique per vCenter.")
    moref: str = Field(min_length=1, description="vCenter managed-object id (e.g. 'vm-1042').")
    instance_uuid: str | None = Field(
        default=None, description="vCenter instanceUuid — survives vMotion; cross-collection id."
    )
    is_template: bool = Field(description="Templates are collected, not dropped (§5.3).")
    power_state: VmPowerState
    guest_hostname: str | None = Field(
        default=None, description="VMware-Tools hostname; None when Tools absent."
    )
    guest_ip_addresses: tuple[IPv4Address | IPv6Address, ...] = Field(
        default=(),
        description="Deduplicated, sorted union of Tools-reported IPs; () when Tools absent.",
    )
    host_name: str | None = Field(
        default=None,
        description="Placement: host the VM runs on (joins NormalizedHypervisorHost.name); "
        "None for unplaced/orphaned VMs.",
    )
    cluster_name: str | None = Field(
        default=None,
        description="Placement: cluster of that host; None for standalone hosts. Denormalized "
        "onto the VM so derivation survives a partial collection (§5.3).",
    )
    datacenter: str | None = Field(
        default=None, description="Disambiguation scope for name joins (§5.5)."
    )
    nics: tuple[NormalizedVirtualNic, ...] = Field(
        default=(), description="Nested vNICs; () = none."
    )
    description: str | None = Field(default=None, description="vSphere annotation, free text.")


class NormalizedHypervisorHost(NormalizedRecord):
    """A hypervisor host with cluster membership + pNICs (ADR-0051 §5.3).

    Keyed on ``(device_id, moref)`` with ``name`` the human join field.
    ``name`` is the join target of :attr:`NormalizedVirtualMachine.host_name`
    and the LLDP/CDP system-name bridge to physical-switch neighbor tables. No
    field carries a secret (host root credentials are never collected).
    """

    name: str = Field(min_length=1, description="Host name as inventoried (typically FQDN).")
    moref: str = Field(min_length=1, description="e.g. 'host-123'.")
    cluster_name: str | None = Field(default=None, description="None = standalone host.")
    datacenter: str | None = None
    vendor: str | None = Field(default=None, description="Hardware vendor.")
    model: str | None = Field(default=None, description="Hardware model.")
    hypervisor_version: str | None = Field(
        default=None, description="e.g. 'VMware ESXi 8.0.2 build-…'."
    )
    connection_state: HostConnectionState
    in_maintenance_mode: bool = Field(description="Drained host ≠ failed host (impact analysis).")
    management_ip: IPv4Address | IPv6Address | None = Field(
        default=None, description="Management vmkernel address."
    )
    pnics: tuple[NormalizedPhysicalNic, ...] = Field(
        default=(), description="Nested physical adapters; () = none."
    )


class NormalizedComputeCluster(NormalizedRecord):
    """A compute cluster (ADR-0051 §5.3).

    Keyed on ``(device_id, moref)``; ``name`` is the join target of the
    ``cluster_name`` fields (unique per datacenter, not per vCenter, §5.5). No
    field carries a secret.
    """

    name: str = Field(min_length=1, description="Cluster name — join target of cluster_name.")
    moref: str = Field(min_length=1, description="e.g. 'domain-c8'.")
    datacenter: str | None = Field(
        default=None, description="Cluster names are unique per datacenter (§5.5)."
    )
    drs_enabled: bool | None = Field(
        default=None, description="Placement volatility signal — DRS moves VMs between hosts."
    )
    ha_enabled: bool | None = Field(
        default=None, description="HA cluster ⇒ VM restarts elsewhere on host failure."
    )


class NormalizedPortGroup(NormalizedRecord):
    """A standard or distributed port group (ADR-0051 §5.3).

    ``name`` is the join target of :attr:`NormalizedVirtualNic.port_group_name`.
    Standard port groups exist per host (``host_name`` set; same name may repeat
    across hosts, §5.5) and have no ``moref``; distributed port groups are
    vCenter-wide (``host_name`` None) and keyed on ``(device_id, moref)``.
    ``uplink_pnic_names`` completes the vNIC → port group → pNIC →
    physical-switchport chain. No field carries a secret.
    """

    name: str = Field(min_length=1, description="Join target of a vNIC's port_group_name.")
    switch_name: str = Field(min_length=1, description="Parent vSwitch / distributed vSwitch name.")
    switch_type: VirtualSwitchType
    datacenter: str | None = None
    host_name: str | None = Field(
        default=None,
        description="Scope: standard port groups exist per host; None for distributed (§5.5).",
    )
    vlan_id: int | None = Field(
        default=None,
        ge=0,
        le=4094,
        description="Access VLAN; None for trunk/private-VLAN port groups (richness in raw).",
    )
    moref: str | None = Field(
        default=None,
        description="Distributed portgroup key (e.g. 'dvportgroup-123'); None for standard.",
    )
    uplink_pnic_names: tuple[str, ...] = Field(
        default=(),
        description="Effective uplink pNICs (per-portgroup teaming override respected); () = none.",
    )
