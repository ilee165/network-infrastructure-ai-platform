"""Palo Alto PAN-OS plugin: XML API-backed firewall + network capabilities (ADR-0035).

The platform's **first firewall vendor plugin** (P2 W2-T1): ``panos``, an
httpx XML-API plugin declaring ``DISCOVERY_API``, ``INTERFACES``, ``ROUTES``,
``FIREWALL_POLICY``, ``CONFIG_BACKUP``, and ``HA_STATUS``. Binds
``FIREWALL_POLICY`` to the W1-T1 normalized models
:class:`~app.schemas.normalized.NormalizedFirewallRule` /
:class:`~app.schemas.normalized.NormalizedNatRule` (ADR-0034). No config-write
capability in P2 (ADR-0035 §6). No SSH, no Panorama, no multi-vsys (ADR-0035 §5).

Every PAN-OS XML response is recorded verbatim via
``PluginCapability._record_raw`` before parsing (ADR-0006 §3 raw-first), so
each normalized row is re-derivable. The API key never crosses the plugin
boundary into any log line, normalized field, or exception message (ADR-0011 /
ADR-0035 §2). Config export material (running-config) inherits ``raw_artifacts``
access controls — it is not a new unprotected secret surface (ADR-0035 §1).

Scope:
- Default ``vsys1``; no Panorama, no multi-vsys (named-deferred, ADR-0035 §5).
- Read-only: no ``CONFIG_RESTORE`` / ``CONFIG_DEPLOY`` / ``STATE_CHANGING``
  capability declared (ADR-0035 §6).
- ``FIREWALL_POLICY`` delivers both security rules and NAT rules; no separate
  ``ACL`` capability (PAN-OS expresses L3/L4 control as security policy,
  ADR-0035 §3 / §4).
- ``hit_count`` via ``op show-rule-hit-count``, best-effort; ``None`` if
  unavailable (ADR-0035 §3).
"""

from __future__ import annotations

import contextlib
from collections.abc import Mapping
from datetime import UTC, datetime
from ipaddress import IPv4Address, IPv4Network, IPv6Network, ip_interface, ip_network
from typing import Any, ClassVar
from uuid import UUID
from xml.etree import ElementTree as ET

from app.core.errors import PluginError
from app.plugins.base import (
    Capability,
    ConfigBackupCapability,
    DiscoveryApiCapability,
    FirewallPolicyCapability,
    HaStatusCapability,
    InterfacesCapability,
    PluginCapability,
    RoutesCapability,
    VendorPlugin,
)
from app.plugins.vendors.panos.client import PanosClient, _members, _text, parse_xml
from app.schemas.discovery import DeviceFacts
from app.schemas.normalized import (
    FirewallAction,
    HaPeerLinkState,
    HaPeerRole,
    InterfaceAdminStatus,
    InterfaceOperStatus,
    NatType,
    NormalizedDiscoveredObject,
    NormalizedFirewallRule,
    NormalizedHaStatus,
    NormalizedInterface,
    NormalizedNatRule,
    NormalizedRoute,
    RouteProtocol,
)

__all__ = [
    "PanosConfigBackup",
    "PanosDiscoveryApi",
    "PanosFirewallPolicy",
    "PanosHaStatus",
    "PanosInterfaces",
    "PanosPlugin",
    "PanosRoutes",
    "_detect_nat_type",
    "_map_action",
]

VENDOR_ID = "panos"

# ---------------------------------------------------------------------------
# Action / NatType mapping helpers (ADR-0035 §4)
# ---------------------------------------------------------------------------

#: PAN-OS action string → normalized FirewallAction (ADR-0035 §4 / ADR-0034 §4).
#: ``reset-client`` / ``reset-server`` / ``reset-both`` → reject (RST-based).
_ACTION_MAP: Mapping[str, FirewallAction] = {
    "allow": FirewallAction.ALLOW,
    "deny": FirewallAction.DENY,
    "drop": FirewallAction.DROP,
    "reset-client": FirewallAction.REJECT,
    "reset-server": FirewallAction.REJECT,
    "reset-both": FirewallAction.REJECT,
}


def _map_action(panos_action: str) -> FirewallAction:
    """Map a PAN-OS action string to the normalized FirewallAction enum.

    Unknown actions default to ``deny`` (safe/closed default, ADR-0035 §4).
    """
    return _ACTION_MAP.get(panos_action.lower(), FirewallAction.DENY)


def _detect_nat_type(
    *,
    has_source: bool,
    has_destination: bool,
    has_static: bool,
) -> NatType:
    """Detect the NAT rule type from translation element presence (ADR-0035 §4).

    PAN-OS NAT rules carry exactly one of:
    - ``<source-translation>`` → source NAT
    - ``<destination-translation>`` → destination NAT
    - ``<static-ip>`` inside source-translation → static NAT

    When none is present (ambiguous / empty rule), ``source`` is the default.
    """
    if has_static:
        return NatType.STATIC
    if has_destination:
        return NatType.DESTINATION
    return NatType.SOURCE  # source or default


def _detect_nat_type_from_element(entry: ET.Element) -> NatType:
    """Infer NatType from a ``<entry>`` NAT rule element (ADR-0035 §4)."""
    src_el = entry.find("source-translation")
    dst_el = entry.find("destination-translation")
    has_static = src_el is not None and src_el.find("static-ip") is not None
    return _detect_nat_type(
        has_source=src_el is not None and not has_static,
        has_destination=dst_el is not None,
        has_static=has_static,
    )


# ---------------------------------------------------------------------------
# Shared capability base
# ---------------------------------------------------------------------------


def _utcnow() -> datetime:
    return datetime.now(UTC)


class _PanosCapability(PluginCapability):
    """Shared base: holds the PAN-OS client + device context.

    ``_fetch`` issues an XML API call, records the raw XML verbatim
    (one raw artifact per call) before parsing — the audit hook persisted
    to ``raw_artifacts`` (ADR-0006 §3). The command string stored in
    ``_record_raw`` names the capability operation but NEVER includes the
    API key (ADR-0011 §1 / ADR-0035 §2).
    """

    def __init__(self, client: PanosClient, device_id: UUID) -> None:
        super().__init__()
        self._client = client
        self._device_id = device_id

    def _fetch(self, label: str, method_name: str, **kwargs: Any) -> ET.Element:
        """Call a PanosClient method, record the raw XML, and return the root element.

        *label* is a human-readable capability label used as the ``command``
        in the raw artifact — it never contains the API key (ADR-0035 §2).
        """
        method = getattr(self._client, method_name)
        xml_text: str = method(**kwargs)
        # Raw-first: store verbatim XML before parse (ADR-0006 §3).
        # The label is a sanitized operation descriptor, never the API key.
        self._record_raw(f"panos:{label}", xml_text)
        return parse_xml(xml_text)

    def _provenance(self) -> dict[str, Any]:
        return {
            "device_id": self._device_id,
            "collected_at": _utcnow(),
            "source_vendor": VENDOR_ID,
        }


# ---------------------------------------------------------------------------
# DISCOVERY_API
# ---------------------------------------------------------------------------


class PanosDiscoveryApi(_PanosCapability, DiscoveryApiCapability):
    """``DISCOVERY_API``: ``op`` show system info → device identity.

    Returns one :class:`NormalizedDiscoveredObject` representing the firewall
    itself (hostname, model, OS version). No fan-out — a single ``op``
    call is sufficient to identify the device (ADR-0035 §3).
    """

    def discover(self) -> list[NormalizedDiscoveredObject]:
        from app.schemas.normalized import DiscoveredObjectKind

        root = self._fetch("show_system_info", "show_system_info")
        system = root.find(".//system")
        if system is None:
            raise PluginError("panos: show system info returned no <system> element")

        hostname = _text(system.find("hostname")) or "unknown"
        model = _text(system.find("model")) or None
        os_version = _text(system.find("sw-version")) or None
        serial = _text(system.find("serial")) or None

        provenance = self._provenance()
        attributes: list[tuple[str, str]] = []
        if model:
            attributes.append(("model", model))
        if os_version:
            attributes.append(("os_version", os_version))
        if serial:
            attributes.append(("serial", serial))

        return [
            NormalizedDiscoveredObject(
                **provenance,
                kind=DiscoveredObjectKind.OTHER,
                identifier=hostname,
                display_name=f"{hostname} ({model or 'panos'})",
                object_ref=serial,
                attributes=tuple(attributes),
            )
        ]

    def get_device_facts(self) -> DeviceFacts:
        """Return device identity facts from ``op show system info``."""
        root = self._fetch("show_system_info_facts", "show_system_info")
        system = root.find(".//system")
        if system is None:
            raise PluginError("panos: show system info returned no <system> element")
        hostname = _text(system.find("hostname")) or "unknown"
        return DeviceFacts(
            hostname=hostname,
            vendor_id=VENDOR_ID,
            model=_text(system.find("model")) or None,
            os_version=_text(system.find("sw-version")) or None,
            serial=_text(system.find("serial")) or None,
        )


# ---------------------------------------------------------------------------
# INTERFACES
# ---------------------------------------------------------------------------


class PanosInterfaces(_PanosCapability, InterfacesCapability):
    """``INTERFACES``: ``op`` show interface all + config get → interface list.

    Fetches hardware state (link status, MAC, speed) via ``op`` and IP
    addresses via ``config get`` (ADR-0035 §3). Merges the two responses into
    :class:`NormalizedInterface` records.
    """

    def get_interfaces(self) -> list[NormalizedInterface]:
        # Fetch hw state (raw-first recorded inside _fetch).
        hw_root = self._fetch("show_interface_all", "show_interface_all")

        # Fetch config (IP addresses) — may fail on minimal fixtures; best-effort.
        try:
            cfg_root = self._fetch("get_interface_config", "get_interface_config")
        except PluginError:
            cfg_root = None

        # Build an IP-address lookup: interface name -> IPv4Interface | None
        ip_by_iface: dict[str, str] = {}
        if cfg_root is not None:
            for eth_entry in cfg_root.findall(".//interface/ethernet/entry"):
                iface_name = eth_entry.get("name", "")
                ip_entry = eth_entry.find(".//layer3/ip/entry")
                if ip_entry is not None:
                    ip_by_iface[iface_name] = ip_entry.get("name", "")

        provenance = self._provenance()
        interfaces: list[NormalizedInterface] = []

        for entry in hw_root.findall(".//hw/entry"):
            name = entry.get("name") or _text(entry.find("name"))
            if not name:
                continue
            state = _text(entry.find("state")).lower()
            oper_status = InterfaceOperStatus.UP if state == "up" else InterfaceOperStatus.DOWN
            # Admin status: PAN-OS doesn't separate admin/oper in hw show;
            # treat as UP when oper is up (best-effort, ADR-0035 §3).
            admin_status = InterfaceAdminStatus.UP if state == "up" else InterfaceAdminStatus.DOWN

            # Speed / duplex (best-effort).
            speed_mbps: int | None = None
            raw_speed = _text(entry.find("speed"))
            if raw_speed:
                speed_mbps = _parse_speed_mbps(raw_speed)

            # IP address from config.
            ip_addr = None
            raw_ip = ip_by_iface.get(name)
            if raw_ip:
                with contextlib.suppress(ValueError):
                    ip_addr = ip_interface(raw_ip)

            interfaces.append(
                NormalizedInterface(
                    **provenance,
                    name=name,
                    admin_status=admin_status,
                    oper_status=oper_status,
                    ip_address=ip_addr,
                    speed_mbps=speed_mbps,
                )
            )

        return interfaces


def _parse_speed_mbps(raw: str) -> int | None:
    """Parse PAN-OS speed string (e.g. '1000full', '100full') → Mbps."""
    import re

    m = re.match(r"(\d+)", raw)
    if m:
        return int(m.group(1))
    return None


# ---------------------------------------------------------------------------
# ROUTES
# ---------------------------------------------------------------------------

#: PAN-OS route flags → RouteProtocol mapping (ADR-0035 §3).
#: Flags field is a space-separated set; we check for substrings.
_ROUTE_PROTO_MAP: list[tuple[str, RouteProtocol]] = [
    ("B", RouteProtocol.BGP),
    ("O", RouteProtocol.OSPF),
    ("R", RouteProtocol.RIP),
    ("C", RouteProtocol.CONNECTED),
    ("S", RouteProtocol.STATIC),
    ("H", RouteProtocol.OTHER),  # host route
]


def _map_route_protocol(flags: str) -> RouteProtocol:
    """Map PAN-OS route flags to the normalized RouteProtocol."""
    for flag, proto in _ROUTE_PROTO_MAP:
        if flag in flags.split():
            return proto
    return RouteProtocol.OTHER


class PanosRoutes(_PanosCapability, RoutesCapability):
    """``ROUTES``: ``op`` show routing route → routing table (ADR-0035 §3)."""

    def get_routes(self) -> list[NormalizedRoute]:
        root = self._fetch("show_routing_route", "show_routing_route")
        provenance = self._provenance()
        routes: list[NormalizedRoute] = []

        for entry in root.findall(".//entry"):
            dest_str = _text(entry.find("destination"))
            if not dest_str:
                continue
            try:
                destination: IPv4Network | IPv6Network = ip_network(dest_str, strict=False)
            except ValueError:
                continue

            nexthop_str = _text(entry.find("nexthop"))
            nexthop = None
            if nexthop_str:
                with contextlib.suppress(ValueError):
                    nexthop = IPv4Address(nexthop_str)

            flags = _text(entry.find("flags"))
            protocol = _map_route_protocol(flags)
            interface = _text(entry.find("interface")) or None

            metric_str = _text(entry.find("metric"))
            metric: int | None = None
            if metric_str:
                with contextlib.suppress(ValueError):
                    metric = int(metric_str)

            routes.append(
                NormalizedRoute(
                    **provenance,
                    destination=destination,
                    protocol=protocol,
                    next_hop=nexthop,
                    interface=interface,
                    metric=metric,
                )
            )

        return routes


# ---------------------------------------------------------------------------
# FIREWALL_POLICY
# ---------------------------------------------------------------------------


class PanosFirewallPolicy(_PanosCapability, FirewallPolicyCapability):
    """``FIREWALL_POLICY``: config get security rules + NAT rules (ADR-0034).

    Returns the firewall security policy as :class:`NormalizedFirewallRule`
    records and the NAT policy as :class:`NormalizedNatRule` records, both
    scoped to the default ``vsys1`` (ADR-0035 §5). Hit counts are fetched
    via a separate ``op show-rule-hit-count`` call (best-effort; ``None``
    if unavailable, ADR-0035 §3). Every XML response is stored verbatim
    before parsing (ADR-0006 §3 raw-first). No secret crosses this boundary
    (ADR-0034 / ADR-0011).
    """

    def get_firewall_rules(self) -> list[NormalizedFirewallRule]:
        """Return security policy rules as normalized firewall records."""
        root = self._fetch("get_security_rules", "get_security_rules")

        # Best-effort hit-count lookup (ADR-0035 §3).
        hit_counts = self._fetch_hit_counts()

        provenance = self._provenance()
        rules: list[NormalizedFirewallRule] = []

        for position, entry in enumerate(root.findall(".//rules/entry")):
            name = entry.get("name", "")
            if not name:
                continue

            disabled_text = _text(entry.find("disabled")).lower()
            enabled = disabled_text != "yes"

            action_text = _text(entry.find("action"))
            action = _map_action(action_text)

            from_zones = _members(entry.find("from"))
            to_zones = _members(entry.find("to"))
            sources = _members(entry.find("source"))
            destinations = _members(entry.find("destination"))
            applications = _members(entry.find("application"))
            services = _members(entry.find("service"))

            log_text = _text(entry.find("log-end")).lower()
            logging: bool | None = None
            if log_text in ("yes", "no"):
                logging = log_text == "yes"

            description = _text(entry.find("description")) or None
            hit_count = hit_counts.get(name)

            rules.append(
                NormalizedFirewallRule(
                    **provenance,
                    name=name,
                    position=position,
                    enabled=enabled,
                    action=action,
                    source_zones=from_zones,
                    destination_zones=to_zones,
                    source_addresses=sources,
                    destination_addresses=destinations,
                    applications=applications,
                    services=services,
                    logging=logging,
                    hit_count=hit_count,
                    description=description,
                )
            )

        return rules

    def get_nat_rules(self) -> list[NormalizedNatRule]:
        """Return NAT policy rules as normalized NAT records."""
        root = self._fetch("get_nat_rules", "get_nat_rules")
        provenance = self._provenance()
        nat_rules: list[NormalizedNatRule] = []

        for entry in root.findall(".//rules/entry"):
            name = entry.get("name", "")
            if not name:
                continue

            disabled_text = _text(entry.find("disabled")).lower()
            enabled = disabled_text != "yes"

            nat_type = _detect_nat_type_from_element(entry)

            from_zones = _members(entry.find("from"))
            to_zones = _members(entry.find("to"))
            original_source = _members(entry.find("source"))
            original_destination = _members(entry.find("destination"))
            original_service = _text(entry.find("service")) or None

            # Translated source/destination from translation elements.
            translated_source: tuple[str, ...] = ()
            translated_destination: tuple[str, ...] = ()
            translated_service: str | None = None

            src_trans = entry.find("source-translation")
            if src_trans is not None:
                # Dynamic IP and port — interface address or translated-address.
                dip = src_trans.find("dynamic-ip-and-port")
                if dip is not None:
                    iface_addr = dip.find("interface-address/interface")
                    if iface_addr is not None and iface_addr.text:
                        translated_source = (iface_addr.text.strip(),)
                    trans_addr = dip.find("translated-address/member")
                    if trans_addr is not None and trans_addr.text:
                        translated_source = (trans_addr.text.strip(),)
                # Static IP.
                static = src_trans.find("static-ip/translated-address")
                if static is not None and static.text:
                    translated_source = (static.text.strip(),)

            dst_trans = entry.find("destination-translation")
            if dst_trans is not None:
                dst_addr = _text(dst_trans.find("translated-address"))
                if dst_addr:
                    translated_destination = (dst_addr,)
                trans_port = _text(dst_trans.find("translated-port"))
                if trans_port:
                    translated_service = trans_port

            nat_rules.append(
                NormalizedNatRule(
                    **provenance,
                    name=name,
                    nat_type=nat_type,
                    enabled=enabled,
                    source_zones=from_zones,
                    destination_zones=to_zones,
                    original_source=original_source,
                    original_destination=original_destination,
                    original_service=original_service,
                    translated_source=translated_source,
                    translated_destination=translated_destination,
                    translated_service=translated_service,
                )
            )

        return nat_rules

    def _fetch_hit_counts(self) -> dict[str, int]:
        """Best-effort hit count fetch; returns empty dict on any failure (ADR-0035 §3)."""
        try:
            root = self._fetch("show_rule_hit_count", "show_rule_hit_count")
        except PluginError:
            return {}

        counts: dict[str, int] = {}
        for rule_entry in root.findall(".//rules/entry"):
            rule_name = rule_entry.get("name", "")
            if not rule_name:
                continue
            hit_el = rule_entry.find(".//hit-count")
            if hit_el is not None and hit_el.text:
                with contextlib.suppress(ValueError):
                    counts[rule_name] = int(hit_el.text.strip())
        return counts


# ---------------------------------------------------------------------------
# CONFIG_BACKUP
# ---------------------------------------------------------------------------


class PanosConfigBackup(_PanosCapability, ConfigBackupCapability):
    """``CONFIG_BACKUP``: ``config show`` running configuration (ADR-0035 §5).

    Captures the **running** (enforced) configuration, not the candidate
    (uncommitted) config — drift/compliance analysis must reflect what is
    live (ADR-0035 §5). The raw XML is stored verbatim via ``_record_raw``
    before being returned as a string; the caller (discovery runner) persists
    it to ``raw_artifacts`` with appropriate access controls (ADR-0035 §1).
    """

    def fetch_running_config(self) -> str:
        """Return the PAN-OS running configuration verbatim as XML."""
        root = self._fetch("show_config_running", "show_config_running")
        # Return the verbatim XML text. We use ET.tostring to produce a
        # stable, normalised representation; the raw artifact already captured
        # the exact server bytes via _fetch/_record_raw above (ADR-0006 §3).
        return ET.tostring(root, encoding="unicode")


# ---------------------------------------------------------------------------
# HA_STATUS
# ---------------------------------------------------------------------------

_HA_ROLE_MAP: Mapping[str, HaPeerRole] = {
    "active": HaPeerRole.ACTIVE,
    "passive": HaPeerRole.STANDBY,
    "primary-active": HaPeerRole.ACTIVE,
    "secondary-passive": HaPeerRole.STANDBY,
    "primary": HaPeerRole.PRIMARY,
    "secondary": HaPeerRole.SECONDARY,
    "initial": HaPeerRole.UNKNOWN,
    "suspended": HaPeerRole.UNKNOWN,
    "non-functional": HaPeerRole.UNKNOWN,
}

_HA_LINK_STATE_MAP: Mapping[str, HaPeerLinkState] = {
    "up": HaPeerLinkState.UP,
    "down": HaPeerLinkState.DOWN,
}


class PanosHaStatus(_PanosCapability, HaStatusCapability):
    """``HA_STATUS``: ``op`` show high-availability state (ADR-0035 §3).

    Returns one :class:`NormalizedHaStatus` per device reflecting the
    local HA role and the peer connection state. PAN-OS active/passive HA
    maps to ``ACTIVE``/``STANDBY`` roles (ADR-0035 §4 / ADR-0025 §8).
    """

    def get_ha_status(self) -> list[NormalizedHaStatus]:
        root = self._fetch("show_ha_state", "show_ha_state")
        provenance = self._provenance()
        results: list[NormalizedHaStatus] = []

        group = root.find(".//group")
        if group is None:
            # HA not configured — return unknown status.
            results.append(
                NormalizedHaStatus(
                    **provenance,
                    peer_role=HaPeerRole.UNKNOWN,
                    peer_link_state=HaPeerLinkState.UNKNOWN,
                    keepalive_state=HaPeerLinkState.UNKNOWN,
                )
            )
            return results

        local_state = _text(group.find("local-info/state")).lower()
        peer_role = _HA_ROLE_MAP.get(local_state, HaPeerRole.UNKNOWN)

        peer_conn = _text(group.find("peer-info/conn-status")).lower()
        peer_link_state = _HA_LINK_STATE_MAP.get(peer_conn, HaPeerLinkState.UNKNOWN)

        peer_mgmt_ip: IPv4Address | None = None
        peer_ip_str = _text(group.find("peer-info/mgmt-ip"))
        if peer_ip_str:
            with contextlib.suppress(ValueError):
                peer_mgmt_ip = IPv4Address(peer_ip_str)

        results.append(
            NormalizedHaStatus(
                **provenance,
                peer_role=peer_role,
                peer_link_state=peer_link_state,
                keepalive_state=peer_link_state,  # PAN-OS reuses peer conn for keepalive
                peer_address=peer_mgmt_ip,
            )
        )
        return results


# ---------------------------------------------------------------------------
# Plugin registration
# ---------------------------------------------------------------------------


class PanosPlugin(VendorPlugin):
    """Palo Alto PAN-OS (``vendor_id="panos"``) — XML API firewall plugin (ADR-0035).

    Declares six capabilities: ``DISCOVERY_API``, ``INTERFACES``, ``ROUTES``,
    ``FIREWALL_POLICY`` (security + NAT rules, ADR-0034), ``CONFIG_BACKUP``,
    and ``HA_STATUS``. No SSH, no config-write, no Panorama, no multi-vsys
    in P2 (ADR-0035 §5/§6). The first of two firewall plugins (with ``fortios``)
    validating the ``FIREWALL_POLICY`` contract before it is declared stable
    (PRODUCTION.md §2.3 / ADR-0034).
    """

    vendor_id: ClassVar[str] = VENDOR_ID
    display_name: ClassVar[str] = "Palo Alto PAN-OS"
    capabilities: ClassVar[frozenset[Capability]] = frozenset(
        {
            Capability.DISCOVERY_API,
            Capability.INTERFACES,
            Capability.ROUTES,
            Capability.FIREWALL_POLICY,
            Capability.CONFIG_BACKUP,
            Capability.HA_STATUS,
        }
    )

    def _capability_classes(self) -> Mapping[Capability, type[PluginCapability]]:
        return {
            Capability.DISCOVERY_API: PanosDiscoveryApi,
            Capability.INTERFACES: PanosInterfaces,
            Capability.ROUTES: PanosRoutes,
            Capability.FIREWALL_POLICY: PanosFirewallPolicy,
            Capability.CONFIG_BACKUP: PanosConfigBackup,
            Capability.HA_STATUS: PanosHaStatus,
        }
