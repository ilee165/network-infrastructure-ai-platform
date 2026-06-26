"""Fortinet FortiOS plugin: REST + netmiko SSH (single-transport per capability, ADR-0036).

The platform's **second firewall vendor plugin** (P2 W2-T2): ``fortios``,
declaring ``DISCOVERY_API``, ``INTERFACES``, ``ROUTES``, ``FIREWALL_POLICY``,
``CONFIG_BACKUP``, and ``HA_STATUS``. Binds ``FIREWALL_POLICY`` to the W1-T1
normalized models
:class:`~app.schemas.normalized.NormalizedFirewallRule` /
:class:`~app.schemas.normalized.NormalizedNatRule` (ADR-0034). No config-write
capability in P2 (ADR-0036 §5). Root VDOM only; multi-VDOM deferred (ADR-0036 §4).

Per-capability transport (each capability uses exactly one transport in P2 —
a cross-transport fallback that is never reached would be dead surface,
ADR-0036 §1):
- ``DISCOVERY_API``: REST /monitor/system/status (SSH fallback named-deferred)
- ``INTERFACES``:    REST /monitor/system/interface (SSH fallback named-deferred)
- ``ROUTES``:        REST /monitor/router/ipv4 (SSH fallback named-deferred)
- ``FIREWALL_POLICY``: REST /cmdb/firewall/policy + /cmdb/firewall/*nat*
- ``CONFIG_BACKUP``: SSH show full-configuration (REST fallback named-deferred)
- ``HA_STATUS``:     REST /monitor/system/ha-* (SSH fallback named-deferred)

The SSH transport (netmiko ``fortinet``, ADR-0007) backs only ``CONFIG_BACKUP``
in P2 — the one capability whose full-config text is cleaner over the CLI
(ADR-0036 Consequences). The cross-transport fallbacks listed in the ADR-0036 §1
table are named-deferred until a follow-up ADR wires try-primary/except-fallback
logic; shipping them as inert docstring claims would be the dead surface §1 warns
against.

Every REST response and every SSH output is recorded verbatim via
``PluginCapability._record_raw`` before parsing (ADR-0006 §3 raw-first).
The REST token and SSH password never cross the plugin boundary into any log
line, normalized field, or exception message (ADR-0011 / ADR-0036 §2).

ADR-0034 cross-vendor agreement with panos confirmed (ADR-0036 §6):
- FortiOS ``accept``→``allow``, ``deny``→``deny``.
  (PAN-OS additionally supplies ``drop``/``reject`` — the full enum union.)
- ``hit_count`` via /monitor/firewall/policy/select, best-effort; None otherwise.
- No ADR-0034 field is unrealizable from FortiOS REST surface.
"""

from __future__ import annotations

import contextlib
import json
from collections.abc import Mapping
from datetime import UTC, datetime
from ipaddress import IPv4Address, IPv4Network, IPv6Network, ip_network
from typing import Any, ClassVar
from uuid import UUID

from app.core.errors import PluginError
from app.plugins.base import (
    Capability,
    CommandTransport,
    ConfigBackupCapability,
    DiscoveryApiCapability,
    FirewallPolicyCapability,
    HaStatusCapability,
    InterfacesCapability,
    PluginCapability,
    RoutesCapability,
    VendorPlugin,
)
from app.plugins.vendors.fortios.client import FortiosRestClient
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
    "FortiosConfigBackup",
    "FortiosDiscoveryApi",
    "FortiosFirewallPolicy",
    "FortiosHaStatus",
    "FortiosInterfaces",
    "FortiosPlugin",
    "FortiosRoutes",
    "_detect_nat_type",
    "_map_action",
]

VENDOR_ID = "fortios"

# ---------------------------------------------------------------------------
# Action / NatType mapping helpers (ADR-0036 §3)
# ---------------------------------------------------------------------------

#: FortiOS action string → normalized FirewallAction.
#: FortiOS has no native drop/reject verb distinct from deny (ADR-0036 §3).
_ACTION_MAP: Mapping[str, FirewallAction] = {
    "accept": FirewallAction.ALLOW,
    "deny": FirewallAction.DENY,
}


def _map_action(fortios_action: str) -> FirewallAction:
    """Map a FortiOS action string to the normalized FirewallAction enum.

    FortiOS uses only ``accept`` and ``deny`` (ADR-0036 §3): ``deny`` silently
    drops (no RST/ICMP), mapping to ``deny``. Unknown actions default to
    ``deny`` (safe/closed default).
    """
    return _ACTION_MAP.get(fortios_action.lower(), FirewallAction.DENY)


def _detect_nat_type(nat_kind: str) -> NatType:
    """Detect NatType from the rule origin kind (ADR-0036 §3).

    - ``snat`` / ``source`` (central-SNAT pool, IP pool) → ``source``
    - ``vip`` / ``destination`` / ``dnat`` → ``destination``
    - ``static`` (central-SNAT static) → ``static``
    - anything else → ``source`` (safe default)
    """
    key = nat_kind.lower()
    if key in ("vip", "destination", "dnat"):
        return NatType.DESTINATION
    if key == "static":
        return NatType.STATIC
    return NatType.SOURCE  # snat, source, ip-pool, or unknown → source


# ---------------------------------------------------------------------------
# Route protocol mapping
# ---------------------------------------------------------------------------

#: FortiOS route type string → RouteProtocol.
_ROUTE_PROTO_MAP: Mapping[str, RouteProtocol] = {
    "static": RouteProtocol.STATIC,
    "connect": RouteProtocol.CONNECTED,
    "connected": RouteProtocol.CONNECTED,
    "ospf": RouteProtocol.OSPF,
    "bgp": RouteProtocol.BGP,
    "rip": RouteProtocol.RIP,
    "isis": RouteProtocol.OTHER,
}


def _map_route_protocol(route_type: str) -> RouteProtocol:
    """Map FortiOS route type to the normalized RouteProtocol."""
    return _ROUTE_PROTO_MAP.get(route_type.lower(), RouteProtocol.OTHER)


# HA role/link state mapping
_HA_ROLE_MAP: Mapping[str, HaPeerRole] = {
    "primary": HaPeerRole.ACTIVE,
    "master": HaPeerRole.ACTIVE,
    "secondary": HaPeerRole.STANDBY,
    "slave": HaPeerRole.STANDBY,
    "standalone": HaPeerRole.UNKNOWN,
}

_HA_LINK_STATE_MAP: Mapping[str, HaPeerLinkState] = {
    "up": HaPeerLinkState.UP,
    "down": HaPeerLinkState.DOWN,
}


# ---------------------------------------------------------------------------
# Shared capability base
# ---------------------------------------------------------------------------


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _parse_json(raw: str, context: str) -> Any:
    """Parse JSON text; raises PluginError on failure (context is logged, not the raw data)."""
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        raise PluginError(f"fortios: {context} returned non-JSON body") from None


class _FortiosCapability(PluginCapability):
    """Shared base: holds the REST client + SSH transport + device context.

    The REST client and SSH transport each carry their own credential. Neither
    credential is ever stored on this class — it is held inside the transports
    (name-mangled). Raw-first: every response is stored verbatim via
    ``_record_raw`` before parsing (ADR-0006 §3).
    """

    def __init__(
        self,
        rest_client: FortiosRestClient,
        ssh_transport: CommandTransport,
        device_id: UUID,
    ) -> None:
        super().__init__()
        self._rest = rest_client
        self._ssh = ssh_transport
        self._device_id = device_id

    def _fetch_rest(self, label: str, method_name: str) -> Any:
        """Call a REST client method, record the raw JSON, and return parsed data.

        *label* is a human-readable capability label stored in the raw artifact
        command field — it never contains the REST token (ADR-0036 §2).
        """
        method = getattr(self._rest, method_name)
        raw: str = method()
        # Raw-first: store verbatim JSON before parse (ADR-0006 §3).
        self._record_raw(f"fortios:{label}", raw)
        data = _parse_json(raw, label)
        return data

    def _fetch_ssh(self, label: str, command: str) -> str:
        """Send an SSH command, record the raw text, and return verbatim output.

        *label* is stored in the raw artifact command field — it never contains
        the SSH password (ADR-0011 §1). The SSH credential lives inside the
        transport and is never accessed here.
        """
        raw: str = self._ssh.send_command(command)
        # Raw-first: store verbatim CLI output before any use (ADR-0006 §3).
        self._record_raw(f"fortios:{label}", raw)
        return raw

    def _provenance(self) -> dict[str, Any]:
        return {
            "device_id": self._device_id,
            "collected_at": _utcnow(),
            "source_vendor": VENDOR_ID,
        }


# ---------------------------------------------------------------------------
# DISCOVERY_API — REST only (SSH fallback named-deferred, ADR-0036 §1)
# ---------------------------------------------------------------------------


class FortiosDiscoveryApi(_FortiosCapability, DiscoveryApiCapability):
    """``DISCOVERY_API``: REST /monitor/system/status → device identity.

    Returns one :class:`NormalizedDiscoveredObject` representing the firewall
    itself (hostname, model, OS version). REST-only in P2; the ADR-0036 §1 SSH
    ``get system status`` fallback is named-deferred (no try-REST/except-SSH
    path is wired yet). Raw-first on the REST response (ADR-0006 §3).
    """

    def discover(self) -> list[NormalizedDiscoveredObject]:
        from app.schemas.normalized import DiscoveredObjectKind

        # REST primary (ADR-0036 §1).
        data = self._fetch_rest("system_status", "get_system_status")
        results = data.get("results", {})

        hostname = results.get("hostname") or "unknown"
        model = results.get("model_name") or None
        os_version = results.get("version") or None
        serial = results.get("serial") or None

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
                display_name=f"{hostname} ({model or 'fortios'})",
                object_ref=serial,
                attributes=tuple(attributes),
            )
        ]

    def get_device_facts(self) -> DeviceFacts:
        """Return device identity facts from REST /monitor/system/status."""
        data = self._fetch_rest("system_status_facts", "get_system_status")
        results = data.get("results", {})
        hostname = results.get("hostname") or "unknown"
        return DeviceFacts(
            hostname=hostname,
            vendor_id=VENDOR_ID,
            model=results.get("model_name") or None,
            os_version=results.get("version") or None,
            serial=results.get("serial") or None,
        )


# ---------------------------------------------------------------------------
# INTERFACES — REST only (SSH fallback named-deferred, ADR-0036 §1)
# ---------------------------------------------------------------------------


class FortiosInterfaces(_FortiosCapability, InterfacesCapability):
    """``INTERFACES``: REST /monitor/system/interface → interface list.

    Returns :class:`NormalizedInterface` records. REST-only in P2; the ADR-0036
    §1 SSH fallback is named-deferred (no fallback path is wired yet). Raw-first
    on the REST response (ADR-0006 §3).
    """

    def get_interfaces(self) -> list[NormalizedInterface]:
        # REST primary (ADR-0036 §1).
        data = self._fetch_rest("system_interface", "get_system_interface")
        results = data.get("results", [])

        provenance = self._provenance()
        interfaces: list[NormalizedInterface] = []

        for entry in results:
            name = entry.get("name", "")
            if not name:
                continue

            status = entry.get("status", "").lower()
            link = entry.get("link", False)

            oper_up = status == "up" or link is True
            oper_status = InterfaceOperStatus.UP if oper_up else InterfaceOperStatus.DOWN
            admin_status = InterfaceAdminStatus.UP if oper_up else InterfaceAdminStatus.DOWN

            # Speed (Mbps)
            speed_mbps: int | None = None
            raw_speed = entry.get("speed")
            if raw_speed is not None:
                with contextlib.suppress(ValueError, TypeError):
                    speed_mbps = int(raw_speed)

            # IP address (FortiOS returns ip + netmask separately)
            ip_addr = None
            raw_ip = entry.get("ip", "")
            raw_mask = entry.get("netmask", "")
            if raw_ip and raw_ip not in ("0.0.0.0", "") and raw_mask not in ("0.0.0.0", ""):
                with contextlib.suppress(ValueError):
                    from ipaddress import ip_interface

                    # Convert dotted netmask to prefix length
                    prefix = _dotted_mask_to_prefix(raw_mask)
                    if prefix is not None:
                        ip_addr = ip_interface(f"{raw_ip}/{prefix}")
                    else:
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


def _dotted_mask_to_prefix(mask: str) -> int | None:
    """Convert a dotted-decimal netmask to a prefix length (e.g. '255.255.255.0' → 24)."""
    try:
        import ipaddress

        return bin(int(ipaddress.IPv4Address(mask))).count("1")
    except Exception:  # noqa: BLE001
        return None


# ---------------------------------------------------------------------------
# ROUTES — REST only (SSH fallback named-deferred, ADR-0036 §1)
# ---------------------------------------------------------------------------


class FortiosRoutes(_FortiosCapability, RoutesCapability):
    """``ROUTES``: REST /monitor/router/ipv4 → IPv4 routing table.

    REST-only in P2; the ADR-0036 §1 SSH ``get router info routing-table``
    fallback is named-deferred (no fallback path is wired yet). Raw-first on the
    REST response (ADR-0006 §3).
    """

    def get_routes(self) -> list[NormalizedRoute]:
        # REST primary (ADR-0036 §1).
        data = self._fetch_rest("router_ipv4", "get_router_ipv4")
        results = data.get("results", [])

        provenance = self._provenance()
        routes: list[NormalizedRoute] = []

        for entry in results:
            ip_mask = entry.get("ip_mask", "")
            if not ip_mask:
                continue
            try:
                destination: IPv4Network | IPv6Network = ip_network(ip_mask, strict=False)
            except ValueError:
                continue

            nexthop: IPv4Address | None = None
            gw = entry.get("gateway", "")
            if gw and gw not in ("0.0.0.0", ""):
                with contextlib.suppress(ValueError):
                    nexthop = IPv4Address(gw)

            route_type = entry.get("type", "")
            protocol = _map_route_protocol(route_type)
            interface = entry.get("interface") or None

            metric: int | None = None
            raw_metric = entry.get("metric")
            if raw_metric is not None:
                with contextlib.suppress(ValueError, TypeError):
                    metric = int(raw_metric)

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
# FIREWALL_POLICY — REST only; no SSH fallback (ADR-0036 §1)
# ---------------------------------------------------------------------------


class FortiosFirewallPolicy(_FortiosCapability, FirewallPolicyCapability):
    """``FIREWALL_POLICY``: REST /cmdb/firewall/policy + /cmdb/firewall/*nat* (ADR-0034).

    Returns the firewall security policy as :class:`NormalizedFirewallRule`
    records and the NAT policy as :class:`NormalizedNatRule` records, scoped
    to the root VDOM (ADR-0036 §4). Hit counts are fetched via a separate
    monitor call (best-effort; ``None`` if unavailable, ADR-0036 §3).
    No SSH fallback — REST fully serves FIREWALL_POLICY (ADR-0036 §1).
    Raw-first: every REST response recorded before parsing (ADR-0006 §3).
    No secret crosses this boundary (ADR-0034 / ADR-0011).
    """

    def get_firewall_rules(self) -> list[NormalizedFirewallRule]:
        """Return FortiOS security policy rules as normalized firewall records."""
        data = self._fetch_rest("firewall_policy", "get_firewall_policy")
        results = data.get("results", [])

        # Best-effort hit-count lookup (ADR-0036 §3).
        hit_counts = self._fetch_hit_counts()

        provenance = self._provenance()
        rules: list[NormalizedFirewallRule] = []

        for position, entry in enumerate(results):
            name = entry.get("name", "") or str(entry.get("policyid", ""))
            if not name:
                continue

            # FortiOS "enable"/"disable" status field.
            status = entry.get("status", "enable").lower()
            enabled = status == "enable"

            action_text = entry.get("action", "deny")
            action = _map_action(action_text)

            # Zones / interfaces (FortiOS uses srcintf/dstintf as zone names)
            source_zones = tuple(
                iface.get("name", "") for iface in entry.get("srcintf", []) if iface.get("name")
            )
            destination_zones = tuple(
                iface.get("name", "") for iface in entry.get("dstintf", []) if iface.get("name")
            )

            # Address objects (names)
            source_addresses = tuple(
                addr.get("name", "") for addr in entry.get("srcaddr", []) if addr.get("name")
            )
            destination_addresses = tuple(
                addr.get("name", "") for addr in entry.get("dstaddr", []) if addr.get("name")
            )

            # Service and application objects
            services = tuple(
                svc.get("name", "") for svc in entry.get("service", []) if svc.get("name")
            )
            applications = tuple(
                app.get("name", "") for app in entry.get("application", []) if app.get("name")
            )

            # logtraffic: "all"/"utm" → True, "disable" → False, None otherwise
            logtraffic = entry.get("logtraffic", "")
            logging_val: bool | None = None
            if logtraffic == "disable":
                logging_val = False
            elif logtraffic in ("all", "utm"):
                logging_val = True

            description = entry.get("comments") or None

            # Hit count keyed by policyid (best-effort)
            policyid = entry.get("policyid")
            hit_count = hit_counts.get(policyid) if policyid is not None else None

            rules.append(
                NormalizedFirewallRule(
                    **provenance,
                    name=name,
                    position=position,
                    enabled=enabled,
                    action=action,
                    source_zones=source_zones,
                    destination_zones=destination_zones,
                    source_addresses=source_addresses,
                    destination_addresses=destination_addresses,
                    applications=applications,
                    services=services,
                    logging=logging_val,
                    hit_count=hit_count,
                    description=description,
                )
            )

        return rules

    def get_nat_rules(self) -> list[NormalizedNatRule]:
        """Return FortiOS NAT rules as normalized NAT records.

        Collects:
        - VIP (virtual IP) entries → ``destination`` NAT (DNAT)
        - Central-SNAT map entries → ``source`` NAT (or ``static`` for static SNAT)

        ADR-0036 §3: FortiOS SNAT (IP pool) → source, VIP/DNAT → destination,
        central-SNAT static → static.
        """
        provenance = self._provenance()
        nat_rules: list[NormalizedNatRule] = []

        # VIP / DNAT rules (destination NAT)
        vip_data = self._fetch_rest("firewall_vip", "get_firewall_vip")
        for entry in vip_data.get("results", []):
            name = entry.get("name", "")
            if not name:
                continue

            status_str = entry.get("status", "enable").lower()
            enabled = status_str == "enable"

            # VIP entries are destination NAT (static-nat / portforward both DNAT).
            nat_type = _detect_nat_type("vip")

            # Original (external) IP → original destination
            extip = entry.get("extip", "")
            original_destination = (extip,) if extip else ()

            # Mapped (internal) IP → translated destination
            mapped_ips = entry.get("mappedip", [])
            translated_destination = tuple(m.get("range", "") for m in mapped_ips if m.get("range"))

            # Port forwarding service
            translated_service: str | None = None
            if entry.get("portforward") == "enable":
                mapped_port = entry.get("mappedport", "")
                if mapped_port:
                    translated_service = str(mapped_port)

            extintf = entry.get("extintf", "")
            destination_zones = (extintf,) if extintf else ()

            nat_rules.append(
                NormalizedNatRule(
                    **provenance,
                    name=name,
                    nat_type=nat_type,
                    enabled=enabled,
                    source_zones=(),
                    destination_zones=destination_zones,
                    original_source=(),
                    original_destination=original_destination,
                    original_service=None,
                    translated_source=(),
                    translated_destination=translated_destination,
                    translated_service=translated_service,
                )
            )

        # Central-SNAT map rules (source NAT)
        snat_data = self._fetch_rest("firewall_central_snat", "get_firewall_central_snat")
        for entry in snat_data.get("results", []):
            # Central-SNAT entries may use numeric id or name field
            name = entry.get("name", "") or str(entry.get("id", ""))
            if not name:
                continue

            status_str = entry.get("status", "enable").lower()
            enabled = status_str == "enable"

            # Determine NAT type from the actual central-SNAT entry shape
            # (ADR-0036 §3): a pooled/masquerade SNAT (nat-ippool present, or no
            # explicit static source) is source NAT; an entry with no pool but a
            # fixed nat-source-address is a static one-to-one source translation.
            nat_pool = entry.get("nat-ippool", [])
            nat_source = entry.get("nat-source-address", [])
            nat_kind = "static" if not nat_pool and nat_source else "snat"
            nat_type = _detect_nat_type(nat_kind)

            # Source zones from srcintf
            source_zones = tuple(
                iface.get("name", "") for iface in entry.get("srcintf", []) if iface.get("name")
            )

            # Original source addresses
            original_source = tuple(
                addr.get("name", "") for addr in entry.get("orig-addr", []) if addr.get("name")
            )

            # Translated source (NAT pool names)
            translated_source = tuple(pool.get("name", "") for pool in nat_pool if pool.get("name"))

            # Outbound interface as destination zone
            outintf = entry.get("outintf", [])
            destination_zones = tuple(
                iface.get("name", "") for iface in outintf if iface.get("name")
            )

            nat_rules.append(
                NormalizedNatRule(
                    **provenance,
                    name=name,
                    nat_type=nat_type,
                    enabled=enabled,
                    source_zones=source_zones,
                    destination_zones=destination_zones,
                    original_source=original_source,
                    original_destination=(),
                    original_service=None,
                    translated_source=translated_source,
                    translated_destination=(),
                    translated_service=None,
                )
            )

        return nat_rules

    def _fetch_hit_counts(self) -> dict[int, int]:
        """Best-effort policy hit-count fetch; returns empty dict on any failure (ADR-0036 §3)."""
        try:
            data = self._fetch_rest("policy_hit_count", "get_policy_hit_count")
        except PluginError:
            return {}

        counts: dict[int, int] = {}
        for entry in data.get("results", []):
            policyid = entry.get("policyid")
            hit_count = entry.get("hit_count")
            if policyid is not None and hit_count is not None:
                with contextlib.suppress(ValueError, TypeError):
                    counts[int(policyid)] = int(hit_count)
        return counts


# ---------------------------------------------------------------------------
# CONFIG_BACKUP — SSH only (REST fallback named-deferred, ADR-0036 §1)
# ---------------------------------------------------------------------------

#: SSH command to retrieve the full FortiOS running configuration.
_CMD_SHOW_FULL_CONFIG = "show full-configuration"


class FortiosConfigBackup(_FortiosCapability, ConfigBackupCapability):
    """``CONFIG_BACKUP``: SSH ``show full-configuration`` (ADR-0036 §1).

    The full FortiOS running config is the established, lossless CLI surface
    (ADR-0036 §1: "full config text is cleaner over CLI"). SSH is the sole
    transport for this capability in P2; the ADR-0036 §1 REST backup-endpoint
    fallback is named-deferred (no except-SSH/then-REST path is wired yet).
    The raw CLI output is stored verbatim via ``_record_raw`` before being
    returned (ADR-0006 §3).

    The config text may contain pre-shared keys, SNMP communities, and other
    secret material — the caller (discovery runner) persists it to
    ``raw_artifacts`` with appropriate access controls (ADR-0006 §3 / ADR-0011).
    Normalized ``FIREWALL_POLICY`` models remain secret-free (ADR-0034).
    """

    def fetch_running_config(self) -> str:
        """Return the FortiOS running configuration verbatim via SSH."""
        # SSH primary (ADR-0036 §1 — full-config text is cleaner over CLI).
        raw = self._fetch_ssh("show_full_configuration", _CMD_SHOW_FULL_CONFIG)
        return raw


# ---------------------------------------------------------------------------
# HA_STATUS — REST only (SSH fallback named-deferred, ADR-0036 §1)
# ---------------------------------------------------------------------------


class FortiosHaStatus(_FortiosCapability, HaStatusCapability):
    """``HA_STATUS``: REST /monitor/system/ha-* → HA cluster state.

    Returns one :class:`NormalizedHaStatus` per device reflecting the local HA
    role and the peer connection state. FortiOS a-p (active-passive) HA:
    primary → ACTIVE, secondary → STANDBY (ADR-0025 §8). REST-only in P2; the
    ADR-0036 §1 SSH ``get system ha status`` fallback is named-deferred (no
    fallback path is wired yet).
    """

    def get_ha_status(self) -> list[NormalizedHaStatus]:
        # REST primary (ADR-0036 §1).
        data = self._fetch_rest("ha_statistics", "get_ha_statistics")
        results = data.get("results", {})

        provenance = self._provenance()
        ha_results: list[NormalizedHaStatus] = []

        members = results.get("members", [])
        if not members:
            # HA not configured or standalone — return unknown status.
            ha_results.append(
                NormalizedHaStatus(
                    **provenance,
                    peer_role=HaPeerRole.UNKNOWN,
                    peer_link_state=HaPeerLinkState.UNKNOWN,
                    keepalive_state=HaPeerLinkState.UNKNOWN,
                )
            )
            return ha_results

        # Find local member by matching the local serial number.
        local_sn = results.get("local-sn", "")
        local_member: dict[str, Any] | None = None
        peer_member: dict[str, Any] | None = None

        for member in members:
            if member.get("serial-no") == local_sn:
                local_member = member
            else:
                peer_member = member

        if local_member is None and members:
            # Fallback: treat first member as local.
            local_member = members[0]
            peer_member = members[1] if len(members) > 1 else None

        local_role = (local_member or {}).get("role", "").lower()
        peer_role = _HA_ROLE_MAP.get(local_role, HaPeerRole.UNKNOWN)

        peer_link_raw = (peer_member or {}).get("link-status", "").lower() if peer_member else ""
        peer_link_state = _HA_LINK_STATE_MAP.get(peer_link_raw, HaPeerLinkState.UNKNOWN)

        peer_address: IPv4Address | None = None
        if peer_member:
            peer_ip_str = peer_member.get("ip", "")
            if peer_ip_str:
                with contextlib.suppress(ValueError):
                    peer_address = IPv4Address(peer_ip_str)

        ha_results.append(
            NormalizedHaStatus(
                **provenance,
                peer_role=peer_role,
                peer_link_state=peer_link_state,
                keepalive_state=peer_link_state,  # FortiOS reuses link state for keepalive
                peer_address=peer_address,
            )
        )
        return ha_results


# ---------------------------------------------------------------------------
# Plugin registration
# ---------------------------------------------------------------------------


class FortiosPlugin(VendorPlugin):
    """Fortinet FortiOS (``vendor_id="fortios"``) — REST + SSH firewall plugin (ADR-0036).

    Declares six capabilities: ``DISCOVERY_API``, ``INTERFACES``, ``ROUTES``,
    ``FIREWALL_POLICY`` (security + NAT rules, ADR-0034), ``CONFIG_BACKUP``,
    and ``HA_STATUS``. REST-only for all but CONFIG_BACKUP (which is SSH-only);
    the ADR-0036 §1 cross-transport fallbacks are named-deferred in P2. No
    config-write, root VDOM only in P2 (ADR-0036 §4/§5).
    The second of two firewall plugins (with ``panos``) validating the
    ``FIREWALL_POLICY`` contract before it is declared stable
    (PRODUCTION.md §2.3 / ADR-0034 two-vendor rule).
    """

    vendor_id: ClassVar[str] = VENDOR_ID
    display_name: ClassVar[str] = "Fortinet FortiOS"
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
            Capability.DISCOVERY_API: FortiosDiscoveryApi,
            Capability.INTERFACES: FortiosInterfaces,
            Capability.ROUTES: FortiosRoutes,
            Capability.FIREWALL_POLICY: FortiosFirewallPolicy,
            Capability.CONFIG_BACKUP: FortiosConfigBackup,
            Capability.HA_STATUS: FortiosHaStatus,
        }
