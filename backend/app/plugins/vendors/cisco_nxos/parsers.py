"""Cisco NX-OS show-output parsers: ntc-templates/TextFSM → normalized models.

Single source of parsing for the ``cisco_nxos`` plugin (ADR-0025, REPO-STRUCTURE §6
step 7). Each function takes verbatim show-output text — already preserved as
:class:`~app.plugins.base.RawOutput` by the capability layer — and returns
normalized Pydantic models. Template lookups use the real ntc-templates index
with platform key ``"cisco_nxos"`` (ADR-0007); parse and validation failures
raise :class:`~app.core.errors.PluginError`.

NX-OS-specific decisions (ADR-0025):
- Feature-gated commands (BGP, OSPF, LLDP) return ``[]`` when the feature is
  disabled — "feature not enabled" / empty output normalizes to empty, not error.
- Route/BGP/OSPF collection uses ``vrf all`` forms; the VRF is carried into each
  normalized record's ``vrf`` field (ADR-0025 §3).
- ``NormalizedOspfNeighbor.vrf`` is populated (added as W1 schema extension,
  ADR-0025 §6).
- ``show vpc | json`` is parsed as structured JSON: it is the one P1 command
  that uses the ``| json`` escape hatch because vPC state spans multiple
  interleaved output sections with release-varying indentation that the
  existing ntc-templates NX-OS templates do not cover (ADR-0025 §3, §8).
  HA_STATUS is constructed from the decoded JSON document.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from datetime import datetime
from ipaddress import (
    IPv4Address,
    IPv4Network,
    IPv6Address,
    ip_address,
    ip_interface,
    ip_network,
)
from typing import cast
from uuid import UUID

from ntc_templates.parse import ParsingException, parse_output
from pydantic import ValidationError

from app.core.errors import PluginError
from app.schemas.discovery import DeviceFacts
from app.schemas.normalized import (
    AclAction,
    BgpPeerState,
    HaPeerLinkState,
    HaPeerRole,
    InterfaceAdminStatus,
    InterfaceDuplex,
    InterfaceOperStatus,
    NeighborProtocol,
    NormalizedAclEntry,
    NormalizedBgpPeer,
    NormalizedHaStatus,
    NormalizedInterface,
    NormalizedNeighbor,
    NormalizedOspfNeighbor,
    NormalizedRoute,
    OspfNeighborState,
    RouteProtocol,
)

__all__ = [
    "PLATFORM",
    "SNMP_OID_SYSDESCR",
    "SNMP_OID_SYSNAME",
    "SNMP_OID_SYSOBJECTID",
    "parse_acls",
    "parse_bgp_peers",
    "parse_cdp_neighbors",
    "parse_device_facts",
    "parse_ha_status",
    "parse_interfaces",
    "parse_lldp_neighbors",
    "parse_ospf_neighbors",
    "parse_routes",
    "parse_snmp_device_facts",
]

PLATFORM = "cisco_nxos"
"""ntc-templates platform key (must match the template index)."""

# System-MIB OIDs queried by SNMP discovery (RFC 1213 / SNMPv2-MIB).
SNMP_OID_SYSDESCR = "1.3.6.1.2.1.1.1.0"
SNMP_OID_SYSOBJECTID = "1.3.6.1.2.1.1.2.0"
SNMP_OID_SYSNAME = "1.3.6.1.2.1.1.5.0"

# Sentinel patterns that indicate a feature-gated command was run without the
# feature enabled (ADR-0025 §4). These normalize to [] rather than PluginError.
_FEATURE_DISABLED_RE = re.compile(
    r"(?i)(?:feature\s+not\s+enabled|invalid\s+command|"
    r"this\s+command\s+requires\s+the\s+\w+\s+feature|"
    r"error:\s*this\s+command\s+requires)"
)

#: ``sysDescr`` patterns for best-effort fact extraction (SNMP discovery).
_SYSDESCR_VERSION_RE = re.compile(r"Version\s+([^,\s]+)", re.IGNORECASE)
_SYSDESCR_MODEL_RE = re.compile(r"cisco\s+Nexus[^\s]*\s+(\S+)", re.IGNORECASE)

#: NX-OS route protocol codes → unified protocol.
_ROUTE_PROTOCOLS: dict[str, RouteProtocol] = {
    "direct": RouteProtocol.CONNECTED,
    "local": RouteProtocol.LOCAL,
    "static": RouteProtocol.STATIC,
    "rip": RouteProtocol.RIP,
    "ospf": RouteProtocol.OSPF,
    "ospf-1": RouteProtocol.OSPF,
    "eigrp": RouteProtocol.EIGRP,
    "bgp": RouteProtocol.BGP,
    "bgp-65001": RouteProtocol.BGP,
    "isis": RouteProtocol.ISIS,
}

#: NX-OS BGP State/PfxRcd column → BGP FSM state (same semantics as IOS).
_BGP_STATES: dict[str, BgpPeerState] = {
    "idle": BgpPeerState.IDLE,
    "idle(admin)": BgpPeerState.IDLE,
    "connect": BgpPeerState.CONNECT,
    "active": BgpPeerState.ACTIVE,
    "opensent": BgpPeerState.OPEN_SENT,
    "openconfirm": BgpPeerState.OPEN_CONFIRM,
    "established": BgpPeerState.ESTABLISHED,
}

#: NX-OS OSPF State column (role suffix stripped) → OSPF FSM state.
_OSPF_STATES: dict[str, OspfNeighborState] = {
    "down": OspfNeighborState.DOWN,
    "attempt": OspfNeighborState.ATTEMPT,
    "init": OspfNeighborState.INIT,
    "2way": OspfNeighborState.TWO_WAY,
    "exstart": OspfNeighborState.EXSTART,
    "exchange": OspfNeighborState.EXCHANGE,
    "loading": OspfNeighborState.LOADING,
    "full": OspfNeighborState.FULL,
}

# vPC domain-level state keys from ``show vpc | json`` (ADR-0025 §3, §8).
# vPC is the one P1 command that uses the ``| json`` escape hatch because its
# state spans interleaved sections with release-varying indentation that the
# ntc-templates NX-OS templates do not cover; we read structured JSON instead.
_VPC_KEY_DOMAIN_ID = "vpc-domain-id"
_VPC_KEY_KEEPALIVE = "vpc-peer-keepalive-status"
_VPC_KEY_CONSISTENCY = "vpc-peer-consistency"
_VPC_KEY_ROLE = "vpc-role"
_VPC_KEY_PEERLINK_TABLE = "TABLE_peerlink"
_VPC_KEY_PEERLINK_ROW = "ROW_peerlink"
_VPC_KEY_PEERLINK_PORT_STATE = "peer-link-port-state"


def _is_feature_disabled(output: str) -> bool:
    """Return True if *output* signals a feature-gated NX-OS command ran without the feature."""
    return bool(_FEATURE_DISABLED_RE.search(output)) or not output.strip()


def _parse_with_template(command: str, raw_output: str) -> list[dict[str, str]]:
    """Run *raw_output* through the ntc-templates index for *command*."""
    try:
        rows = parse_output(platform=PLATFORM, command=command, data=raw_output)
    except ParsingException as exc:
        raise PluginError(f"cisco_nxos: failed to parse output of {command!r}: {exc}") from exc
    return cast("list[dict[str, str]]", rows)


def _int_or_none(value: str) -> int | None:
    """Coerce a TextFSM field to ``int``; empty/garbage become ``None``."""
    value = value.strip()
    if not value:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def _address_or_none(value: str) -> IPv4Address | IPv6Address | None:
    """Coerce a TextFSM field to an IP address; empty/garbage become ``None``."""
    value = value.strip()
    if not value:
        return None
    try:
        return ip_address(value)
    except ValueError:
        return None


def _statuses(
    link_status: str, admin_state: str
) -> tuple[InterfaceAdminStatus, InterfaceOperStatus]:
    """Map NX-OS link_status/admin_state fields to admin/oper statuses.

    NX-OS ``show interface`` emits ``INTERFACE is <link_status>`` on the first
    line and ``admin state is <admin_state>`` on the second.  ``link_status``
    is the operational (line-protocol) state; ``admin_state`` drives whether
    the interface is administratively up.
    """
    link_lower = link_status.lower().strip()
    admin_lower = admin_state.lower().strip()

    # Admin status: if admin_state says "down" the port is shut.
    admin = InterfaceAdminStatus.DOWN if "down" in admin_lower else InterfaceAdminStatus.UP
    # Oper status: driven by link_status (the "is <state>" field from the show).
    if "up" in link_lower:
        oper = InterfaceOperStatus.UP
    elif "down" in link_lower:
        oper = InterfaceOperStatus.DOWN
    else:
        oper = InterfaceOperStatus.UNKNOWN
    return admin, oper


def _speed_mbps(speed: str, bandwidth: str) -> int | None:
    """Derive Mb/s from the NX-OS ``speed`` field or ``BW ... Kbit``."""
    speed = speed.strip()
    # NX-OS speed: "10 Gb/s", "1000 Mb/s", "100 Mb/s", "auto"
    m = re.search(r"(\d+)\s*(Gb|Mb)/s", speed, re.IGNORECASE)
    if m:
        value = int(m.group(1))
        return value * 1000 if m.group(2).lower() == "gb" else value
    # Fallback: BW field "10000000 Kbit"
    bw_m = re.search(r"(\d+)\s*Kbit", bandwidth, re.IGNORECASE)
    if bw_m:
        return int(bw_m.group(1)) // 1000
    return None


def _duplex(value: str) -> InterfaceDuplex | None:
    """Map NX-OS duplex strings."""
    lowered = value.lower()
    if "full" in lowered:
        return InterfaceDuplex.FULL
    if "half" in lowered:
        return InterfaceDuplex.HALF
    if "auto" in lowered:
        return InterfaceDuplex.AUTO
    return None


def _capability_tokens(value: str) -> tuple[str, ...]:
    """Split CDP/LLDP capability strings (``Router Switch IGMP``, ``B,R``)."""
    return tuple(token for token in re.split(r"[,\s]+", value.strip()) if token)


def _route_protocol(raw: str) -> RouteProtocol:
    """Map NX-OS route protocol label to :class:`RouteProtocol`.

    NX-OS uses strings like ``direct``, ``local``, ``static``, ``ospf-1``,
    ``bgp-65001``, etc. Strip numeric suffixes for lookup; fall back to OTHER.
    """
    key = raw.strip().lower()
    if key in _ROUTE_PROTOCOLS:
        return _ROUTE_PROTOCOLS[key]
    # Strip numeric suffix: "ospf-1" → "ospf", "bgp-65001" → "bgp"
    base = re.sub(r"[-_]\d+$", "", key)
    return _ROUTE_PROTOCOLS.get(base, RouteProtocol.OTHER)


def parse_device_facts(raw_output: str) -> DeviceFacts:
    """Parse ``show version`` output into :class:`DeviceFacts`.

    NX-OS ``show version`` has different field names from IOS. The ntc-templates
    NX-OS template provides: ``hostname``, ``os``, ``platform``, ``serial``.
    """
    rows = _parse_with_template("show version", raw_output)
    if not rows:
        raise PluginError(
            "cisco_nxos: 'show version' output did not match the ntc-templates template "
            "(no rows parsed)"
        )
    row = cast("dict[str, object]", rows[0])
    hostname = str(row.get("hostname") or "").strip()
    os_version = str(row.get("os") or "").strip() or None
    model = str(row.get("platform") or "").strip() or None
    serial = str(row.get("serial") or "").strip() or None
    try:
        return DeviceFacts(
            hostname=hostname,
            vendor_id=PLATFORM,
            model=model,
            os_version=os_version,
            serial=serial,
        )
    except ValidationError as exc:
        raise PluginError(f"cisco_nxos: invalid 'show version' row: {exc}") from exc


def parse_snmp_device_facts(values: Mapping[str, str]) -> DeviceFacts:
    """Map system-MIB GET *values* (``{dotted_oid: pretty_value}``) to facts.

    Uses the same system MIB OIDs as ``cisco_ios`` (RFC 1213 / SNMPv2-MIB);
    the NX-OS sysDescr format differs so we use NX-OS-specific regexes.
    """
    hostname = values.get(SNMP_OID_SYSNAME, "").strip()
    if not hostname:
        raise PluginError(
            f"cisco_nxos: SNMP discovery returned no sysName ({SNMP_OID_SYSNAME}) — "
            "cannot establish device identity"
        )
    sysdescr = values.get(SNMP_OID_SYSDESCR, "")
    version_match = _SYSDESCR_VERSION_RE.search(sysdescr)
    model_match = _SYSDESCR_MODEL_RE.search(sysdescr)
    return DeviceFacts(
        hostname=hostname,
        vendor_id=PLATFORM,
        model=model_match.group(1) if model_match else None,
        os_version=version_match.group(1) if version_match else None,
        serial=None,
    )


def parse_interfaces(
    raw_output: str, *, device_id: UUID, collected_at: datetime
) -> list[NormalizedInterface]:
    """Parse ``show interface`` output into :class:`NormalizedInterface` records.

    NX-OS template field names differ from IOS: ``link_status`` / ``admin_state``
    instead of ``link_status`` / ``protocol_status``.
    """
    rows = _parse_with_template("show interface", raw_output)
    try:
        return [
            NormalizedInterface(
                device_id=device_id,
                collected_at=collected_at,
                source_vendor=PLATFORM,
                name=row["interface"],
                description=row["description"] or None,
                admin_status=_statuses(row["link_status"], row["admin_state"])[0],
                oper_status=_statuses(row["link_status"], row["admin_state"])[1],
                mac_address=row["mac_address"] or None,
                ip_address=(
                    ip_interface(f"{row['ip_address']}/{row['prefix_length']}")
                    if row["ip_address"] and row["prefix_length"]
                    else None
                ),
                mtu=_int_or_none(row["mtu"]),
                speed_mbps=_speed_mbps(row["speed"], row["bandwidth"]),
                duplex=_duplex(row["duplex"]),
                vlan_id=_int_or_none(row["vlan_id"]),
                input_errors=_int_or_none(row["input_errors"]),
                output_errors=_int_or_none(row["output_errors"]),
            )
            for row in rows
            if row["interface"]
        ]
    except (KeyError, ValueError, ValidationError) as exc:
        raise PluginError(f"cisco_nxos: invalid 'show interface' row: {exc}") from exc


def parse_routes(
    raw_output: str, *, device_id: UUID, collected_at: datetime
) -> list[NormalizedRoute]:
    """Parse ``show ip route vrf all`` output into :class:`NormalizedRoute` records.

    The NX-OS template has a Filldown ``vrf`` field populated from the
    ``IP Route Table for VRF "..."`` section headers (ADR-0025 §3).
    """
    rows = _parse_with_template("show ip route", raw_output)
    results: list[NormalizedRoute] = []
    try:
        for row in rows:
            network = row.get("network", "").strip()
            prefix_length = row.get("prefix_length", "").strip()
            if not network or not prefix_length:
                continue
            vrf = row.get("vrf", "").strip() or None
            protocol_raw = row.get("protocol", "").strip()
            results.append(
                NormalizedRoute(
                    device_id=device_id,
                    collected_at=collected_at,
                    source_vendor=PLATFORM,
                    destination=ip_network(f"{network}/{prefix_length}"),
                    protocol=_route_protocol(protocol_raw),
                    next_hop=_address_or_none(row.get("nexthop_ip", "")),
                    interface=row.get("nexthop_if", "").strip() or None,
                    vrf=vrf,
                    distance=_int_or_none(row.get("distance", "")),
                    metric=_int_or_none(row.get("metric", "")),
                )
            )
    except (KeyError, ValueError, ValidationError) as exc:
        raise PluginError(f"cisco_nxos: invalid 'show ip route vrf all' row: {exc}") from exc
    return results


def parse_cdp_neighbors(
    raw_output: str, *, device_id: UUID, collected_at: datetime
) -> list[NormalizedNeighbor]:
    """Parse ``show cdp neighbors detail`` output into :class:`NormalizedNeighbor` records.

    The NX-OS cdp neighbors detail template field names differ slightly from IOS.
    ``chassis_id`` is the Device ID (used as neighbor_name when ``neighbor_name``
    is absent); ``interface_ip`` is the peer interface address; ``mgmt_address``
    is the management address.
    """
    rows = _parse_with_template("show cdp neighbors detail", raw_output)
    try:
        return [
            NormalizedNeighbor(
                device_id=device_id,
                collected_at=collected_at,
                source_vendor=PLATFORM,
                protocol=NeighborProtocol.CDP,
                # NX-OS template: local_interface may be empty if captured before
                # the Version block; use chassis_id as a fallback neighbor identifier.
                local_interface=row["local_interface"] or row["chassis_id"] or "unknown",
                neighbor_name=row["neighbor_name"] or row["chassis_id"],
                neighbor_interface=row["neighbor_interface"] or None,
                neighbor_platform=row["platform"] or None,
                # Prefer the management address; fall back to interface IP.
                neighbor_address=_address_or_none(row["mgmt_address"])
                or _address_or_none(row["interface_ip"]),
                neighbor_capabilities=_capability_tokens(row["capabilities"]),
            )
            for row in rows
            if (row["chassis_id"] or row["neighbor_name"])
        ]
    except (KeyError, ValueError, ValidationError) as exc:
        raise PluginError(f"cisco_nxos: invalid 'show cdp neighbors detail' row: {exc}") from exc


def parse_lldp_neighbors(
    raw_output: str, *, device_id: UUID, collected_at: datetime
) -> list[NormalizedNeighbor]:
    """Parse ``show lldp neighbors detail`` output into :class:`NormalizedNeighbor` records.

    Feature-gated (``feature lldp``): empty / "feature disabled" output
    returns ``[]`` per ADR-0025 §4.
    """
    if _is_feature_disabled(raw_output):
        return []
    rows = _parse_with_template("show lldp neighbors detail", raw_output)
    try:
        return [
            NormalizedNeighbor(
                device_id=device_id,
                collected_at=collected_at,
                source_vendor=PLATFORM,
                protocol=NeighborProtocol.LLDP,
                local_interface=row["local_interface"],
                neighbor_name=row["neighbor_name"],
                neighbor_interface=row["neighbor_interface"] or None,
                neighbor_platform=row["neighbor_description"] or None,
                neighbor_address=_address_or_none(row["mgmt_address"]),
                neighbor_capabilities=_capability_tokens(row["capabilities"]),
            )
            for row in rows
            if row["neighbor_name"] and row["local_interface"]
        ]
    except (KeyError, ValueError, ValidationError) as exc:
        raise PluginError(f"cisco_nxos: invalid 'show lldp neighbors detail' row: {exc}") from exc


def parse_bgp_peers(
    raw_output: str, *, device_id: UUID, collected_at: datetime
) -> list[NormalizedBgpPeer]:
    """Parse ``show ip bgp summary vrf all`` into :class:`NormalizedBgpPeer` records.

    Feature-gated (``feature bgp``): empty / "feature disabled" output
    returns ``[]`` per ADR-0025 §4.

    The ``show ip bgp summary vrf`` template has a Filldown ``vrf`` field
    populated from the VRF section headers, carrying each peer's VRF into the
    normalized record (ADR-0025 §3).
    """
    if _is_feature_disabled(raw_output):
        return []
    # Use the multi-VRF template key (ADR-0025 §1 table: "show ip bgp summary vrf all")
    rows = _parse_with_template("show ip bgp summary vrf", raw_output)
    peers: list[NormalizedBgpPeer] = []
    try:
        for row in rows:
            neighbor = row.get("bgp_neigh", "").strip()
            if not neighbor:
                continue
            state_or_pfx = row.get("state_pfxrcd", "").strip()
            prefixes = _int_or_none(state_or_pfx)
            if prefixes is not None:
                state = BgpPeerState.ESTABLISHED
            else:
                state = _BGP_STATES.get(state_or_pfx.lower().replace(" ", ""), BgpPeerState.IDLE)
            vrf = row.get("vrf", "").strip() or None
            local_as = _int_or_none(row.get("local_as", ""))
            peers.append(
                NormalizedBgpPeer(
                    device_id=device_id,
                    collected_at=collected_at,
                    source_vendor=PLATFORM,
                    peer_address=ip_address(neighbor),
                    remote_as=int(row.get("neigh_as", "0").strip()),
                    local_as=local_as,
                    state=state,
                    prefixes_received=prefixes,
                    vrf=vrf,
                    address_family=row.get("address_family", "").strip() or None,
                )
            )
    except (KeyError, ValueError, ValidationError) as exc:
        raise PluginError(f"cisco_nxos: invalid 'show ip bgp summary vrf all' row: {exc}") from exc
    return peers


def parse_ospf_neighbors(
    raw_output: str, *, device_id: UUID, collected_at: datetime
) -> list[NormalizedOspfNeighbor]:
    """Parse ``show ip ospf neighbor vrf all`` into :class:`NormalizedOspfNeighbor` records.

    Feature-gated (``feature ospf``): empty / "feature disabled" output
    returns ``[]`` per ADR-0025 §4. The template has a Filldown ``vrf`` field
    populated from the "OSPF Process ID N VRF <vrf>" section header; this
    carries the VRF into the normalized record's ``vrf`` field (ADR-0025 §6).
    """
    if _is_feature_disabled(raw_output):
        return []
    rows = _parse_with_template("show ip ospf neighbor", raw_output)
    try:
        return [
            NormalizedOspfNeighbor(
                device_id=device_id,
                collected_at=collected_at,
                source_vendor=PLATFORM,
                neighbor_id=IPv4Address(row["neighbor_id"].strip()),
                interface=row["interface"],
                state=_OSPF_STATES.get(
                    row["state"].split("/")[0].strip().lower(), OspfNeighborState.DOWN
                ),
                neighbor_address=_address_or_none(row.get("ip_address", "")),
                vrf=row.get("vrf", "").strip() or None,
            )
            for row in rows
            if row.get("neighbor_id", "").strip()
        ]
    except (KeyError, ValueError, ValidationError) as exc:
        raise PluginError(
            f"cisco_nxos: invalid 'show ip ospf neighbor vrf all' row: {exc}"
        ) from exc


def parse_acls(
    raw_output: str, *, device_id: UUID, collected_at: datetime
) -> list[NormalizedAclEntry]:
    """Parse ``show ip access-lists`` (NX-OS: ``show access-lists``) output.

    The NX-OS ntc-templates template command key is ``show access-lists``
    (without the ``ip``). The field names are: ``name``, ``sn``, ``action``,
    ``protocol``, ``source``, ``destination``, ``port``, ``modifier``.
    NX-OS ACL entries use CIDR notation (e.g. ``192.0.2.0/24``), not
    wildcard masks.
    """
    rows = _parse_with_template("show access-lists", raw_output)
    entries: list[NormalizedAclEntry] = []
    try:
        for row in rows:
            action = row["action"].strip().lower()
            if not action or not row["sn"].strip():
                continue
            if row.get("remark", "").strip():
                continue  # Skip remark entries (not ACEs)
            entries.append(
                NormalizedAclEntry(
                    device_id=device_id,
                    collected_at=collected_at,
                    source_vendor=PLATFORM,
                    acl_name=row["name"],
                    action=AclAction(action),
                    protocol=row["protocol"].strip() or "ip",
                    sequence=_int_or_none(row["sn"]),
                    source=_nxos_acl_endpoint(row["source"]),
                    source_is_any=_nxos_is_any(row["source"]),
                    source_port=row.get("port", "").strip() or None,
                    destination=_nxos_acl_endpoint(row["destination"]),
                    destination_is_any=_nxos_is_any(row["destination"]),
                    destination_port=_nxos_acl_dest_port(row),
                )
            )
    except (KeyError, ValueError, ValidationError) as exc:
        raise PluginError(f"cisco_nxos: invalid 'show access-lists' row: {exc}") from exc
    return entries


def _nxos_is_any(value: str) -> bool:
    """``True`` only for the literal ``any`` token, never for a collapsed group.

    Both ``any`` and an ``addrgroup`` reference resolve to ``source``/``destination``
    of ``None`` (see :func:`_nxos_acl_endpoint`); this flag carries the bit that
    disambiguates a genuine *any* from an unresolved object-group.
    """
    return value.strip().lower() == "any"


def _nxos_acl_endpoint(value: str) -> IPv4Network | None:
    """Resolve an NX-OS ACE source/destination to a network (``None`` means *any*).

    NX-OS uses CIDR notation (``192.0.2.0/24``) or ``any``, unlike IOS which
    uses network + wildcard mask. An ``addrgroup`` reference normalizes to None
    (group membership is not resolved at parse time).
    """
    value = value.strip()
    if not value or value.lower() == "any" or value.lower().startswith("addrgroup"):
        return None
    try:
        return IPv4Network(value, strict=False)
    except ValueError:
        # May be a bare host address like "192.0.2.1"
        try:
            return IPv4Network(f"{value}/32", strict=False)
        except ValueError:
            return None


def _nxos_acl_dest_port(row: dict[str, str]) -> str | None:
    """Assemble destination port from modifier field (NX-OS ACL format).

    NX-OS ACL ``modifier`` field catches the port clause (``eq 22``) when it
    follows the destination address. The ``port`` field catches source-port
    clauses.
    """
    modifier = row.get("modifier", "").strip()
    # Only treat modifier as destination port if it starts with a port operator.
    port_ops = ("eq ", "gt ", "lt ", "neq ", "range ")
    for op in port_ops:
        if modifier.lower().startswith(op):
            return modifier
    return None


def _vpc_peer_link_state(document: Mapping[str, object]) -> HaPeerLinkState:
    """Map the ``TABLE_peerlink`` row's port state to a peer-link state.

    NX-OS ``show vpc | json`` reports the peer-link state as a numeric flag
    (``"1"`` = up) under ``TABLE_peerlink``/``ROW_peerlink``. The row may be a
    single object or a list (release-varying); the first row is authoritative.
    """
    table = document.get(_VPC_KEY_PEERLINK_TABLE)
    if not isinstance(table, Mapping):
        return HaPeerLinkState.UNKNOWN
    row = table.get(_VPC_KEY_PEERLINK_ROW)
    if isinstance(row, list):
        row = row[0] if row else None
    if not isinstance(row, Mapping):
        return HaPeerLinkState.UNKNOWN
    state = str(row.get(_VPC_KEY_PEERLINK_PORT_STATE, "")).strip().lower()
    if state in {"1", "up"}:
        return HaPeerLinkState.UP
    if state in {"0", "2", "down"}:
        return HaPeerLinkState.DOWN
    return HaPeerLinkState.UNKNOWN


def parse_ha_status(
    raw_output: str, *, device_id: UUID, collected_at: datetime
) -> list[NormalizedHaStatus]:
    """Parse ``show vpc | json`` output into :class:`NormalizedHaStatus` records.

    Decodes the structured JSON document emitted by ``show vpc | json``. Per
    ADR-0025 §3/§8, ``show vpc`` is the one P1 command that uses the ``| json``
    escape hatch because vPC state spans interleaved sections with
    release-varying indentation the ntc-templates NX-OS templates do not cover.
    Returns an empty list when vPC is not configured / the feature is disabled
    (empty, sentinel, or non-JSON output with no domain id).
    """
    if _is_feature_disabled(raw_output):
        return []

    try:
        document = json.loads(raw_output)
    except json.JSONDecodeError:
        # vPC-not-configured / feature-disabled banners are plain text, not JSON.
        return []
    if not isinstance(document, Mapping):
        return []

    domain_id = str(document.get(_VPC_KEY_DOMAIN_ID, "")).strip()
    if not domain_id:
        return []

    # Keepalive state (``vpc-peer-keepalive-status``: e.g. "peer-alive").
    keepalive_state = HaPeerLinkState.UNKNOWN
    keepalive_text = str(document.get(_VPC_KEY_KEEPALIVE, "")).strip().lower()
    if "alive" in keepalive_text:
        keepalive_state = HaPeerLinkState.UP
    elif any(token in keepalive_text for token in ("down", "failed", "suspended")):
        keepalive_state = HaPeerLinkState.DOWN

    # Role (``vpc-role``: "primary" / "secondary" / "primary, operational secondary").
    peer_role = HaPeerRole.UNKNOWN
    role_text = str(document.get(_VPC_KEY_ROLE, "")).strip().lower()
    if "secondary" in role_text:
        peer_role = HaPeerRole.SECONDARY
    elif "primary" in role_text:
        peer_role = HaPeerRole.PRIMARY

    # Consistency (``vpc-peer-consistency``: "consistent" / "inconsistent").
    consistency_ok: bool | None = None
    consistency_text = str(document.get(_VPC_KEY_CONSISTENCY, "")).strip().lower()
    if consistency_text:
        consistency_ok = consistency_text == "consistent"

    peer_link_state = _vpc_peer_link_state(document)

    try:
        return [
            NormalizedHaStatus(
                device_id=device_id,
                collected_at=collected_at,
                source_vendor=PLATFORM,
                ha_domain=domain_id,
                peer_role=peer_role,
                peer_link_state=peer_link_state,
                keepalive_state=keepalive_state,
                consistency_check_ok=consistency_ok,
            )
        ]
    except ValidationError as exc:
        raise PluginError(f"cisco_nxos: invalid 'show vpc | json' HA status: {exc}") from exc
