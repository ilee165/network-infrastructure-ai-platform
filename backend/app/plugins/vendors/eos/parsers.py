"""Arista EOS show-output parsers: ntc-templates/TextFSM → normalized models.

Single source of parsing for the ``eos`` plugin (REPO-STRUCTURE §6 step 7).
Each function takes verbatim show-output text — already preserved as
:class:`~app.plugins.base.RawOutput` by the capability layer — and returns
normalized Pydantic models.  Template lookups use the real ntc-templates index
with platform key ``"arista_eos"`` (ADR-0007); parse and validation failures
raise :class:`~app.core.errors.PluginError`.

EOS-specific field notes
------------------------
- ``show version``:   MODEL, IMAGE (software version), SERIAL_NUMBER.
- ``show interfaces``:  IP_ADDRESS is ``<addr>/<prefix>``; BANDWIDTH is
  ``<n> kbit``; LINK_STATUS ``adminDown`` signals admin-down.
- ``show ip route``:  PROTOCOL is multi-token for eBGP (``"B E"``); NEXT_HOP
  and INTERFACE are list-valued (take first element); ``connected`` next-hop
  means no gateway.
- ``show lldp neighbors detail``: LOCAL_INTERFACE / NEIGHBOR_NAME /
  NEIGHBOR_INTERFACE / MGMT_ADDRESS / NEIGHBOR_DESCRIPTION.
- ``show ip bgp summary``: EOS template exposes separate ``state`` and
  ``state_pfxrcd`` columns (unlike IOS where the column is overloaded).
  ``state_pfxrcd`` is populated only for ESTABLISHED sessions.
- ``show ip ospf neighbor``: EOS ``state`` column has no ``/DR``-role suffix;
  state token may be uppercase (``FULL``, ``2WAY``, …).
- ``show ip access-lists``: EOS uses CIDR notation (``10.1.1.0/24``) for
  network prefixes; ``host <ip>`` for host entries; the ``modifier`` field
  carries the destination port match (e.g. ``eq telnet``).
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from datetime import datetime
from ipaddress import IPv4Address, IPv4Network, IPv6Address, ip_address, ip_interface, ip_network
from typing import cast
from uuid import UUID

from ntc_templates.parse import ParsingException, parse_output
from pydantic import ValidationError
from textfsm.parser import TextFSMError

from app.core.errors import PluginError
from app.schemas.discovery import DeviceFacts
from app.schemas.normalized import (
    AclAction,
    BgpPeerState,
    InterfaceAdminStatus,
    InterfaceOperStatus,
    NeighborProtocol,
    NormalizedAclEntry,
    NormalizedBgpPeer,
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
    "parse_device_facts",
    "parse_interfaces",
    "parse_lldp_neighbors",
    "parse_ospf_neighbors",
    "parse_routes",
    "parse_snmp_device_facts",
]

PLATFORM = "arista_eos"
"""ntc-templates platform key (must match the template index)."""

# System-MIB OIDs queried by SNMP discovery (RFC 1213 / SNMPv2-MIB).
SNMP_OID_SYSDESCR = "1.3.6.1.2.1.1.1.0"
SNMP_OID_SYSOBJECTID = "1.3.6.1.2.1.1.2.0"
SNMP_OID_SYSNAME = "1.3.6.1.2.1.1.5.0"

#: ``sysDescr`` pattern: "Arista Networks EOS version <ver> running on …"
_SYSDESCR_VERSION_RE = re.compile(r"EOS\s+version\s+(\S+)", re.IGNORECASE)

#: BANDWIDTH field: "<n> kbit" → Mb/s
_BW_KBIT_RE = re.compile(r"(\d+)\s*kbit", re.IGNORECASE)

#: EOS route protocol column → unified protocol.
_ROUTE_PROTOCOLS: dict[str, RouteProtocol] = {
    "C": RouteProtocol.CONNECTED,
    "S": RouteProtocol.STATIC,
    "K": RouteProtocol.OTHER,
    "O": RouteProtocol.OSPF,
    "B": RouteProtocol.BGP,
    "B E": RouteProtocol.BGP,
    "B I": RouteProtocol.BGP,
    "R": RouteProtocol.RIP,
    "I L1": RouteProtocol.ISIS,
    "I L2": RouteProtocol.ISIS,
}

#: EOS ``show ip bgp summary`` ``state`` column → BGP FSM state.
#: Unlike IOS, EOS uses separate ``state`` and ``state_pfxrcd`` columns;
#: ``state_pfxrcd`` is populated (non-empty) only when the session is
#: ESTABLISHED.  We detect ESTABLISHED by checking ``state_pfxrcd`` first.
_BGP_STATES: dict[str, BgpPeerState] = {
    "idle": BgpPeerState.IDLE,
    "connect": BgpPeerState.CONNECT,
    "active": BgpPeerState.ACTIVE,
    "opensent": BgpPeerState.OPEN_SENT,
    "openconfirm": BgpPeerState.OPEN_CONFIRM,
    "established": BgpPeerState.ESTABLISHED,
}

#: EOS ``show ip ospf neighbor`` ``state`` column → OSPF FSM state.
#: EOS emits plain state tokens in uppercase without a ``/DR``-role suffix.
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


def _parse_with_template(command: str, raw_output: str) -> list[dict[str, object]]:
    """Run *raw_output* through the ntc-templates index for *command*.

    Catches both :class:`~ntc_templates.parse.ParsingException` (index miss)
    and :class:`~textfsm.parser.TextFSMError` (template state error — EOS
    templates use ``Error`` transitions on unrecognized input).
    """
    try:
        rows = parse_output(platform=PLATFORM, command=command, data=raw_output)
    except (ParsingException, TextFSMError) as exc:
        raise PluginError(f"eos: failed to parse output of {command!r}: {exc}") from exc
    return cast("list[dict[str, object]]", rows)


def _int_or_none(value: object) -> int | None:
    """Coerce a TextFSM field to ``int``; empty/garbage fields become ``None``."""
    text = str(value).strip() if value is not None else ""
    if not text:
        return None
    try:
        return int(text)
    except ValueError:
        return None


def _address_or_none(value: object) -> IPv4Address | IPv6Address | None:
    """Coerce a TextFSM field to an IP address; empty/garbage become ``None``."""
    text = str(value).strip() if value is not None else ""
    if not text:
        return None
    try:
        return ip_address(text)
    except ValueError:
        return None


def _statuses(link_status: str) -> tuple[InterfaceAdminStatus, InterfaceOperStatus]:
    """Map EOS link_status token to admin/oper statuses.

    EOS ``link_status`` is the first token of the ``<iface> is <status>``
    line.  ``adminDown`` means the operator shut the port; ``up``/``down``
    reflect physical/protocol state.
    """
    lower = link_status.lower()
    if lower == "admindown":
        return InterfaceAdminStatus.DOWN, InterfaceOperStatus.DOWN
    admin = InterfaceAdminStatus.UP
    oper = InterfaceOperStatus.UP if lower == "up" else InterfaceOperStatus.DOWN
    return admin, oper


def _speed_mbps_from_bandwidth(bandwidth: str) -> int | None:
    """Derive Mb/s from the EOS ``BW <n> kbit`` bandwidth field."""
    match = _BW_KBIT_RE.search(bandwidth)
    if match:
        kbits = int(match.group(1))
        return kbits // 1000 if kbits >= 1000 else None
    return None


def _first_list(value: object) -> str:
    """Return the first element when TextFSM emits a list-valued field."""
    if isinstance(value, list):
        return str(value[0]) if value else ""
    return str(value)


def parse_device_facts(raw_output: str) -> DeviceFacts:
    """Parse ``show version`` output into :class:`DeviceFacts`.

    EOS ``show version`` does not contain the configured hostname; the
    discovery engine should call SNMP or ``show hostname`` to resolve it.
    This function uses the serial number as a best-effort ``hostname``
    placeholder so the mandatory ``DeviceFacts.hostname`` field is non-empty.
    If the serial is also absent (cEOS labs, etc.) the system MAC serves as
    the fallback.
    """
    rows = _parse_with_template("show version", raw_output)
    if not rows:
        raise PluginError(
            "eos: 'show version' output did not match the ntc-templates template (no rows parsed)"
        )
    row = rows[0]
    serial = str(row.get("serial_number") or "").strip()
    sys_mac = str(row.get("sys_mac") or "").strip()
    # Use serial > sys_mac > model as hostname placeholder; at least one must exist.
    hostname_placeholder = serial or sys_mac or str(row.get("model") or "").strip()
    if not hostname_placeholder:
        raise PluginError(
            "eos: 'show version' row lacks serial, sys_mac, and model — "
            "cannot derive a hostname placeholder"
        )
    try:
        return DeviceFacts(
            hostname=hostname_placeholder,
            vendor_id=PLATFORM,
            model=str(row.get("model") or "").strip() or None,
            os_version=str(row.get("image") or "").strip() or None,
            serial=serial or None,
        )
    except ValidationError as exc:
        raise PluginError(f"eos: invalid 'show version' row: {exc}") from exc


def parse_snmp_device_facts(values: Mapping[str, str]) -> DeviceFacts:
    """Map system-MIB GET *values* (``{dotted_oid: pretty_value}``) to facts.

    ``sysName`` is required (it becomes ``hostname``); ``os_version`` is
    best-effort from ``sysDescr`` ("EOS version <ver>"); ``serial`` is not
    exposed by the system MIB.
    """
    hostname = values.get(SNMP_OID_SYSNAME, "").strip()
    if not hostname:
        raise PluginError(
            f"eos: SNMP discovery returned no sysName ({SNMP_OID_SYSNAME}) — "
            "cannot establish device identity"
        )
    sysdescr = values.get(SNMP_OID_SYSDESCR, "")
    version_match = _SYSDESCR_VERSION_RE.search(sysdescr)
    return DeviceFacts(
        hostname=hostname,
        vendor_id=PLATFORM,
        model=None,
        os_version=version_match.group(1) if version_match else None,
        serial=None,
    )


def parse_interfaces(
    raw_output: str, *, device_id: UUID, collected_at: datetime
) -> list[NormalizedInterface]:
    """Parse ``show interfaces`` output into :class:`NormalizedInterface` records.

    EOS-specific mappings:
    - ``ip_address`` field is already ``<addr>/<prefix>`` — parse via
      ``ip_interface`` directly.
    - ``bandwidth`` is ``<n> kbit`` — convert to Mb/s.
    - No duplex field in this template (not captured); ``duplex`` is ``None``.
    - ``mac_address`` is in EOS dot-notation (``001c.7300.1234``);
      ``normalize_mac`` handles it.
    """
    rows = _parse_with_template("show interfaces", raw_output)
    try:
        result: list[NormalizedInterface] = []
        for row in rows:
            admin_status, oper_status = _statuses(str(row.get("link_status", "")))
            ip_str = str(row.get("ip_address") or "").strip()
            ip_iface = ip_interface(ip_str) if ip_str else None
            result.append(
                NormalizedInterface(
                    device_id=device_id,
                    collected_at=collected_at,
                    source_vendor=PLATFORM,
                    name=str(row["interface"]),
                    description=str(row.get("description") or "").strip() or None,
                    admin_status=admin_status,
                    oper_status=oper_status,
                    mac_address=str(row.get("mac_address") or "").strip() or None,
                    ip_address=ip_iface,
                    mtu=_int_or_none(row.get("mtu")),
                    speed_mbps=_speed_mbps_from_bandwidth(str(row.get("bandwidth") or "")),
                    duplex=None,
                    vlan_id=None,
                    input_errors=None,
                    output_errors=None,
                )
            )
        return result
    except (KeyError, ValueError, ValidationError) as exc:
        raise PluginError(f"eos: invalid 'show interfaces' row: {exc}") from exc


def parse_routes(
    raw_output: str, *, device_id: UUID, collected_at: datetime
) -> list[NormalizedRoute]:
    """Parse ``show ip route`` output into :class:`NormalizedRoute` records.

    EOS-specific:
    - ``protocol`` can be multi-token (``"B E"`` for eBGP) — look up full
      token before falling back to first character.
    - ``next_hop`` and ``interface`` are list-valued; take the first element.
    - ``"connected"`` next-hop → ``next_hop=None`` (directly connected route).
    """
    rows = _parse_with_template("show ip route", raw_output)
    try:
        result: list[NormalizedRoute] = []
        for row in rows:
            protocol_token = str(row.get("protocol", "")).strip()
            protocol = _ROUTE_PROTOCOLS.get(
                protocol_token,
                _ROUTE_PROTOCOLS.get(protocol_token.split()[0], RouteProtocol.OTHER),
            )
            next_hop_raw = _first_list(row.get("next_hop", "")).strip()
            next_hop = (
                _address_or_none(next_hop_raw)
                if next_hop_raw and next_hop_raw != "connected"
                else None
            )
            iface_raw = _first_list(row.get("interface", "")).strip()
            result.append(
                NormalizedRoute(
                    device_id=device_id,
                    collected_at=collected_at,
                    source_vendor=PLATFORM,
                    destination=ip_network(
                        f"{row['network']}/{row['prefix_length']}", strict=False
                    ),
                    protocol=protocol,
                    next_hop=next_hop,
                    interface=iface_raw or None,
                    vrf=str(row.get("vrf") or "").strip() or None,
                    distance=_int_or_none(row.get("distance")),
                    metric=_int_or_none(row.get("metric")),
                )
            )
        return result
    except (KeyError, ValueError, ValidationError) as exc:
        raise PluginError(f"eos: invalid 'show ip route' row: {exc}") from exc


def _hms_to_seconds(value: str) -> int | None:
    """Convert an EOS ``HH:MM:SS`` dead-time field to whole seconds."""
    value = value.strip()
    parts = value.split(":")
    if len(parts) != 3 or not all(part.isdigit() for part in parts):
        return None
    hours, minutes, seconds = (int(part) for part in parts)
    return hours * 3600 + minutes * 60 + seconds


def _eos_acl_endpoint(source: str) -> IPv4Network | None:
    """Resolve an EOS ACE source/destination to a network.

    EOS ``show ip access-lists`` emits three forms:
    - ``any``           → ``None`` (matches everything)
    - ``host <ip>``     → ``/32`` host network
    - ``<ip>/<prefix>`` → CIDR network

    EOS ACLs are IPv4-only at this capability tier, so we cast to IPv4Network.
    """
    src = source.strip()
    if not src or src == "any":
        return None
    if src.startswith("host "):
        host_ip = src[5:].strip()
        try:
            return cast("IPv4Network", ip_network(f"{host_ip}/32"))
        except (ValueError, OSError):
            return None
    try:
        return cast("IPv4Network", ip_network(src, strict=False))
    except (ValueError, OSError):
        return None


def parse_lldp_neighbors(
    raw_output: str, *, device_id: UUID, collected_at: datetime
) -> list[NormalizedNeighbor]:
    """Parse ``show lldp neighbors detail`` into :class:`NormalizedNeighbor` records.

    EOS-specific field mapping:
    - ``local_interface`` → :attr:`NormalizedNeighbor.local_interface`
    - ``neighbor_name`` → :attr:`NormalizedNeighbor.neighbor_name`
    - ``neighbor_interface`` → :attr:`NormalizedNeighbor.neighbor_interface`
    - ``neighbor_description`` → :attr:`NormalizedNeighbor.neighbor_platform`
    - ``mgmt_address`` → :attr:`NormalizedNeighbor.neighbor_address`
    """
    rows = _parse_with_template("show lldp neighbors detail", raw_output)
    try:
        return [
            NormalizedNeighbor(
                device_id=device_id,
                collected_at=collected_at,
                source_vendor=PLATFORM,
                protocol=NeighborProtocol.LLDP,
                local_interface=str(row["local_interface"]),
                neighbor_name=str(row["neighbor_name"]),
                neighbor_interface=str(row.get("neighbor_interface") or "").strip() or None,
                neighbor_platform=str(row.get("neighbor_description") or "").strip() or None,
                neighbor_address=_address_or_none(row.get("mgmt_address")),
                neighbor_capabilities=(),
            )
            for row in rows
        ]
    except (KeyError, ValueError, ValidationError) as exc:
        raise PluginError(f"eos: invalid 'show lldp neighbors detail' row: {exc}") from exc


def parse_bgp_peers(
    raw_output: str, *, device_id: UUID, collected_at: datetime
) -> list[NormalizedBgpPeer]:
    """Parse ``show ip bgp summary`` output into :class:`NormalizedBgpPeer` records.

    EOS-specific differences from IOS:
    - The template provides separate ``state`` and ``state_pfxrcd`` columns.
    - When ``state_pfxrcd`` is non-empty the session is ESTABLISHED and the
      value is the accepted-prefix count.
    - When ``state_pfxrcd`` is empty, ``state`` holds the FSM token
      (``Idle``, ``Active``, …) — look up case-insensitively.
    """
    rows = _parse_with_template("show ip bgp summary", raw_output)
    peers: list[NormalizedBgpPeer] = []
    try:
        for row in rows:
            pfxrcd = str(row.get("state_pfxrcd", "")).strip()
            prefixes = _int_or_none(pfxrcd)
            if prefixes is not None:
                state = BgpPeerState.ESTABLISHED
            else:
                state_token = str(row.get("state", "")).strip().lower()
                state = _BGP_STATES.get(state_token, BgpPeerState.IDLE)
            peers.append(
                NormalizedBgpPeer(
                    device_id=device_id,
                    collected_at=collected_at,
                    source_vendor=PLATFORM,
                    peer_address=ip_address(str(row["bgp_neigh"])),
                    remote_as=int(str(row["neigh_as"]).strip()),
                    local_as=_int_or_none(row.get("local_as")),
                    state=state,
                    prefixes_received=prefixes,
                )
            )
    except (KeyError, ValueError, ValidationError) as exc:
        raise PluginError(f"eos: invalid 'show ip bgp summary' row: {exc}") from exc
    return peers


def parse_ospf_neighbors(
    raw_output: str, *, device_id: UUID, collected_at: datetime
) -> list[NormalizedOspfNeighbor]:
    """Parse ``show ip ospf neighbor`` output into :class:`NormalizedOspfNeighbor` records.

    EOS-specific: the ``state`` column is plain uppercase (``FULL``, ``2WAY``,
    ``EXSTART``, …) with no ``/DR``-role suffix.  State tokens are matched
    case-insensitively against ``_OSPF_STATES``.
    """
    rows = _parse_with_template("show ip ospf neighbor", raw_output)
    try:
        return [
            NormalizedOspfNeighbor(
                device_id=device_id,
                collected_at=collected_at,
                source_vendor=PLATFORM,
                neighbor_id=IPv4Address(str(row["neighbor_id"]).strip()),
                interface=str(row["interface"]),
                state=_OSPF_STATES.get(str(row["state"]).strip().lower(), OspfNeighborState.DOWN),
                neighbor_address=_address_or_none(row.get("ip_address")),
                priority=_int_or_none(row.get("priority")),
                dead_time_seconds=_hms_to_seconds(str(row.get("dead_time", ""))),
            )
            for row in rows
        ]
    except (KeyError, ValueError, ValidationError) as exc:
        raise PluginError(f"eos: invalid 'show ip ospf neighbor' row: {exc}") from exc


def parse_acls(
    raw_output: str, *, device_id: UUID, collected_at: datetime
) -> list[NormalizedAclEntry]:
    """Parse ``show ip access-lists`` output into :class:`NormalizedAclEntry` records.

    EOS-specific differences from IOS:
    - Network prefixes are CIDR (``10.1.1.0/24``), not wildcard-mask pairs.
    - Host entries are ``host <ip>`` (same as IOS extended ACLs).
    - ``any`` source/destination → ``None`` (matches everything).
    - The destination port match (e.g. ``eq telnet``) is in the ``modifier``
      field (not split into ``port_modifier``/``port_range``).
    - The template emits one row per ACE (no Filldown header-only rows);
      rows without an ``action`` field are skipped defensively.
    """
    rows = _parse_with_template("show ip access-lists", raw_output)
    entries: list[NormalizedAclEntry] = []
    try:
        for row in rows:
            action_raw = str(row.get("action", "")).strip().lower()
            if not action_raw:
                continue  # defensive skip for any header-only rows
            entries.append(
                NormalizedAclEntry(
                    device_id=device_id,
                    collected_at=collected_at,
                    source_vendor=PLATFORM,
                    acl_name=str(row["name"]),
                    action=AclAction(action_raw),
                    protocol=str(row.get("protocol", "")).strip() or "ip",
                    sequence=_int_or_none(row.get("sn")),
                    source=_eos_acl_endpoint(str(row.get("source", ""))),
                    source_port=None,  # EOS template does not expose source port separately
                    destination=_eos_acl_endpoint(str(row.get("destination", ""))),
                    destination_port=str(row.get("modifier", "")).strip() or None,
                    hits=None,  # EOS template does not capture match counts
                )
            )
    except (KeyError, ValueError, ValidationError) as exc:
        raise PluginError(f"eos: invalid 'show ip access-lists' row: {exc}") from exc
    return entries
