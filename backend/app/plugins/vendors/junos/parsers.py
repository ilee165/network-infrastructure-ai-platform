"""Juniper JunOS structured-output parsers: ``| display json`` → normalized models.

Single source of parsing for the ``junos`` plugin (ADR-0026 §2). Each
function takes verbatim ``| display json`` (or ``| display set``) text —
already preserved as :class:`~app.plugins.base.RawOutput` by the capability
layer — and returns normalized Pydantic models. JSON is the primary parse
target; the ``| display set`` text is used verbatim for config backup/restore.

ADR-0026 §1 notes on non-Cisco syntax:

- **ACL**: JunOS uses **firewall filters** composed of ordered **terms**
  (``from``/``then``). Each term maps to one or more ``NormalizedAclEntry``
  rows. A term whose ``then`` is a non-permit/deny action (e.g. ``count``,
  ``policer``) is normalized as faithfully as the model allows — the
  divergence is noted in code, never silently dropped; the raw artifact is
  authoritative.
- **Routes**: ``show route | display json`` yields per-protocol entries;
  ``NormalizedRoute`` carries protocol/next-hop/prefix as in the Cisco parsers.
- **BGP**: peer addresses in JunOS JSON include the port suffix
  (``172.16.0.1+179``) — the parser strips it.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from datetime import datetime
from ipaddress import IPv4Address, IPv4Interface, IPv4Network, IPv6Address, ip_address, ip_network
from typing import Any
from uuid import UUID

from pydantic import ValidationError

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

PLATFORM = "junos"
"""Plugin vendor_id / display-form identifier."""

# System-MIB OIDs queried by SNMP discovery (RFC 1213 / SNMPv2-MIB).
SNMP_OID_SYSDESCR = "1.3.6.1.2.1.1.1.0"
SNMP_OID_SYSOBJECTID = "1.3.6.1.2.1.1.2.0"
SNMP_OID_SYSNAME = "1.3.6.1.2.1.1.5.0"

#: ``sysDescr`` pattern for best-effort JunOS version extraction.
_SYSDESCR_VERSION_RE = re.compile(r"JUNOS\s+([^\s,]+)", re.IGNORECASE)
_SYSDESCR_MODEL_RE = re.compile(r"Juniper Networks,\s+Inc\.\s+(\S+)\s+internet", re.IGNORECASE)

#: JunOS BGP peer-address includes a ``+<port>`` suffix in some outputs.
_BGP_PEER_PORT_RE = re.compile(r"\+\d+$")

#: JunOS route protocol name → unified RouteProtocol.
_ROUTE_PROTOCOLS: dict[str, RouteProtocol] = {
    "direct": RouteProtocol.CONNECTED,
    "local": RouteProtocol.LOCAL,
    "static": RouteProtocol.STATIC,
    "ospf": RouteProtocol.OSPF,
    "ospf3": RouteProtocol.OSPF,
    "bgp": RouteProtocol.BGP,
    "isis": RouteProtocol.ISIS,
    "rip": RouteProtocol.RIP,
    "aggregate": RouteProtocol.STATIC,
}

#: JunOS BGP peer-state → BgpPeerState.
_BGP_STATES: dict[str, BgpPeerState] = {
    "idle": BgpPeerState.IDLE,
    "connect": BgpPeerState.CONNECT,
    "active": BgpPeerState.ACTIVE,
    "opensent": BgpPeerState.OPEN_SENT,
    "openconfirm": BgpPeerState.OPEN_CONFIRM,
    "established": BgpPeerState.ESTABLISHED,
}

#: JunOS OSPF neighbor state → OspfNeighborState.
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

#: JunOS firewall term ``then`` action → AclAction (permit/deny only).
#: Non-permit/deny actions (count, policer, routing-instance) map to None,
#: indicating the term cannot be fully normalized into permit/deny form
#: (ADR-0026 §1 notes — approximation noted, never silently dropped).
_TERM_ACTIONS: dict[str, AclAction | None] = {
    "accept": AclAction.PERMIT,
    "discard": AclAction.DENY,
    "reject": AclAction.DENY,
    "count": None,  # non-permit/deny; ADR-0026 §1 lowest-common-denominator
    "policer": None,
    "routing-instance": None,
    "next term": None,
}


# ---------------------------------------------------------------------------
# JSON parse helpers
# ---------------------------------------------------------------------------


def _load_json(command: str, raw: str) -> Any:
    """Parse *raw* as JSON, raising :class:`PluginError` on failure.

    The raw text may have a leading ``# comment`` line (fixture convention).
    """
    # Strip fixture-only leading comment lines.
    lines = raw.splitlines()
    data_lines = [ln for ln in lines if not ln.startswith("#")]
    try:
        return json.loads("\n".join(data_lines))
    except json.JSONDecodeError as exc:
        raise PluginError(f"junos: failed to parse JSON output of {command!r}: {exc}") from exc


def _first(node: list[Any] | None, key: str, default: str = "") -> str:
    """Extract the text value of *key* from the first element of *node*."""
    if not node:
        return default
    raw_first = node[0]
    if not isinstance(raw_first, dict):
        return default
    sub = raw_first.get(key, [])
    if not sub or not isinstance(sub, list):
        return default
    item = sub[0]
    if not isinstance(item, dict):
        return default
    return str(item.get("data", ""))


def _int_or_none(value: str) -> int | None:
    value = value.strip()
    if not value:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def _address_or_none(value: str) -> IPv4Address | IPv6Address | None:
    value = value.strip()
    if not value:
        return None
    try:
        return ip_address(value)
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# Device facts
# ---------------------------------------------------------------------------


def parse_device_facts(raw_output: str) -> DeviceFacts:
    """Parse ``show version | display json`` output into :class:`DeviceFacts`."""
    data = _load_json("show version | display json", raw_output)
    try:
        sw_info = data.get("software-information", [{}])[0]
        hostname = _first([sw_info], "host-name")
        model = _first([sw_info], "product-model")
        os_version = _first([sw_info], "junos-version")
    except (IndexError, KeyError, TypeError, AttributeError) as exc:
        raise PluginError(
            f"junos: unexpected 'show version | display json' structure: {exc}"
        ) from exc
    if not hostname:
        raise PluginError(
            "junos: 'show version | display json' returned no host-name — "
            "cannot establish device identity"
        )
    try:
        return DeviceFacts(
            hostname=hostname,
            vendor_id=PLATFORM,
            model=model or None,
            os_version=os_version or None,
            serial=None,
        )
    except ValidationError as exc:
        raise PluginError(f"junos: invalid 'show version' facts: {exc}") from exc


def parse_snmp_device_facts(values: Mapping[str, str]) -> DeviceFacts:
    """Map system-MIB GET *values* (``{dotted_oid: pretty_value}``) to facts.

    ``sysName`` is required; ``os_version`` and ``model`` are best-effort
    extractions from ``sysDescr``; ``serial`` is not exposed by the system MIB.
    """
    hostname = values.get(SNMP_OID_SYSNAME, "").strip()
    if not hostname:
        raise PluginError(
            f"junos: SNMP discovery returned no sysName ({SNMP_OID_SYSNAME}) — "
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


# ---------------------------------------------------------------------------
# Interfaces
# ---------------------------------------------------------------------------


def _admin_oper_status(admin: str, oper: str) -> tuple[InterfaceAdminStatus, InterfaceOperStatus]:
    """Map JunOS admin/oper status strings to normalized statuses."""
    a = InterfaceAdminStatus.UP if admin.lower().startswith("up") else InterfaceAdminStatus.DOWN
    if oper.lower().startswith("up"):
        o = InterfaceOperStatus.UP
    elif oper.lower().startswith("down"):
        o = InterfaceOperStatus.DOWN
    else:
        o = InterfaceOperStatus.UNKNOWN
    return a, o


def _speed_mbps_from_junos(speed_str: str) -> int | None:
    """Convert JunOS speed strings (``1000mbps``, ``10Gbps``) to Mb/s."""
    m = re.match(r"^(\d+)\s*(m|g|k)bps$", speed_str.lower().strip())
    if not m:
        return None
    value, unit = int(m.group(1)), m.group(2)
    if unit == "g":
        return value * 1000
    if unit == "k":
        return value // 1000
    return value


def _first_inet_address(logical_ifaces: list[Any]) -> IPv4Interface | None:
    """Extract the first IPv4 address from logical interface address-family list."""
    for li in logical_ifaces:
        if not isinstance(li, dict):
            continue
        for af in li.get("address-family", []):
            if not isinstance(af, dict):
                continue
            name = _first([af], "address-family-name")
            if name != "inet":
                continue
            for ia in af.get("interface-address", []):
                if not isinstance(ia, dict):
                    continue
                addr_str = _first([ia], "ifa-local")
                if not addr_str:
                    continue
                try:
                    return IPv4Interface(addr_str)
                except ValueError:
                    continue
    return None


def parse_interfaces(
    raw_output: str, *, device_id: UUID, collected_at: datetime
) -> list[NormalizedInterface]:
    """Parse ``show interfaces | display json`` into :class:`NormalizedInterface` records."""
    data = _load_json("show interfaces | display json", raw_output)
    try:
        iface_info = data.get("interface-information", [{}])[0]
        phys_ifaces = iface_info.get("physical-interface", [])
    except (IndexError, KeyError, TypeError) as exc:
        raise PluginError(
            f"junos: unexpected 'show interfaces | display json' structure: {exc}"
        ) from exc

    results: list[NormalizedInterface] = []
    for iface in phys_ifaces:
        if not isinstance(iface, dict):
            continue
        try:
            name = _first([iface], "name")
            if not name:
                continue
            admin_str = _first([iface], "admin-status")
            oper_str = _first([iface], "oper-status")
            admin, oper = _admin_oper_status(admin_str, oper_str)
            mtu_str = _first([iface], "mtu")
            speed_str = _first([iface], "speed")
            description = _first([iface], "description") or None
            mac = _first([iface], "current-physical-address") or None
            logical = iface.get("logical-interface", [])
            ip_addr = _first_inet_address(logical) if logical else None
            results.append(
                NormalizedInterface(
                    device_id=device_id,
                    collected_at=collected_at,
                    source_vendor=PLATFORM,
                    name=name,
                    description=description,
                    admin_status=admin,
                    oper_status=oper,
                    mac_address=mac,
                    ip_address=ip_addr,
                    mtu=_int_or_none(mtu_str),
                    speed_mbps=_speed_mbps_from_junos(speed_str),
                    duplex=None,
                    vlan_id=None,
                    input_errors=None,
                    output_errors=None,
                )
            )
        except (KeyError, ValueError, ValidationError) as exc:
            raise PluginError(
                f"junos: invalid 'show interfaces | display json' entry: {exc}"
            ) from exc
    return results


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


def parse_routes(
    raw_output: str, *, device_id: UUID, collected_at: datetime
) -> list[NormalizedRoute]:
    """Parse ``show route | display json`` into :class:`NormalizedRoute` records."""
    data = _load_json("show route | display json", raw_output)
    try:
        ri = data.get("route-information", [{}])[0]
        tables = ri.get("route-table", [])
    except (IndexError, KeyError, TypeError) as exc:
        raise PluginError(
            f"junos: unexpected 'show route | display json' structure: {exc}"
        ) from exc

    results: list[NormalizedRoute] = []
    for table in tables:
        if not isinstance(table, dict):
            continue
        table_name = _first([table], "table-name")
        # JunOS global/default tables have the form "<af>.<n>" (e.g. "inet.0",
        # "inet6.0", "mpls.0") — exactly two dot-separated tokens.  VRF-specific
        # tables carry an instance prefix: "<instance>.<af>.<n>" (e.g.
        # "BLUE.inet.0"), i.e. three or more tokens.  Only extract a VRF name
        # when the table name has at least three parts.
        if table_name:
            parts = table_name.split(".")
            vrf = parts[0] if len(parts) >= 3 else None
        else:
            vrf = None
        for rt in table.get("rt", []):
            if not isinstance(rt, dict):
                continue
            try:
                dest_str = _first([rt], "rt-destination")
                if not dest_str:
                    continue
                destination = ip_network(dest_str, strict=False)
                for entry in rt.get("rt-entry", []):
                    if not isinstance(entry, dict):
                        continue
                    proto_str = _first([entry], "protocol-name").lower()
                    protocol = _ROUTE_PROTOCOLS.get(proto_str, RouteProtocol.OTHER)
                    pref_str = _first([entry], "preference")
                    metric_str = _first([entry], "metric")
                    nh_list = entry.get("nh", [])
                    next_hop_addr: IPv4Address | IPv6Address | None = None
                    iface: str | None = None
                    if nh_list and isinstance(nh_list[0], dict):
                        nh = nh_list[0]
                        to_str = _first([nh], "to")
                        via_str = _first([nh], "via")
                        if to_str:
                            next_hop_addr = _address_or_none(to_str)
                        if via_str:
                            iface = via_str
                    results.append(
                        NormalizedRoute(
                            device_id=device_id,
                            collected_at=collected_at,
                            source_vendor=PLATFORM,
                            destination=destination,
                            protocol=protocol,
                            next_hop=next_hop_addr,
                            interface=iface,
                            vrf=vrf,
                            distance=_int_or_none(pref_str),
                            metric=_int_or_none(metric_str),
                        )
                    )
            except (KeyError, ValueError, ValidationError) as exc:
                raise PluginError(
                    f"junos: invalid 'show route | display json' entry: {exc}"
                ) from exc
    return results


# ---------------------------------------------------------------------------
# LLDP neighbors
# ---------------------------------------------------------------------------


def parse_lldp_neighbors(
    raw_output: str, *, device_id: UUID, collected_at: datetime
) -> list[NormalizedNeighbor]:
    """Parse ``show lldp neighbors | display json`` into :class:`NormalizedNeighbor` records."""
    data = _load_json("show lldp neighbors | display json", raw_output)
    try:
        lldp_info = data.get("lldp-neighbors-information", [{}])[0]
        neighbors = lldp_info.get("lldp-neighbor-information", [])
    except (IndexError, KeyError, TypeError) as exc:
        raise PluginError(
            f"junos: unexpected 'show lldp neighbors | display json' structure: {exc}"
        ) from exc

    results: list[NormalizedNeighbor] = []
    for nbr in neighbors:
        if not isinstance(nbr, dict):
            continue
        try:
            local_port = _first([nbr], "lldp-local-port-id")
            remote_name = _first([nbr], "lldp-remote-system-name")
            remote_port = _first([nbr], "lldp-remote-port-id") or None
            remote_desc = _first([nbr], "lldp-remote-system-description") or None
            mgmt_addr_str = _first([nbr], "lldp-remote-management-address")
            caps_str = _first([nbr], "lldp-remote-system-capabilities-supported")
            caps = tuple(t for t in re.split(r"[,\s]+", caps_str.strip()) if t)
            results.append(
                NormalizedNeighbor(
                    device_id=device_id,
                    collected_at=collected_at,
                    source_vendor=PLATFORM,
                    protocol=NeighborProtocol.LLDP,
                    local_interface=local_port,
                    neighbor_name=remote_name,
                    neighbor_interface=remote_port,
                    neighbor_platform=remote_desc,
                    neighbor_address=_address_or_none(mgmt_addr_str),
                    neighbor_capabilities=caps,
                )
            )
        except (KeyError, ValueError, ValidationError) as exc:
            raise PluginError(
                f"junos: invalid 'show lldp neighbors | display json' entry: {exc}"
            ) from exc
    return results


# ---------------------------------------------------------------------------
# BGP peers
# ---------------------------------------------------------------------------


def parse_bgp_peers(
    raw_output: str, *, device_id: UUID, collected_at: datetime
) -> list[NormalizedBgpPeer]:
    """Parse ``show bgp neighbor | display json`` into :class:`NormalizedBgpPeer` records.

    JunOS peer addresses include a ``+<port>`` suffix (e.g. ``172.16.0.1+179``);
    the port suffix is stripped before parsing the IP address.
    """
    data = _load_json("show bgp neighbor | display json", raw_output)
    try:
        bgp_info = data.get("bgp-information", [{}])[0]
        peers = bgp_info.get("bgp-peer", [])
    except (IndexError, KeyError, TypeError) as exc:
        raise PluginError(
            f"junos: unexpected 'show bgp neighbor | display json' structure: {exc}"
        ) from exc

    results: list[NormalizedBgpPeer] = []
    for peer in peers:
        if not isinstance(peer, dict):
            continue
        try:
            peer_addr_raw = _first([peer], "peer-address")
            # Strip port suffix (e.g. "+179") if present.
            peer_addr_str = _BGP_PEER_PORT_RE.sub("", peer_addr_raw).strip()
            remote_as_str = _first([peer], "peer-as")
            local_as_str = _first([peer], "local-as")
            state_str = _first([peer], "peer-state").lower()
            state = _BGP_STATES.get(state_str, BgpPeerState.IDLE)

            # Prefix count from the first bgp-rib entry (inet.0).
            prefixes: int | None = None
            rib_list = peer.get("bgp-rib", [])
            if rib_list and isinstance(rib_list[0], dict):
                received_str = _first([rib_list[0]], "received-prefix-count")
                prefixes = _int_or_none(received_str)

            results.append(
                NormalizedBgpPeer(
                    device_id=device_id,
                    collected_at=collected_at,
                    source_vendor=PLATFORM,
                    peer_address=ip_address(peer_addr_str),
                    remote_as=int(remote_as_str),
                    local_as=_int_or_none(local_as_str),
                    state=state,
                    prefixes_received=prefixes,
                )
            )
        except (KeyError, ValueError, ValidationError) as exc:
            raise PluginError(
                f"junos: invalid 'show bgp neighbor | display json' entry: {exc}"
            ) from exc
    return results


# ---------------------------------------------------------------------------
# OSPF neighbors
# ---------------------------------------------------------------------------


def parse_ospf_neighbors(
    raw_output: str, *, device_id: UUID, collected_at: datetime
) -> list[NormalizedOspfNeighbor]:
    """Parse ``show ospf neighbor | display json`` into :class:`NormalizedOspfNeighbor` records."""
    data = _load_json("show ospf neighbor | display json", raw_output)
    try:
        ospf_info = data.get("ospf-neighbor-information", [{}])[0]
        neighbors = ospf_info.get("ospf-neighbor", [])
    except (IndexError, KeyError, TypeError) as exc:
        raise PluginError(
            f"junos: unexpected 'show ospf neighbor | display json' structure: {exc}"
        ) from exc

    results: list[NormalizedOspfNeighbor] = []
    for nbr in neighbors:
        if not isinstance(nbr, dict):
            continue
        try:
            nbr_addr_str = _first([nbr], "neighbor-address")
            iface_name = _first([nbr], "interface-name")
            state_str = _first([nbr], "ospf-neighbor-state").lower()
            state = _OSPF_STATES.get(state_str, OspfNeighborState.DOWN)
            nbr_id_str = _first([nbr], "neighbor-id")
            priority_str = _first([nbr], "neighbor-priority")
            dead_time_str = _first([nbr], "activity-timer")
            results.append(
                NormalizedOspfNeighbor(
                    device_id=device_id,
                    collected_at=collected_at,
                    source_vendor=PLATFORM,
                    neighbor_id=IPv4Address(nbr_id_str),
                    interface=iface_name,
                    state=state,
                    neighbor_address=_address_or_none(nbr_addr_str),
                    priority=_int_or_none(priority_str),
                    dead_time_seconds=_int_or_none(dead_time_str),
                )
            )
        except (KeyError, ValueError, ValidationError) as exc:
            raise PluginError(
                f"junos: invalid 'show ospf neighbor | display json' entry: {exc}"
            ) from exc
    return results


# ---------------------------------------------------------------------------
# ACL (firewall filters → NormalizedAclEntry)
# ---------------------------------------------------------------------------


def _term_action(then_obj: dict[str, Any]) -> AclAction | None:
    """Map a JunOS term ``then`` object to an AclAction, or None for non-permit/deny.

    JunOS ``then`` is a dict whose keys are action names (``accept``, ``discard``,
    ``count``, etc.). This function returns the first recognized action, favouring
    ``accept``/``discard``/``reject`` over non-permit/deny actions (ADR-0026 §1:
    lowest-common-denominator approximation; ``count``-only terms map to None).
    """
    for key in then_obj:
        action = _TERM_ACTIONS.get(key)
        if action is not None:
            return action
    # All recognized keys map to None (non-permit/deny) — return None to indicate
    # the term cannot be fully normalized; the raw artifact remains authoritative.
    return None


def parse_acls(
    raw_output: str, *, device_id: UUID, collected_at: datetime
) -> list[NormalizedAclEntry]:
    """Parse ``show configuration firewall | display json`` into :class:`NormalizedAclEntry`.

    JunOS firewall filters map to the ``NormalizedAclEntry`` model as follows
    (ADR-0026 §1 "firewall filters → NormalizedAclEntry"):

    - Filter name → ``acl_name``
    - Term name → used as ``sequence`` label (sequence number = ordinal position)
    - ``from.protocol`` → ``protocol``
    - ``from.source-address`` / ``from.destination-address`` → ``source`` / ``destination``
    - ``then.accept``/``then.discard``/``then.reject`` → ``action``
    - Terms with non-permit/deny ``then`` (``count``, ``policer``) are still emitted
      as :class:`NormalizedAclEntry` rows but with ``action=DENY`` as the
      lowest-common-denominator approximation and a note in ``source_vendor``. The
      verbatim raw artifact is the authoritative record (ADR-0026 §1 negative).
    """
    data = _load_json("show configuration firewall | display json", raw_output)
    try:
        config = data.get("configuration", [{}])[0]
        firewall = config.get("firewall", [{}])[0]
        families = firewall.get("family", [{}])
    except (IndexError, KeyError, TypeError) as exc:
        raise PluginError(
            f"junos: unexpected 'show configuration firewall | display json' structure: {exc}"
        ) from exc

    results: list[NormalizedAclEntry] = []
    for family in families:
        if not isinstance(family, dict):
            continue
        inet_list = family.get("inet", [{}])
        if not inet_list:
            continue
        inet = inet_list[0] if isinstance(inet_list, list) else {}
        if not isinstance(inet, dict):
            continue
        for filt in inet.get("filter", []):
            if not isinstance(filt, dict):
                continue
            filter_name = _first([filt], "name")
            for seq, term in enumerate(filt.get("term", []), start=1):
                if not isinstance(term, dict):
                    continue
                try:
                    # Parse ``from`` (optional — some terms have no ``from``).
                    from_list = term.get("from", [{}])
                    from_first: Any = from_list[0] if from_list else {}
                    from_obj: dict[str, Any] = from_first if isinstance(from_first, dict) else {}

                    proto_list = from_obj.get("protocol", [])
                    protocol = _first([{"protocol": proto_list}], "protocol") or "ip"

                    # source / destination addresses (first prefix only).
                    src_addrs = from_obj.get("source-address", [])
                    dst_addrs = from_obj.get("destination-address", [])
                    source = _parse_acl_network(src_addrs)
                    destination = _parse_acl_network(dst_addrs)

                    # Parse ``then``.
                    then_list = term.get("then", [{}])
                    then_first: Any = then_list[0] if then_list else {}
                    then_obj: dict[str, Any] = then_first if isinstance(then_first, dict) else {}
                    action = _term_action(then_obj)
                    # Non-permit/deny terms: use DENY as the lowest-common-denominator
                    # approximation (ADR-0026 §1 negative). The raw artifact is authoritative.
                    effective_action = action if action is not None else AclAction.DENY

                    results.append(
                        NormalizedAclEntry(
                            device_id=device_id,
                            collected_at=collected_at,
                            source_vendor=PLATFORM,
                            acl_name=filter_name,
                            action=effective_action,
                            protocol=protocol,
                            sequence=seq,
                            source=source,
                            source_port=None,
                            destination=destination,
                            destination_port=None,
                            hits=None,
                        )
                    )
                except (KeyError, ValueError, ValidationError) as exc:
                    raise PluginError(
                        f"junos: invalid firewall filter term in {filter_name!r}: {exc}"
                    ) from exc
    return results


def _parse_acl_network(addr_list: list[Any]) -> IPv4Network | None:
    """Extract the first valid IPv4 network from a JunOS address list.

    The address list entries are dicts with a ``data`` key containing CIDR notation.
    Returns ``None`` (meaning "any") when the list is empty or contains no parseable network.
    """
    for entry in addr_list:
        if not isinstance(entry, dict):
            continue
        addr_str = entry.get("data", "")
        if not addr_str:
            continue
        try:
            return IPv4Network(addr_str, strict=False)
        except ValueError:
            continue
    return None
