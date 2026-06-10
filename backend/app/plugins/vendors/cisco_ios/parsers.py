"""Cisco IOS show-output parsers: ntc-templates/TextFSM → normalized models.

Single source of parsing for the ``cisco_ios`` plugin (REPO-STRUCTURE §6
step 7). Each function takes verbatim show-output text — already preserved as
:class:`~app.plugins.base.RawOutput` by the capability layer — and returns
normalized Pydantic models. Template lookups use the real ntc-templates index
with platform key ``"cisco_ios"`` (ADR-0007); parse and validation failures
raise :class:`~app.core.errors.PluginError`.
"""

from __future__ import annotations

import re
from datetime import datetime
from ipaddress import IPv4Address, IPv6Address, ip_address, ip_interface, ip_network
from typing import cast
from uuid import UUID

from ntc_templates.parse import ParsingException, parse_output
from pydantic import ValidationError

from app.core.errors import PluginError
from app.schemas.normalized import (
    InterfaceAdminStatus,
    InterfaceDuplex,
    InterfaceOperStatus,
    NeighborProtocol,
    NormalizedInterface,
    NormalizedNeighbor,
    NormalizedRoute,
    RouteProtocol,
)

__all__ = [
    "PLATFORM",
    "parse_cdp_neighbors",
    "parse_interfaces",
    "parse_lldp_neighbors",
    "parse_routes",
]

PLATFORM = "cisco_ios"
"""ntc-templates platform key (must match the template index)."""

_SPEED_RE = re.compile(r"(\d+)\s*([GM])b", re.IGNORECASE)
_BANDWIDTH_KBIT_RE = re.compile(r"(\d+)\s*Kbit", re.IGNORECASE)

#: ``show ip route`` protocol-code column → unified protocol.
_ROUTE_PROTOCOLS: dict[str, RouteProtocol] = {
    "C": RouteProtocol.CONNECTED,
    "L": RouteProtocol.LOCAL,
    "S": RouteProtocol.STATIC,
    "R": RouteProtocol.RIP,
    "O": RouteProtocol.OSPF,
    "D": RouteProtocol.EIGRP,
    "B": RouteProtocol.BGP,
    "i": RouteProtocol.ISIS,
    "I": RouteProtocol.ISIS,
}


def _parse_with_template(command: str, raw_output: str) -> list[dict[str, str]]:
    """Run *raw_output* through the ntc-templates index for *command*."""
    try:
        rows = parse_output(platform=PLATFORM, command=command, data=raw_output)
    except ParsingException as exc:
        raise PluginError(f"cisco_ios: failed to parse output of {command!r}: {exc}") from exc
    return cast("list[dict[str, str]]", rows)


def _int_or_none(value: str) -> int | None:
    """Coerce a TextFSM field to ``int``; empty/garbage fields become ``None``."""
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
    link_status: str, protocol_status: str
) -> tuple[InterfaceAdminStatus, InterfaceOperStatus]:
    """Map IOS ``<link>, line protocol is <proto>`` to admin/oper statuses."""
    admin = (
        InterfaceAdminStatus.DOWN
        if "administratively" in link_status.lower()
        else InterfaceAdminStatus.UP
    )
    proto = protocol_status.lower()
    if proto.startswith("up"):
        oper = InterfaceOperStatus.UP
    elif proto.startswith("down"):
        oper = InterfaceOperStatus.DOWN
    else:
        oper = InterfaceOperStatus.UNKNOWN
    return admin, oper


def _speed_mbps(speed: str, bandwidth: str) -> int | None:
    """Derive Mb/s from the ``speed`` field, falling back to ``BW ... Kbit``."""
    match = _SPEED_RE.search(speed)
    if match:
        value = int(match.group(1))
        return value * 1000 if match.group(2).upper() == "G" else value
    bw_match = _BANDWIDTH_KBIT_RE.search(bandwidth)
    if bw_match:
        return int(bw_match.group(1)) // 1000
    return None


def _duplex(value: str) -> InterfaceDuplex | None:
    """Map IOS duplex strings (``Full Duplex``, ``Auto-duplex``, …)."""
    lowered = value.lower()
    if "full" in lowered:
        return InterfaceDuplex.FULL
    if "half" in lowered:
        return InterfaceDuplex.HALF
    if "auto" in lowered:
        return InterfaceDuplex.AUTO
    return None


def _capability_tokens(value: str) -> tuple[str, ...]:
    """Split CDP (``Router Switch IGMP``) / LLDP (``B,R``) capability strings."""
    return tuple(token for token in re.split(r"[,\s]+", value.strip()) if token)


def parse_interfaces(
    raw_output: str, *, device_id: UUID, collected_at: datetime
) -> list[NormalizedInterface]:
    """Parse ``show interfaces`` output into :class:`NormalizedInterface` records."""
    rows = _parse_with_template("show interfaces", raw_output)
    try:
        return [
            NormalizedInterface(
                device_id=device_id,
                collected_at=collected_at,
                source_vendor=PLATFORM,
                name=row["interface"],
                description=row["description"] or None,
                admin_status=_statuses(row["link_status"], row["protocol_status"])[0],
                oper_status=_statuses(row["link_status"], row["protocol_status"])[1],
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
        ]
    except (KeyError, ValueError, ValidationError) as exc:
        raise PluginError(f"cisco_ios: invalid 'show interfaces' row: {exc}") from exc


def parse_routes(
    raw_output: str, *, device_id: UUID, collected_at: datetime
) -> list[NormalizedRoute]:
    """Parse ``show ip route`` output into :class:`NormalizedRoute` records."""
    rows = _parse_with_template("show ip route", raw_output)
    try:
        return [
            NormalizedRoute(
                device_id=device_id,
                collected_at=collected_at,
                source_vendor=PLATFORM,
                destination=ip_network(f"{row['network']}/{row['prefix_length']}"),
                protocol=_ROUTE_PROTOCOLS.get(
                    row["protocol"].strip().rstrip("*"), RouteProtocol.OTHER
                ),
                next_hop=_address_or_none(row["nexthop_ip"]),
                interface=row["nexthop_if"] or None,
                vrf=row["vrf"] or None,
                distance=_int_or_none(row["distance"]),
                metric=_int_or_none(row["metric"]),
            )
            for row in rows
        ]
    except (KeyError, ValueError, ValidationError) as exc:
        raise PluginError(f"cisco_ios: invalid 'show ip route' row: {exc}") from exc


def parse_cdp_neighbors(
    raw_output: str, *, device_id: UUID, collected_at: datetime
) -> list[NormalizedNeighbor]:
    """Parse ``show cdp neighbors detail`` into :class:`NormalizedNeighbor` records."""
    rows = _parse_with_template("show cdp neighbors detail", raw_output)
    try:
        return [
            NormalizedNeighbor(
                device_id=device_id,
                collected_at=collected_at,
                source_vendor=PLATFORM,
                protocol=NeighborProtocol.CDP,
                local_interface=row["local_interface"],
                neighbor_name=row["neighbor_name"],
                neighbor_interface=row["neighbor_interface"] or None,
                neighbor_platform=row["platform"] or None,
                neighbor_address=_address_or_none(row["mgmt_address"]),
                neighbor_capabilities=_capability_tokens(row["capabilities"]),
            )
            for row in rows
        ]
    except (KeyError, ValueError, ValidationError) as exc:
        raise PluginError(f"cisco_ios: invalid 'show cdp neighbors detail' row: {exc}") from exc


def parse_lldp_neighbors(
    raw_output: str, *, device_id: UUID, collected_at: datetime
) -> list[NormalizedNeighbor]:
    """Parse ``show lldp neighbors detail`` into :class:`NormalizedNeighbor` records."""
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
                # Prefer the LLDP Port ID TLV; fall back to port description.
                neighbor_interface=(row["neighbor_port_id"] or row["neighbor_interface"]) or None,
                neighbor_platform=(row["platform"] or row["neighbor_description"]) or None,
                neighbor_address=_address_or_none(row["mgmt_address"]),
                neighbor_capabilities=_capability_tokens(row["capabilities"]),
            )
            for row in rows
        ]
    except (KeyError, ValueError, ValidationError) as exc:
        raise PluginError(f"cisco_ios: invalid 'show lldp neighbors detail' row: {exc}") from exc
