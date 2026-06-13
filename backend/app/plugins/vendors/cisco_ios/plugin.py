"""Cisco IOS plugin: capability implementations over a ``CommandTransport``.

Reference implementation of the D6/ADR-0006 plugin contract. Capability
classes are instantiated per device session with a connected
:class:`~app.plugins.base.CommandTransport` (netmiko-backed in M1) plus the
inventory ``device_id``; every executed command is recorded verbatim via
``PluginCapability._record_raw`` before parsing (brief §4, D11).

Command strings live in this module's ``SHOW_*`` constants — the single
source of command text for the plugin (REPO-STRUCTURE §6 step 7; the
``commands.py``/``capabilities/`` split of the full reference layout is an
M1 refactor once more capabilities land).
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from typing import ClassVar
from uuid import UUID

from app.core.errors import PluginError
from app.plugins.base import (
    AclCapability,
    BgpCapability,
    Capability,
    CommandTransport,
    ConfigBackupCapability,
    DiscoverySnmpCapability,
    DiscoverySshCapability,
    InterfacesCapability,
    NeighborsCapability,
    OspfCapability,
    PluginCapability,
    RoutesCapability,
    SnmpReadTransport,
    VendorPlugin,
)
from app.plugins.vendors.cisco_ios import parsers
from app.plugins.vendors.cisco_ios.parsers import (
    SNMP_OID_SYSDESCR,
    SNMP_OID_SYSNAME,
    SNMP_OID_SYSOBJECTID,
)
from app.schemas.discovery import DeviceFacts
from app.schemas.normalized import (
    NormalizedAclEntry,
    NormalizedBgpPeer,
    NormalizedInterface,
    NormalizedNeighbor,
    NormalizedOspfNeighbor,
    NormalizedRoute,
)

__all__ = [
    "SNMP_OID_SYSDESCR",
    "SNMP_OID_SYSNAME",
    "SNMP_OID_SYSOBJECTID",
    "CiscoIosAcl",
    "CiscoIosBgp",
    "CiscoIosConfigBackup",
    "CiscoIosDiscoverySnmp",
    "CiscoIosDiscoverySsh",
    "CiscoIosInterfaces",
    "CiscoIosNeighbors",
    "CiscoIosOspf",
    "CiscoIosPlugin",
    "CiscoIosRoutes",
]

VENDOR_ID = "cisco_ios"

# Command text — must match the ntc-templates index entries for cisco_ios.
SHOW_VERSION = "show version"
SHOW_INTERFACES = "show interfaces"
SHOW_IP_ROUTE = "show ip route"
SHOW_CDP_NEIGHBORS_DETAIL = "show cdp neighbors detail"
SHOW_LLDP_NEIGHBORS_DETAIL = "show lldp neighbors detail"
SHOW_RUNNING_CONFIG = "show running-config"
SHOW_IP_BGP_SUMMARY = "show ip bgp summary"
SHOW_IP_OSPF_NEIGHBOR = "show ip ospf neighbor"
SHOW_IP_ACCESS_LISTS = "show ip access-lists"

#: System-MIB OIDs collected by SNMP discovery, in request order.
_SNMP_DISCOVERY_OIDS = (SNMP_OID_SYSDESCR, SNMP_OID_SYSOBJECTID, SNMP_OID_SYSNAME)


class _CiscoIosCommandCapability(PluginCapability):
    """Shared base: holds the transport/device context and runs commands.

    ``_run`` records every output verbatim (RawOutput) before any parsing —
    the audit hook the M1 discovery runner persists to ``raw_artifacts``.
    """

    def __init__(self, transport: CommandTransport, device_id: UUID) -> None:
        super().__init__()
        self._transport = transport
        self._device_id = device_id

    def _run(self, command: str) -> str:
        """Execute *command* and return its output, recorded verbatim."""
        output = self._transport.send_command(command)
        return self._record_raw(command, output)

    @staticmethod
    def _now() -> datetime:
        """Collection instant stamped onto normalized records."""
        return datetime.now(UTC)


class CiscoIosDiscoverySsh(_CiscoIosCommandCapability, DiscoverySshCapability):
    """``DISCOVERY_SSH``: ``show version`` → :class:`DeviceFacts`."""

    def get_device_facts(self) -> DeviceFacts:
        """Collect and parse the device identity over the CLI transport."""
        output = self._run(SHOW_VERSION)
        return parsers.parse_device_facts(output)


class CiscoIosDiscoverySnmp(DiscoverySnmpCapability):
    """``DISCOVERY_SNMP``: system-MIB GET → :class:`DeviceFacts` (best-effort).

    Takes an :class:`~app.plugins.base.SnmpReadTransport` (the M1-08
    ``SnmpClient`` in production, fakes in tests). The returned values are
    recorded verbatim as a :class:`~app.plugins.base.RawOutput` — one line
    per OID — before mapping, mirroring the CLI capabilities' audit trail.
    """

    def __init__(self, snmp: SnmpReadTransport, device_id: UUID) -> None:
        super().__init__()
        self._snmp = snmp
        self._device_id = device_id

    def get_device_facts(self) -> DeviceFacts:
        """Query sysDescr/sysObjectID/sysName and map them to device facts."""
        values = self._snmp.get(list(_SNMP_DISCOVERY_OIDS))
        self._record_raw(
            f"SNMP GET {' '.join(_SNMP_DISCOVERY_OIDS)}",
            "\n".join(f"{oid} = {values.get(oid, '')}" for oid in _SNMP_DISCOVERY_OIDS),
        )
        return parsers.parse_snmp_device_facts(values)


class CiscoIosInterfaces(_CiscoIosCommandCapability, InterfacesCapability):
    """``INTERFACES``: ``show interfaces`` → :class:`NormalizedInterface`."""

    def get_interfaces(self) -> list[NormalizedInterface]:
        """Collect and normalize the device interface inventory."""
        output = self._run(SHOW_INTERFACES)
        return parsers.parse_interfaces(output, device_id=self._device_id, collected_at=self._now())


class CiscoIosRoutes(_CiscoIosCommandCapability, RoutesCapability):
    """``ROUTES``: ``show ip route`` → :class:`NormalizedRoute`."""

    def get_routes(self) -> list[NormalizedRoute]:
        """Collect and normalize the global IPv4 routing table."""
        output = self._run(SHOW_IP_ROUTE)
        return parsers.parse_routes(output, device_id=self._device_id, collected_at=self._now())


class CiscoIosNeighbors(_CiscoIosCommandCapability, NeighborsCapability):
    """``NEIGHBORS_LLDP`` + ``NEIGHBORS_CDP`` → :class:`NormalizedNeighbor`."""

    def get_lldp_neighbors(self) -> list[NormalizedNeighbor]:
        """Collect and normalize LLDP adjacencies."""
        output = self._run(SHOW_LLDP_NEIGHBORS_DETAIL)
        return parsers.parse_lldp_neighbors(
            output, device_id=self._device_id, collected_at=self._now()
        )

    def get_cdp_neighbors(self) -> list[NormalizedNeighbor]:
        """Collect and normalize CDP adjacencies."""
        output = self._run(SHOW_CDP_NEIGHBORS_DETAIL)
        return parsers.parse_cdp_neighbors(
            output, device_id=self._device_id, collected_at=self._now()
        )


class CiscoIosBgp(_CiscoIosCommandCapability, BgpCapability):
    """``BGP``: ``show ip bgp summary`` → :class:`NormalizedBgpPeer`."""

    def get_bgp_peers(self) -> list[NormalizedBgpPeer]:
        """Collect and normalize the IPv4-unicast BGP peering sessions."""
        output = self._run(SHOW_IP_BGP_SUMMARY)
        return parsers.parse_bgp_peers(output, device_id=self._device_id, collected_at=self._now())


class CiscoIosOspf(_CiscoIosCommandCapability, OspfCapability):
    """``OSPF``: ``show ip ospf neighbor`` → :class:`NormalizedOspfNeighbor`."""

    def get_ospf_neighbors(self) -> list[NormalizedOspfNeighbor]:
        """Collect and normalize the OSPF neighbor adjacencies."""
        output = self._run(SHOW_IP_OSPF_NEIGHBOR)
        return parsers.parse_ospf_neighbors(
            output, device_id=self._device_id, collected_at=self._now()
        )


class CiscoIosAcl(_CiscoIosCommandCapability, AclCapability):
    """``ACL``: ``show ip access-lists`` → :class:`NormalizedAclEntry`."""

    def get_acls(self) -> list[NormalizedAclEntry]:
        """Collect and normalize the configured IP access-list entries."""
        output = self._run(SHOW_IP_ACCESS_LISTS)
        return parsers.parse_acls(output, device_id=self._device_id, collected_at=self._now())


class CiscoIosConfigBackup(_CiscoIosCommandCapability, ConfigBackupCapability):
    """``CONFIG_BACKUP``: ``show running-config`` returned verbatim."""

    def fetch_running_config(self) -> str:
        """Return the running configuration exactly as the device emitted it."""
        output = self._run(SHOW_RUNNING_CONFIG)
        if not output.strip():
            raise PluginError(
                f"cisco_ios: {SHOW_RUNNING_CONFIG!r} returned empty output "
                f"for device {self._device_id}"
            )
        return output


class CiscoIosPlugin(VendorPlugin):
    """Cisco IOS (``vendor_id="cisco_ios"``) — M0/M1 reference plugin.

    Declares only what is implemented (REPO-STRUCTURE §6 step 4): the full
    M1 capability set — SSH/SNMP discovery, interface inventory, route
    collection, LLDP/CDP neighbors — plus config backup and the M3
    troubleshooting trio (BGP/OSPF/ACL).
    """

    vendor_id: ClassVar[str] = VENDOR_ID
    display_name: ClassVar[str] = "Cisco IOS"
    capabilities: ClassVar[frozenset[Capability]] = frozenset(
        {
            Capability.DISCOVERY_SSH,
            Capability.DISCOVERY_SNMP,
            Capability.INTERFACES,
            Capability.ROUTES,
            Capability.NEIGHBORS_LLDP,
            Capability.NEIGHBORS_CDP,
            Capability.BGP,
            Capability.OSPF,
            Capability.ACL,
            Capability.CONFIG_BACKUP,
        }
    )

    def _capability_classes(self) -> Mapping[Capability, type[PluginCapability]]:
        return {
            Capability.DISCOVERY_SSH: CiscoIosDiscoverySsh,
            Capability.DISCOVERY_SNMP: CiscoIosDiscoverySnmp,
            Capability.INTERFACES: CiscoIosInterfaces,
            Capability.ROUTES: CiscoIosRoutes,
            Capability.NEIGHBORS_LLDP: CiscoIosNeighbors,
            Capability.NEIGHBORS_CDP: CiscoIosNeighbors,
            Capability.BGP: CiscoIosBgp,
            Capability.OSPF: CiscoIosOspf,
            Capability.ACL: CiscoIosAcl,
            Capability.CONFIG_BACKUP: CiscoIosConfigBackup,
        }
