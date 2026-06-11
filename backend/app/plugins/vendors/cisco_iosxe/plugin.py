"""Cisco IOS-XE plugin: capability implementations over a ``CommandTransport``.

IOS-XE (Cat9k, CSR1000v, ISR4000, etc.) shares the same CLI show-command
syntax and ntc-templates parsing as classic IOS (ADR-0007: both use the
``cisco_ios`` platform key).  Rather than duplicating parsers, this module
imports the shared cisco_ios parser functions directly and wraps them in
IOS-XE-specific capability classes whose ``source_vendor`` is ``cisco_iosxe``.

The netmiko ``device_type`` for IOS-XE is ``cisco_xe``.

Command strings are the same as cisco_ios; they are redeclared here as the
single source of command text for this plugin (REPO-STRUCTURE §6 step 7).
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from typing import ClassVar
from uuid import UUID

from app.core.errors import PluginError
from app.plugins.base import (
    Capability,
    CommandTransport,
    ConfigBackupCapability,
    DiscoverySnmpCapability,
    DiscoverySshCapability,
    InterfacesCapability,
    NeighborsCapability,
    PluginCapability,
    RoutesCapability,
    SnmpReadTransport,
    VendorPlugin,
)

# Re-use cisco_ios parsers: IOS-XE show output is parsed with the same
# ntc-templates platform key ("cisco_ios").  Only source_vendor changes.
from app.plugins.vendors.cisco_ios import parsers as _ios_parsers
from app.plugins.vendors.cisco_ios.parsers import (
    SNMP_OID_SYSDESCR,
    SNMP_OID_SYSNAME,
    SNMP_OID_SYSOBJECTID,
)
from app.schemas.discovery import DeviceFacts
from app.schemas.normalized import NormalizedInterface, NormalizedNeighbor, NormalizedRoute

__all__ = [
    "SNMP_OID_SYSDESCR",
    "SNMP_OID_SYSNAME",
    "SNMP_OID_SYSOBJECTID",
    "CiscoIosXeConfigBackup",
    "CiscoIosXeDiscoverySnmp",
    "CiscoIosXeDiscoverySsh",
    "CiscoIosXeInterfaces",
    "CiscoIosXeNeighbors",
    "CiscoIosXePlugin",
    "CiscoIosXeRoutes",
]

VENDOR_ID = "cisco_iosxe"

# Command text — ntc-templates index entries for cisco_ios cover IOS-XE output.
SHOW_VERSION = "show version"
SHOW_INTERFACES = "show interfaces"
SHOW_IP_ROUTE = "show ip route"
SHOW_CDP_NEIGHBORS_DETAIL = "show cdp neighbors detail"
SHOW_LLDP_NEIGHBORS_DETAIL = "show lldp neighbors detail"
SHOW_RUNNING_CONFIG = "show running-config"

#: System-MIB OIDs collected by SNMP discovery, in request order.
_SNMP_DISCOVERY_OIDS = (SNMP_OID_SYSDESCR, SNMP_OID_SYSOBJECTID, SNMP_OID_SYSNAME)


class _CiscoIosXeCommandCapability(PluginCapability):
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


class CiscoIosXeDiscoverySsh(_CiscoIosXeCommandCapability, DiscoverySshCapability):
    """``DISCOVERY_SSH``: ``show version`` → :class:`DeviceFacts`.

    Delegates parsing to the shared cisco_ios parser (same template),
    then overwrites ``vendor_id`` to ``cisco_iosxe``.
    """

    def get_device_facts(self) -> DeviceFacts:
        """Collect and parse the device identity over the CLI transport."""
        output = self._run(SHOW_VERSION)
        facts = _ios_parsers.parse_device_facts(output)
        return facts.model_copy(update={"vendor_id": VENDOR_ID})


class CiscoIosXeDiscoverySnmp(DiscoverySnmpCapability):
    """``DISCOVERY_SNMP``: system-MIB GET → :class:`DeviceFacts` (best-effort).

    Delegates to the shared cisco_ios SNMP parser then stamps
    ``vendor_id = cisco_iosxe``.
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
        facts = _ios_parsers.parse_snmp_device_facts(values)
        return facts.model_copy(update={"vendor_id": VENDOR_ID})


class CiscoIosXeInterfaces(_CiscoIosXeCommandCapability, InterfacesCapability):
    """``INTERFACES``: ``show interfaces`` → :class:`NormalizedInterface`."""

    def get_interfaces(self) -> list[NormalizedInterface]:
        """Collect and normalize the device interface inventory."""
        output = self._run(SHOW_INTERFACES)
        records = _ios_parsers.parse_interfaces(
            output, device_id=self._device_id, collected_at=self._now()
        )
        return [r.model_copy(update={"source_vendor": VENDOR_ID}) for r in records]


class CiscoIosXeRoutes(_CiscoIosXeCommandCapability, RoutesCapability):
    """``ROUTES``: ``show ip route`` → :class:`NormalizedRoute`."""

    def get_routes(self) -> list[NormalizedRoute]:
        """Collect and normalize the global IPv4 routing table."""
        output = self._run(SHOW_IP_ROUTE)
        records = _ios_parsers.parse_routes(
            output, device_id=self._device_id, collected_at=self._now()
        )
        return [r.model_copy(update={"source_vendor": VENDOR_ID}) for r in records]


class CiscoIosXeNeighbors(_CiscoIosXeCommandCapability, NeighborsCapability):
    """``NEIGHBORS_LLDP`` + ``NEIGHBORS_CDP`` → :class:`NormalizedNeighbor`."""

    def get_lldp_neighbors(self) -> list[NormalizedNeighbor]:
        """Collect and normalize LLDP adjacencies."""
        output = self._run(SHOW_LLDP_NEIGHBORS_DETAIL)
        records = _ios_parsers.parse_lldp_neighbors(
            output, device_id=self._device_id, collected_at=self._now()
        )
        return [r.model_copy(update={"source_vendor": VENDOR_ID}) for r in records]

    def get_cdp_neighbors(self) -> list[NormalizedNeighbor]:
        """Collect and normalize CDP adjacencies."""
        output = self._run(SHOW_CDP_NEIGHBORS_DETAIL)
        records = _ios_parsers.parse_cdp_neighbors(
            output, device_id=self._device_id, collected_at=self._now()
        )
        return [r.model_copy(update={"source_vendor": VENDOR_ID}) for r in records]


class CiscoIosXeConfigBackup(_CiscoIosXeCommandCapability, ConfigBackupCapability):
    """``CONFIG_BACKUP``: ``show running-config`` returned verbatim."""

    def fetch_running_config(self) -> str:
        """Return the running configuration exactly as the device emitted it."""
        output = self._run(SHOW_RUNNING_CONFIG)
        if not output.strip():
            raise PluginError(
                f"cisco_iosxe: {SHOW_RUNNING_CONFIG!r} returned empty output "
                f"for device {self._device_id}"
            )
        return output


class CiscoIosXePlugin(VendorPlugin):
    """Cisco IOS-XE (``vendor_id="cisco_iosxe"``) — Cat9k/CSR/ISR plugin.

    Declares the full M1 capability set — SSH/SNMP discovery, interface
    inventory, route collection, LLDP/CDP neighbors, and config backup.
    Parsing is delegated to the ``cisco_ios`` parser module because
    IOS-XE ``show`` output is handled by the same ntc-templates templates
    (platform key ``cisco_ios``; ADR-0007).
    """

    vendor_id: ClassVar[str] = VENDOR_ID
    display_name: ClassVar[str] = "Cisco IOS-XE"
    capabilities: ClassVar[frozenset[Capability]] = frozenset(
        {
            Capability.DISCOVERY_SSH,
            Capability.DISCOVERY_SNMP,
            Capability.INTERFACES,
            Capability.ROUTES,
            Capability.NEIGHBORS_LLDP,
            Capability.NEIGHBORS_CDP,
            Capability.CONFIG_BACKUP,
        }
    )

    def _capability_classes(self) -> Mapping[Capability, type[PluginCapability]]:
        return {
            Capability.DISCOVERY_SSH: CiscoIosXeDiscoverySsh,
            Capability.DISCOVERY_SNMP: CiscoIosXeDiscoverySnmp,
            Capability.INTERFACES: CiscoIosXeInterfaces,
            Capability.ROUTES: CiscoIosXeRoutes,
            Capability.NEIGHBORS_LLDP: CiscoIosXeNeighbors,
            Capability.NEIGHBORS_CDP: CiscoIosXeNeighbors,
            Capability.CONFIG_BACKUP: CiscoIosXeConfigBackup,
        }
