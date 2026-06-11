"""Arista EOS plugin: capability implementations over a ``CommandTransport``.

EOS-specific notes
------------------
- netmiko ``device_type``: ``arista_eos``
- ntc-templates platform key: ``arista_eos``
- No CDP support on EOS — ``NEIGHBORS_CDP`` is intentionally absent from the
  declared capability set (EOS uses LLDP exclusively for L2 neighbor discovery).
- ``show version`` on EOS does **not** emit ``hostname``; :meth:`EosDiscoverySsh`
  returns ``hostname=""`` from the CLI path.  SNMP discovery (``sysName``)
  provides the authoritative hostname.
- ``show ip route`` PROTOCOL is multi-token for eBGP/iBGP (``"B E"`` / ``"B I"``).

Command strings live in module-level ``SHOW_*`` constants — the single
source of command text for this plugin (REPO-STRUCTURE §6 step 7).
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from typing import ClassVar
from uuid import UUID

from app.plugins.base import (
    Capability,
    CommandTransport,
    DiscoverySnmpCapability,
    DiscoverySshCapability,
    InterfacesCapability,
    NeighborsCapability,
    PluginCapability,
    RoutesCapability,
    SnmpReadTransport,
    VendorPlugin,
)
from app.plugins.vendors.eos import parsers
from app.plugins.vendors.eos.parsers import (
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
    "EosDiscoverySnmp",
    "EosDiscoverySsh",
    "EosInterfaces",
    "EosNeighbors",
    "EosPlugin",
    "EosRoutes",
]

VENDOR_ID = "eos"

# Command text — must match the ntc-templates index entries for arista_eos.
SHOW_VERSION = "show version"
SHOW_INTERFACES = "show interfaces"
SHOW_IP_ROUTE = "show ip route"
SHOW_LLDP_NEIGHBORS_DETAIL = "show lldp neighbors detail"

#: System-MIB OIDs collected by SNMP discovery, in request order.
_SNMP_DISCOVERY_OIDS = (SNMP_OID_SYSDESCR, SNMP_OID_SYSOBJECTID, SNMP_OID_SYSNAME)


class _EosCommandCapability(PluginCapability):
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


class EosDiscoverySsh(_EosCommandCapability, DiscoverySshCapability):
    """``DISCOVERY_SSH``: ``show version`` → :class:`DeviceFacts`.

    EOS ``show version`` does not include the device hostname; the returned
    :class:`DeviceFacts` will have ``hostname=""`` when using the SSH path.
    Use SNMP discovery (``sysName``) for authoritative hostname resolution.
    The parser stamps ``vendor_id="arista_eos"`` (ntc-templates platform key);
    we overwrite it with the plugin vendor_id ``"eos"`` on return.
    """

    def get_device_facts(self) -> DeviceFacts:
        """Collect and parse the device identity over the CLI transport."""
        output = self._run(SHOW_VERSION)
        facts = parsers.parse_device_facts(output)
        return facts.model_copy(update={"vendor_id": VENDOR_ID})


class EosDiscoverySnmp(DiscoverySnmpCapability):
    """``DISCOVERY_SNMP``: system-MIB GET → :class:`DeviceFacts` (best-effort).

    Takes an :class:`~app.plugins.base.SnmpReadTransport` (the M1-08
    ``SnmpClient`` in production, fakes in tests). The returned values are
    recorded verbatim as a :class:`~app.plugins.base.RawOutput` — one line
    per OID — before mapping.
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
        facts = parsers.parse_snmp_device_facts(values)
        return facts.model_copy(update={"vendor_id": VENDOR_ID})


class EosInterfaces(_EosCommandCapability, InterfacesCapability):
    """``INTERFACES``: ``show interfaces`` → :class:`NormalizedInterface`."""

    def get_interfaces(self) -> list[NormalizedInterface]:
        """Collect and normalize the device interface inventory."""
        output = self._run(SHOW_INTERFACES)
        records = parsers.parse_interfaces(
            output, device_id=self._device_id, collected_at=self._now()
        )
        return [r.model_copy(update={"source_vendor": VENDOR_ID}) for r in records]


class EosRoutes(_EosCommandCapability, RoutesCapability):
    """``ROUTES``: ``show ip route`` → :class:`NormalizedRoute`."""

    def get_routes(self) -> list[NormalizedRoute]:
        """Collect and normalize the global IPv4 routing table."""
        output = self._run(SHOW_IP_ROUTE)
        records = parsers.parse_routes(output, device_id=self._device_id, collected_at=self._now())
        return [r.model_copy(update={"source_vendor": VENDOR_ID}) for r in records]


class EosNeighbors(_EosCommandCapability, NeighborsCapability):
    """``NEIGHBORS_LLDP`` — LLDP adjacencies only.

    EOS does not implement CDP; ``get_cdp_neighbors`` satisfies the abstract
    method of :class:`~app.plugins.base.NeighborsCapability` but always
    returns an empty list.  The plugin does **not** declare
    ``Capability.NEIGHBORS_CDP`` in its capability set, so the conformance
    suite never calls ``get_cdp_neighbors`` through the fixture path.
    """

    def get_lldp_neighbors(self) -> list[NormalizedNeighbor]:
        """Collect and normalize LLDP adjacencies."""
        output = self._run(SHOW_LLDP_NEIGHBORS_DETAIL)
        records = parsers.parse_lldp_neighbors(
            output, device_id=self._device_id, collected_at=self._now()
        )
        return [r.model_copy(update={"source_vendor": VENDOR_ID}) for r in records]

    def get_cdp_neighbors(self) -> list[NormalizedNeighbor]:
        """EOS does not support CDP; always returns an empty list."""
        return []


class EosPlugin(VendorPlugin):
    """Arista EOS (``vendor_id="eos"``) — leaf/spine switching plugin.

    Declares: SSH/SNMP discovery, interface inventory, route collection, and
    LLDP neighbors.  CDP is intentionally absent — EOS does not implement it.
    """

    vendor_id: ClassVar[str] = VENDOR_ID
    display_name: ClassVar[str] = "Arista EOS"
    capabilities: ClassVar[frozenset[Capability]] = frozenset(
        {
            Capability.DISCOVERY_SSH,
            Capability.DISCOVERY_SNMP,
            Capability.INTERFACES,
            Capability.ROUTES,
            Capability.NEIGHBORS_LLDP,
        }
    )

    def _capability_classes(self) -> Mapping[Capability, type[PluginCapability]]:
        return {
            Capability.DISCOVERY_SSH: EosDiscoverySsh,
            Capability.DISCOVERY_SNMP: EosDiscoverySnmp,
            Capability.INTERFACES: EosInterfaces,
            Capability.ROUTES: EosRoutes,
            Capability.NEIGHBORS_LLDP: EosNeighbors,
        }
