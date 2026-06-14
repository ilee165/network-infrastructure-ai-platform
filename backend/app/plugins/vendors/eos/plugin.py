"""Arista EOS plugin: capability implementations over a ``CommandTransport``.

EOS-specific notes
------------------
- netmiko ``device_type``: ``arista_eos``
- ntc-templates platform key: ``arista_eos``
- No CDP support on EOS — ``NEIGHBORS_CDP`` is intentionally absent from the
  declared capability set (EOS uses LLDP exclusively for L2 neighbor discovery).
- ``show version`` on EOS does **not** emit ``hostname``; :meth:`EosDiscoverySsh`
  returns a placeholder hostname (serial > sys_mac > model) from the CLI path.
  SNMP discovery (``sysName``) provides the authoritative hostname.
- ``show ip route`` PROTOCOL is multi-token for eBGP/iBGP (``"B E"`` / ``"B I"``).

Command strings live in module-level ``SHOW_*`` constants — the single
source of command text for this plugin (REPO-STRUCTURE §6 step 7).
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
from app.plugins.vendors.eos import parsers
from app.plugins.vendors.eos.parsers import (
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
    "EosAcl",
    "EosBgp",
    "EosConfigBackup",
    "EosDiscoverySnmp",
    "EosDiscoverySsh",
    "EosInterfaces",
    "EosNeighbors",
    "EosOspf",
    "EosPlugin",
    "EosRoutes",
]

VENDOR_ID = "eos"

# Command text — must match the ntc-templates index entries for arista_eos.
SHOW_VERSION = "show version"
SHOW_INTERFACES = "show interfaces"
SHOW_IP_ROUTE = "show ip route"
SHOW_LLDP_NEIGHBORS_DETAIL = "show lldp neighbors detail"
SHOW_RUNNING_CONFIG = "show running-config"
SHOW_IP_BGP_SUMMARY = "show ip bgp summary"
SHOW_IP_OSPF_NEIGHBOR = "show ip ospf neighbor"
SHOW_IP_ACCESS_LISTS = "show ip access-lists"

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
    :class:`DeviceFacts` carries a non-empty placeholder hostname (serial >
    sys_mac > model) when using the SSH path.  Use SNMP discovery
    (``sysName``) for authoritative hostname resolution.
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


class EosBgp(_EosCommandCapability, BgpCapability):
    """``BGP``: ``show ip bgp summary`` → :class:`NormalizedBgpPeer`.

    EOS uses separate ``state`` and ``state_pfxrcd`` columns in the TextFSM
    template (unlike IOS which overloads a single column).
    """

    def get_bgp_peers(self) -> list[NormalizedBgpPeer]:
        """Collect and normalize the IPv4-unicast BGP peering sessions."""
        output = self._run(SHOW_IP_BGP_SUMMARY)
        records = parsers.parse_bgp_peers(
            output, device_id=self._device_id, collected_at=self._now()
        )
        return [r.model_copy(update={"source_vendor": VENDOR_ID}) for r in records]


class EosOspf(_EosCommandCapability, OspfCapability):
    """``OSPF``: ``show ip ospf neighbor`` → :class:`NormalizedOspfNeighbor`.

    EOS emits plain uppercase state tokens (``FULL``, ``2WAY``, …) without
    the ``/DR``-role suffix seen in IOS output.
    """

    def get_ospf_neighbors(self) -> list[NormalizedOspfNeighbor]:
        """Collect and normalize the OSPF neighbor adjacencies."""
        output = self._run(SHOW_IP_OSPF_NEIGHBOR)
        records = parsers.parse_ospf_neighbors(
            output, device_id=self._device_id, collected_at=self._now()
        )
        return [r.model_copy(update={"source_vendor": VENDOR_ID}) for r in records]


class EosAcl(_EosCommandCapability, AclCapability):
    """``ACL``: ``show ip access-lists`` → :class:`NormalizedAclEntry`.

    EOS uses CIDR notation for network prefixes and the ``modifier`` field for
    destination port matches; host entries use the ``host <ip>`` form.
    """

    def get_acls(self) -> list[NormalizedAclEntry]:
        """Collect and normalize the configured IP access-list entries."""
        output = self._run(SHOW_IP_ACCESS_LISTS)
        records = parsers.parse_acls(output, device_id=self._device_id, collected_at=self._now())
        return [r.model_copy(update={"source_vendor": VENDOR_ID}) for r in records]


class EosConfigBackup(_EosCommandCapability, ConfigBackupCapability):
    """``CONFIG_BACKUP``: ``show running-config`` returned verbatim.

    EOS ``show running-config`` emits the full running configuration as plain
    text over SSH (``arista_eos`` netmiko device_type).  The output is
    returned unchanged — no trimming, no redaction — per ADR-0017 verbatim
    storage requirement.  Redaction happens only at the LLM boundary
    (``llm/redaction.py``, ADR-0017 §5).
    """

    def fetch_running_config(self) -> str:
        """Return the running configuration exactly as the device emitted it."""
        output = self._run(SHOW_RUNNING_CONFIG)
        if not output.strip():
            raise PluginError(
                f"eos: {SHOW_RUNNING_CONFIG!r} returned empty output for device {self._device_id}"
            )
        return output


class EosPlugin(VendorPlugin):
    """Arista EOS (``vendor_id="eos"``) — leaf/spine switching plugin.

    Declares: SSH/SNMP discovery, interface inventory, route collection,
    LLDP neighbors, and the M3 troubleshooting trio (BGP/OSPF/ACL).
    CDP is intentionally absent — EOS does not implement it.
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
            Capability.BGP,
            Capability.OSPF,
            Capability.ACL,
            Capability.CONFIG_BACKUP,
        }
    )

    def _capability_classes(self) -> Mapping[Capability, type[PluginCapability]]:
        return {
            Capability.DISCOVERY_SSH: EosDiscoverySsh,
            Capability.DISCOVERY_SNMP: EosDiscoverySnmp,
            Capability.INTERFACES: EosInterfaces,
            Capability.ROUTES: EosRoutes,
            Capability.NEIGHBORS_LLDP: EosNeighbors,
            Capability.BGP: EosBgp,
            Capability.OSPF: EosOspf,
            Capability.ACL: EosAcl,
            Capability.CONFIG_BACKUP: EosConfigBackup,
        }
