"""cisco_ios discovery capabilities (M1-09): SSH + SNMP device facts.

Fixture-driven: SSH discovery replays a recorded ``show version``; SNMP
discovery replays recorded system-MIB values. No device, no network (D16).
"""

from __future__ import annotations

from importlib.metadata import entry_points
from pathlib import Path
from uuid import uuid4

import pytest

from app.core.errors import PluginError
from app.plugins.base import (
    Capability,
    CommandTransport,
    DiscoverySnmpCapability,
    DiscoverySshCapability,
    SnmpReadTransport,
)
from app.plugins.registry import ENTRY_POINT_GROUP
from app.plugins.vendors.cisco_ios import parsers
from app.plugins.vendors.cisco_ios.plugin import (
    SNMP_OID_SYSDESCR,
    SNMP_OID_SYSNAME,
    SNMP_OID_SYSOBJECTID,
    CiscoIosDiscoverySnmp,
    CiscoIosDiscoverySsh,
    CiscoIosPlugin,
)
from app.schemas.discovery import DeviceFacts
from tests.plugins.conformance import FixtureReplayTransport, FixtureSnmpTransport

FIXTURES = Path(__file__).parent / "fixtures"

SHOW_VERSION_OUTPUT = (FIXTURES / "show_version.txt").read_text(encoding="utf-8")

#: Recorded system-MIB values of the same lab switch the CLI fixtures cover.
SNMP_SYSTEM_VALUES = {
    SNMP_OID_SYSDESCR: (
        "Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M), "
        "Version 15.0(2)SE11, RELEASE SOFTWARE (fc3)\r\n"
        "Technical Support: http://www.cisco.com/techsupport\r\n"
        "Copyright (c) 1986-2017 by Cisco Systems, Inc."
    ),
    SNMP_OID_SYSOBJECTID: "1.3.6.1.4.1.9.1.716",
    SNMP_OID_SYSNAME: "dist-sw01.example.net",
}


class TestParseDeviceFacts:
    def test_parses_recorded_show_version(self) -> None:
        facts = parsers.parse_device_facts(SHOW_VERSION_OUTPUT)
        assert facts == DeviceFacts(
            hostname="dist-sw01",
            vendor_id="cisco_ios",
            model="WS-C2960-24TT-L",
            os_version="15.0(2)SE11",
            serial="FOC1316W2C4",
        )

    def test_unparseable_output_raises_plugin_error(self) -> None:
        with pytest.raises(PluginError, match="show version"):
            parsers.parse_device_facts("% Invalid input detected at '^' marker.")


class TestParseSnmpDeviceFacts:
    def test_maps_system_mib_values(self) -> None:
        facts = parsers.parse_snmp_device_facts(SNMP_SYSTEM_VALUES)
        assert facts.hostname == "dist-sw01.example.net"
        assert facts.vendor_id == "cisco_ios"
        assert facts.os_version == "15.0(2)SE11"
        assert facts.model == "C2960"
        assert facts.serial is None  # not exposed by the system MIB

    def test_best_effort_fields_default_to_none_without_sysdescr(self) -> None:
        facts = parsers.parse_snmp_device_facts({SNMP_OID_SYSNAME: "core-rtr01"})
        assert facts.hostname == "core-rtr01"
        assert facts.os_version is None
        assert facts.model is None
        assert facts.serial is None

    def test_missing_sysname_raises_plugin_error(self) -> None:
        with pytest.raises(PluginError, match="sysName"):
            parsers.parse_snmp_device_facts({SNMP_OID_SYSDESCR: "Cisco IOS Software"})


class TestCiscoIosDiscoverySsh:
    def test_collects_and_parses_show_version(self) -> None:
        transport = FixtureReplayTransport({"show version": SHOW_VERSION_OUTPUT})
        capability = CiscoIosDiscoverySsh(transport, uuid4())
        facts = capability.get_device_facts()
        assert facts.hostname == "dist-sw01"
        assert facts.vendor_id == "cisco_ios"
        assert transport.commands == ["show version"]

    def test_raw_output_is_preserved_verbatim(self) -> None:
        capability = CiscoIosDiscoverySsh(
            FixtureReplayTransport({"show version": SHOW_VERSION_OUTPUT}), uuid4()
        )
        capability.get_device_facts()
        (raw,) = capability.raw_outputs
        assert raw.command == "show version"
        assert raw.output == SHOW_VERSION_OUTPUT

    def test_is_a_discovery_ssh_capability(self) -> None:
        assert issubclass(CiscoIosDiscoverySsh, DiscoverySshCapability)
        assert CiscoIosDiscoverySsh.capabilities == frozenset({Capability.DISCOVERY_SSH})


class TestCiscoIosDiscoverySnmp:
    def test_collects_and_maps_system_mib(self) -> None:
        transport = FixtureSnmpTransport(SNMP_SYSTEM_VALUES)
        capability = CiscoIosDiscoverySnmp(transport, uuid4())
        facts = capability.get_device_facts()
        assert facts.hostname == "dist-sw01.example.net"
        assert facts.vendor_id == "cisco_ios"
        assert transport.requests == [[SNMP_OID_SYSDESCR, SNMP_OID_SYSOBJECTID, SNMP_OID_SYSNAME]]

    def test_raw_values_are_preserved_for_artifact_storage(self) -> None:
        capability = CiscoIosDiscoverySnmp(FixtureSnmpTransport(SNMP_SYSTEM_VALUES), uuid4())
        capability.get_device_facts()
        (raw,) = capability.raw_outputs
        assert SNMP_OID_SYSNAME in raw.command
        for oid, value in SNMP_SYSTEM_VALUES.items():
            assert oid in raw.output
            assert value in raw.output

    def test_is_a_discovery_snmp_capability(self) -> None:
        assert issubclass(CiscoIosDiscoverySnmp, DiscoverySnmpCapability)
        assert CiscoIosDiscoverySnmp.capabilities == frozenset({Capability.DISCOVERY_SNMP})


class TestFixtureTransportProtocols:
    def test_replay_transport_satisfies_command_transport(self) -> None:
        assert isinstance(FixtureReplayTransport({}), CommandTransport)

    def test_snmp_transport_satisfies_snmp_read_transport(self) -> None:
        assert isinstance(FixtureSnmpTransport({}), SnmpReadTransport)


class TestPluginDeclaration:
    def test_declares_the_full_m1_capability_set(self) -> None:
        assert CiscoIosPlugin.capabilities >= {
            Capability.DISCOVERY_SSH,
            Capability.DISCOVERY_SNMP,
            Capability.INTERFACES,
            Capability.ROUTES,
            Capability.NEIGHBORS_LLDP,
            Capability.NEIGHBORS_CDP,
        }

    def test_discovery_capabilities_resolve(self) -> None:
        plugin = CiscoIosPlugin()
        assert plugin.get_capability(Capability.DISCOVERY_SSH) is CiscoIosDiscoverySsh
        assert plugin.get_capability(Capability.DISCOVERY_SNMP) is CiscoIosDiscoverySnmp


class TestEntryPointRegistration:
    def test_cisco_ios_entry_point_loads_the_plugin_class(self) -> None:
        eps = {ep.name: ep for ep in entry_points(group=ENTRY_POINT_GROUP)}
        assert "cisco_ios" in eps, (
            f"entry point 'cisco_ios' missing from group {ENTRY_POINT_GROUP!r} "
            "(run: pip install -e . --no-deps to refresh metadata)"
        )
        assert eps["cisco_ios"].load() is CiscoIosPlugin
