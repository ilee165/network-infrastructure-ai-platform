"""Tests for the eos plugin: parsing recorded fixture text.

A FakeTransport replays sanitized recorded ``show`` output from
``tests/plugins/fixtures/eos/`` — no device, no network (D16, REPO-STRUCTURE §5).
"""

from __future__ import annotations

from ipaddress import IPv4Address, IPv4Interface, IPv4Network
from pathlib import Path
from uuid import UUID, uuid4

import pytest

from app.core.errors import PluginError
from app.plugins.base import Capability, CommandTransport
from app.plugins.vendors.eos import parsers
from app.plugins.vendors.eos.plugin import (
    SHOW_INTERFACES,
    SHOW_IP_ROUTE,
    SHOW_LLDP_NEIGHBORS_DETAIL,
    SHOW_RUNNING_CONFIG,
    SHOW_VERSION,
    EosConfigBackup,
    EosInterfaces,
    EosNeighbors,
    EosPlugin,
    EosRoutes,
)
from app.schemas.normalized import (
    InterfaceAdminStatus,
    InterfaceOperStatus,
    NeighborProtocol,
    RouteProtocol,
)

FIXTURES = Path(__file__).parent / "fixtures" / "eos"


def _fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


class FakeTransport:
    """In-memory CommandTransport replaying recorded device output."""

    def __init__(self, responses: dict[str, str]) -> None:
        self._responses = dict(responses)
        self.commands: list[str] = []

    def send_command(self, command: str) -> str:
        self.commands.append(command)
        try:
            return self._responses[command]
        except KeyError:  # pragma: no cover - signals a broken test setup
            raise AssertionError(f"unexpected command sent to device: {command!r}") from None


@pytest.fixture()
def device_id() -> UUID:
    return uuid4()


@pytest.fixture()
def transport() -> FakeTransport:
    return FakeTransport(
        {
            SHOW_VERSION: _fixture("show_version.txt"),
            SHOW_INTERFACES: _fixture("show_interfaces.txt"),
            SHOW_IP_ROUTE: _fixture("show_ip_route.txt"),
            SHOW_LLDP_NEIGHBORS_DETAIL: _fixture("show_lldp_neighbors_detail.txt"),
        }
    )


class TestPluginDeclaration:
    def test_plugin_identity_and_declared_capabilities(self) -> None:
        plugin = EosPlugin()
        assert plugin.vendor_id == "eos"
        assert plugin.display_name == "Arista EOS"
        assert plugin.capabilities == frozenset(
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
                Capability.CONFIG_RESTORE,
                Capability.CONFIG_DEPLOY,
            }
        )

    def test_neighbors_cdp_not_declared(self) -> None:
        """EOS does not support CDP — must not be in capabilities."""
        plugin = EosPlugin()
        assert Capability.NEIGHBORS_CDP not in plugin.capabilities
        with pytest.raises(PluginError, match="does not implement"):
            plugin.get_capability(Capability.NEIGHBORS_CDP)

    def test_lldp_resolves_to_eos_neighbors(self) -> None:
        from app.plugins.vendors.eos.plugin import EosNeighbors

        plugin = EosPlugin()
        assert plugin.get_capability(Capability.NEIGHBORS_LLDP) is EosNeighbors

    def test_fake_transport_satisfies_the_command_transport_protocol(
        self, transport: FakeTransport
    ) -> None:
        assert isinstance(transport, CommandTransport)


class TestDeviceFacts:
    def test_parse_device_facts_fields(self) -> None:
        # parsers.parse_device_facts stamps the ntc-templates platform key;
        # the plugin layer overwrites vendor_id to "eos" via model_copy.
        facts = parsers.parse_device_facts(_fixture("show_version.txt"))
        assert facts.vendor_id == "arista_eos"  # raw parser output
        assert facts.model == "DCS-7050TX-64"
        assert facts.os_version == "4.28.3M"
        assert facts.serial == "JPE19101327"
        # EOS show version lacks hostname — serial is used as placeholder.
        assert facts.hostname == "JPE19101327"

    def test_parse_device_facts_empty_raises(self) -> None:
        with pytest.raises(PluginError, match="no rows parsed"):
            parsers.parse_device_facts("")

    def test_parse_snmp_device_facts(self) -> None:
        from app.plugins.vendors.eos.parsers import (
            SNMP_OID_SYSDESCR,
            SNMP_OID_SYSNAME,
            SNMP_OID_SYSOBJECTID,
        )

        values = {
            SNMP_OID_SYSDESCR: "Arista Networks EOS version 4.28.3M running on DCS-7050TX-64",
            SNMP_OID_SYSOBJECTID: "1.3.6.1.4.1.30065.1.3011.7050",
            SNMP_OID_SYSNAME: "leaf01.example.net",
        }
        facts = parsers.parse_snmp_device_facts(values)
        assert facts.hostname == "leaf01.example.net"
        assert facts.vendor_id == "arista_eos"
        assert facts.os_version == "4.28.3M"
        assert facts.model is None
        assert facts.serial is None

    def test_parse_snmp_device_facts_missing_sysname_raises(self) -> None:
        with pytest.raises(PluginError, match="no sysName"):
            parsers.parse_snmp_device_facts({})


class TestInterfaces:
    def test_get_interfaces_normalizes_all(self, transport: FakeTransport, device_id: UUID) -> None:
        interfaces = EosInterfaces(transport, device_id).get_interfaces()
        assert [i.name for i in interfaces] == [
            "Ethernet1",
            "Ethernet2",
            "Ethernet3",
            "Management0",
        ]

    def test_ethernet1_field_mapping(self, transport: FakeTransport, device_id: UUID) -> None:
        eth1 = EosInterfaces(transport, device_id).get_interfaces()[0]
        assert eth1.description == "uplink-to-spine01"
        assert eth1.admin_status is InterfaceAdminStatus.UP
        assert eth1.oper_status is InterfaceOperStatus.UP
        assert eth1.ip_address == IPv4Interface("10.0.0.1/30")
        assert eth1.mtu == 9214
        assert eth1.speed_mbps == 10000

    def test_admin_down_interface(self, transport: FakeTransport, device_id: UUID) -> None:
        eth3 = EosInterfaces(transport, device_id).get_interfaces()[2]
        assert eth3.name == "Ethernet3"
        assert eth3.admin_status is InterfaceAdminStatus.DOWN
        assert eth3.oper_status is InterfaceOperStatus.DOWN
        assert eth3.ip_address is None

    def test_get_interfaces_stamps_provenance(
        self, transport: FakeTransport, device_id: UUID
    ) -> None:
        eth1 = EosInterfaces(transport, device_id).get_interfaces()[0]
        assert eth1.device_id == device_id
        assert eth1.source_vendor == "eos"  # plugin vendor_id, not parser PLATFORM
        assert eth1.collected_at.tzinfo is not None

    def test_get_interfaces_records_raw_output(
        self, transport: FakeTransport, device_id: UUID
    ) -> None:
        cap = EosInterfaces(transport, device_id)
        cap.get_interfaces()
        assert len(cap.raw_outputs) == 1
        assert cap.raw_outputs[0].command == SHOW_INTERFACES
        assert cap.raw_outputs[0].output == _fixture("show_interfaces.txt")

    def test_parse_interfaces_invalid_input_raises(self, device_id: UUID) -> None:
        # EOS textfsm template uses Error on unrecognized lines — raises PluginError.
        from datetime import UTC, datetime

        with pytest.raises(PluginError, match="failed to parse"):
            parsers.parse_interfaces(
                "% Invalid input detected\n", device_id=device_id, collected_at=datetime.now(UTC)
            )

    def test_parse_failure_raises_plugin_error(
        self, transport: FakeTransport, device_id: UUID, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from ntc_templates.parse import ParsingException

        def _boom(**kwargs: object) -> None:
            raise ParsingException("template error")

        monkeypatch.setattr(parsers, "parse_output", _boom)
        with pytest.raises(PluginError, match="failed to parse"):
            EosInterfaces(transport, device_id).get_interfaces()


class TestRoutes:
    def test_get_routes_count(self, transport: FakeTransport, device_id: UUID) -> None:
        routes = EosRoutes(transport, device_id).get_routes()
        assert len(routes) == 6

    def test_static_default_route(self, transport: FakeTransport, device_id: UUID) -> None:
        default = EosRoutes(transport, device_id).get_routes()[0]
        assert default.destination == IPv4Network("0.0.0.0/0")
        assert default.protocol is RouteProtocol.STATIC
        assert default.next_hop == IPv4Address("10.0.0.2")
        assert default.distance == 1
        assert default.metric == 0

    def test_connected_route_no_next_hop(self, transport: FakeTransport, device_id: UUID) -> None:
        routes = EosRoutes(transport, device_id).get_routes()
        connected = next(r for r in routes if r.destination == IPv4Network("10.0.0.0/30"))
        assert connected.protocol is RouteProtocol.CONNECTED
        assert connected.next_hop is None
        assert connected.interface == "Ethernet1"

    def test_ospf_route(self, transport: FakeTransport, device_id: UUID) -> None:
        routes = EosRoutes(transport, device_id).get_routes()
        ospf = next(r for r in routes if r.protocol is RouteProtocol.OSPF)
        assert ospf.destination == IPv4Network("10.10.0.0/24")
        assert ospf.distance == 110
        assert ospf.metric == 20

    def test_bgp_route(self, transport: FakeTransport, device_id: UUID) -> None:
        routes = EosRoutes(transport, device_id).get_routes()
        bgp = next(r for r in routes if r.protocol is RouteProtocol.BGP)
        assert bgp.destination == IPv4Network("10.20.0.0/16")
        assert bgp.next_hop == IPv4Address("172.16.0.1")

    def test_vrf_is_default(self, transport: FakeTransport, device_id: UUID) -> None:
        routes = EosRoutes(transport, device_id).get_routes()
        assert all(r.vrf == "default" for r in routes)

    def test_routes_stamps_provenance(self, transport: FakeTransport, device_id: UUID) -> None:
        route = EosRoutes(transport, device_id).get_routes()[0]
        assert route.device_id == device_id
        assert route.source_vendor == "eos"


class TestLldpNeighbors:
    def test_get_lldp_neighbors_count(self, transport: FakeTransport, device_id: UUID) -> None:
        neighbors = EosNeighbors(transport, device_id).get_lldp_neighbors()
        assert len(neighbors) == 2

    def test_first_neighbor_fields(self, transport: FakeTransport, device_id: UUID) -> None:
        first = EosNeighbors(transport, device_id).get_lldp_neighbors()[0]
        assert first.protocol is NeighborProtocol.LLDP
        assert first.local_interface == "Ethernet1"
        assert first.neighbor_name == "spine01.example.net"
        assert first.neighbor_interface == "Ethernet49/1"
        assert first.neighbor_address == IPv4Address("10.0.255.1")
        assert "EOS" in (first.neighbor_platform or "")

    def test_second_neighbor_fields(self, transport: FakeTransport, device_id: UUID) -> None:
        second = EosNeighbors(transport, device_id).get_lldp_neighbors()[1]
        assert second.local_interface == "Ethernet2"
        assert second.neighbor_name == "spine02.example.net"
        assert second.neighbor_address == IPv4Address("10.0.255.2")

    def test_get_cdp_neighbors_returns_empty(
        self, transport: FakeTransport, device_id: UUID
    ) -> None:
        """EOS has no CDP; get_cdp_neighbors always returns []."""
        assert EosNeighbors(transport, device_id).get_cdp_neighbors() == []

    def test_lldp_records_raw_output(self, transport: FakeTransport, device_id: UUID) -> None:
        cap = EosNeighbors(transport, device_id)
        cap.get_lldp_neighbors()
        assert len(cap.raw_outputs) == 1
        assert cap.raw_outputs[0].command == SHOW_LLDP_NEIGHBORS_DETAIL

    def test_neighbors_stamps_provenance(self, transport: FakeTransport, device_id: UUID) -> None:
        first = EosNeighbors(transport, device_id).get_lldp_neighbors()[0]
        assert first.device_id == device_id
        assert first.source_vendor == "eos"


class TestConfigBackup:
    def test_fetch_running_config_returns_verbatim_text(
        self, transport: FakeTransport, device_id: UUID
    ) -> None:
        full_transport = FakeTransport(
            {
                SHOW_VERSION: _fixture("show_version.txt"),
                SHOW_INTERFACES: _fixture("show_interfaces.txt"),
                SHOW_IP_ROUTE: _fixture("show_ip_route.txt"),
                SHOW_LLDP_NEIGHBORS_DETAIL: _fixture("show_lldp_neighbors_detail.txt"),
                SHOW_RUNNING_CONFIG: _fixture("show_running_config.txt"),
            }
        )
        capability = EosConfigBackup(full_transport, device_id)
        config = capability.fetch_running_config()
        assert config == _fixture("show_running_config.txt")
        assert "hostname leaf01" in config
        assert capability.raw_outputs[0].command == SHOW_RUNNING_CONFIG
        assert capability.raw_outputs[0].output == config

    def test_fetch_running_config_raises_on_empty_output(self, device_id: UUID) -> None:
        empty = FakeTransport({"show running-config": "   \n"})
        with pytest.raises(PluginError, match="empty output"):
            EosConfigBackup(empty, device_id).fetch_running_config()

    def test_config_backup_resolves_via_plugin(self, device_id: UUID) -> None:
        plugin = EosPlugin()
        assert plugin.get_capability(Capability.CONFIG_BACKUP) is EosConfigBackup
