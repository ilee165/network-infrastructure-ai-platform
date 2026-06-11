"""Tests for the cisco_iosxe plugin: parsing recorded Cat9k/CSR fixture text.

A FakeTransport replays sanitized recorded ``show`` output from
``tests/plugins/fixtures/cisco_iosxe/`` — no device, no network (D16,
REPO-STRUCTURE §5).
"""

from __future__ import annotations

from ipaddress import IPv4Address, IPv4Interface, IPv4Network
from pathlib import Path
from uuid import UUID, uuid4

import pytest

from app.core.errors import PluginError
from app.plugins.base import Capability, CommandTransport
from app.plugins.vendors.cisco_iosxe.plugin import (
    SHOW_INTERFACES,
    SHOW_RUNNING_CONFIG,
    SHOW_VERSION,
    CiscoIosXeConfigBackup,
    CiscoIosXeDiscoverySsh,
    CiscoIosXeInterfaces,
    CiscoIosXeNeighbors,
    CiscoIosXePlugin,
    CiscoIosXeRoutes,
)
from app.schemas.normalized import (
    InterfaceAdminStatus,
    InterfaceDuplex,
    InterfaceOperStatus,
    NeighborProtocol,
    RouteProtocol,
)

FIXTURES = Path(__file__).parent / "fixtures" / "cisco_iosxe"


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
            "show version": _fixture("show_version.txt"),
            "show interfaces": _fixture("show_interfaces.txt"),
            "show ip route": _fixture("show_ip_route.txt"),
            "show cdp neighbors detail": _fixture("show_cdp_neighbors_detail.txt"),
            "show lldp neighbors detail": _fixture("show_lldp_neighbors_detail.txt"),
            "show running-config": _fixture("show_running_config.txt"),
        }
    )


class TestPluginDeclaration:
    def test_plugin_identity_and_declared_capabilities(self) -> None:
        plugin = CiscoIosXePlugin()
        assert plugin.vendor_id == "cisco_iosxe"
        assert plugin.display_name == "Cisco IOS-XE"
        assert plugin.capabilities == frozenset(
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

    def test_both_neighbor_capabilities_resolve_to_the_same_class(self) -> None:
        plugin = CiscoIosXePlugin()
        assert plugin.get_capability(Capability.NEIGHBORS_LLDP) is CiscoIosXeNeighbors
        assert plugin.get_capability(Capability.NEIGHBORS_CDP) is CiscoIosXeNeighbors

    def test_undeclared_capability_fails_fast(self) -> None:
        plugin = CiscoIosXePlugin()
        with pytest.raises(PluginError, match="does not implement"):
            plugin.get_capability(Capability.BGP)

    def test_fake_transport_satisfies_the_command_transport_protocol(
        self, transport: FakeTransport
    ) -> None:
        assert isinstance(transport, CommandTransport)


class TestDiscoverySsh:
    def test_get_device_facts_parses_cat9k_show_version(
        self, transport: FakeTransport, device_id: UUID
    ) -> None:
        facts = CiscoIosXeDiscoverySsh(transport, device_id).get_device_facts()
        assert facts.hostname == "core-sw01"
        assert facts.vendor_id == "cisco_iosxe"
        assert facts.model == "C9300-48U"
        assert facts.os_version == "17.6.4"
        assert facts.serial == "FCW2152H0VF"

    def test_get_device_facts_records_raw_output(
        self, transport: FakeTransport, device_id: UUID
    ) -> None:
        capability = CiscoIosXeDiscoverySsh(transport, device_id)
        capability.get_device_facts()
        assert len(capability.raw_outputs) == 1
        assert capability.raw_outputs[0].command == SHOW_VERSION
        assert capability.raw_outputs[0].output == _fixture("show_version.txt")


class TestInterfaces:
    def test_get_interfaces_normalizes_all_blocks(
        self, transport: FakeTransport, device_id: UUID
    ) -> None:
        interfaces = CiscoIosXeInterfaces(transport, device_id).get_interfaces()
        assert [i.name for i in interfaces] == [
            "GigabitEthernet1/0/1",
            "GigabitEthernet1/0/2",
            "GigabitEthernet1/0/48",
        ]

    def test_get_interfaces_field_mapping(self, transport: FakeTransport, device_id: UUID) -> None:
        gi1 = CiscoIosXeInterfaces(transport, device_id).get_interfaces()[0]
        assert gi1.description == "uplink to core-rtr01"
        assert gi1.admin_status is InterfaceAdminStatus.UP
        assert gi1.oper_status is InterfaceOperStatus.UP
        assert gi1.ip_address == IPv4Interface("10.0.0.1/30")
        assert gi1.mac_address == "a8:9d:21:f0:00:81"
        assert gi1.mtu == 1500
        assert gi1.speed_mbps == 1000
        assert gi1.duplex is InterfaceDuplex.FULL
        assert gi1.input_errors == 2
        assert gi1.output_errors == 0

    def test_get_interfaces_detects_admin_down(
        self, transport: FakeTransport, device_id: UUID
    ) -> None:
        gi48 = CiscoIosXeInterfaces(transport, device_id).get_interfaces()[2]
        assert gi48.admin_status is InterfaceAdminStatus.DOWN
        assert gi48.oper_status is InterfaceOperStatus.DOWN
        assert gi48.duplex is InterfaceDuplex.AUTO
        assert gi48.ip_address is None
        assert gi48.description == "reserved for OOB mgmt"

    def test_get_interfaces_stamps_vendor_id(
        self, transport: FakeTransport, device_id: UUID
    ) -> None:
        gi1 = CiscoIosXeInterfaces(transport, device_id).get_interfaces()[0]
        assert gi1.source_vendor == "cisco_iosxe"
        assert gi1.device_id == device_id
        assert gi1.collected_at.tzinfo is not None

    def test_get_interfaces_records_raw_output_verbatim(
        self, transport: FakeTransport, device_id: UUID
    ) -> None:
        capability = CiscoIosXeInterfaces(transport, device_id)
        capability.get_interfaces()
        assert len(capability.raw_outputs) == 1
        assert capability.raw_outputs[0].command == SHOW_INTERFACES
        assert capability.raw_outputs[0].output == _fixture("show_interfaces.txt")


class TestRoutes:
    def test_get_routes_normalizes_the_full_table(
        self, transport: FakeTransport, device_id: UUID
    ) -> None:
        routes = CiscoIosXeRoutes(transport, device_id).get_routes()
        assert len(routes) == 7

    def test_static_default_route(self, transport: FakeTransport, device_id: UUID) -> None:
        default = CiscoIosXeRoutes(transport, device_id).get_routes()[0]
        assert default.destination == IPv4Network("0.0.0.0/0")
        assert default.protocol is RouteProtocol.STATIC
        assert default.next_hop == IPv4Address("10.0.0.2")
        assert default.distance == 1
        assert default.metric == 0

    def test_connected_route_has_interface_and_no_next_hop(
        self, transport: FakeTransport, device_id: UUID
    ) -> None:
        routes = CiscoIosXeRoutes(transport, device_id).get_routes()
        connected = next(r for r in routes if r.destination == IPv4Network("10.0.0.0/30"))
        assert connected.protocol is RouteProtocol.CONNECTED
        assert connected.next_hop is None
        assert connected.interface == "GigabitEthernet1/0/1"

    def test_ospf_and_bgp_routes_carry_distance_and_metric(
        self, transport: FakeTransport, device_id: UUID
    ) -> None:
        routes = CiscoIosXeRoutes(transport, device_id).get_routes()
        ospf = next(r for r in routes if r.protocol is RouteProtocol.OSPF)
        assert (ospf.distance, ospf.metric) == (110, 2)
        assert ospf.next_hop == IPv4Address("10.0.0.2")
        bgp = next(r for r in routes if r.protocol is RouteProtocol.BGP)
        assert bgp.destination == IPv4Network("10.2.0.0/16")

    def test_routes_stamp_vendor_id(self, transport: FakeTransport, device_id: UUID) -> None:
        routes = CiscoIosXeRoutes(transport, device_id).get_routes()
        assert all(r.source_vendor == "cisco_iosxe" for r in routes)


class TestNeighbors:
    def test_get_cdp_neighbors(self, transport: FakeTransport, device_id: UUID) -> None:
        neighbors = CiscoIosXeNeighbors(transport, device_id).get_cdp_neighbors()
        assert len(neighbors) == 2
        first = neighbors[0]
        assert first.protocol is NeighborProtocol.CDP
        assert first.local_interface == "GigabitEthernet1/0/1"
        assert first.neighbor_name == "core-rtr01.example.net"
        assert first.neighbor_interface == "GigabitEthernet1"
        assert first.neighbor_address == IPv4Address("10.0.0.2")
        assert first.neighbor_platform == "cisco CSR1000V"
        assert first.neighbor_capabilities == ("Router", "Source-Route-Bridge")

    def test_get_lldp_neighbors(self, transport: FakeTransport, device_id: UUID) -> None:
        neighbors = CiscoIosXeNeighbors(transport, device_id).get_lldp_neighbors()
        assert len(neighbors) == 2
        first = neighbors[0]
        assert first.protocol is NeighborProtocol.LLDP
        assert first.local_interface == "Gi1/0/1"
        assert first.neighbor_name == "core-rtr01.example.net"
        assert first.neighbor_interface == "Gi1"
        assert first.neighbor_address == IPv4Address("10.0.0.2")
        assert first.neighbor_capabilities == ("R",)

    def test_neighbors_stamp_vendor_id(self, transport: FakeTransport, device_id: UUID) -> None:
        cdp = CiscoIosXeNeighbors(transport, device_id).get_cdp_neighbors()
        assert all(n.source_vendor == "cisco_iosxe" for n in cdp)

    def test_one_instance_serves_both_protocols_and_records_both_commands(
        self, transport: FakeTransport, device_id: UUID
    ) -> None:
        capability = CiscoIosXeNeighbors(transport, device_id)
        capability.get_lldp_neighbors()
        capability.get_cdp_neighbors()
        assert [raw.command for raw in capability.raw_outputs] == [
            "show lldp neighbors detail",
            "show cdp neighbors detail",
        ]


class TestConfigBackup:
    def test_fetch_running_config_returns_verbatim_text(
        self, transport: FakeTransport, device_id: UUID
    ) -> None:
        capability = CiscoIosXeConfigBackup(transport, device_id)
        config = capability.fetch_running_config()
        assert config == _fixture("show_running_config.txt")
        assert "hostname core-sw01" in config
        assert capability.raw_outputs[0].command == SHOW_RUNNING_CONFIG
        assert capability.raw_outputs[0].output == config

    def test_fetch_running_config_raises_on_empty_output(self, device_id: UUID) -> None:
        empty = FakeTransport({"show running-config": "   \n"})
        with pytest.raises(PluginError, match="empty output"):
            CiscoIosXeConfigBackup(empty, device_id).fetch_running_config()
