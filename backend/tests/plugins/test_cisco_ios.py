"""Tests for the cisco_ios reference plugin: parsing recorded fixture text.

A FakeTransport replays sanitized recorded ``show`` output from
``tests/plugins/fixtures/`` — no device, no network (D16, REPO-STRUCTURE §5).
"""

from __future__ import annotations

from ipaddress import IPv4Address, IPv4Interface, IPv4Network
from pathlib import Path
from uuid import UUID, uuid4

import pytest

from app.core.errors import PluginError
from app.plugins.base import Capability, CommandTransport
from app.plugins.vendors.cisco_ios import parsers
from app.plugins.vendors.cisco_ios.plugin import (
    SHOW_INTERFACES,
    SHOW_RUNNING_CONFIG,
    CiscoIosConfigBackup,
    CiscoIosInterfaces,
    CiscoIosNeighbors,
    CiscoIosPlugin,
    CiscoIosRoutes,
)
from app.schemas.normalized import (
    InterfaceAdminStatus,
    InterfaceDuplex,
    InterfaceOperStatus,
    NeighborProtocol,
    RouteProtocol,
)

FIXTURES = Path(__file__).parent / "fixtures"


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
            "show interfaces": _fixture("show_interfaces.txt"),
            "show ip route": _fixture("show_ip_route.txt"),
            "show cdp neighbors detail": _fixture("show_cdp_neighbors_detail.txt"),
            "show lldp neighbors detail": _fixture("show_lldp_neighbors_detail.txt"),
            "show running-config": _fixture("show_running_config.txt"),
        }
    )


class TestPluginDeclaration:
    def test_plugin_identity_and_declared_capabilities(self) -> None:
        plugin = CiscoIosPlugin()
        assert plugin.vendor_id == "cisco_ios"
        assert plugin.display_name == "Cisco IOS"
        assert plugin.capabilities == frozenset(
            {
                Capability.INTERFACES,
                Capability.ROUTES,
                Capability.NEIGHBORS_LLDP,
                Capability.NEIGHBORS_CDP,
                Capability.CONFIG_BACKUP,
            }
        )

    def test_both_neighbor_capabilities_resolve_to_the_same_class(self) -> None:
        plugin = CiscoIosPlugin()
        assert plugin.get_capability(Capability.NEIGHBORS_LLDP) is CiscoIosNeighbors
        assert plugin.get_capability(Capability.NEIGHBORS_CDP) is CiscoIosNeighbors

    def test_undeclared_capability_fails_fast(self) -> None:
        plugin = CiscoIosPlugin()
        with pytest.raises(PluginError, match="does not implement"):
            plugin.get_capability(Capability.BGP)

    def test_fake_transport_satisfies_the_command_transport_protocol(
        self, transport: FakeTransport
    ) -> None:
        assert isinstance(transport, CommandTransport)


class TestInterfaces:
    def test_get_interfaces_normalizes_all_blocks(
        self, transport: FakeTransport, device_id: UUID
    ) -> None:
        interfaces = CiscoIosInterfaces(transport, device_id).get_interfaces()
        assert [i.name for i in interfaces] == [
            "GigabitEthernet0/0",
            "GigabitEthernet0/1",
            "GigabitEthernet0/2",
        ]

    def test_get_interfaces_field_mapping(self, transport: FakeTransport, device_id: UUID) -> None:
        gi0 = CiscoIosInterfaces(transport, device_id).get_interfaces()[0]
        assert gi0.description == "WAN uplink to edge-rtr01"
        assert gi0.admin_status is InterfaceAdminStatus.UP
        assert gi0.oper_status is InterfaceOperStatus.UP
        assert gi0.ip_address == IPv4Interface("192.0.2.10/30")
        assert gi0.mac_address == "52:54:00:12:34:56"
        assert gi0.mtu == 1500
        assert gi0.speed_mbps == 1000
        assert gi0.duplex is InterfaceDuplex.FULL
        assert gi0.input_errors == 3
        assert gi0.output_errors == 0

    def test_get_interfaces_detects_admin_down(
        self, transport: FakeTransport, device_id: UUID
    ) -> None:
        gi2 = CiscoIosInterfaces(transport, device_id).get_interfaces()[2]
        assert gi2.admin_status is InterfaceAdminStatus.DOWN
        assert gi2.oper_status is InterfaceOperStatus.DOWN
        assert gi2.duplex is InterfaceDuplex.AUTO
        assert gi2.ip_address is None
        assert gi2.description == "spare port"

    def test_get_interfaces_stamps_provenance(
        self, transport: FakeTransport, device_id: UUID
    ) -> None:
        gi0 = CiscoIosInterfaces(transport, device_id).get_interfaces()[0]
        assert gi0.device_id == device_id
        assert gi0.source_vendor == "cisco_ios"
        assert gi0.collected_at.tzinfo is not None

    def test_get_interfaces_records_raw_output_verbatim(
        self, transport: FakeTransport, device_id: UUID
    ) -> None:
        capability = CiscoIosInterfaces(transport, device_id)
        capability.get_interfaces()
        assert len(capability.raw_outputs) == 1
        assert capability.raw_outputs[0].command == SHOW_INTERFACES
        assert capability.raw_outputs[0].output == _fixture("show_interfaces.txt")

    def test_parse_interfaces_returns_empty_for_unrecognized_text(self, device_id: UUID) -> None:
        from datetime import UTC, datetime

        result = parsers.parse_interfaces(
            "% Invalid input detected\n", device_id=device_id, collected_at=datetime.now(UTC)
        )
        assert result == []

    def test_parse_failure_raises_plugin_error(
        self, transport: FakeTransport, device_id: UUID, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from ntc_templates.parse import ParsingException

        def _boom(**kwargs: object) -> None:
            raise ParsingException("template error")

        monkeypatch.setattr(parsers, "parse_output", _boom)
        with pytest.raises(PluginError, match="failed to parse"):
            CiscoIosInterfaces(transport, device_id).get_interfaces()


class TestRoutes:
    def test_get_routes_normalizes_the_full_table(
        self, transport: FakeTransport, device_id: UUID
    ) -> None:
        routes = CiscoIosRoutes(transport, device_id).get_routes()
        assert len(routes) == 7

    def test_static_default_route(self, transport: FakeTransport, device_id: UUID) -> None:
        default = CiscoIosRoutes(transport, device_id).get_routes()[0]
        assert default.destination == IPv4Network("0.0.0.0/0")
        assert default.protocol is RouteProtocol.STATIC
        assert default.next_hop == IPv4Address("192.0.2.9")
        assert default.distance == 1
        assert default.metric == 0

    def test_connected_route_has_interface_and_no_next_hop(
        self, transport: FakeTransport, device_id: UUID
    ) -> None:
        routes = CiscoIosRoutes(transport, device_id).get_routes()
        connected = next(r for r in routes if r.destination == IPv4Network("10.10.0.0/24"))
        assert connected.protocol is RouteProtocol.CONNECTED
        assert connected.next_hop is None
        assert connected.interface == "GigabitEthernet0/1"

    def test_ospf_and_bgp_routes_carry_distance_and_metric(
        self, transport: FakeTransport, device_id: UUID
    ) -> None:
        routes = CiscoIosRoutes(transport, device_id).get_routes()
        ospf = next(r for r in routes if r.protocol is RouteProtocol.OSPF)
        assert (ospf.distance, ospf.metric) == (110, 20)
        assert ospf.next_hop == IPv4Address("10.10.0.2")
        bgp = next(r for r in routes if r.protocol is RouteProtocol.BGP)
        assert bgp.destination == IPv4Network("10.30.0.0/16")


class TestNeighbors:
    def test_get_cdp_neighbors(self, transport: FakeTransport, device_id: UUID) -> None:
        neighbors = CiscoIosNeighbors(transport, device_id).get_cdp_neighbors()
        assert len(neighbors) == 2
        first = neighbors[0]
        assert first.protocol is NeighborProtocol.CDP
        assert first.local_interface == "GigabitEthernet0/1"
        assert first.neighbor_name == "dist-sw01.example.net"
        assert first.neighbor_interface == "GigabitEthernet1/0/24"
        assert first.neighbor_address == IPv4Address("10.10.0.2")
        assert first.neighbor_platform == "cisco WS-C3850-24T"
        assert first.neighbor_capabilities == ("Switch", "IGMP")

    def test_get_lldp_neighbors(self, transport: FakeTransport, device_id: UUID) -> None:
        neighbors = CiscoIosNeighbors(transport, device_id).get_lldp_neighbors()
        assert len(neighbors) == 2
        first = neighbors[0]
        assert first.protocol is NeighborProtocol.LLDP
        assert first.local_interface == "Gi0/1"
        assert first.neighbor_name == "leaf-sw02.example.net"
        assert first.neighbor_interface == "Et48"
        assert first.neighbor_address == IPv4Address("10.10.0.3")
        assert first.neighbor_capabilities == ("B", "R")

    def test_one_instance_serves_both_protocols_and_records_both_commands(
        self, transport: FakeTransport, device_id: UUID
    ) -> None:
        capability = CiscoIosNeighbors(transport, device_id)
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
        capability = CiscoIosConfigBackup(transport, device_id)
        config = capability.fetch_running_config()
        assert config == _fixture("show_running_config.txt")
        assert "hostname core-rtr01" in config
        assert capability.raw_outputs[0].command == SHOW_RUNNING_CONFIG
        assert capability.raw_outputs[0].output == config

    def test_fetch_running_config_raises_on_empty_output(self, device_id: UUID) -> None:
        empty = FakeTransport({"show running-config": "   \n"})
        with pytest.raises(PluginError, match="empty output"):
            CiscoIosConfigBackup(empty, device_id).fetch_running_config()
