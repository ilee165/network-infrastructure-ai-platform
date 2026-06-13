"""Tests for cisco_iosxe BGP/OSPF/ACL capabilities (M3-09).

IOS-XE shares parsers with cisco_ios (same ntc-templates platform key).
These tests verify that the IOS-XE capability classes correctly:
 - delegate to the shared cisco_ios parsers
 - stamp ``source_vendor = "cisco_iosxe"`` on every normalized record
 - record verbatim raw output before parsing
 - resolve from the plugin capability map

A FakeTransport replays recorded Cat9k fixture output from
``tests/plugins/fixtures/cisco_iosxe/`` — no device, no network (D16).
"""

from __future__ import annotations

from datetime import UTC, datetime
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path
from uuid import UUID, uuid4

import pytest

from app.plugins.base import Capability
from app.plugins.vendors.cisco_iosxe.plugin import (
    SHOW_IP_ACCESS_LISTS,
    SHOW_IP_BGP_SUMMARY,
    SHOW_IP_OSPF_NEIGHBOR,
    CiscoIosXeAcl,
    CiscoIosXeBgp,
    CiscoIosXeNeighbors,
    CiscoIosXeOspf,
    CiscoIosXePlugin,
)
from app.schemas.normalized import (
    AclAction,
    BgpPeerState,
    OspfNeighborState,
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
            "show ip bgp summary": _fixture("show_ip_bgp_summary.txt"),
            "show ip ospf neighbor": _fixture("show_ip_ospf_neighbor.txt"),
            "show ip access-lists": _fixture("show_ip_access_lists.txt"),
        }
    )


class TestPluginDeclaration:
    def test_bgp_ospf_acl_are_declared_and_resolve(self) -> None:
        plugin = CiscoIosXePlugin()
        assert {Capability.BGP, Capability.OSPF, Capability.ACL} <= plugin.capabilities
        assert plugin.get_capability(Capability.BGP) is CiscoIosXeBgp
        assert plugin.get_capability(Capability.OSPF) is CiscoIosXeOspf
        assert plugin.get_capability(Capability.ACL) is CiscoIosXeAcl

    def test_neighbors_unchanged(self) -> None:
        plugin = CiscoIosXePlugin()
        assert plugin.get_capability(Capability.NEIGHBORS_CDP) is CiscoIosXeNeighbors


class TestBgp:
    def test_get_bgp_peers_normalizes_every_row(
        self, transport: FakeTransport, device_id: UUID
    ) -> None:
        peers = CiscoIosXeBgp(transport, device_id).get_bgp_peers()
        assert [str(p.peer_address) for p in peers] == [
            "10.0.0.2",
            "10.0.0.3",
            "192.0.2.1",
            "192.0.2.5",
        ]

    def test_established_peer_carries_prefix_count(
        self, transport: FakeTransport, device_id: UUID
    ) -> None:
        peer = CiscoIosXeBgp(transport, device_id).get_bgp_peers()[0]
        assert peer.peer_address == IPv4Address("10.0.0.2")
        assert peer.remote_as == 65002
        assert peer.local_as == 65001
        assert peer.state is BgpPeerState.ESTABLISHED
        assert peer.prefixes_received == 6

    def test_non_established_states_map_from_text(
        self, transport: FakeTransport, device_id: UUID
    ) -> None:
        peers = CiscoIosXeBgp(transport, device_id).get_bgp_peers()
        idle = next(p for p in peers if p.peer_address == IPv4Address("192.0.2.1"))
        assert idle.state is BgpPeerState.IDLE
        assert idle.prefixes_received is None
        active = next(p for p in peers if p.peer_address == IPv4Address("192.0.2.5"))
        assert active.state is BgpPeerState.ACTIVE

    def test_provenance_and_raw_capture(self, transport: FakeTransport, device_id: UUID) -> None:
        capability = CiscoIosXeBgp(transport, device_id)
        peers = capability.get_bgp_peers()
        assert peers[0].device_id == device_id
        assert peers[0].source_vendor == "cisco_iosxe"
        assert peers[0].collected_at.tzinfo is not None
        assert capability.raw_outputs[0].command == SHOW_IP_BGP_SUMMARY
        assert capability.raw_outputs[0].output == _fixture("show_ip_bgp_summary.txt")

    def test_empty_output_returns_no_peers(self, device_id: UUID) -> None:
        # Delegate to the shared ios parser — same empty-handling behaviour.
        from app.plugins.vendors.cisco_ios import parsers as _parsers

        result = _parsers.parse_bgp_peers(
            "% BGP not active\n", device_id=device_id, collected_at=datetime.now(UTC)
        )
        assert result == []


class TestOspf:
    def test_get_ospf_neighbors_normalizes_every_row(
        self, transport: FakeTransport, device_id: UUID
    ) -> None:
        neighbors = CiscoIosXeOspf(transport, device_id).get_ospf_neighbors()
        assert [str(n.neighbor_id) for n in neighbors] == [
            "10.0.0.2",
            "10.0.0.3",
            "10.0.0.4",
        ]

    def test_field_mapping(self, transport: FakeTransport, device_id: UUID) -> None:
        first = CiscoIosXeOspf(transport, device_id).get_ospf_neighbors()[0]
        assert first.neighbor_id == IPv4Address("10.0.0.2")
        assert first.interface == "GigabitEthernet1/0/1"
        assert first.state is OspfNeighborState.FULL
        assert first.neighbor_address == IPv4Address("10.10.0.2")
        assert first.priority == 1
        assert first.dead_time_seconds == 38

    def test_state_strips_dr_role_suffix(self, transport: FakeTransport, device_id: UUID) -> None:
        neighbors = CiscoIosXeOspf(transport, device_id).get_ospf_neighbors()
        two_way = next(n for n in neighbors if n.neighbor_id == IPv4Address("10.0.0.4"))
        assert two_way.state is OspfNeighborState.TWO_WAY

    def test_provenance_and_raw_capture(self, transport: FakeTransport, device_id: UUID) -> None:
        capability = CiscoIosXeOspf(transport, device_id)
        neighbors = capability.get_ospf_neighbors()
        assert neighbors[0].source_vendor == "cisco_iosxe"
        assert capability.raw_outputs[0].command == SHOW_IP_OSPF_NEIGHBOR

    def test_empty_output_returns_no_neighbors(self, device_id: UUID) -> None:
        from app.plugins.vendors.cisco_ios import parsers as _parsers

        result = _parsers.parse_ospf_neighbors(
            "\n", device_id=device_id, collected_at=datetime.now(UTC)
        )
        assert result == []


class TestAcl:
    def test_get_acls_skips_header_rows(self, transport: FakeTransport, device_id: UUID) -> None:
        entries = CiscoIosXeAcl(transport, device_id).get_acls()
        # 5 rule rows across 2 ACLs; the two header rows are dropped.
        assert len(entries) == 5
        assert {e.acl_name for e in entries} == {"MGMT-ACCESS", "INET-FILTER"}

    def test_standard_acl_network_and_any(self, transport: FakeTransport, device_id: UUID) -> None:
        entries = CiscoIosXeAcl(transport, device_id).get_acls()
        permit = next(e for e in entries if e.acl_name == "MGMT-ACCESS" and e.sequence == 10)
        assert permit.action is AclAction.PERMIT
        assert permit.source == IPv4Network("10.0.0.0/24")
        assert permit.destination is None  # standard ACL: no explicit destination
        assert permit.hits == 48
        deny_any = next(e for e in entries if e.acl_name == "MGMT-ACCESS" and e.sequence == 20)
        assert deny_any.action is AclAction.DENY
        assert deny_any.source is None  # 'any'

    def test_extended_acl_host_and_ports(self, transport: FakeTransport, device_id: UUID) -> None:
        entries = CiscoIosXeAcl(transport, device_id).get_acls()
        telnet = next(e for e in entries if e.acl_name == "INET-FILTER" and e.sequence == 10)
        assert telnet.action is AclAction.DENY
        assert telnet.protocol == "tcp"
        assert telnet.source is None  # any
        assert telnet.destination == IPv4Network("192.168.1.100/32")  # host
        assert telnet.destination_port == "eq telnet"
        assert telnet.hits == 3
        www = next(e for e in entries if e.acl_name == "INET-FILTER" and e.sequence == 20)
        assert www.source == IPv4Network("10.0.0.0/24")
        assert www.destination is None  # any
        assert www.destination_port == "eq www"

    def test_provenance_and_raw_capture(self, transport: FakeTransport, device_id: UUID) -> None:
        capability = CiscoIosXeAcl(transport, device_id)
        entries = capability.get_acls()
        assert entries[0].source_vendor == "cisco_iosxe"
        assert capability.raw_outputs[0].command == SHOW_IP_ACCESS_LISTS

    def test_empty_output_returns_no_entries(self, device_id: UUID) -> None:
        from app.plugins.vendors.cisco_ios import parsers as _parsers

        result = _parsers.parse_acls("\n", device_id=device_id, collected_at=datetime.now(UTC))
        assert result == []
