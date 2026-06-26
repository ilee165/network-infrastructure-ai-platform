"""Tests for cisco_ios BGP/OSPF/ACL capabilities (M3-08).

A FakeTransport replays recorded ``show`` output from
``tests/plugins/fixtures/`` — no device, no network (D16, REPO-STRUCTURE §5).
These exercise the parser pattern that cisco_iosxe + eos mirror: verbatim raw
output recorded before parsing, normalized records with the provenance triple,
and graceful empty/edge handling.
"""

from __future__ import annotations

from datetime import UTC, datetime
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path
from uuid import UUID, uuid4

import pytest

from app.core.errors import PluginError
from app.plugins.base import Capability
from app.plugins.vendors.cisco_ios import parsers
from app.plugins.vendors.cisco_ios.plugin import (
    SHOW_IP_ACCESS_LISTS,
    SHOW_IP_BGP_SUMMARY,
    SHOW_IP_OSPF_NEIGHBOR,
    CiscoIosAcl,
    CiscoIosBgp,
    CiscoIosNeighbors,
    CiscoIosOspf,
    CiscoIosPlugin,
)
from app.schemas.normalized import (
    AclAction,
    BgpPeerState,
    OspfNeighborState,
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
            "show ip bgp summary": _fixture("show_ip_bgp_summary.txt"),
            "show ip ospf neighbor": _fixture("show_ip_ospf_neighbor.txt"),
            "show ip access-lists": _fixture("show_ip_access_lists.txt"),
        }
    )


class TestPluginDeclaration:
    def test_bgp_ospf_acl_are_declared_and_resolve(self) -> None:
        plugin = CiscoIosPlugin()
        assert {Capability.BGP, Capability.OSPF, Capability.ACL} <= plugin.capabilities
        assert plugin.get_capability(Capability.BGP) is CiscoIosBgp
        assert plugin.get_capability(Capability.OSPF) is CiscoIosOspf
        assert plugin.get_capability(Capability.ACL) is CiscoIosAcl

    def test_neighbors_unchanged(self) -> None:
        plugin = CiscoIosPlugin()
        assert plugin.get_capability(Capability.NEIGHBORS_CDP) is CiscoIosNeighbors


class TestBgp:
    def test_get_bgp_peers_normalizes_every_row(
        self, transport: FakeTransport, device_id: UUID
    ) -> None:
        peers = CiscoIosBgp(transport, device_id).get_bgp_peers()
        assert [str(p.peer_address) for p in peers] == [
            "10.0.0.2",
            "10.0.0.3",
            "192.0.2.9",
            "192.0.2.13",
        ]

    def test_established_peer_carries_prefix_count(
        self, transport: FakeTransport, device_id: UUID
    ) -> None:
        peer = CiscoIosBgp(transport, device_id).get_bgp_peers()[0]
        assert peer.peer_address == IPv4Address("10.0.0.2")
        assert peer.remote_as == 65002
        assert peer.local_as == 65001
        assert peer.state is BgpPeerState.ESTABLISHED
        assert peer.prefixes_received == 12

    def test_non_established_states_map_from_text(
        self, transport: FakeTransport, device_id: UUID
    ) -> None:
        peers = CiscoIosBgp(transport, device_id).get_bgp_peers()
        idle = next(p for p in peers if p.peer_address == IPv4Address("192.0.2.9"))
        assert idle.state is BgpPeerState.IDLE
        assert idle.prefixes_received is None
        active = next(p for p in peers if p.peer_address == IPv4Address("192.0.2.13"))
        assert active.state is BgpPeerState.ACTIVE

    def test_provenance_and_raw_capture(self, transport: FakeTransport, device_id: UUID) -> None:
        capability = CiscoIosBgp(transport, device_id)
        peers = capability.get_bgp_peers()
        assert peers[0].device_id == device_id
        assert peers[0].source_vendor == "cisco_ios"
        assert peers[0].collected_at.tzinfo is not None
        assert capability.raw_outputs[0].command == SHOW_IP_BGP_SUMMARY
        assert capability.raw_outputs[0].output == _fixture("show_ip_bgp_summary.txt")

    def test_empty_output_returns_no_peers(self, device_id: UUID) -> None:
        result = parsers.parse_bgp_peers(
            "% BGP not active\n", device_id=device_id, collected_at=datetime.now(UTC)
        )
        assert result == []

    @pytest.mark.parametrize(
        ("neighbor_as", "expected_remote_as"),
        [
            ("65002", 65002),  # plain AS (asplain notation)
            ("1.1000", 66536),  # asdot notation: 1*65536 + 1000
            ("0.65002", 65002),  # asdot notation where high-order word is 0
            ("2.0", 131072),  # asdot notation: 2*65536 + 0
        ],
    )
    def test_parse_as_number_handles_asdot_and_asplain(
        self, neighbor_as: str, expected_remote_as: int
    ) -> None:
        """_parse_as_number must correctly decode both asplain and asdot AS notation."""
        from app.plugins.vendors.cisco_ios.parsers import _parse_as_number  # noqa: PLC2701

        assert _parse_as_number(neighbor_as) == expected_remote_as

    def test_parse_failure_raises_plugin_error(
        self, transport: FakeTransport, device_id: UUID, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from ntc_templates.parse import ParsingException

        def _boom(**kwargs: object) -> None:
            raise ParsingException("template error")

        monkeypatch.setattr(parsers, "parse_output", _boom)
        with pytest.raises(PluginError, match="failed to parse"):
            CiscoIosBgp(transport, device_id).get_bgp_peers()


class TestOspf:
    def test_get_ospf_neighbors_normalizes_every_row(
        self, transport: FakeTransport, device_id: UUID
    ) -> None:
        neighbors = CiscoIosOspf(transport, device_id).get_ospf_neighbors()
        assert [str(n.neighbor_id) for n in neighbors] == [
            "10.0.0.2",
            "10.0.0.3",
            "10.0.0.4",
            "10.0.0.5",
        ]

    def test_field_mapping(self, transport: FakeTransport, device_id: UUID) -> None:
        first = CiscoIosOspf(transport, device_id).get_ospf_neighbors()[0]
        assert first.neighbor_id == IPv4Address("10.0.0.2")
        assert first.interface == "GigabitEthernet0/1"
        assert first.state is OspfNeighborState.FULL
        assert first.neighbor_address == IPv4Address("10.10.0.2")
        assert first.priority == 1
        assert first.dead_time_seconds == 35

    def test_state_strips_dr_role_suffix(self, transport: FakeTransport, device_id: UUID) -> None:
        neighbors = CiscoIosOspf(transport, device_id).get_ospf_neighbors()
        two_way = next(n for n in neighbors if n.neighbor_id == IPv4Address("10.0.0.4"))
        assert two_way.state is OspfNeighborState.TWO_WAY
        exstart = next(n for n in neighbors if n.neighbor_id == IPv4Address("10.0.0.5"))
        assert exstart.state is OspfNeighborState.EXSTART

    def test_provenance_and_raw_capture(self, transport: FakeTransport, device_id: UUID) -> None:
        capability = CiscoIosOspf(transport, device_id)
        neighbors = capability.get_ospf_neighbors()
        assert neighbors[0].source_vendor == "cisco_ios"
        assert capability.raw_outputs[0].command == SHOW_IP_OSPF_NEIGHBOR

    def test_empty_output_returns_no_neighbors(self, device_id: UUID) -> None:
        result = parsers.parse_ospf_neighbors(
            "\n", device_id=device_id, collected_at=datetime.now(UTC)
        )
        assert result == []


class TestAcl:
    def test_get_acls_skips_header_rows(self, transport: FakeTransport, device_id: UUID) -> None:
        entries = CiscoIosAcl(transport, device_id).get_acls()
        # 5 rule rows across 2 ACLs; the two header rows are dropped.
        assert len(entries) == 5
        assert {e.acl_name for e in entries} == {"10", "BLOCK-TELNET"}

    def test_standard_acl_network_and_any(self, transport: FakeTransport, device_id: UUID) -> None:
        entries = CiscoIosAcl(transport, device_id).get_acls()
        permit = next(e for e in entries if e.acl_name == "10" and e.sequence == 10)
        assert permit.action is AclAction.PERMIT
        assert permit.source == IPv4Network("10.1.1.0/24")
        assert permit.source_is_any is False  # scoped network, not the literal 'any'
        assert permit.destination is None  # standard ACL: no explicit destination
        assert permit.destination_is_any is False  # implicit (no 'any' token emitted)
        assert permit.hits == 120
        deny_any = next(e for e in entries if e.acl_name == "10" and e.sequence == 20)
        assert deny_any.action is AclAction.DENY
        assert deny_any.source is None  # 'any'
        assert deny_any.source_is_any is True  # explicit literal 'any' token

    def test_extended_acl_host_and_ports(self, transport: FakeTransport, device_id: UUID) -> None:
        entries = CiscoIosAcl(transport, device_id).get_acls()
        telnet = next(e for e in entries if e.acl_name == "BLOCK-TELNET" and e.sequence == 10)
        assert telnet.action is AclAction.DENY
        assert telnet.protocol == "tcp"
        assert telnet.source is None  # any
        assert telnet.source_is_any is True  # explicit 'any' token
        assert telnet.destination == IPv4Network("10.0.0.5/32")  # host
        assert telnet.destination_is_any is False  # scoped host, not 'any'
        assert telnet.destination_port == "eq telnet"
        assert telnet.hits == 5
        www = next(e for e in entries if e.acl_name == "BLOCK-TELNET" and e.sequence == 20)
        assert www.source == IPv4Network("192.0.2.0/24")
        assert www.source_is_any is False
        assert www.destination is None  # any
        assert www.destination_is_any is True  # explicit 'any' token
        assert www.destination_port == "eq www"

    def test_provenance_and_raw_capture(self, transport: FakeTransport, device_id: UUID) -> None:
        capability = CiscoIosAcl(transport, device_id)
        entries = capability.get_acls()
        assert entries[0].source_vendor == "cisco_ios"
        assert capability.raw_outputs[0].command == SHOW_IP_ACCESS_LISTS

    def test_empty_output_returns_no_entries(self, device_id: UUID) -> None:
        result = parsers.parse_acls("\n", device_id=device_id, collected_at=datetime.now(UTC))
        assert result == []
