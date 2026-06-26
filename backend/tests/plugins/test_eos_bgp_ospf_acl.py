"""Tests for eos BGP/OSPF/ACL capabilities (M3-10).

A FakeTransport replays recorded ``show`` output from
``tests/plugins/fixtures/eos/`` — no device, no network (D16, REPO-STRUCTURE §5).
Mirrors the pattern established in ``test_cisco_ios_bgp_ospf_acl.py``:
verbatim raw output recorded before parsing, normalized records with the
provenance triple, and graceful empty/edge handling.

EOS differences from IOS
-------------------------
- BGP: EOS template uses separate ``state`` + ``state_pfxrcd`` columns (not
  the overloaded IOS ``State/PfxRcd`` column); ``state_pfxrcd`` is empty
  for non-ESTABLISHED sessions.
- OSPF: EOS ``state`` column has no ``/DR``-role suffix; mapping is
  case-insensitive.
- ACL: EOS uses CIDR notation for network prefixes (``10.1.1.0/24``);
  ``host <ip>`` prefix for host entries; ``modifier`` field carries the
  destination port match (``eq telnet``).
"""

from __future__ import annotations

from datetime import UTC, datetime
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path
from uuid import UUID, uuid4

import pytest

from app.core.errors import PluginError
from app.plugins.base import Capability
from app.plugins.vendors.eos import parsers
from app.plugins.vendors.eos.plugin import (
    SHOW_IP_ACCESS_LISTS,
    SHOW_IP_BGP_SUMMARY,
    SHOW_IP_OSPF_NEIGHBOR,
    EosAcl,
    EosBgp,
    EosOspf,
    EosPlugin,
)
from app.schemas.normalized import (
    AclAction,
    BgpPeerState,
    OspfNeighborState,
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
            SHOW_IP_BGP_SUMMARY: _fixture("show_ip_bgp_summary.txt"),
            SHOW_IP_OSPF_NEIGHBOR: _fixture("show_ip_ospf_neighbor.txt"),
            SHOW_IP_ACCESS_LISTS: _fixture("show_ip_access_lists.txt"),
        }
    )


class TestPluginDeclaration:
    def test_bgp_ospf_acl_are_declared_and_resolve(self) -> None:
        plugin = EosPlugin()
        assert {Capability.BGP, Capability.OSPF, Capability.ACL} <= plugin.capabilities
        assert plugin.get_capability(Capability.BGP) is EosBgp
        assert plugin.get_capability(Capability.OSPF) is EosOspf
        assert plugin.get_capability(Capability.ACL) is EosAcl

    def test_cdp_still_absent(self) -> None:
        plugin = EosPlugin()
        assert Capability.NEIGHBORS_CDP not in plugin.capabilities

    def test_capabilities_include_prior_m1_set(self) -> None:
        plugin = EosPlugin()
        assert {
            Capability.DISCOVERY_SSH,
            Capability.DISCOVERY_SNMP,
            Capability.INTERFACES,
            Capability.ROUTES,
            Capability.NEIGHBORS_LLDP,
        } <= plugin.capabilities


class TestBgp:
    def test_get_bgp_peers_normalizes_every_row(
        self, transport: FakeTransport, device_id: UUID
    ) -> None:
        peers = EosBgp(transport, device_id).get_bgp_peers()
        assert [str(p.peer_address) for p in peers] == [
            "10.0.0.2",
            "10.0.0.3",
            "192.0.2.9",
            "192.0.2.13",
        ]

    def test_established_peer_carries_prefix_count(
        self, transport: FakeTransport, device_id: UUID
    ) -> None:
        peer = EosBgp(transport, device_id).get_bgp_peers()[0]
        assert peer.peer_address == IPv4Address("10.0.0.2")
        assert peer.remote_as == 65100
        assert peer.local_as == 65001
        assert peer.state is BgpPeerState.ESTABLISHED
        assert peer.prefixes_received == 12

    def test_non_established_states_map_from_text(
        self, transport: FakeTransport, device_id: UUID
    ) -> None:
        peers = EosBgp(transport, device_id).get_bgp_peers()
        idle = next(p for p in peers if p.peer_address == IPv4Address("192.0.2.9"))
        assert idle.state is BgpPeerState.IDLE
        assert idle.prefixes_received is None
        active = next(p for p in peers if p.peer_address == IPv4Address("192.0.2.13"))
        assert active.state is BgpPeerState.ACTIVE

    def test_provenance_and_raw_capture(self, transport: FakeTransport, device_id: UUID) -> None:
        capability = EosBgp(transport, device_id)
        peers = capability.get_bgp_peers()
        assert peers[0].device_id == device_id
        assert peers[0].source_vendor == "eos"
        assert peers[0].collected_at.tzinfo is not None
        assert capability.raw_outputs[0].command == SHOW_IP_BGP_SUMMARY
        assert capability.raw_outputs[0].output == _fixture("show_ip_bgp_summary.txt")

    def test_empty_output_returns_no_peers(self, device_id: UUID) -> None:
        # EOS TextFSM template uses Error transitions, so only a genuinely
        # empty/blank output produces zero rows without raising; IOS-style
        # '% BGP not active' would trigger a TextFSMError on the EOS template.
        result = parsers.parse_bgp_peers("", device_id=device_id, collected_at=datetime.now(UTC))
        assert result == []

    def test_parse_failure_raises_plugin_error(
        self, transport: FakeTransport, device_id: UUID, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from ntc_templates.parse import ParsingException

        def _boom(**kwargs: object) -> None:
            raise ParsingException("template error")

        monkeypatch.setattr(parsers, "parse_output", _boom)
        with pytest.raises(PluginError, match="failed to parse"):
            EosBgp(transport, device_id).get_bgp_peers()


class TestOspf:
    def test_get_ospf_neighbors_normalizes_every_row(
        self, transport: FakeTransport, device_id: UUID
    ) -> None:
        neighbors = EosOspf(transport, device_id).get_ospf_neighbors()
        assert [str(n.neighbor_id) for n in neighbors] == [
            "10.0.0.2",
            "10.0.0.3",
            "10.0.0.4",
            "10.0.0.5",
        ]

    def test_field_mapping(self, transport: FakeTransport, device_id: UUID) -> None:
        first = EosOspf(transport, device_id).get_ospf_neighbors()[0]
        assert first.neighbor_id == IPv4Address("10.0.0.2")
        assert first.interface == "Ethernet1"
        assert first.state is OspfNeighborState.FULL
        assert first.neighbor_address == IPv4Address("10.10.0.2")
        assert first.priority == 1
        assert first.dead_time_seconds == 35

    def test_state_maps_without_role_suffix(
        self, transport: FakeTransport, device_id: UUID
    ) -> None:
        neighbors = EosOspf(transport, device_id).get_ospf_neighbors()
        two_way = next(n for n in neighbors if n.neighbor_id == IPv4Address("10.0.0.4"))
        assert two_way.state is OspfNeighborState.TWO_WAY
        exstart = next(n for n in neighbors if n.neighbor_id == IPv4Address("10.0.0.5"))
        assert exstart.state is OspfNeighborState.EXSTART

    def test_provenance_and_raw_capture(self, transport: FakeTransport, device_id: UUID) -> None:
        capability = EosOspf(transport, device_id)
        neighbors = capability.get_ospf_neighbors()
        assert neighbors[0].source_vendor == "eos"
        assert capability.raw_outputs[0].command == SHOW_IP_OSPF_NEIGHBOR

    def test_empty_output_returns_no_neighbors(self, device_id: UUID) -> None:
        result = parsers.parse_ospf_neighbors(
            "\n", device_id=device_id, collected_at=datetime.now(UTC)
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
            EosOspf(transport, device_id).get_ospf_neighbors()


class TestAcl:
    def test_get_acls_returns_all_ace_rows(self, transport: FakeTransport, device_id: UUID) -> None:
        entries = EosAcl(transport, device_id).get_acls()
        # 2 ACLs × combined 5 ACE rows (2 in PERMIT-MGMT + 3 in BLOCK-TELNET)
        assert len(entries) == 5
        assert {e.acl_name for e in entries} == {"PERMIT-MGMT", "BLOCK-TELNET"}

    def test_cidr_source_is_parsed(self, transport: FakeTransport, device_id: UUID) -> None:
        entries = EosAcl(transport, device_id).get_acls()
        first = next(e for e in entries if e.acl_name == "PERMIT-MGMT" and e.sequence == 10)
        assert first.action is AclAction.PERMIT
        assert first.source == IPv4Network("10.1.1.0/24")
        assert first.source_is_any is False
        assert first.destination is None  # 'any'
        assert first.destination_is_any is True

    def test_any_source_destination_is_none(
        self, transport: FakeTransport, device_id: UUID
    ) -> None:
        entries = EosAcl(transport, device_id).get_acls()
        deny_any = next(e for e in entries if e.acl_name == "PERMIT-MGMT" and e.sequence == 20)
        assert deny_any.action is AclAction.DENY
        assert deny_any.source is None
        assert deny_any.source_is_any is True  # literal 'any', not a collapsed group
        assert deny_any.destination is None
        assert deny_any.destination_is_any is True

    def test_host_destination_and_port_modifier(
        self, transport: FakeTransport, device_id: UUID
    ) -> None:
        entries = EosAcl(transport, device_id).get_acls()
        telnet = next(e for e in entries if e.acl_name == "BLOCK-TELNET" and e.sequence == 10)
        assert telnet.action is AclAction.DENY
        assert telnet.protocol == "tcp"
        assert telnet.source is None  # any
        assert telnet.source_is_any is True
        assert telnet.destination == IPv4Network("10.0.0.5/32")  # host 10.0.0.5
        assert telnet.destination_is_any is False
        assert telnet.destination_port == "eq telnet"

    def test_cidr_source_with_destination_port(
        self, transport: FakeTransport, device_id: UUID
    ) -> None:
        entries = EosAcl(transport, device_id).get_acls()
        www = next(e for e in entries if e.acl_name == "BLOCK-TELNET" and e.sequence == 20)
        assert www.action is AclAction.PERMIT
        assert www.source == IPv4Network("192.0.2.0/24")
        assert www.source_is_any is False
        assert www.destination is None  # any
        assert www.destination_is_any is True
        assert www.destination_port == "eq www"

    def test_any_detection_is_case_insensitive(self) -> None:
        # If EOS output preserves ``ANY``/``Any``, both the endpoint resolution and
        # the explicit-any flag must treat it as *any* — otherwise a definite
        # exposure is silently downgraded to advisory.
        for token in ("any", "ANY", "Any", " any "):
            assert parsers._eos_is_any(token) is True
            assert parsers._eos_acl_endpoint(token) is None
        assert parsers._eos_is_any("host 10.0.0.1") is False
        assert parsers._eos_is_any("") is False

    def test_provenance_and_raw_capture(self, transport: FakeTransport, device_id: UUID) -> None:
        capability = EosAcl(transport, device_id)
        entries = capability.get_acls()
        assert entries[0].source_vendor == "eos"
        assert capability.raw_outputs[0].command == SHOW_IP_ACCESS_LISTS

    def test_empty_output_returns_no_entries(self, device_id: UUID) -> None:
        result = parsers.parse_acls("\n", device_id=device_id, collected_at=datetime.now(UTC))
        assert result == []

    def test_parse_failure_raises_plugin_error(
        self, transport: FakeTransport, device_id: UUID, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from ntc_templates.parse import ParsingException

        def _boom(**kwargs: object) -> None:
            raise ParsingException("template error")

        monkeypatch.setattr(parsers, "parse_output", _boom)
        with pytest.raises(PluginError, match="failed to parse"):
            EosAcl(transport, device_id).get_acls()
