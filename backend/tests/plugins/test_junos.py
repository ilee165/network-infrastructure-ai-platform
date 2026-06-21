"""Tests for the junos plugin: parsing fixture JSON and plugin declaration (ADR-0026).

A FakeTransport replays source-derived ``| display json`` / ``| display set``
fixture text from ``tests/plugins/fixtures/junos/`` — no device, no network
(D16, REPO-STRUCTURE §5).  All fixtures are labelled "source-derived, not
live-recorded" per ADR-0024 §5 convention.
"""

from __future__ import annotations

from collections.abc import Sequence
from ipaddress import IPv4Address, IPv4Interface, IPv4Network
from pathlib import Path
from uuid import UUID, uuid4

import pytest

from app.core.errors import PluginError
from app.plugins.base import Capability, CommandTransport
from app.plugins.vendors.junos import parsers
from app.plugins.vendors.junos.plugin import (
    SHOW_BGP_NEIGHBOR,
    SHOW_CONFIGURATION_FIREWALL,
    SHOW_CONFIGURATION_SET,
    SHOW_INTERFACES,
    SHOW_LLDP_NEIGHBORS,
    SHOW_OSPF_NEIGHBOR,
    SHOW_ROUTE,
    SHOW_VERSION,
    SNMP_OID_SYSDESCR,
    SNMP_OID_SYSNAME,
    SNMP_OID_SYSOBJECTID,
    JunosBgp,
    JunosConfigBackup,
    JunosDiscoverySnmp,
    JunosDiscoverySsh,
    JunosInterfaces,
    JunosNeighbors,
    JunosOspf,
    JunosPlugin,
    JunosRoutes,
)
from app.schemas.normalized import (
    AclAction,
    BgpPeerState,
    InterfaceAdminStatus,
    InterfaceOperStatus,
    NeighborProtocol,
    OspfNeighborState,
    RouteProtocol,
)

FIXTURES = Path(__file__).parent / "fixtures" / "junos"


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


#: System-MIB values replayed by the SNMP discovery raw-output test.
_SNMP_SYSTEM_VALUES = {
    SNMP_OID_SYSDESCR: ("Juniper Networks, Inc. MX480 internet router, kernel JUNOS 23.1R1.8"),
    SNMP_OID_SYSOBJECTID: "1.3.6.1.4.1.2636.1.1.1.2.65",
    SNMP_OID_SYSNAME: "juniper-mx01.example.net",
}


class FakeSnmpTransport:
    """In-memory ``SnmpReadTransport`` replaying recorded system-MIB values."""

    def __init__(self, values: dict[str, str]) -> None:
        self._values = dict(values)
        self.requests: list[list[str]] = []

    def get(self, oids: Sequence[str]) -> dict[str, str]:
        self.requests.append(list(oids))
        return {oid: self._values[oid] for oid in oids if oid in self._values}


@pytest.fixture()
def device_id() -> UUID:
    return uuid4()


@pytest.fixture()
def transport() -> FakeTransport:
    return FakeTransport(
        {
            SHOW_VERSION: _fixture("show_version_display_json.txt"),
            SHOW_INTERFACES: _fixture("show_interfaces_display_json.txt"),
            SHOW_ROUTE: _fixture("show_route_display_json.txt"),
            SHOW_LLDP_NEIGHBORS: _fixture("show_lldp_neighbors_display_json.txt"),
            SHOW_BGP_NEIGHBOR: _fixture("show_bgp_neighbor_display_json.txt"),
            SHOW_OSPF_NEIGHBOR: _fixture("show_ospf_neighbor_display_json.txt"),
            SHOW_CONFIGURATION_FIREWALL: _fixture("show_configuration_firewall_display_json.txt"),
            SHOW_CONFIGURATION_SET: _fixture("show_configuration_display_set.txt"),
        }
    )


# ---------------------------------------------------------------------------
# Plugin declaration
# ---------------------------------------------------------------------------


class TestPluginDeclaration:
    def test_plugin_identity(self) -> None:
        plugin = JunosPlugin()
        assert plugin.vendor_id == "junos"
        assert plugin.display_name == "Juniper JunOS"

    def test_declared_capabilities(self) -> None:
        plugin = JunosPlugin()
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

    def test_cdp_not_declared(self) -> None:
        """JunOS does not speak CDP — NEIGHBORS_CDP must not be in capabilities."""
        plugin = JunosPlugin()
        assert Capability.NEIGHBORS_CDP not in plugin.capabilities
        with pytest.raises(PluginError, match="does not implement"):
            plugin.get_capability(Capability.NEIGHBORS_CDP)

    def test_lldp_resolves_to_junos_neighbors(self) -> None:
        from app.plugins.vendors.junos.plugin import JunosNeighbors

        plugin = JunosPlugin()
        assert plugin.get_capability(Capability.NEIGHBORS_LLDP) is JunosNeighbors

    def test_fake_transport_satisfies_command_transport_protocol(
        self, transport: FakeTransport
    ) -> None:
        assert isinstance(transport, CommandTransport)


# ---------------------------------------------------------------------------
# Device facts (SSH)
# ---------------------------------------------------------------------------


class TestDeviceFacts:
    def test_parse_device_facts_fields(self) -> None:
        facts = parsers.parse_device_facts(_fixture("show_version_display_json.txt"))
        assert facts.hostname == "juniper-mx01"
        assert facts.vendor_id == "junos"
        assert facts.model == "MX480"
        assert facts.os_version == "23.1R1.8"
        assert facts.serial is None

    def test_parse_device_facts_missing_hostname_raises(self) -> None:
        raw = '{"software-information": [{"product-model": [{"data": "MX480"}]}]}'
        with pytest.raises(PluginError, match="no host-name"):
            parsers.parse_device_facts(raw)

    def test_parse_device_facts_invalid_json_raises(self) -> None:
        with pytest.raises(PluginError, match="failed to parse JSON"):
            parsers.parse_device_facts("not json at all")

    def test_parse_snmp_device_facts(self) -> None:
        from app.plugins.vendors.junos.parsers import (
            SNMP_OID_SYSDESCR,
            SNMP_OID_SYSNAME,
            SNMP_OID_SYSOBJECTID,
        )

        values = {
            SNMP_OID_SYSDESCR: (
                "Juniper Networks, Inc. MX480 internet router, kernel JUNOS 23.1R1.8"
            ),
            SNMP_OID_SYSOBJECTID: "1.3.6.1.4.1.2636.1.1.1.2.65",
            SNMP_OID_SYSNAME: "juniper-mx01.example.net",
        }
        facts = parsers.parse_snmp_device_facts(values)
        assert facts.hostname == "juniper-mx01.example.net"
        assert facts.vendor_id == "junos"
        assert facts.os_version == "23.1R1.8"
        assert facts.model == "MX480"
        assert facts.serial is None

    def test_parse_snmp_device_facts_missing_sysname_raises(self) -> None:
        with pytest.raises(PluginError, match="no sysName"):
            parsers.parse_snmp_device_facts({})

    def test_ssh_records_raw_output_before_parsing(
        self, transport: FakeTransport, device_id: UUID
    ) -> None:
        """DISCOVERY_SSH records the verbatim ``| display json`` before parsing (Spec §5)."""
        cap = JunosDiscoverySsh(transport, device_id)
        cap.get_device_facts()
        assert len(cap.raw_outputs) == 1
        assert cap.raw_outputs[0].command == SHOW_VERSION
        assert cap.raw_outputs[0].output == _fixture("show_version_display_json.txt")

    def test_snmp_records_raw_output_before_parsing(self, device_id: UUID) -> None:
        """DISCOVERY_SNMP records the verbatim OID GET response before parsing (Spec §5)."""
        snmp = FakeSnmpTransport(_SNMP_SYSTEM_VALUES)
        cap = JunosDiscoverySnmp(snmp, device_id)
        cap.get_device_facts()
        assert len(cap.raw_outputs) == 1
        raw = cap.raw_outputs[0]
        # The verbatim SNMP GET response is recorded — one line per OID.
        for oid in (SNMP_OID_SYSDESCR, SNMP_OID_SYSOBJECTID, SNMP_OID_SYSNAME):
            assert oid in raw.output
            assert _SNMP_SYSTEM_VALUES[oid] in raw.output


# ---------------------------------------------------------------------------
# Interfaces
# ---------------------------------------------------------------------------


class TestInterfaces:
    def test_get_interfaces_count(self, transport: FakeTransport, device_id: UUID) -> None:
        interfaces = JunosInterfaces(transport, device_id).get_interfaces()
        assert len(interfaces) == 3

    def test_ge_0_0_0_fields(self, transport: FakeTransport, device_id: UUID) -> None:
        ifaces = JunosInterfaces(transport, device_id).get_interfaces()
        ge000 = next(i for i in ifaces if i.name == "ge-0/0/0")
        assert ge000.description == "uplink-to-core01"
        assert ge000.admin_status is InterfaceAdminStatus.UP
        assert ge000.oper_status is InterfaceOperStatus.UP
        assert ge000.ip_address == IPv4Interface("10.0.0.1/30")
        assert ge000.mtu == 1514
        assert ge000.speed_mbps == 1000

    def test_down_interface(self, transport: FakeTransport, device_id: UUID) -> None:
        ifaces = JunosInterfaces(transport, device_id).get_interfaces()
        ge001 = next(i for i in ifaces if i.name == "ge-0/0/1")
        assert ge001.admin_status is InterfaceAdminStatus.UP
        assert ge001.oper_status is InterfaceOperStatus.DOWN
        assert ge001.ip_address is None

    def test_mgmt_interface(self, transport: FakeTransport, device_id: UUID) -> None:
        ifaces = JunosInterfaces(transport, device_id).get_interfaces()
        fxp0 = next(i for i in ifaces if i.name == "fxp0")
        assert fxp0.description == "oob-mgmt"
        assert fxp0.ip_address == IPv4Interface("192.168.100.20/24")

    def test_stamps_provenance(self, transport: FakeTransport, device_id: UUID) -> None:
        ge000 = JunosInterfaces(transport, device_id).get_interfaces()[0]
        assert ge000.device_id == device_id
        assert ge000.source_vendor == "junos"
        assert ge000.collected_at.tzinfo is not None

    def test_records_raw_output_before_parsing(
        self, transport: FakeTransport, device_id: UUID
    ) -> None:
        cap = JunosInterfaces(transport, device_id)
        cap.get_interfaces()
        assert len(cap.raw_outputs) == 1
        assert cap.raw_outputs[0].command == SHOW_INTERFACES
        assert cap.raw_outputs[0].output == _fixture("show_interfaces_display_json.txt")


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


class TestRoutes:
    def test_get_routes_count(self, transport: FakeTransport, device_id: UUID) -> None:
        routes = JunosRoutes(transport, device_id).get_routes()
        assert len(routes) == 4

    def test_static_default_route(self, transport: FakeTransport, device_id: UUID) -> None:
        routes = JunosRoutes(transport, device_id).get_routes()
        default = next(r for r in routes if str(r.destination) == "0.0.0.0/0")
        assert default.protocol is RouteProtocol.STATIC
        assert default.next_hop == IPv4Address("10.0.0.2")
        assert default.interface == "ge-0/0/0.0"

    def test_direct_connected_route(self, transport: FakeTransport, device_id: UUID) -> None:
        routes = JunosRoutes(transport, device_id).get_routes()
        connected = next(r for r in routes if r.destination == IPv4Network("10.0.0.0/30"))
        assert connected.protocol is RouteProtocol.CONNECTED
        assert connected.next_hop is None

    def test_ospf_route(self, transport: FakeTransport, device_id: UUID) -> None:
        routes = JunosRoutes(transport, device_id).get_routes()
        ospf = next(r for r in routes if r.protocol is RouteProtocol.OSPF)
        assert ospf.destination == IPv4Network("10.10.0.0/24")
        assert ospf.distance == 10

    def test_bgp_route(self, transport: FakeTransport, device_id: UUID) -> None:
        routes = JunosRoutes(transport, device_id).get_routes()
        bgp = next(r for r in routes if r.protocol is RouteProtocol.BGP)
        assert bgp.destination == IPv4Network("10.20.0.0/16")
        assert bgp.next_hop == IPv4Address("172.16.0.1")

    def test_stamps_provenance(self, transport: FakeTransport, device_id: UUID) -> None:
        route = JunosRoutes(transport, device_id).get_routes()[0]
        assert route.device_id == device_id
        assert route.source_vendor == "junos"

    def test_records_raw_output_before_parsing(
        self, transport: FakeTransport, device_id: UUID
    ) -> None:
        """ROUTES records the verbatim ``| display json`` before parsing (Spec §5)."""
        cap = JunosRoutes(transport, device_id)
        cap.get_routes()
        assert len(cap.raw_outputs) == 1
        assert cap.raw_outputs[0].command == SHOW_ROUTE
        assert cap.raw_outputs[0].output == _fixture("show_route_display_json.txt")


# ---------------------------------------------------------------------------
# LLDP neighbors
# ---------------------------------------------------------------------------


class TestLldpNeighbors:
    def test_get_lldp_neighbors_count(self, transport: FakeTransport, device_id: UUID) -> None:
        neighbors = JunosNeighbors(transport, device_id).get_lldp_neighbors()
        assert len(neighbors) == 2

    def test_first_neighbor_fields(self, transport: FakeTransport, device_id: UUID) -> None:
        first = JunosNeighbors(transport, device_id).get_lldp_neighbors()[0]
        assert first.protocol is NeighborProtocol.LLDP
        assert first.local_interface == "ge-0/0/0"
        assert first.neighbor_name == "spine01.example.net"
        assert first.neighbor_interface == "xe-0/0/0"
        assert first.neighbor_address == IPv4Address("10.0.255.1")

    def test_second_neighbor_fields(self, transport: FakeTransport, device_id: UUID) -> None:
        second = JunosNeighbors(transport, device_id).get_lldp_neighbors()[1]
        assert second.local_interface == "ge-0/0/1"
        assert second.neighbor_name == "spine02.example.net"
        assert second.neighbor_address == IPv4Address("10.0.255.2")

    def test_cdp_returns_empty(self, transport: FakeTransport, device_id: UUID) -> None:
        """JunOS has no CDP; get_cdp_neighbors always returns []."""
        assert JunosNeighbors(transport, device_id).get_cdp_neighbors() == []

    def test_records_raw_output(self, transport: FakeTransport, device_id: UUID) -> None:
        cap = JunosNeighbors(transport, device_id)
        cap.get_lldp_neighbors()
        assert len(cap.raw_outputs) == 1
        assert cap.raw_outputs[0].command == SHOW_LLDP_NEIGHBORS

    def test_stamps_provenance(self, transport: FakeTransport, device_id: UUID) -> None:
        first = JunosNeighbors(transport, device_id).get_lldp_neighbors()[0]
        assert first.device_id == device_id
        assert first.source_vendor == "junos"


# ---------------------------------------------------------------------------
# BGP peers
# ---------------------------------------------------------------------------


class TestBgpPeers:
    def test_get_bgp_peers_count(self, transport: FakeTransport, device_id: UUID) -> None:
        peers = JunosBgp(transport, device_id).get_bgp_peers()
        assert len(peers) == 2

    def test_established_peer(self, transport: FakeTransport, device_id: UUID) -> None:
        peers = JunosBgp(transport, device_id).get_bgp_peers()
        established = next(p for p in peers if p.state is BgpPeerState.ESTABLISHED)
        assert established.peer_address == IPv4Address("172.16.0.1")
        assert established.remote_as == 65000
        assert established.local_as == 65001
        assert established.prefixes_received == 42

    def test_active_peer(self, transport: FakeTransport, device_id: UUID) -> None:
        peers = JunosBgp(transport, device_id).get_bgp_peers()
        active = next(p for p in peers if p.state is BgpPeerState.ACTIVE)
        assert active.peer_address == IPv4Address("192.168.1.2")
        assert active.remote_as == 65002
        assert active.prefixes_received is None

    def test_peer_port_suffix_stripped(self, transport: FakeTransport, device_id: UUID) -> None:
        """JunOS peer addresses include +179 port suffix — must be stripped."""
        peers = JunosBgp(transport, device_id).get_bgp_peers()
        # Verify we can parse all addresses as IPs (port suffix would cause ValueError).
        for peer in peers:
            assert peer.peer_address is not None

    def test_stamps_provenance(self, transport: FakeTransport, device_id: UUID) -> None:
        peer = JunosBgp(transport, device_id).get_bgp_peers()[0]
        assert peer.device_id == device_id
        assert peer.source_vendor == "junos"

    def test_records_raw_output_before_parsing(
        self, transport: FakeTransport, device_id: UUID
    ) -> None:
        """BGP records the verbatim ``| display json`` before parsing (Spec §5)."""
        cap = JunosBgp(transport, device_id)
        cap.get_bgp_peers()
        assert len(cap.raw_outputs) == 1
        assert cap.raw_outputs[0].command == SHOW_BGP_NEIGHBOR
        assert cap.raw_outputs[0].output == _fixture("show_bgp_neighbor_display_json.txt")


# ---------------------------------------------------------------------------
# OSPF neighbors
# ---------------------------------------------------------------------------


class TestOspfNeighbors:
    def test_get_ospf_neighbors_count(self, transport: FakeTransport, device_id: UUID) -> None:
        neighbors = JunosOspf(transport, device_id).get_ospf_neighbors()
        assert len(neighbors) == 2

    def test_full_neighbor(self, transport: FakeTransport, device_id: UUID) -> None:
        nbrs = JunosOspf(transport, device_id).get_ospf_neighbors()
        full = next(n for n in nbrs if n.state is OspfNeighborState.FULL)
        assert full.neighbor_id == IPv4Address("10.255.0.2")
        assert full.interface == "ge-0/0/0.0"
        assert full.neighbor_address == IPv4Address("10.0.0.2")
        assert full.priority == 128
        assert full.dead_time_seconds == 31

    def test_init_neighbor(self, transport: FakeTransport, device_id: UUID) -> None:
        nbrs = JunosOspf(transport, device_id).get_ospf_neighbors()
        init = next(n for n in nbrs if n.state is OspfNeighborState.INIT)
        assert init.neighbor_id == IPv4Address("10.255.0.3")
        assert init.interface == "ge-0/0/1.0"

    def test_stamps_provenance(self, transport: FakeTransport, device_id: UUID) -> None:
        nbr = JunosOspf(transport, device_id).get_ospf_neighbors()[0]
        assert nbr.device_id == device_id
        assert nbr.source_vendor == "junos"

    def test_records_raw_output_before_parsing(
        self, transport: FakeTransport, device_id: UUID
    ) -> None:
        """OSPF records the verbatim ``| display json`` before parsing (Spec §5)."""
        cap = JunosOspf(transport, device_id)
        cap.get_ospf_neighbors()
        assert len(cap.raw_outputs) == 1
        assert cap.raw_outputs[0].command == SHOW_OSPF_NEIGHBOR
        assert cap.raw_outputs[0].output == _fixture("show_ospf_neighbor_display_json.txt")


# ---------------------------------------------------------------------------
# ACL (firewall filters)
# ---------------------------------------------------------------------------


class TestAcl:
    def test_get_acls_count(self, transport: FakeTransport, device_id: UUID) -> None:
        from app.plugins.vendors.junos.plugin import JunosAcl

        acls = JunosAcl(transport, device_id).get_acls()
        # ALLOW-MGMT: 3 terms, BLOCK-BOGONS: 2 terms = 5 total
        assert len(acls) == 5

    def test_permit_term(self, transport: FakeTransport, device_id: UUID) -> None:
        from app.plugins.vendors.junos.plugin import JunosAcl

        acls = JunosAcl(transport, device_id).get_acls()
        permit_ssh = next(a for a in acls if a.acl_name == "ALLOW-MGMT" and a.sequence == 1)
        assert permit_ssh.action is AclAction.PERMIT
        assert permit_ssh.protocol == "tcp"

    def test_deny_term(self, transport: FakeTransport, device_id: UUID) -> None:
        from app.plugins.vendors.junos.plugin import JunosAcl

        acls = JunosAcl(transport, device_id).get_acls()
        deny_rest = next(a for a in acls if a.acl_name == "ALLOW-MGMT" and a.sequence == 3)
        assert deny_rest.action is AclAction.DENY

    def test_non_permit_deny_term_normalized_as_deny(
        self, transport: FakeTransport, device_id: UUID
    ) -> None:
        """count-only terms (ADR-0026 §1 lowest-common-denominator) map to DENY."""
        from app.plugins.vendors.junos.plugin import JunosAcl

        acls = JunosAcl(transport, device_id).get_acls()
        count_term = next(a for a in acls if a.acl_name == "BLOCK-BOGONS" and a.sequence == 2)
        # count-only term: normalized as DENY (lowest-common-denominator approximation)
        assert count_term.action is AclAction.DENY

    def test_filter_names(self, transport: FakeTransport, device_id: UUID) -> None:
        from app.plugins.vendors.junos.plugin import JunosAcl

        acls = JunosAcl(transport, device_id).get_acls()
        filter_names = {a.acl_name for a in acls}
        assert "ALLOW-MGMT" in filter_names
        assert "BLOCK-BOGONS" in filter_names

    def test_source_address_extracted(self, transport: FakeTransport, device_id: UUID) -> None:
        from app.plugins.vendors.junos.plugin import JunosAcl

        acls = JunosAcl(transport, device_id).get_acls()
        bogon_term = next(a for a in acls if a.acl_name == "BLOCK-BOGONS" and a.sequence == 1)
        assert bogon_term.source is not None
        # First source address in the list: 10.0.0.0/8
        assert bogon_term.source == IPv4Network("10.0.0.0/8")

    def test_stamps_provenance(self, transport: FakeTransport, device_id: UUID) -> None:
        from app.plugins.vendors.junos.plugin import JunosAcl

        acls = JunosAcl(transport, device_id).get_acls()
        assert all(a.source_vendor == "junos" for a in acls)
        assert all(a.device_id == device_id for a in acls)

    def test_records_raw_output_before_parsing(
        self, transport: FakeTransport, device_id: UUID
    ) -> None:
        from app.plugins.vendors.junos.plugin import JunosAcl

        cap = JunosAcl(transport, device_id)
        cap.get_acls()
        assert len(cap.raw_outputs) == 1
        assert cap.raw_outputs[0].command == SHOW_CONFIGURATION_FIREWALL


# ---------------------------------------------------------------------------
# Config backup
# ---------------------------------------------------------------------------


class TestConfigBackup:
    def test_fetch_running_config_returns_verbatim_text(
        self, transport: FakeTransport, device_id: UUID
    ) -> None:
        cap = JunosConfigBackup(transport, device_id)
        config = cap.fetch_running_config()
        assert config == _fixture("show_configuration_display_set.txt")
        assert "set system host-name juniper-mx01" in config
        assert cap.raw_outputs[0].command == SHOW_CONFIGURATION_SET
        assert cap.raw_outputs[0].output == config

    def test_empty_output_raises(self, device_id: UUID) -> None:
        empty = FakeTransport({"show configuration | display set": "   \n"})
        with pytest.raises(PluginError, match="empty output"):
            JunosConfigBackup(empty, device_id).fetch_running_config()

    def test_config_backup_resolves_via_plugin(self, device_id: UUID) -> None:
        plugin = JunosPlugin()
        assert plugin.get_capability(Capability.CONFIG_BACKUP) is JunosConfigBackup


# ---------------------------------------------------------------------------
# _normalize_config
# ---------------------------------------------------------------------------


class TestNormalizeConfig:
    def test_strips_last_commit_header(self) -> None:
        from app.plugins.vendors.junos.plugin import _normalize_config

        raw = "## Last commit: 2026-06-20 10:00:00 UTC by admin\nset system host-name mx01\n"
        normalized = _normalize_config(raw)
        assert "Last commit" not in normalized
        assert "set system host-name mx01" in normalized

    def test_strips_version_header(self) -> None:
        from app.plugins.vendors.junos.plugin import _normalize_config

        raw = "## version 23.1R1.8;\nset system host-name mx01\n"
        normalized = _normalize_config(raw)
        assert "version 23.1R1.8" not in normalized
        assert "set system host-name mx01" in normalized

    def test_cr_lf_normalized(self) -> None:
        from app.plugins.vendors.junos.plugin import _normalize_config

        assert _normalize_config("set a 1\r\nset b 2\r\n") == "set a 1\nset b 2\n"

    def test_single_trailing_newline(self) -> None:
        from app.plugins.vendors.junos.plugin import _normalize_config

        result = _normalize_config("set a 1\nset b 2")
        assert result.endswith("\n")
        assert not result.endswith("\n\n")

    def test_empty_input_returns_empty(self) -> None:
        from app.plugins.vendors.junos.plugin import _normalize_config

        assert _normalize_config("") == ""
        assert _normalize_config("   \n  \n  ") == ""
