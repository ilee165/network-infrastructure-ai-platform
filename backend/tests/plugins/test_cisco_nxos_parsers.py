"""Unit tests for the cisco_nxos parser functions (ADR-0025 §7).

Covers:
- Happy-path parse of every capability's fixture.
- Feature-gate tolerance (BGP, OSPF, LLDP): "feature not enabled" → [] not error.
- Multi-VRF route/BGP/OSPF tagging (ADR-0025 §3/§6).
- Empty-output handling for feature-gated capabilities.
- NX-OS-specific vPC HA status parsing (ADR-0025 §8).
- SNMP device facts extraction.
- Config normalization (preamble stripping).
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest

from app.core.errors import PluginError
from app.plugins.vendors.cisco_nxos import parsers
from app.plugins.vendors.cisco_nxos.parsers import (
    PLATFORM,
    SNMP_OID_SYSDESCR,
    SNMP_OID_SYSNAME,
    SNMP_OID_SYSOBJECTID,
)
from app.plugins.vendors.cisco_nxos.plugin import _normalize_config
from app.schemas.normalized import (
    BgpPeerState,
    HaPeerLinkState,
    HaPeerRole,
    InterfaceAdminStatus,
    InterfaceOperStatus,
    NeighborProtocol,
    OspfNeighborState,
    RouteProtocol,
)

FIXTURES = Path(__file__).parent / "fixtures" / "cisco_nxos"
_DEVICE_ID = uuid4()
_NOW = datetime(2024, 1, 1, tzinfo=UTC)


def _fix(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# parse_device_facts
# ---------------------------------------------------------------------------


class TestParseDeviceFacts:
    def test_parses_hostname(self) -> None:
        facts = parsers.parse_device_facts(_fix("show_version.txt"))
        assert facts.hostname == "nxos-spine01"

    def test_parses_vendor_id(self) -> None:
        facts = parsers.parse_device_facts(_fix("show_version.txt"))
        assert facts.vendor_id == PLATFORM

    def test_parses_model(self) -> None:
        facts = parsers.parse_device_facts(_fix("show_version.txt"))
        assert facts.model is not None and "9372" in facts.model

    def test_parses_os_version(self) -> None:
        facts = parsers.parse_device_facts(_fix("show_version.txt"))
        assert facts.os_version is not None and "9.3" in facts.os_version

    def test_parses_serial(self) -> None:
        facts = parsers.parse_device_facts(_fix("show_version.txt"))
        assert facts.serial == "SAL1234ABCD"

    def test_empty_output_raises_plugin_error(self) -> None:
        with pytest.raises(PluginError, match="no rows parsed"):
            parsers.parse_device_facts("")


# ---------------------------------------------------------------------------
# parse_snmp_device_facts
# ---------------------------------------------------------------------------


class TestParseSnmpDeviceFacts:
    _VALUES = {
        SNMP_OID_SYSDESCR: (
            "Cisco NX-OS(tm) nxos64-cs, Software (nxos64-cs-release), "
            "Version 9.3(8), RELEASE SOFTWARE"
        ),
        SNMP_OID_SYSOBJECTID: "1.3.6.1.4.1.9.12.3.1.3.1282",
        SNMP_OID_SYSNAME: "nxos-spine01",
    }

    def test_hostname(self) -> None:
        facts = parsers.parse_snmp_device_facts(self._VALUES)
        assert facts.hostname == "nxos-spine01"

    def test_vendor_id(self) -> None:
        facts = parsers.parse_snmp_device_facts(self._VALUES)
        assert facts.vendor_id == PLATFORM

    def test_os_version_from_sysdescr(self) -> None:
        facts = parsers.parse_snmp_device_facts(self._VALUES)
        assert facts.os_version is not None and "9.3" in facts.os_version

    def test_serial_is_none(self) -> None:
        facts = parsers.parse_snmp_device_facts(self._VALUES)
        assert facts.serial is None

    def test_missing_sysname_raises_plugin_error(self) -> None:
        with pytest.raises(PluginError, match="no sysName"):
            parsers.parse_snmp_device_facts({})


# ---------------------------------------------------------------------------
# parse_interfaces
# ---------------------------------------------------------------------------


class TestParseInterfaces:
    def test_returns_multiple_interfaces(self) -> None:
        ifaces = parsers.parse_interfaces(
            _fix("show_interface.txt"), device_id=_DEVICE_ID, collected_at=_NOW
        )
        assert len(ifaces) >= 2

    def test_source_vendor(self) -> None:
        ifaces = parsers.parse_interfaces(
            _fix("show_interface.txt"), device_id=_DEVICE_ID, collected_at=_NOW
        )
        assert all(i.source_vendor == PLATFORM for i in ifaces)

    def test_uplink_interface_is_up(self) -> None:
        ifaces = parsers.parse_interfaces(
            _fix("show_interface.txt"), device_id=_DEVICE_ID, collected_at=_NOW
        )
        eth1 = next(i for i in ifaces if i.name == "Ethernet1/1")
        assert eth1.admin_status == InterfaceAdminStatus.UP
        assert eth1.oper_status == InterfaceOperStatus.UP

    def test_uplink_ip_address(self) -> None:
        ifaces = parsers.parse_interfaces(
            _fix("show_interface.txt"), device_id=_DEVICE_ID, collected_at=_NOW
        )
        eth1 = next(i for i in ifaces if i.name == "Ethernet1/1")
        assert eth1.ip_address is not None
        assert str(eth1.ip_address.ip) == "10.0.0.1"

    def test_mgmt_interface_ip(self) -> None:
        ifaces = parsers.parse_interfaces(
            _fix("show_interface.txt"), device_id=_DEVICE_ID, collected_at=_NOW
        )
        mgmt = next((i for i in ifaces if "mgmt" in i.name.lower()), None)
        assert mgmt is not None
        assert mgmt.ip_address is not None


# ---------------------------------------------------------------------------
# parse_routes — VRF tagging
# ---------------------------------------------------------------------------


class TestParseRoutes:
    def test_returns_routes(self) -> None:
        routes = parsers.parse_routes(
            _fix("show_ip_route_vrf_all.txt"), device_id=_DEVICE_ID, collected_at=_NOW
        )
        assert len(routes) >= 4

    def test_source_vendor(self) -> None:
        routes = parsers.parse_routes(
            _fix("show_ip_route_vrf_all.txt"), device_id=_DEVICE_ID, collected_at=_NOW
        )
        assert all(r.source_vendor == PLATFORM for r in routes)

    def test_default_vrf_routes_carry_vrf(self) -> None:
        routes = parsers.parse_routes(
            _fix("show_ip_route_vrf_all.txt"), device_id=_DEVICE_ID, collected_at=_NOW
        )
        default_routes = [r for r in routes if r.vrf == "default"]
        assert len(default_routes) >= 1

    def test_management_vrf_routes_carry_vrf(self) -> None:
        routes = parsers.parse_routes(
            _fix("show_ip_route_vrf_all.txt"), device_id=_DEVICE_ID, collected_at=_NOW
        )
        mgmt_routes = [r for r in routes if r.vrf == "management"]
        assert len(mgmt_routes) >= 1

    def test_connected_route_protocol(self) -> None:
        routes = parsers.parse_routes(
            _fix("show_ip_route_vrf_all.txt"), device_id=_DEVICE_ID, collected_at=_NOW
        )
        direct_routes = [r for r in routes if r.protocol == RouteProtocol.CONNECTED]
        assert len(direct_routes) >= 1

    def test_static_route_in_management_vrf(self) -> None:
        routes = parsers.parse_routes(
            _fix("show_ip_route_vrf_all.txt"), device_id=_DEVICE_ID, collected_at=_NOW
        )
        static = [r for r in routes if r.protocol == RouteProtocol.STATIC and r.vrf == "management"]
        assert len(static) >= 1


# ---------------------------------------------------------------------------
# parse_cdp_neighbors
# ---------------------------------------------------------------------------


class TestParseCdpNeighbors:
    def test_returns_neighbors(self) -> None:
        neighbors = parsers.parse_cdp_neighbors(
            _fix("show_cdp_neighbors_detail.txt"), device_id=_DEVICE_ID, collected_at=_NOW
        )
        assert len(neighbors) >= 1

    def test_protocol_is_cdp(self) -> None:
        neighbors = parsers.parse_cdp_neighbors(
            _fix("show_cdp_neighbors_detail.txt"), device_id=_DEVICE_ID, collected_at=_NOW
        )
        assert all(n.protocol == NeighborProtocol.CDP for n in neighbors)

    def test_source_vendor(self) -> None:
        neighbors = parsers.parse_cdp_neighbors(
            _fix("show_cdp_neighbors_detail.txt"), device_id=_DEVICE_ID, collected_at=_NOW
        )
        assert all(n.source_vendor == PLATFORM for n in neighbors)

    def test_neighbor_name_populated(self) -> None:
        neighbors = parsers.parse_cdp_neighbors(
            _fix("show_cdp_neighbors_detail.txt"), device_id=_DEVICE_ID, collected_at=_NOW
        )
        assert all(n.neighbor_name for n in neighbors)

    def test_mgmt_address_parsed(self) -> None:
        neighbors = parsers.parse_cdp_neighbors(
            _fix("show_cdp_neighbors_detail.txt"), device_id=_DEVICE_ID, collected_at=_NOW
        )
        # At least one neighbor should have a non-None address
        assert any(n.neighbor_address is not None for n in neighbors)


# ---------------------------------------------------------------------------
# parse_lldp_neighbors — feature-gate tolerance
# ---------------------------------------------------------------------------


class TestParseLldpNeighbors:
    def test_returns_neighbors(self) -> None:
        neighbors = parsers.parse_lldp_neighbors(
            _fix("show_lldp_neighbors_detail.txt"), device_id=_DEVICE_ID, collected_at=_NOW
        )
        assert len(neighbors) >= 1

    def test_protocol_is_lldp(self) -> None:
        neighbors = parsers.parse_lldp_neighbors(
            _fix("show_lldp_neighbors_detail.txt"), device_id=_DEVICE_ID, collected_at=_NOW
        )
        assert all(n.protocol == NeighborProtocol.LLDP for n in neighbors)

    def test_source_vendor(self) -> None:
        neighbors = parsers.parse_lldp_neighbors(
            _fix("show_lldp_neighbors_detail.txt"), device_id=_DEVICE_ID, collected_at=_NOW
        )
        assert all(n.source_vendor == PLATFORM for n in neighbors)

    def test_feature_disabled_returns_empty_list(self) -> None:
        """Feature-gate tolerance (ADR-0025 §4): "feature not enabled" → []."""
        sentinel = "ERROR: This command requires the lldp feature to be enabled first."
        result = parsers.parse_lldp_neighbors(sentinel, device_id=_DEVICE_ID, collected_at=_NOW)
        assert result == []

    def test_empty_output_returns_empty_list(self) -> None:
        result = parsers.parse_lldp_neighbors("", device_id=_DEVICE_ID, collected_at=_NOW)
        assert result == []


# ---------------------------------------------------------------------------
# parse_bgp_peers — VRF tagging + feature-gate tolerance
# ---------------------------------------------------------------------------


class TestParseBgpPeers:
    def test_returns_peers(self) -> None:
        peers = parsers.parse_bgp_peers(
            _fix("show_ip_bgp_summary_vrf_all.txt"), device_id=_DEVICE_ID, collected_at=_NOW
        )
        assert len(peers) >= 1

    def test_source_vendor(self) -> None:
        peers = parsers.parse_bgp_peers(
            _fix("show_ip_bgp_summary_vrf_all.txt"), device_id=_DEVICE_ID, collected_at=_NOW
        )
        assert all(p.source_vendor == PLATFORM for p in peers)

    def test_established_peer_state(self) -> None:
        peers = parsers.parse_bgp_peers(
            _fix("show_ip_bgp_summary_vrf_all.txt"), device_id=_DEVICE_ID, collected_at=_NOW
        )
        assert any(p.state == BgpPeerState.ESTABLISHED for p in peers)

    def test_vrf_field_populated(self) -> None:
        """VRF tagging (ADR-0025 §3): each BGP peer carries its VRF."""
        peers = parsers.parse_bgp_peers(
            _fix("show_ip_bgp_summary_vrf_all.txt"), device_id=_DEVICE_ID, collected_at=_NOW
        )
        # At least one peer should have VRF set to "default"
        assert any(p.vrf == "default" for p in peers)

    def test_feature_disabled_returns_empty_list(self) -> None:
        sentinel = "ERROR: This command requires the bgp feature to be enabled first."
        result = parsers.parse_bgp_peers(sentinel, device_id=_DEVICE_ID, collected_at=_NOW)
        assert result == []

    def test_empty_output_returns_empty_list(self) -> None:
        result = parsers.parse_bgp_peers("", device_id=_DEVICE_ID, collected_at=_NOW)
        assert result == []


# ---------------------------------------------------------------------------
# parse_ospf_neighbors — VRF tagging + feature-gate tolerance
# ---------------------------------------------------------------------------


class TestParseOspfNeighbors:
    def test_returns_neighbors(self) -> None:
        neighbors = parsers.parse_ospf_neighbors(
            _fix("show_ip_ospf_neighbor_vrf_all.txt"), device_id=_DEVICE_ID, collected_at=_NOW
        )
        assert len(neighbors) >= 1

    def test_source_vendor(self) -> None:
        neighbors = parsers.parse_ospf_neighbors(
            _fix("show_ip_ospf_neighbor_vrf_all.txt"), device_id=_DEVICE_ID, collected_at=_NOW
        )
        assert all(n.source_vendor == PLATFORM for n in neighbors)

    def test_full_state(self) -> None:
        neighbors = parsers.parse_ospf_neighbors(
            _fix("show_ip_ospf_neighbor_vrf_all.txt"), device_id=_DEVICE_ID, collected_at=_NOW
        )
        assert any(n.state == OspfNeighborState.FULL for n in neighbors)

    def test_vrf_field_populated(self) -> None:
        """VRF tagging (ADR-0025 §6): NormalizedOspfNeighbor.vrf is populated."""
        neighbors = parsers.parse_ospf_neighbors(
            _fix("show_ip_ospf_neighbor_vrf_all.txt"), device_id=_DEVICE_ID, collected_at=_NOW
        )
        assert any(n.vrf is not None for n in neighbors)

    def test_feature_disabled_returns_empty_list(self) -> None:
        """Feature-gate tolerance (ADR-0025 §4): "feature not enabled" → []."""
        disabled = _fix("show_ip_ospf_neighbor_feature_disabled.txt")
        result = parsers.parse_ospf_neighbors(disabled, device_id=_DEVICE_ID, collected_at=_NOW)
        assert result == []

    def test_empty_output_returns_empty_list(self) -> None:
        result = parsers.parse_ospf_neighbors("", device_id=_DEVICE_ID, collected_at=_NOW)
        assert result == []


# ---------------------------------------------------------------------------
# parse_acls
# ---------------------------------------------------------------------------


class TestParseAcls:
    def test_returns_entries(self) -> None:
        entries = parsers.parse_acls(
            _fix("show_ip_access_lists.txt"), device_id=_DEVICE_ID, collected_at=_NOW
        )
        assert len(entries) >= 1

    def test_source_vendor(self) -> None:
        entries = parsers.parse_acls(
            _fix("show_ip_access_lists.txt"), device_id=_DEVICE_ID, collected_at=_NOW
        )
        assert all(e.source_vendor == PLATFORM for e in entries)

    def test_acl_name_populated(self) -> None:
        entries = parsers.parse_acls(
            _fix("show_ip_access_lists.txt"), device_id=_DEVICE_ID, collected_at=_NOW
        )
        assert all(e.acl_name == "MGMT-IN" for e in entries)

    def test_permit_and_deny_actions(self) -> None:
        from app.schemas.normalized import AclAction

        entries = parsers.parse_acls(
            _fix("show_ip_access_lists.txt"), device_id=_DEVICE_ID, collected_at=_NOW
        )
        actions = {e.action for e in entries}
        assert AclAction.PERMIT in actions
        assert AclAction.DENY in actions


# ---------------------------------------------------------------------------
# parse_ha_status — vPC state (ADR-0025 §8)
# ---------------------------------------------------------------------------


class TestParseHaStatus:
    def test_returns_one_record(self) -> None:
        records = parsers.parse_ha_status(
            _fix("show_vpc_json.txt"), device_id=_DEVICE_ID, collected_at=_NOW
        )
        assert len(records) == 1

    def test_source_vendor(self) -> None:
        records = parsers.parse_ha_status(
            _fix("show_vpc_json.txt"), device_id=_DEVICE_ID, collected_at=_NOW
        )
        assert records[0].source_vendor == PLATFORM

    def test_domain_id(self) -> None:
        records = parsers.parse_ha_status(
            _fix("show_vpc_json.txt"), device_id=_DEVICE_ID, collected_at=_NOW
        )
        assert records[0].ha_domain == "1"

    def test_peer_role_primary(self) -> None:
        records = parsers.parse_ha_status(
            _fix("show_vpc_json.txt"), device_id=_DEVICE_ID, collected_at=_NOW
        )
        assert records[0].peer_role == HaPeerRole.PRIMARY

    def test_peer_link_up(self) -> None:
        records = parsers.parse_ha_status(
            _fix("show_vpc_json.txt"), device_id=_DEVICE_ID, collected_at=_NOW
        )
        assert records[0].peer_link_state == HaPeerLinkState.UP

    def test_keepalive_up(self) -> None:
        records = parsers.parse_ha_status(
            _fix("show_vpc_json.txt"), device_id=_DEVICE_ID, collected_at=_NOW
        )
        assert records[0].keepalive_state == HaPeerLinkState.UP

    def test_consistency_ok(self) -> None:
        records = parsers.parse_ha_status(
            _fix("show_vpc_json.txt"), device_id=_DEVICE_ID, collected_at=_NOW
        )
        assert records[0].consistency_check_ok is True

    def test_empty_output_returns_empty(self) -> None:
        result = parsers.parse_ha_status("", device_id=_DEVICE_ID, collected_at=_NOW)
        assert result == []

    def test_vpc_not_configured_returns_empty(self) -> None:
        result = parsers.parse_ha_status(
            "vPC is not configured", device_id=_DEVICE_ID, collected_at=_NOW
        )
        assert result == []

    def test_feature_disabled_returns_empty(self) -> None:
        sentinel = "ERROR: This command requires the vpc feature to be enabled first."
        result = parsers.parse_ha_status(sentinel, device_id=_DEVICE_ID, collected_at=_NOW)
        assert result == []

    def test_parses_structured_json_not_plain_text(self) -> None:
        """ADR-0025 §3/§8: the parser consumes ``show vpc | json`` JSON, not CLI text.

        The legacy plain-text ``show vpc`` rendering is not valid JSON, so it
        must normalize to empty (no spurious record) — proving the parser is on
        the JSON path, not the rejected regex-over-CLI-text path.
        """
        plain_text = (
            "vPC domain id                     : 1\nvPC role                          : primary\n"
        )
        assert parsers.parse_ha_status(plain_text, device_id=_DEVICE_ID, collected_at=_NOW) == []

    def test_secondary_role_from_json(self) -> None:
        document = '{"vpc-domain-id": "7", "vpc-role": "secondary"}'
        records = parsers.parse_ha_status(document, device_id=_DEVICE_ID, collected_at=_NOW)
        assert records[0].peer_role == HaPeerRole.SECONDARY
        assert records[0].ha_domain == "7"

    def test_peer_link_down_from_json(self) -> None:
        document = (
            '{"vpc-domain-id": "1", '
            '"TABLE_peerlink": {"ROW_peerlink": {"peer-link-port-state": "0"}}}'
        )
        records = parsers.parse_ha_status(document, device_id=_DEVICE_ID, collected_at=_NOW)
        assert records[0].peer_link_state == HaPeerLinkState.DOWN


# ---------------------------------------------------------------------------
# _normalize_config (ADR-0021 §1 parity / ADR-0025 §5)
# ---------------------------------------------------------------------------


class TestNormalizeConfig:
    def test_strips_command_preamble(self) -> None:
        raw = "!Command: show running-config\nhostname nxos-spine01\n"
        normalized = _normalize_config(raw)
        assert "!Command:" not in normalized
        assert "hostname nxos-spine01" in normalized

    def test_strips_timestamp_preamble(self) -> None:
        raw = (
            "!Running configuration last done at: Fri Nov  5 11:00:00 2021\nhostname nxos-spine01\n"
        )
        normalized = _normalize_config(raw)
        assert "!Running configuration" not in normalized
        assert "hostname nxos-spine01" in normalized

    def test_strips_time_preamble(self) -> None:
        raw = "!Time: Fri Nov  5 11:00:00 2021\nhostname nxos-spine01\n"
        normalized = _normalize_config(raw)
        assert "!Time:" not in normalized

    def test_ends_with_single_newline(self) -> None:
        raw = "hostname nxos-spine01"
        normalized = _normalize_config(raw)
        assert normalized.endswith("\n")
        assert not normalized.endswith("\n\n")

    def test_empty_input_returns_empty(self) -> None:
        assert _normalize_config("") == ""

    def test_crlf_normalized(self) -> None:
        raw = "hostname nxos-spine01\r\nip domain-lookup\r\n"
        normalized = _normalize_config(raw)
        assert "\r" not in normalized


# ---------------------------------------------------------------------------
# Feature-gate helpers
# ---------------------------------------------------------------------------


class TestFeatureGateHelpers:
    def test_feature_disabled_sentinel_detected(self) -> None:
        assert parsers._is_feature_disabled(
            "ERROR: This command requires the bgp feature to be enabled first."
        )

    def test_invalid_command_detected(self) -> None:
        assert parsers._is_feature_disabled("Invalid command at '^' marker")

    def test_empty_output_detected(self) -> None:
        assert parsers._is_feature_disabled("")

    def test_whitespace_only_detected(self) -> None:
        assert parsers._is_feature_disabled("   \n   ")

    def test_normal_output_not_detected(self) -> None:
        assert not parsers._is_feature_disabled(
            " OSPF Process ID 1 VRF default\n Neighbor ID     Pri State"
        )
