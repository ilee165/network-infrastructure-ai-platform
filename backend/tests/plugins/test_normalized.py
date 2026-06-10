"""Validation tests for the normalized network models (app/schemas/normalized.py)."""

from __future__ import annotations

from datetime import UTC, datetime
from ipaddress import IPv4Address, IPv4Interface, IPv4Network
from typing import Any
from uuid import uuid4

import pytest
from pydantic import ValidationError

from app.schemas.normalized import (
    AclAction,
    BgpPeerState,
    DnsRecordType,
    InterfaceAdminStatus,
    InterfaceOperStatus,
    NeighborProtocol,
    NormalizedAclEntry,
    NormalizedArpEntry,
    NormalizedBgpPeer,
    NormalizedDnsRecord,
    NormalizedInterface,
    NormalizedNeighbor,
    NormalizedOspfNeighbor,
    NormalizedRoute,
    NormalizedVlan,
    OspfNeighborState,
    RouteProtocol,
    VlanStatus,
    normalize_mac,
)


@pytest.fixture()
def provenance() -> dict[str, Any]:
    """The provenance triple every normalized record must carry."""
    return {
        "device_id": uuid4(),
        "collected_at": datetime(2026, 6, 10, 12, 0, 0, tzinfo=UTC),
        "source_vendor": "cisco_ios",
    }


class TestNormalizeMac:
    @pytest.mark.parametrize(
        "raw",
        ["fa16.3e11.2233", "FA:16:3E:11:22:33", "fa-16-3e-11-22-33", "FA163E112233"],
    )
    def test_normalize_mac_accepts_common_vendor_formats(self, raw: str) -> None:
        assert normalize_mac(raw) == "fa:16:3e:11:22:33"

    @pytest.mark.parametrize("raw", ["", "zz16.3e11.2233", "fa16.3e11.22", "fa16.3e11.223344"])
    def test_normalize_mac_rejects_invalid_input(self, raw: str) -> None:
        with pytest.raises(ValueError, match="invalid MAC address"):
            normalize_mac(raw)


class TestProvenanceContract:
    def test_naive_collected_at_is_rejected(self, provenance: dict[str, Any]) -> None:
        provenance["collected_at"] = datetime(2026, 6, 10, 12, 0, 0)  # noqa: DTZ001
        with pytest.raises(ValidationError):
            NormalizedVlan(vlan_id=10, **provenance)

    def test_records_are_frozen(self, provenance: dict[str, Any]) -> None:
        vlan = NormalizedVlan(vlan_id=10, **provenance)
        with pytest.raises(ValidationError):
            vlan.vlan_id = 20  # type: ignore[misc]

    def test_unknown_fields_are_rejected(self, provenance: dict[str, Any]) -> None:
        with pytest.raises(ValidationError):
            NormalizedVlan(vlan_id=10, bogus="x", **provenance)  # type: ignore[call-arg]

    def test_empty_source_vendor_is_rejected(self, provenance: dict[str, Any]) -> None:
        provenance["source_vendor"] = ""
        with pytest.raises(ValidationError):
            NormalizedVlan(vlan_id=10, **provenance)


class TestNormalizedInterface:
    def test_interface_coerces_ip_and_normalizes_mac(self, provenance: dict[str, Any]) -> None:
        interface = NormalizedInterface(
            name="GigabitEthernet0/0",
            admin_status=InterfaceAdminStatus.UP,
            oper_status=InterfaceOperStatus.UP,
            mac_address="5254.0012.3456",
            ip_address="192.0.2.10/30",
            **provenance,
        )
        assert interface.ip_address == IPv4Interface("192.0.2.10/30")
        assert interface.mac_address == "52:54:00:12:34:56"

    def test_interface_rejects_out_of_range_vlan(self, provenance: dict[str, Any]) -> None:
        with pytest.raises(ValidationError):
            NormalizedInterface(
                name="Gi0/0",
                admin_status=InterfaceAdminStatus.UP,
                oper_status=InterfaceOperStatus.UP,
                vlan_id=5000,
                **provenance,
            )

    def test_interface_status_accepts_wire_strings(self, provenance: dict[str, Any]) -> None:
        interface = NormalizedInterface(
            name="Gi0/0", admin_status="down", oper_status="unknown", **provenance
        )
        assert interface.admin_status is InterfaceAdminStatus.DOWN
        assert interface.oper_status is InterfaceOperStatus.UNKNOWN


class TestNormalizedRoute:
    def test_route_coerces_destination_network(self, provenance: dict[str, Any]) -> None:
        route = NormalizedRoute(
            destination="10.20.0.0/24",
            protocol=RouteProtocol.OSPF,
            next_hop="10.10.0.2",
            distance=110,
            metric=20,
            **provenance,
        )
        assert route.destination == IPv4Network("10.20.0.0/24")
        assert route.next_hop == IPv4Address("10.10.0.2")

    def test_route_rejects_distance_above_255(self, provenance: dict[str, Any]) -> None:
        with pytest.raises(ValidationError):
            NormalizedRoute(
                destination="0.0.0.0/0",
                protocol=RouteProtocol.STATIC,
                distance=300,
                **provenance,
            )


class TestRemainingModels:
    def test_neighbor_validates(self, provenance: dict[str, Any]) -> None:
        neighbor = NormalizedNeighbor(
            protocol=NeighborProtocol.LLDP,
            local_interface="Gi0/1",
            neighbor_name="leaf-sw02.example.net",
            neighbor_address="10.10.0.3",
            neighbor_capabilities=["B", "R"],
            **provenance,
        )
        assert neighbor.neighbor_address == IPv4Address("10.10.0.3")
        assert neighbor.neighbor_capabilities == ("B", "R")

    def test_bgp_peer_validates_and_bounds_asn(self, provenance: dict[str, Any]) -> None:
        peer = NormalizedBgpPeer(
            peer_address="192.0.2.9",
            remote_as=65001,
            state="established",
            prefixes_received=42,
            **provenance,
        )
        assert peer.state is BgpPeerState.ESTABLISHED
        with pytest.raises(ValidationError):
            NormalizedBgpPeer(
                peer_address="192.0.2.9",
                remote_as=4_294_967_296,
                state=BgpPeerState.IDLE,
                **provenance,
            )

    def test_ospf_neighbor_validates(self, provenance: dict[str, Any]) -> None:
        neighbor = NormalizedOspfNeighbor(
            neighbor_id="10.10.0.2",
            interface="Gi0/1",
            state=OspfNeighborState.FULL,
            area="0",
            priority=1,
            **provenance,
        )
        assert neighbor.neighbor_id == IPv4Address("10.10.0.2")

    def test_acl_entry_none_means_any(self, provenance: dict[str, Any]) -> None:
        entry = NormalizedAclEntry(
            acl_name="EDGE-IN",
            action=AclAction.DENY,
            protocol="tcp",
            sequence=10,
            destination="10.10.0.0/24",
            destination_port="22",
            **provenance,
        )
        assert entry.source is None  # any
        assert entry.destination == IPv4Network("10.10.0.0/24")

    def test_arp_entry_normalizes_mac(self, provenance: dict[str, Any]) -> None:
        entry = NormalizedArpEntry(
            ip_address="10.10.0.2",
            mac_address="001C.73AA.BB01",
            interface="Gi0/1",
            **provenance,
        )
        assert entry.mac_address == "00:1c:73:aa:bb:01"

    def test_vlan_status_defaults_to_unknown(self, provenance: dict[str, Any]) -> None:
        vlan = NormalizedVlan(vlan_id=100, name="USERS", **provenance)
        assert vlan.status is VlanStatus.UNKNOWN

    def test_dns_record_validates(self, provenance: dict[str, Any]) -> None:
        record = NormalizedDnsRecord(
            name="core-rtr01.example.net.",
            record_type=DnsRecordType.A,
            value="10.10.0.1",
            ttl=3600,
            zone="example.net",
            **provenance,
        )
        assert record.record_type is DnsRecordType.A
