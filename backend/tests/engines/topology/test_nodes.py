"""Node derivation (M2-04): typed graph-node records + derive_nodes purity.

Fixtures construct ORM rows directly (no session) — derivation is a pure
function over in-memory ``Device`` / ``NormalizedInterfaceRow`` /
``NormalizedRouteRow`` instances.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest

from app.engines.topology import (
    DerivedNodes,
    DeviceNode,
    InterfaceNode,
    IPAddressNode,
    SiteNode,
    SubnetNode,
    VlanNode,
    VrfNode,
    derive_nodes,
)
from app.models.inventory import Device, NormalizedInterfaceRow, NormalizedRouteRow
from app.schemas.normalized import (
    InterfaceAdminStatus,
    InterfaceOperStatus,
    RouteProtocol,
)

COLLECTED_AT = datetime(2026, 6, 12, 12, 0, tzinfo=UTC)
PROJECTED_AT = datetime(2026, 6, 12, 13, 0, tzinfo=UTC)


def make_device(
    hostname: str,
    mgmt_ip: str,
    *,
    device_id: UUID | None = None,
    vendor_id: str | None = "cisco_ios",
    model: str | None = "C9300",
    site: str | None = None,
) -> Device:
    return Device(
        id=device_id or uuid4(),
        hostname=hostname,
        mgmt_ip=mgmt_ip,
        vendor_id=vendor_id,
        model=model,
        site=site,
    )


def make_interface(
    device_id: UUID,
    name: str,
    *,
    row_id: UUID | None = None,
    ip_address: str | None = None,
    vlan_id: int | None = None,
    mac_address: str | None = None,
    admin_status: InterfaceAdminStatus = InterfaceAdminStatus.UP,
    oper_status: InterfaceOperStatus = InterfaceOperStatus.UP,
) -> NormalizedInterfaceRow:
    return NormalizedInterfaceRow(
        id=row_id or uuid4(),
        device_id=device_id,
        raw_artifact_id=uuid4(),
        collected_at=COLLECTED_AT,
        source_vendor="cisco_ios",
        name=name,
        admin_status=admin_status,
        oper_status=oper_status,
        mac_address=mac_address,
        ip_address=ip_address,
        vlan_id=vlan_id,
    )


def make_route(
    device_id: UUID,
    prefix: str,
    *,
    vrf: str = "",
    protocol: RouteProtocol = RouteProtocol.STATIC,
) -> NormalizedRouteRow:
    return NormalizedRouteRow(
        id=uuid4(),
        device_id=device_id,
        raw_artifact_id=uuid4(),
        collected_at=COLLECTED_AT,
        source_vendor="cisco_ios",
        prefix=prefix,
        protocol=protocol,
        next_hop="",
        interface="",
        vrf=vrf,
    )


def small_inventory() -> tuple[
    list[Device], list[NormalizedInterfaceRow], list[NormalizedRouteRow]
]:
    """Two-device fixture inventory exercising every derivation rule."""
    core = make_device("core-1", "10.0.0.1", site="hq")
    edge = make_device("edge-1", "10.0.0.2", site="branch")
    interfaces = [
        make_interface(core.id, "Gi0/0", ip_address="10.10.0.1/24", vlan_id=10),
        make_interface(core.id, "Gi0/1", ip_address="10.20.0.1/24", vlan_id=20),
        make_interface(edge.id, "Gi0/0", ip_address="10.10.0.2/24", vlan_id=10),
        make_interface(edge.id, "Gi0/1"),  # no IP, no VLAN
    ]
    routes = [
        make_route(core.id, "0.0.0.0/0"),
        make_route(core.id, "192.168.50.0/24", vrf="MGMT"),
        make_route(edge.id, "10.20.0.0/24", vrf="MGMT", protocol=RouteProtocol.OSPF),
    ]
    return [core, edge], interfaces, routes


class TestDeviceNodes:
    def test_one_node_per_device_with_display_props(self) -> None:
        device = make_device("core-1", "10.0.0.1", site="hq")
        derived = derive_nodes([device], [], [])
        assert derived.devices == (
            DeviceNode(
                pg_id=device.id,
                hostname="core-1",
                mgmt_ip="10.0.0.1",
                vendor_id="cisco_ios",
                model="C9300",
                site="hq",
            ),
        )

    def test_sorted_by_hostname(self) -> None:
        devices = [make_device("zulu", "10.0.0.9"), make_device("alpha", "10.0.0.8")]
        derived = derive_nodes(devices, [], [])
        assert [node.hostname for node in derived.devices] == ["alpha", "zulu"]

    def test_deduped_by_pg_id(self) -> None:
        device_id = uuid4()
        devices = [
            make_device("core-1", "10.0.0.1", device_id=device_id),
            make_device("core-1", "10.0.0.1", device_id=device_id),
        ]
        derived = derive_nodes(devices, [], [])
        assert len(derived.devices) == 1


class TestInterfaceNodes:
    def test_carries_name_statuses_mac_and_ip_address(self) -> None:
        iface = make_interface(
            uuid4(),
            "Gi0/0",
            ip_address="10.1.0.1/24",
            mac_address="aa:bb:cc:dd:ee:ff",
            admin_status=InterfaceAdminStatus.UP,
            oper_status=InterfaceOperStatus.DOWN,
        )
        derived = derive_nodes([], [iface], [])
        assert derived.interfaces == (
            InterfaceNode(
                pg_id=iface.id,
                name="Gi0/0",
                admin_status=InterfaceAdminStatus.UP,
                oper_status=InterfaceOperStatus.DOWN,
                mac_address="aa:bb:cc:dd:ee:ff",
                ip_address="10.1.0.1/24",
            ),
        )

    def test_ip_address_none_when_interface_has_no_address(self) -> None:
        iface = make_interface(uuid4(), "Gi0/1")
        derived = derive_nodes([], [iface], [])
        assert derived.interfaces[0].ip_address is None

    def test_sorted_by_name_then_pg_id(self) -> None:
        device_id = uuid4()
        ifaces = [
            make_interface(device_id, "Gi0/2"),
            make_interface(device_id, "Gi0/1"),
        ]
        derived = derive_nodes([], ifaces, [])
        assert [node.name for node in derived.interfaces] == ["Gi0/1", "Gi0/2"]


class TestSubnetNodes:
    def test_derived_from_interface_ip_networks(self) -> None:
        _, interfaces, _ = small_inventory()
        derived = derive_nodes([], interfaces, [])
        assert derived.subnets == (
            SubnetNode(cidr="10.10.0.0/24"),
            SubnetNode(cidr="10.20.0.0/24"),
        )

    def test_route_prefixes_create_subnets(self) -> None:
        # M2-05: every ROUTES_TO edge needs a real Subnet endpoint, so route
        # prefixes ARE projected Subnet nodes.
        routes = [make_route(uuid4(), "172.16.0.0/16")]
        derived = derive_nodes([], [], routes)
        assert derived.subnets == (SubnetNode(cidr="172.16.0.0/16"),)

    def test_route_prefix_subnets_merge_with_interface_subnets(self) -> None:
        device_id = uuid4()
        ifaces = [make_interface(device_id, "Gi0/0", ip_address="10.10.0.1/24")]
        routes = [
            make_route(device_id, "10.10.0.0/24"),  # same network — deduped
            make_route(device_id, "0.0.0.0/0"),
        ]
        derived = derive_nodes([], ifaces, routes)
        assert derived.subnets == (
            SubnetNode(cidr="0.0.0.0/0"),
            SubnetNode(cidr="10.10.0.0/24"),
        )

    def test_shared_network_deduped(self) -> None:
        device_id = uuid4()
        ifaces = [
            make_interface(device_id, "Gi0/0", ip_address="10.10.0.1/24"),
            make_interface(device_id, "Gi0/1", ip_address="10.10.0.2/24"),
        ]
        derived = derive_nodes([], ifaces, [])
        assert derived.subnets == (SubnetNode(cidr="10.10.0.0/24"),)

    def test_ipv6_interface_address(self) -> None:
        iface = make_interface(uuid4(), "Gi0/0", ip_address="2001:db8::1/64")
        derived = derive_nodes([], [iface], [])
        assert derived.subnets == (SubnetNode(cidr="2001:db8::/64"),)
        assert derived.ip_addresses == (IPAddressNode(pg_id=iface.id, address="2001:db8::1"),)


class TestIPAddressNodes:
    def test_derived_from_interface_hosts(self) -> None:
        iface = make_interface(uuid4(), "Gi0/0", ip_address="10.10.0.1/24")
        derived = derive_nodes([], [iface], [])
        assert derived.ip_addresses == (IPAddressNode(pg_id=iface.id, address="10.10.0.1"),)

    def test_deduped_by_address_deterministically(self) -> None:
        device_id = uuid4()
        first = make_interface(
            device_id,
            "Gi0/0",
            row_id=UUID("00000000-0000-0000-0000-000000000001"),
            ip_address="10.10.0.1/24",
        )
        second = make_interface(
            device_id,
            "Gi0/1",
            row_id=UUID("00000000-0000-0000-0000-000000000002"),
            ip_address="10.10.0.1/24",
        )
        forward = derive_nodes([], [first, second], [])
        reverse = derive_nodes([], [second, first], [])
        assert forward.ip_addresses == reverse.ip_addresses
        assert forward.ip_addresses == (IPAddressNode(pg_id=first.id, address="10.10.0.1"),)

    def test_sorted_numerically_not_lexically(self) -> None:
        device_id = uuid4()
        ifaces = [
            make_interface(device_id, "Gi0/0", ip_address="10.0.0.10/24"),
            make_interface(device_id, "Gi0/1", ip_address="10.0.0.2/24"),
        ]
        derived = derive_nodes([], ifaces, [])
        assert [node.address for node in derived.ip_addresses] == ["10.0.0.2", "10.0.0.10"]


class TestVlanNodes:
    def test_distinct_vlan_ids_sorted(self) -> None:
        device_id = uuid4()
        ifaces = [
            make_interface(device_id, "Gi0/0", vlan_id=20),
            make_interface(device_id, "Gi0/1", vlan_id=10),
            make_interface(device_id, "Gi0/2", vlan_id=20),
            make_interface(device_id, "Gi0/3"),
        ]
        derived = derive_nodes([], ifaces, [])
        assert derived.vlans == (VlanNode(vlan_id=10), VlanNode(vlan_id=20))


class TestVrfNodes:
    def test_distinct_non_empty_route_vrfs(self) -> None:
        device_id = uuid4()
        routes = [
            make_route(device_id, "0.0.0.0/0"),  # '' sentinel: global table
            make_route(device_id, "10.0.0.0/8", vrf="MGMT"),
            make_route(device_id, "10.1.0.0/16", vrf="CUST"),
            make_route(device_id, "10.2.0.0/16", vrf="MGMT"),
        ]
        derived = derive_nodes([], [], routes)
        assert derived.vrfs == (VrfNode(name="CUST"), VrfNode(name="MGMT"))


class TestSiteNodes:
    def test_distinct_non_null_device_sites(self) -> None:
        devices = [
            make_device("a", "10.0.0.1", site="hq"),
            make_device("b", "10.0.0.2", site="branch"),
            make_device("c", "10.0.0.3", site="hq"),
            make_device("d", "10.0.0.4", site=None),
        ]
        derived = derive_nodes(devices, [], [])
        assert derived.sites == (SiteNode(name="branch"), SiteNode(name="hq"))


class TestDeterminism:
    def test_input_order_does_not_change_output(self) -> None:
        devices, interfaces, routes = small_inventory()
        forward = derive_nodes(devices, interfaces, routes)
        reverse = derive_nodes(devices[::-1], interfaces[::-1], routes[::-1])
        assert forward == reverse

    def test_empty_inputs_yield_empty_node_sets(self) -> None:
        derived = derive_nodes([], [], [])
        assert derived == DerivedNodes()

    def test_inputs_not_mutated(self) -> None:
        devices, interfaces, routes = small_inventory()
        snapshot = ([d.id for d in devices], [i.id for i in interfaces], [r.id for r in routes])
        derive_nodes(devices, interfaces, routes)
        assert snapshot == (
            [d.id for d in devices],
            [i.id for i in interfaces],
            [r.id for r in routes],
        )


class TestNeo4jProperties:
    def test_device_payload_stringifies_uuid_and_stamps_projection_time(self) -> None:
        device_id = uuid.UUID("00000000-0000-0000-0000-0000000000aa")
        node = DeviceNode(
            pg_id=device_id,
            hostname="core-1",
            mgmt_ip="10.0.0.1",
            vendor_id="cisco_ios",
            model="C9300",
            site="hq",
        )
        assert node.neo4j_properties(PROJECTED_AT) == {
            "pg_id": "00000000-0000-0000-0000-0000000000aa",
            "hostname": "core-1",
            "mgmt_ip": "10.0.0.1",
            "vendor_id": "cisco_ios",
            "model": "C9300",
            "site": "hq",
            "last_projected_at": PROJECTED_AT,
        }

    def test_interface_payload_uses_enum_wire_values(self) -> None:
        node = InterfaceNode(
            pg_id=uuid4(),
            name="Gi0/0",
            admin_status=InterfaceAdminStatus.UP,
            oper_status=InterfaceOperStatus.DOWN,
            mac_address=None,
            ip_address=None,
        )
        props = node.neo4j_properties(PROJECTED_AT)
        assert props["admin_status"] == "up"
        assert props["oper_status"] == "down"
        assert type(props["admin_status"]) is str

    def test_naive_projection_instant_rejected(self) -> None:
        node = SiteNode(name="hq")
        with pytest.raises(ValueError, match="timezone-aware"):
            node.neo4j_properties(datetime(2026, 6, 12, 13, 0))  # noqa: DTZ001

    def test_labels_and_key_properties(self) -> None:
        expectations = [
            (DeviceNode, "Device", "pg_id"),
            (InterfaceNode, "Interface", "pg_id"),
            (IPAddressNode, "IPAddress", "pg_id"),
            (SubnetNode, "Subnet", "cidr"),
            (VlanNode, "Vlan", "vlan_id"),
            (VrfNode, "VRF", "name"),
            (SiteNode, "Site", "name"),
        ]
        for node_cls, label, key_property in expectations:
            assert node_cls.label == label
            assert node_cls.key_property == key_property

    def test_key_returns_key_property_value(self) -> None:
        assert VlanNode(vlan_id=10).key == 10
        assert SubnetNode(cidr="10.0.0.0/24").key == "10.0.0.0/24"

    def test_ip_address_key_is_pg_id(self) -> None:
        """IPAddressNode.key must return the pg_id UUID (as UUID, not address string).

        This aligns node.key with NODE_KEY_PROPERTY['IPAddress'] = 'pg_id' so that
        edge builders producing EdgeEndpoint(label='IPAddress', key=node.key) emit
        the same value that _edge_upsert_cypher() resolves in its MATCH clause.
        """
        iface_id = UUID("00000000-0000-0000-0000-000000000042")
        node = IPAddressNode(pg_id=iface_id, address="10.0.0.1")
        assert node.key == iface_id
        assert node.key != "10.0.0.1"

    def test_records_are_frozen(self) -> None:
        node = SiteNode(name="hq")
        with pytest.raises(Exception, match="frozen"):
            node.name = "other"  # type: ignore[misc]
