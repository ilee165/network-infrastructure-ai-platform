"""Edge builders (M2-05): L2 CONNECTED_TO + L3 edge sets.

Fixtures construct ORM rows directly (no session) — building is a pure
function over in-memory ``Device`` / ``NormalizedInterfaceRow`` /
``NormalizedNeighborRow`` / ``NormalizedRouteRow`` instances.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

from app.engines.topology import (
    ConnectedToEdge,
    DerivedL3Edges,
    EdgeEndpoint,
    HasInterfaceEdge,
    InSubnetEdge,
    L3AdjacentEdge,
    RoutesToEdge,
    build_l2_edges,
    build_l3_edges,
    derive_nodes,
)
from app.models.inventory import (
    Device,
    NormalizedInterfaceRow,
    NormalizedNeighborRow,
    NormalizedRouteRow,
)
from app.schemas.normalized import (
    InterfaceAdminStatus,
    InterfaceOperStatus,
    NeighborProtocol,
    RouteProtocol,
)

COLLECTED_AT = datetime(2026, 6, 12, 12, 0, tzinfo=UTC)


def make_device(
    hostname: str,
    mgmt_ip: str,
    *,
    device_id: UUID | None = None,
    site: str | None = None,
) -> Device:
    return Device(
        id=device_id or uuid4(),
        hostname=hostname,
        mgmt_ip=mgmt_ip,
        vendor_id="cisco_ios",
        model="C9300",
        site=site,
    )


def make_interface(
    device_id: UUID,
    name: str,
    *,
    row_id: UUID | None = None,
    ip_address: str | None = None,
    vlan_id: int | None = None,
) -> NormalizedInterfaceRow:
    return NormalizedInterfaceRow(
        id=row_id or uuid4(),
        device_id=device_id,
        raw_artifact_id=uuid4(),
        collected_at=COLLECTED_AT,
        source_vendor="cisco_ios",
        name=name,
        admin_status=InterfaceAdminStatus.UP,
        oper_status=InterfaceOperStatus.UP,
        ip_address=ip_address,
        vlan_id=vlan_id,
    )


def make_neighbor(
    device_id: UUID,
    local_interface: str,
    neighbor_name: str,
    *,
    neighbor_interface: str = "",
    neighbor_address: str | None = None,
    protocol: NeighborProtocol = NeighborProtocol.LLDP,
) -> NormalizedNeighborRow:
    return NormalizedNeighborRow(
        id=uuid4(),
        device_id=device_id,
        raw_artifact_id=uuid4(),
        collected_at=COLLECTED_AT,
        source_vendor="cisco_ios",
        protocol=protocol,
        local_interface=local_interface,
        neighbor_name=neighbor_name,
        neighbor_interface=neighbor_interface,
        neighbor_address=neighbor_address,
    )


def interface_endpoint(row: NormalizedInterfaceRow) -> EdgeEndpoint:
    return EdgeEndpoint(label="Interface", key=str(row.id))


def device_endpoint(device: Device) -> EdgeEndpoint:
    return EdgeEndpoint(label="Device", key=str(device.id))


def l2_inventory() -> tuple[list[Device], list[NormalizedInterfaceRow]]:
    """Two devices, each with two named interfaces."""
    core = make_device("core-1", "10.0.0.1")
    edge = make_device("edge-1", "10.0.0.2")
    interfaces = [
        make_interface(core.id, "Gi0/0"),
        make_interface(core.id, "Gi0/1"),
        make_interface(edge.id, "Gi0/0"),
        make_interface(edge.id, "Gi0/1"),
    ]
    return [core, edge], interfaces


class TestNeighborResolution:
    def test_exact_hostname_match_is_case_insensitive(self) -> None:
        devices, interfaces = l2_inventory()
        neighbors = [make_neighbor(devices[0].id, "Gi0/0", "EDGE-1", neighbor_interface="Gi0/0")]
        result = build_l2_edges(devices, interfaces, neighbors)
        assert len(result.edges) == 1
        assert result.report.unresolved_neighbors == 0

    def test_fqdn_neighbor_matches_bare_hostname(self) -> None:
        devices, interfaces = l2_inventory()
        neighbors = [
            make_neighbor(devices[0].id, "Gi0/0", "edge-1.example.com", neighbor_interface="Gi0/0")
        ]
        result = build_l2_edges(devices, interfaces, neighbors)
        assert len(result.edges) == 1

    def test_bare_neighbor_matches_fqdn_hostname(self) -> None:
        core = make_device("core-1", "10.0.0.1")
        edge = make_device("edge-1.example.com", "10.0.0.2")
        iface_core = make_interface(core.id, "Gi0/0")
        iface_edge = make_interface(edge.id, "Gi0/0")
        neighbors = [make_neighbor(core.id, "Gi0/0", "edge-1", neighbor_interface="Gi0/0")]
        result = build_l2_edges([core, edge], [iface_core, iface_edge], neighbors)
        assert len(result.edges) == 1

    def test_mgmt_ip_fallback_when_name_unknown(self) -> None:
        devices, interfaces = l2_inventory()
        neighbors = [
            make_neighbor(
                devices[0].id,
                "Gi0/0",
                "unknown-name",
                neighbor_interface="Gi0/0",
                neighbor_address="10.0.0.2",
            )
        ]
        result = build_l2_edges(devices, interfaces, neighbors)
        assert len(result.edges) == 1
        assert result.report.unresolved_neighbors == 0

    def test_ambiguous_bare_name_falls_back_to_address(self) -> None:
        a = make_device("sw.site-a.example.com", "10.0.0.2")
        b = make_device("sw.site-b.example.com", "10.0.0.3")
        core = make_device("core-1", "10.0.0.1")
        iface = make_interface(core.id, "Gi0/0")
        neighbors = [make_neighbor(core.id, "Gi0/0", "sw", neighbor_address="10.0.0.3")]
        result = build_l2_edges([core, a, b], [iface], neighbors)
        assert len(result.edges) == 1
        assert result.edges[0].a == interface_endpoint(iface) or result.edges[
            0
        ].b == interface_endpoint(iface)
        assert device_endpoint(b) in (result.edges[0].a, result.edges[0].b)

    def test_unresolved_neighbor_skipped_and_counted(self) -> None:
        devices, interfaces = l2_inventory()
        neighbors = [
            make_neighbor(devices[0].id, "Gi0/0", "ghost-1", neighbor_address="192.0.2.99")
        ]
        result = build_l2_edges(devices, interfaces, neighbors)
        assert result.edges == ()
        assert result.report.neighbor_rows == 1
        assert result.report.unresolved_neighbors == 1
        assert result.report.unresolved_neighbor_names == ("ghost-1",)

    def test_reporting_device_missing_is_unresolved(self) -> None:
        devices, interfaces = l2_inventory()
        neighbors = [make_neighbor(uuid4(), "Gi0/0", "edge-1")]
        result = build_l2_edges(devices, interfaces, neighbors)
        assert result.edges == ()
        assert result.report.unresolved_neighbors == 1


class TestEndpointFallback:
    def test_both_interfaces_resolved_yield_interface_endpoints(self) -> None:
        devices, interfaces = l2_inventory()
        core_if, edge_if = interfaces[0], interfaces[2]
        neighbors = [make_neighbor(devices[0].id, "Gi0/0", "edge-1", neighbor_interface="Gi0/0")]
        result = build_l2_edges(devices, interfaces, neighbors)
        (built,) = result.edges
        expected = tuple(
            sorted(
                [interface_endpoint(core_if), interface_endpoint(edge_if)],
                key=lambda e: (e.label, e.key),
            )
        )
        assert (built.a, built.b) == expected

    def test_empty_neighbor_interface_falls_back_to_device(self) -> None:
        devices, interfaces = l2_inventory()
        neighbors = [make_neighbor(devices[0].id, "Gi0/0", "edge-1")]
        result = build_l2_edges(devices, interfaces, neighbors)
        (built,) = result.edges
        assert device_endpoint(devices[1]) in (built.a, built.b)
        assert interface_endpoint(interfaces[0]) in (built.a, built.b)

    def test_unknown_local_interface_falls_back_to_device(self) -> None:
        devices, interfaces = l2_inventory()
        neighbors = [make_neighbor(devices[0].id, "Te1/0/99", "edge-1", neighbor_interface="Gi0/0")]
        result = build_l2_edges(devices, interfaces, neighbors)
        (built,) = result.edges
        assert device_endpoint(devices[0]) in (built.a, built.b)

    def test_interface_name_matching_is_case_insensitive(self) -> None:
        devices, interfaces = l2_inventory()
        neighbors = [make_neighbor(devices[0].id, "gi0/0", "edge-1", neighbor_interface="GI0/0")]
        result = build_l2_edges(devices, interfaces, neighbors)
        (built,) = result.edges
        assert {built.a.label, built.b.label} == {"Interface"}


class TestBidirectionalDedup:
    def test_adjacency_seen_from_both_ends_is_one_edge(self) -> None:
        devices, interfaces = l2_inventory()
        core, edge = devices
        neighbors = [
            make_neighbor(core.id, "Gi0/0", "edge-1", neighbor_interface="Gi0/0"),
            make_neighbor(edge.id, "Gi0/0", "core-1", neighbor_interface="Gi0/0"),
        ]
        result = build_l2_edges(devices, interfaces, neighbors)
        assert len(result.edges) == 1
        assert result.edges[0].protocols == ("lldp",)

    def test_protocols_merged_across_observations(self) -> None:
        devices, interfaces = l2_inventory()
        core, edge = devices
        neighbors = [
            make_neighbor(
                core.id,
                "Gi0/0",
                "edge-1",
                neighbor_interface="Gi0/0",
                protocol=NeighborProtocol.LLDP,
            ),
            make_neighbor(
                edge.id,
                "Gi0/0",
                "core-1",
                neighbor_interface="Gi0/0",
                protocol=NeighborProtocol.CDP,
            ),
        ]
        result = build_l2_edges(devices, interfaces, neighbors)
        (built,) = result.edges
        assert built.protocols == ("cdp", "lldp")

    def test_edge_carries_interface_names_per_endpoint(self) -> None:
        devices, interfaces = l2_inventory()
        core_if, edge_if = interfaces[1], interfaces[2]
        neighbors = [make_neighbor(devices[0].id, "Gi0/1", "edge-1", neighbor_interface="Gi0/0")]
        result = build_l2_edges(devices, interfaces, neighbors)
        (built,) = result.edges
        names = {
            built.a: built.interface_a,
            built.b: built.interface_b,
        }
        assert names[interface_endpoint(core_if)] == "Gi0/1"
        assert names[interface_endpoint(edge_if)] == "Gi0/0"


class TestExitCriterion:
    def test_removing_one_neighbor_row_removes_exactly_one_edge(self) -> None:
        """M2 exit criterion: one fewer neighbor row -> exactly one fewer edge."""
        devices, interfaces = l2_inventory()
        core, edge = devices
        neighbors = [
            make_neighbor(core.id, "Gi0/0", "edge-1", neighbor_interface="Gi0/0"),
            make_neighbor(core.id, "Gi0/1", "edge-1", neighbor_interface="Gi0/1"),
        ]
        full = build_l2_edges(devices, interfaces, neighbors)
        reduced = build_l2_edges(devices, interfaces, neighbors[:1])
        assert len(full.edges) == 2
        assert len(reduced.edges) == 1
        assert set(reduced.edges) < set(full.edges)

    def test_removing_one_side_of_bidirectional_pair_keeps_the_edge(self) -> None:
        devices, interfaces = l2_inventory()
        core, edge = devices
        neighbors = [
            make_neighbor(core.id, "Gi0/0", "edge-1", neighbor_interface="Gi0/0"),
            make_neighbor(edge.id, "Gi0/0", "core-1", neighbor_interface="Gi0/0"),
        ]
        full = build_l2_edges(devices, interfaces, neighbors)
        reduced = build_l2_edges(devices, interfaces, neighbors[:1])
        assert len(full.edges) == 1
        assert len(reduced.edges) == 1
        assert full.edges[0].a == reduced.edges[0].a
        assert full.edges[0].b == reduced.edges[0].b


class TestL2Determinism:
    def test_input_order_does_not_change_output(self) -> None:
        devices, interfaces = l2_inventory()
        core, edge = devices
        neighbors = [
            make_neighbor(core.id, "Gi0/0", "edge-1", neighbor_interface="Gi0/0"),
            make_neighbor(edge.id, "Gi0/0", "core-1", neighbor_interface="Gi0/0"),
            make_neighbor(core.id, "Gi0/1", "ghost-1"),
        ]
        forward = build_l2_edges(devices, interfaces, neighbors)
        reverse = build_l2_edges(devices[::-1], interfaces[::-1], neighbors[::-1])
        assert forward == reverse

    def test_empty_inputs_yield_empty_result(self) -> None:
        result = build_l2_edges([], [], [])
        assert result.edges == ()
        assert result.report.neighbor_rows == 0
        assert result.report.unresolved_neighbors == 0

    def test_edges_are_frozen_records(self) -> None:
        devices, interfaces = l2_inventory()
        neighbors = [make_neighbor(devices[0].id, "Gi0/0", "edge-1", neighbor_interface="Gi0/0")]
        (built,) = build_l2_edges(devices, interfaces, neighbors).edges
        assert isinstance(built, ConnectedToEdge)
        assert built.model_config.get("frozen") is True


# ---------------------------------------------------------------------------
# L3 builders (sub-deliverable B)
# ---------------------------------------------------------------------------


def make_route(
    device_id: UUID,
    prefix: str,
    *,
    vrf: str = "",
    next_hop: str = "",
    protocol: RouteProtocol = RouteProtocol.STATIC,
    metric: int | None = None,
    distance: int | None = None,
) -> NormalizedRouteRow:
    return NormalizedRouteRow(
        id=uuid4(),
        device_id=device_id,
        raw_artifact_id=uuid4(),
        collected_at=COLLECTED_AT,
        source_vendor="cisco_ios",
        prefix=prefix,
        protocol=protocol,
        next_hop=next_hop,
        interface="",
        vrf=vrf,
        metric=metric,
        distance=distance,
    )


class TestHasInterfaceEdges:
    def test_one_edge_per_interface_of_known_device(self) -> None:
        devices, interfaces = l2_inventory()
        derived = build_l3_edges(devices, interfaces, [])
        assert len(derived.has_interface) == 4
        assert (
            HasInterfaceEdge(device_pg_id=str(devices[0].id), interface_pg_id=str(interfaces[0].id))
            in derived.has_interface
        )

    def test_interface_of_unknown_device_skipped(self) -> None:
        orphan = make_interface(uuid4(), "Gi0/0")
        derived = build_l3_edges([], [orphan], [])
        assert derived.has_interface == ()


class TestInSubnetEdges:
    def test_interface_with_ip_links_to_network_cidr(self) -> None:
        device = make_device("core-1", "10.0.0.1")
        iface = make_interface(device.id, "Gi0/0", ip_address="10.10.0.1/24")
        derived = build_l3_edges([device], [iface], [])
        assert derived.in_subnet == (
            InSubnetEdge(interface_pg_id=str(iface.id), cidr="10.10.0.0/24"),
        )

    def test_interface_without_ip_has_no_edge(self) -> None:
        device = make_device("core-1", "10.0.0.1")
        iface = make_interface(device.id, "Gi0/0")
        derived = build_l3_edges([device], [iface], [])
        assert derived.in_subnet == ()


class TestL3AdjacentEdges:
    def test_devices_sharing_subnet_are_adjacent(self) -> None:
        core = make_device("core-1", "10.0.0.1")
        edge = make_device("edge-1", "10.0.0.2")
        ifaces = [
            make_interface(core.id, "Gi0/0", ip_address="10.10.0.1/24"),
            make_interface(edge.id, "Gi0/0", ip_address="10.10.0.2/24"),
        ]
        derived = build_l3_edges([core, edge], ifaces, [])
        a, b = sorted([str(core.id), str(edge.id)])
        assert derived.l3_adjacent == (
            L3AdjacentEdge(device_a_pg_id=a, device_b_pg_id=b, cidrs=("10.10.0.0/24",)),
        )

    def test_self_pairs_excluded(self) -> None:
        core = make_device("core-1", "10.0.0.1")
        ifaces = [
            make_interface(core.id, "Gi0/0", ip_address="10.10.0.1/24"),
            make_interface(core.id, "Gi0/1", ip_address="10.10.0.2/24"),
        ]
        derived = build_l3_edges([core], ifaces, [])
        assert derived.l3_adjacent == ()

    def test_pair_sharing_two_subnets_is_one_edge_with_both_cidrs(self) -> None:
        core = make_device("core-1", "10.0.0.1")
        edge = make_device("edge-1", "10.0.0.2")
        ifaces = [
            make_interface(core.id, "Gi0/0", ip_address="10.10.0.1/24"),
            make_interface(edge.id, "Gi0/0", ip_address="10.10.0.2/24"),
            make_interface(core.id, "Gi0/1", ip_address="10.20.0.1/24"),
            make_interface(edge.id, "Gi0/1", ip_address="10.20.0.2/24"),
        ]
        derived = build_l3_edges([core, edge], ifaces, [])
        (built,) = derived.l3_adjacent
        assert built.cidrs == ("10.10.0.0/24", "10.20.0.0/24")


class TestRoutesToEdges:
    def test_route_yields_device_to_subnet_edge_with_props(self) -> None:
        core = make_device("core-1", "10.0.0.1")
        route = make_route(
            core.id,
            "192.168.50.0/24",
            vrf="MGMT",
            next_hop="10.10.0.254",
            protocol=RouteProtocol.OSPF,
            metric=20,
            distance=110,
        )
        derived = build_l3_edges([core], [], [route])
        assert derived.routes_to == (
            RoutesToEdge(
                device_pg_id=str(core.id),
                cidr="192.168.50.0/24",
                protocol="ospf",
                next_hop="10.10.0.254",
                vrf="MGMT",
                metric=20,
                distance=110,
            ),
        )

    def test_route_prefix_normalized_to_network_cidr(self) -> None:
        core = make_device("core-1", "10.0.0.1")
        route = make_route(core.id, "10.10.0.1/24")
        derived = build_l3_edges([core], [], [route])
        assert derived.routes_to[0].cidr == "10.10.0.0/24"

    def test_route_target_subnets_exist_as_derived_nodes(self) -> None:
        # ADR-0005 invariant: every ROUTES_TO endpoint is a projected Subnet.
        core = make_device("core-1", "10.0.0.1")
        routes = [make_route(core.id, "0.0.0.0/0"), make_route(core.id, "172.16.0.0/16")]
        derived_edges = build_l3_edges([core], [], routes)
        derived_nodes = derive_nodes([core], [], routes)
        subnet_cidrs = {node.cidr for node in derived_nodes.subnets}
        assert {edge.cidr for edge in derived_edges.routes_to} <= subnet_cidrs

    def test_identical_route_rows_dedupe_to_one_edge(self) -> None:
        core = make_device("core-1", "10.0.0.1")
        routes = [make_route(core.id, "0.0.0.0/0"), make_route(core.id, "0.0.0.0/0")]
        derived = build_l3_edges([core], [], routes)
        assert len(derived.routes_to) == 1

    def test_route_of_unknown_device_skipped(self) -> None:
        derived = build_l3_edges([], [], [make_route(uuid4(), "0.0.0.0/0")])
        assert derived.routes_to == ()


class TestL3Determinism:
    def test_input_order_does_not_change_output(self) -> None:
        core = make_device("core-1", "10.0.0.1")
        edge = make_device("edge-1", "10.0.0.2")
        ifaces = [
            make_interface(core.id, "Gi0/0", ip_address="10.10.0.1/24"),
            make_interface(edge.id, "Gi0/0", ip_address="10.10.0.2/24"),
            make_interface(edge.id, "Gi0/1"),
        ]
        routes = [
            make_route(core.id, "0.0.0.0/0", next_hop="10.10.0.254"),
            make_route(edge.id, "192.168.50.0/24", vrf="MGMT"),
        ]
        forward = build_l3_edges([core, edge], ifaces, routes)
        reverse = build_l3_edges([edge, core], ifaces[::-1], routes[::-1])
        assert forward == reverse

    def test_empty_inputs_yield_empty_edge_sets(self) -> None:
        derived = build_l3_edges([], [], [])
        assert derived == DerivedL3Edges()
