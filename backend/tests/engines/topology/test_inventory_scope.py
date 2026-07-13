"""Wave 5 T4: derived write-set filter for delta projection.

PR #161 review: pass-through Subnet/Vlan/VRF/Site families are written
REFERENCED-ONLY — a node ships in the delta write set only when a kept
(scoped) node or edge references it.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

from app.engines.topology.applications import DerivedApplications
from app.engines.topology.edges import (
    ConnectedToEdge,
    EdgeEndpoint,
    HasInterfaceEdge,
    InSubnetEdge,
    L3AdjacentEdge,
    RoutesToEdge,
)
from app.engines.topology.inventory_load import filter_derived_for_scope
from app.engines.topology.nodes import (
    DerivedNodes,
    DeviceNode,
    InterfaceNode,
    IPAddressNode,
    SiteNode,
    SubnetNode,
    VlanNode,
    VrfNode,
)
from app.engines.topology.projector import DerivedEdges
from app.models.inventory import NormalizedInterfaceRow
from app.schemas.normalized import InterfaceAdminStatus, InterfaceOperStatus


def _iface_row(
    device_id: UUID, row_id: UUID, *, vlan_id: int | None = None
) -> NormalizedInterfaceRow:
    return NormalizedInterfaceRow(
        id=row_id,
        device_id=device_id,
        raw_artifact_id=uuid4(),
        collected_at=datetime(2026, 6, 12, 12, 0, tzinfo=UTC),
        source_vendor="cisco_ios",
        name="Gi0/0",
        admin_status=InterfaceAdminStatus.UP,
        oper_status=InterfaceOperStatus.UP,
        vlan_id=vlan_id,
    )


def test_filter_derived_keeps_only_scoped_devices_and_edges() -> None:
    d1, d2 = uuid4(), uuid4()
    i1, i2 = uuid4(), uuid4()
    nodes = DerivedNodes(
        devices=(
            DeviceNode(
                pg_id=d1, hostname="a", mgmt_ip="10.0.0.1", vendor_id="x", model=None, site=None
            ),
            DeviceNode(
                pg_id=d2, hostname="b", mgmt_ip="10.0.0.2", vendor_id="x", model=None, site=None
            ),
        ),
        interfaces=(
            InterfaceNode(
                pg_id=i1,
                name="Gi0/0",
                admin_status=InterfaceAdminStatus.UP,
                oper_status=InterfaceOperStatus.UP,
                mac_address=None,
                ip_address=None,
            ),
            InterfaceNode(
                pg_id=i2,
                name="Gi0/0",
                admin_status=InterfaceAdminStatus.UP,
                oper_status=InterfaceOperStatus.UP,
                mac_address=None,
                ip_address=None,
            ),
        ),
    )
    edges = DerivedEdges(
        has_interface=(
            HasInterfaceEdge(device_pg_id=str(d1), interface_pg_id=str(i1)),
            HasInterfaceEdge(device_pg_id=str(d2), interface_pg_id=str(i2)),
        ),
        connected_to=(
            ConnectedToEdge(
                a=EdgeEndpoint(label="Device", key=str(d1)),
                b=EdgeEndpoint(label="Device", key=str(d2)),
                protocols=("lldp",),
            ),
        ),
    )
    apps = DerivedApplications()

    sn, se, sa = filter_derived_for_scope(
        nodes=nodes,
        edges=edges,
        applications=apps,
        scope_device_ids={d1},
        scope_interface_ids={i1},
        interfaces=(),
    )
    assert len(sn.devices) == 1
    assert sn.devices[0].pg_id == d1
    assert len(sn.interfaces) == 1
    assert sn.interfaces[0].pg_id == i1
    assert len(se.has_interface) == 1
    assert se.has_interface[0].device_pg_id == str(d1)
    # CONNECTED_TO kept because one end is in scope
    assert len(se.connected_to) == 1
    assert sa is apps


def test_filter_derived_covers_ip_subnet_l3_and_route_branches() -> None:
    """Every scoped edge/node family: in-scope kept, out-of-scope dropped;
    Subnets written only when a KEPT edge references their cidr (PR #161)."""
    d1, d2, d3 = uuid4(), uuid4(), uuid4()
    i1, i2 = uuid4(), uuid4()
    nodes = DerivedNodes(
        ip_addresses=(
            IPAddressNode(pg_id=i1, address="10.0.0.1"),
            IPAddressNode(pg_id=i2, address="10.0.1.1"),
        ),
        subnets=(
            SubnetNode(cidr="10.0.0.0/24"),
            SubnetNode(cidr="10.0.1.0/24"),
            SubnetNode(cidr="172.16.0.0/24"),
        ),
    )
    edges = DerivedEdges(
        in_subnet=(
            InSubnetEdge(interface_pg_id=str(i1), cidr="10.0.0.0/24"),
            InSubnetEdge(interface_pg_id=str(i2), cidr="10.0.1.0/24"),
        ),
        l3_adjacent=(
            # d1 in scope -> kept even though d2 is not.
            L3AdjacentEdge(device_a_pg_id=str(d1), device_b_pg_id=str(d2), cidrs=("10.0.0.0/24",)),
            # Neither endpoint in scope -> dropped.
            L3AdjacentEdge(device_a_pg_id=str(d2), device_b_pg_id=str(d3), cidrs=("10.0.1.0/24",)),
        ),
        routes_to=(
            RoutesToEdge(device_pg_id=str(d1), cidr="10.0.1.0/24", protocol="ospf"),
            RoutesToEdge(device_pg_id=str(d2), cidr="10.0.0.0/24", protocol="ospf"),
            RoutesToEdge(device_pg_id=str(d2), cidr="172.16.0.0/24", protocol="ospf"),
        ),
    )
    apps = DerivedApplications()

    sn, se, sa = filter_derived_for_scope(
        nodes=nodes,
        edges=edges,
        applications=apps,
        scope_device_ids={d1},
        scope_interface_ids={i1},
        interfaces=(),
    )
    # IPAddress nodes are keyed by owning interface row id.
    assert [n.pg_id for n in sn.ip_addresses] == [i1]
    # Referenced-only Subnets: 10.0.0.0/24 via the kept in_subnet(i1) edge and
    # the kept l3_adjacent cidrs; 10.0.1.0/24 via the kept d1 routes_to edge's
    # target cidr; 172.16.0.0/24 is referenced only by DROPPED out-of-scope
    # edges and must not be re-MERGEd by the delta pass.
    assert [n.cidr for n in sn.subnets] == ["10.0.0.0/24", "10.0.1.0/24"]
    assert [e.interface_pg_id for e in se.in_subnet] == [str(i1)]
    assert [e.device_a_pg_id for e in se.l3_adjacent] == [str(d1)]
    assert [e.device_pg_id for e in se.routes_to] == [str(d1)]
    assert sa is apps


def test_filter_derived_scopes_vlan_vrf_site_to_referenced_only() -> None:
    """Vlan/VRF/Site ship only when a kept interface row / ROUTES_TO edge /
    Device node references them (PR #161 review)."""
    d1, d2 = uuid4(), uuid4()
    i1, i2 = uuid4(), uuid4()
    nodes = DerivedNodes(
        devices=(
            DeviceNode(
                pg_id=d1, hostname="a", mgmt_ip="10.0.0.1", vendor_id="x", model=None, site="hq"
            ),
            DeviceNode(
                pg_id=d2,
                hostname="b",
                mgmt_ip="10.0.0.2",
                vendor_id="x",
                model=None,
                site="branch",
            ),
        ),
        vlans=(VlanNode(vlan_id=10), VlanNode(vlan_id=20)),
        vrfs=(VrfNode(name="prod"), VrfNode(name="dev")),
        sites=(SiteNode(name="hq"), SiteNode(name="branch")),
    )
    edges = DerivedEdges(
        routes_to=(
            RoutesToEdge(device_pg_id=str(d1), cidr="10.0.1.0/24", protocol="static", vrf="prod"),
            RoutesToEdge(device_pg_id=str(d2), cidr="10.0.2.0/24", protocol="static", vrf="dev"),
        ),
    )

    sn, se, _sa = filter_derived_for_scope(
        nodes=nodes,
        edges=edges,
        applications=DerivedApplications(),
        scope_device_ids={d1},
        scope_interface_ids={i1},
        interfaces=[_iface_row(d1, i1, vlan_id=10), _iface_row(d2, i2, vlan_id=20)],
    )
    assert [n.vlan_id for n in sn.vlans] == [10]
    assert [n.name for n in sn.vrfs] == ["prod"]
    assert [n.name for n in sn.sites] == ["hq"]
    assert [e.device_pg_id for e in se.routes_to] == [str(d1)]
