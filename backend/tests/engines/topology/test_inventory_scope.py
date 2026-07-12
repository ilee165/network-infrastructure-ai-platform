"""Wave 5 T4: scoped inventory load + derived filter for delta projection."""

from __future__ import annotations

from uuid import uuid4

from app.engines.topology.applications import DerivedApplications
from app.engines.topology.edges import ConnectedToEdge, EdgeEndpoint, HasInterfaceEdge
from app.engines.topology.inventory_load import filter_derived_for_scope
from app.engines.topology.nodes import DerivedNodes, DeviceNode, InterfaceNode
from app.engines.topology.projector import DerivedEdges
from app.schemas.normalized import InterfaceAdminStatus, InterfaceOperStatus


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
