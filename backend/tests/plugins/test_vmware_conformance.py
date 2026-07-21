"""VMware plugin conformance + unit tests (ADR-0051, P4 W1-T2).

Covers:
- Shared conformance suite over recorded **property-set JSON** fixtures replayed
  through the ``VsphereClient.fetch_*`` seam (every declared capability, incl.
  ``fixtures:virtualization_inventory`` — the three-file wiring, ADR-0051 §5.8).
- Every mandatory fixture case (ADR-0051 §8): multi-batch continuation paging;
  a Tools-less VM; a template VM; a powered-off VM; duplicate names across
  folders; a standalone host; a maintenance-mode host; standard + distributed +
  trunked port groups; a disconnected vNIC; dv key→name resolution; a
  teaming-override uplink resolution.
- Zero-plaintext-leakage (the escalated secret surface, ADR-0051 §2): the
  vCenter password AND the SOAP session cookie appear in no raw artifact, log
  record, exception message, or ``repr``.
- Session-expiry regression: a mid-run ``NotAuthenticated`` triggers exactly one
  re-auth + retry; a second failure raises a typed ``PluginError``.
- No write capability is declared anywhere (conformance metadata case).
- Client contract tests pinning the real pyVmomi call shape
  (``RetrievePropertiesEx`` / ``ContinueRetrievePropertiesEx`` /
  ``CreateContainerView`` / ``Destroy`` / ``Disconnect``) and the generic
  vmodl→JSON serialization over constructed pyVmomi objects — the parts a live
  vCenter would exercise (ADR-0051 §9), pinned without one.

Live golden path deferred-accepted (no vCenter) — see
``tests/agents/eval/test_vmware_live_golden_path.py`` and ADR-0051 §8/§9.
"""

from __future__ import annotations

import json
import logging
import urllib.parse
from uuid import uuid4

import pytest
from pyVmomi import vim, vmodl

from app.core.errors import PluginError
from app.plugins.base import Capability, PluginCapability
from app.plugins.vendors.vmware.client import VsphereClient, vmodl_to_json
from app.plugins.vendors.vmware.plugin import (
    VmwareDiscoveryApi,
    VmwarePlugin,
    VmwareVirtualizationInventory,
    _map_connection_state,
    _map_power_state,
    _standard_pnic_name,
)
from app.schemas.normalized import (
    HostConnectionState,
    VirtualSwitchType,
    VmPowerState,
)
from tests.plugins.conformance import (
    ConformanceCase,
    assert_fixture_case_completeness,
    make_conformance_cases,
)

# Obviously-fake secrets — never real credentials.
_FAKE_USERNAME = "netops-ro@vsphere.local"
_FAKE_PASSWORD = "FakeVc+pass/word=="  # noqa: S105 — obviously-fake
_FAKE_COOKIE = 'vmware_soap_session="FAKE-SOAP-SESSION-DO-NOT-LEAK"; Path=/; secure'  # noqa: S105

_DC = "DC1"


# ---------------------------------------------------------------------------
# Recorded property-set JSON fixtures (ADR-0051 §7/§8) — sanitized, DC-scoped.
# ---------------------------------------------------------------------------


def _doc(obj_type: str, moref: str | None, properties: dict) -> dict:
    return {"type": obj_type, "moref": moref, "datacenter": _DC, "properties": properties}


_ABOUT = _doc(
    "AboutInfo",
    None,
    {
        "name": "vcenter.lab",
        "fullName": "VMware vCenter Server 8.0.2 build-22385739",
        "version": "8.0.2",
        "build": "22385739",
        "instanceUuid": "vc-instance-uuid-0001",
        "apiType": "VirtualCenter",
    },
)

_CLUSTERS = [
    _doc(
        "ClusterComputeResource",
        "domain-c10",
        {
            "name": "Cluster-A",
            "configuration.drsConfig.enabled": True,
            "configuration.dasConfig.enabled": True,
        },
    )
]

# A standard vSwitch with two portgroups: an access VLAN and a trunk (4095→None)
# with a per-portgroup NIC-teaming override (uplink resolution).
_HOST_A1_NETWORK = {
    "pnic": [
        {"device": "vmnic0", "mac": "00:11:22:33:44:00", "linkSpeed": {"speedMb": 10000}},
        {"device": "vmnic1", "mac": "00:11:22:33:44:01", "linkSpeed": {"speedMb": 10000}},
        {"device": "vmnic2", "mac": "00:11:22:33:44:02"},  # link down → speed None
    ],
    "vnic": [{"device": "vmk0", "spec": {"ip": {"ipAddress": "10.0.0.21"}}}],
    "vswitch": [
        {
            "name": "vSwitch0",
            "pnic": [
                "key-vim.host.PhysicalNic-vmnic0",
                "key-vim.host.PhysicalNic-vmnic1",
            ],
        }
    ],
    "portgroup": [
        {"spec": {"name": "VM Network", "vswitchName": "vSwitch0", "vlanId": 10}},
        {
            "spec": {
                "name": "Mgmt",
                "vswitchName": "vSwitch0",
                "vlanId": 4095,  # trunk → None
                "policy": {"nicTeaming": {"nicOrder": {"activeNic": ["vmnic1"]}}},  # override
            }
        },
    ],
}

_HOSTS = [
    _doc(
        "HostSystem",
        "host-20",
        {
            "name": "esx-a1.lab",
            "parent": "domain-c10",  # in Cluster-A
            "runtime.connectionState": "connected",
            "runtime.inMaintenanceMode": False,
            "hardware.systemInfo.vendor": "Dell Inc.",
            "hardware.systemInfo.model": "PowerEdge R750",
            "config.product.fullName": "VMware ESXi 8.0.2 build-22380479",
            "config.network": _HOST_A1_NETWORK,
        },
    ),
    _doc(
        "HostSystem",
        "host-21",
        {
            "name": "esx-standalone.lab",
            "parent": "computeresource-99",  # NOT a cluster → standalone
            "runtime.connectionState": "connected",
            "runtime.inMaintenanceMode": False,
            "config.product.fullName": "VMware ESXi 8.0.2 build-22380479",
            "config.network": {
                "pnic": [{"device": "vmnic0", "mac": "00:11:22:33:55:00"}],
                "vswitch": [{"name": "vSwitch0", "pnic": ["key-vim.host.PhysicalNic-vmnic0"]}],
                "portgroup": [
                    {"spec": {"name": "SA-Net", "vswitchName": "vSwitch0", "vlanId": 20}}
                ],
            },
        },
    ),
    _doc(
        "HostSystem",
        "host-22",
        {
            "name": "esx-a2.lab",
            "parent": "domain-c10",  # in Cluster-A
            "runtime.connectionState": "connected",
            "runtime.inMaintenanceMode": True,  # maintenance-mode host
            "config.product.fullName": "VMware ESXi 8.0.2 build-22380479",
            "config.network": {},
        },
    ),
]

_DVSWITCHES = [
    _doc(
        "DistributedVirtualSwitch",
        "dvs-50",
        {
            "name": "DSwitch-A",
            "config.uplinkPortPolicy": {"uplinkPortName": ["Uplink 1", "Uplink 2"]},
            "config.host": [
                {
                    "config": {
                        "backing": {
                            "pnicSpec": [
                                {"pnicDevice": "vmnic2", "uplinkPortKey": "0"},
                                {"pnicDevice": "vmnic3", "uplinkPortKey": "1"},
                            ]
                        }
                    }
                }
            ],
        },
    )
]

_DVPGS = [
    _doc(
        "DistributedVirtualPortgroup",
        "dvportgroup-100",
        {
            "config.name": "DPG-Web",
            "config.distributedVirtualSwitch": "dvs-50",
            "config.defaultPortConfig.vlan": {"vlanId": 30},  # access VLAN
        },
    ),
    _doc(
        "DistributedVirtualPortgroup",
        "dvportgroup-101",
        {
            "config.name": "DPG-Trunk",
            "config.distributedVirtualSwitch": "dvs-50",
            # trunk VLAN range → vlan_id None
            "config.defaultPortConfig.vlan": {"vlanId": [{"start": 100, "end": 200}]},
            "config.defaultPortConfig.uplinkTeamingPolicy": {
                "uplinkPortOrder": {"activeUplinkPort": ["Uplink 1"]}  # override → subset
            },
        },
    ),
]

# VM batch 0.
_VM_APP01_A = _doc(
    "VirtualMachine",
    "vm-1001",
    {
        "name": "app01",  # duplicate name (see vm-1002) — moref disambiguates
        "config.instanceUuid": "uuid-app01",
        "config.template": False,
        "runtime.powerState": "poweredOn",
        "runtime.host": "host-20",
        "guest.hostName": "app01.lab",
        "guest.ipAddress": "10.0.0.101",
        "guest.net": [
            {
                "macAddress": "00:50:56:aa:00:01",
                "deviceConfigId": 4000,
                "connected": True,
                "ipAddress": ["10.0.0.101", "fe80::1"],
                "network": "VM Network",
            }
        ],
        "config.hardware.device": [
            {
                "key": 4000,
                "macAddress": "00:50:56:aa:00:01",
                "deviceInfo": {"label": "Network adapter 1"},
                "connectable": {"connected": True},
                "backing": {"deviceName": "VM Network"},  # standard
            },
            {"key": 2000, "deviceInfo": {"label": "SCSI controller 0"}},  # non-NIC → filtered
        ],
        "config.annotation": "web tier",
    },
)
_VM_APP01_B = _doc(
    "VirtualMachine",
    "vm-1002",
    {
        "name": "app01",  # SAME name as vm-1001, different folder/moref
        "config.template": False,
        "runtime.powerState": "poweredOff",  # powered-off VM
        "runtime.host": "host-22",  # on the maintenance host
        # No guest.* → Tools-less VM (guest_hostname None, guest_ip_addresses ())
        "config.hardware.device": [
            {
                "key": 4000,
                "macAddress": "00:50:56:aa:00:02",
                "deviceInfo": {"label": "Network adapter 1"},
                "connectable": {"connected": False},  # disconnected vNIC
                "backing": {"port": {"portgroupKey": "dvportgroup-100"}},  # dv key→name
            }
        ],
    },
)
# VM batch 1.
_VM_TEMPLATE = _doc(
    "VirtualMachine",
    "vm-1003",
    {
        "name": "golden-template",
        "config.template": True,  # template VM (collected, not dropped)
        "runtime.powerState": "poweredOff",
        "runtime.host": "host-20",
    },
)
_VM_ORPHAN = _doc(
    "VirtualMachine",
    "vm-1004",
    {
        "name": "orphan",
        "config.template": False,
        "runtime.powerState": "poweredOn",
        # No runtime.host → unplaced/orphaned (host_name None)
        "config.hardware.device": [
            {
                "key": 4000,
                "macAddress": "00:50:56:aa:00:04",
                "deviceInfo": {"label": "Network adapter 1"},
                "connectable": {"connected": True},
                "backing": {"deviceName": "SA-Net"},
            }
        ],
    },
)

# Two RetrievePropertiesEx batches → multi-batch continuation paging.
_VM_BATCHES = [[_VM_APP01_A, _VM_APP01_B], [_VM_TEMPLATE, _VM_ORPHAN]]
_HOST_BATCHES = [_HOSTS]
_CLUSTER_BATCHES = [_CLUSTERS]
_DVS_BATCHES = [_DVSWITCHES]
_DVPG_BATCHES = [_DVPGS]


class _FixtureVsphereClient:
    """Replays recorded property-set batches through the ``fetch_*`` seam (ADR-0051 §8).

    No pyVmomi, no vCenter: exactly the documents a real ``VsphereClient`` would
    produce, so the normalized round-trip runs over real payload shapes.
    """

    def __init__(self) -> None:
        self.calls: list[str] = []

    def fetch_about(self) -> dict:
        self.calls.append("about")
        return _ABOUT

    def fetch_virtual_machines(self) -> list:
        self.calls.append("vms")
        return _VM_BATCHES

    def fetch_hypervisor_hosts(self) -> list:
        self.calls.append("hosts")
        return _HOST_BATCHES

    def fetch_compute_clusters(self) -> list:
        self.calls.append("clusters")
        return _CLUSTER_BATCHES

    def fetch_distributed_switches(self) -> list:
        self.calls.append("dvswitches")
        return _DVS_BATCHES

    def fetch_distributed_portgroups(self) -> list:
        self.calls.append("dvpgs")
        return _DVPG_BATCHES


def _inv(client: _FixtureVsphereClient | None = None) -> VmwareVirtualizationInventory:
    return VmwareVirtualizationInventory(client or _FixtureVsphereClient(), uuid4())


# ---------------------------------------------------------------------------
# Conformance suite
# ---------------------------------------------------------------------------


def _make_capability(impl: type[PluginCapability]) -> PluginCapability:
    return impl(_FixtureVsphereClient(), uuid4())


CASES = make_conformance_cases(VmwarePlugin(), capability_factory=_make_capability)


@pytest.mark.parametrize("case", CASES, ids=lambda case: case.id)
def test_vmware_conformance(case: ConformanceCase) -> None:
    case.run()


def test_suite_covers_every_declared_capability() -> None:
    ids = {case.id for case in CASES}
    for capability in VmwarePlugin.capabilities:
        assert f"implementation:{capability.value}" in ids
    assert_fixture_case_completeness(VmwarePlugin(), CASES)


# ---------------------------------------------------------------------------
# Mandatory fixture-case assertions (ADR-0051 §8).
# ---------------------------------------------------------------------------


class TestVmwareVirtualMachines:
    def test_multi_batch_continuation_records_every_batch(self) -> None:
        cap = _inv()
        vms = cap.get_virtual_machines()
        assert len(vms) == 4  # two batches of two
        batch_raws = [r for r in cap.raw_outputs if "virtual_machines[batch=" in r.command]
        assert len(batch_raws) == 2  # every RetrievePropertiesEx batch recorded (§7)

    def test_duplicate_names_disambiguated_by_moref(self) -> None:
        vms = {v.moref: v for v in _inv().get_virtual_machines()}
        assert vms["vm-1001"].name == "app01"
        assert vms["vm-1002"].name == "app01"  # same name, different moref
        assert vms["vm-1001"].moref != vms["vm-1002"].moref

    def test_placement_and_guest_fields(self) -> None:
        vm = next(v for v in _inv().get_virtual_machines() if v.moref == "vm-1001")
        assert vm.power_state == VmPowerState.POWERED_ON
        assert vm.is_template is False
        assert vm.host_name == "esx-a1.lab"
        assert vm.cluster_name == "Cluster-A"
        assert vm.datacenter == "DC1"
        assert vm.guest_hostname == "app01.lab"
        assert [str(ip) for ip in vm.guest_ip_addresses] == ["10.0.0.101", "fe80::1"]
        # Standard-backed, connected vNIC with per-NIC IPs; non-NIC device filtered.
        assert len(vm.nics) == 1
        nic = vm.nics[0]
        assert nic.label == "Network adapter 1"
        assert str(nic.mac_address) == "00:50:56:aa:00:01"
        assert nic.port_group_name == "VM Network"
        assert nic.switch_type == VirtualSwitchType.STANDARD
        assert nic.connected is True
        assert [str(ip) for ip in nic.ip_addresses] == ["10.0.0.101", "fe80::1"]

    def test_tools_less_vm_is_empty_not_error(self) -> None:
        vm = next(v for v in _inv().get_virtual_machines() if v.moref == "vm-1002")
        assert vm.guest_hostname is None
        assert vm.guest_ip_addresses == ()
        assert vm.power_state == VmPowerState.POWERED_OFF

    def test_disconnected_distributed_vnic_dv_key_resolved(self) -> None:
        vm = next(v for v in _inv().get_virtual_machines() if v.moref == "vm-1002")
        nic = vm.nics[0]
        assert nic.connected is False  # disconnected vNIC
        assert nic.switch_type == VirtualSwitchType.DISTRIBUTED
        assert nic.port_group_name == "DPG-Web"  # dv key → name resolved at collection

    def test_template_vm_collected(self) -> None:
        vm = next(v for v in _inv().get_virtual_machines() if v.moref == "vm-1003")
        assert vm.is_template is True

    def test_orphaned_vm_has_no_placement(self) -> None:
        vm = next(v for v in _inv().get_virtual_machines() if v.moref == "vm-1004")
        assert vm.host_name is None
        assert vm.cluster_name is None


class TestVmwareHosts:
    def test_clustered_host(self) -> None:
        host = next(h for h in _inv().get_hypervisor_hosts() if h.moref == "host-20")
        assert host.name == "esx-a1.lab"
        assert host.cluster_name == "Cluster-A"
        assert host.connection_state == HostConnectionState.CONNECTED
        assert host.in_maintenance_mode is False
        assert host.vendor == "Dell Inc."
        assert host.model == "PowerEdge R750"
        assert host.hypervisor_version.startswith("VMware ESXi 8.0.2")
        assert str(host.management_ip) == "10.0.0.21"
        pnics = {p.name: p for p in host.pnics}
        assert str(pnics["vmnic0"].mac_address) == "00:11:22:33:44:00"
        assert pnics["vmnic0"].link_speed_mbps == 10000
        assert pnics["vmnic2"].link_speed_mbps is None  # link down / unreported

    def test_standalone_host_has_no_cluster(self) -> None:
        host = next(h for h in _inv().get_hypervisor_hosts() if h.moref == "host-21")
        assert host.cluster_name is None  # parent is not a cluster

    def test_maintenance_host(self) -> None:
        host = next(h for h in _inv().get_hypervisor_hosts() if h.moref == "host-22")
        assert host.in_maintenance_mode is True


class TestVmwareClusters:
    def test_cluster_flags(self) -> None:
        cluster = _inv().get_compute_clusters()[0]
        assert cluster.name == "Cluster-A"
        assert cluster.moref == "domain-c10"
        assert cluster.drs_enabled is True
        assert cluster.ha_enabled is True
        assert cluster.datacenter == "DC1"


class TestVmwarePortGroups:
    def test_standard_port_group_access_vlan_and_uplinks(self) -> None:
        pgs = _inv().get_port_groups()
        vm_net = next(p for p in pgs if p.name == "VM Network")
        assert vm_net.switch_type == VirtualSwitchType.STANDARD
        assert vm_net.switch_name == "vSwitch0"
        assert vm_net.host_name == "esx-a1.lab"
        assert vm_net.vlan_id == 10
        assert vm_net.moref is None
        assert vm_net.uplink_pnic_names == ("vmnic0", "vmnic1")  # inherit vSwitch uplinks

    def test_standard_trunk_pg_none_vlan_with_teaming_override(self) -> None:
        mgmt = next(p for p in _inv().get_port_groups() if p.name == "Mgmt")
        assert mgmt.vlan_id is None  # 4095 trunk → None
        assert mgmt.uplink_pnic_names == ("vmnic1",)  # per-portgroup teaming override

    def test_distributed_port_group_access_vlan(self) -> None:
        web = next(
            p
            for p in _inv().get_port_groups()
            if p.name == "DPG-Web" and p.switch_type == VirtualSwitchType.DISTRIBUTED
        )
        assert web.switch_name == "DSwitch-A"
        assert web.host_name is None  # distributed is vCenter-wide
        assert web.moref == "dvportgroup-100"
        assert web.vlan_id == 30
        assert web.uplink_pnic_names == ("vmnic2", "vmnic3")  # inherit dvSwitch uplinks

    def test_distributed_trunk_pg_with_teaming_override(self) -> None:
        trunk = next(p for p in _inv().get_port_groups() if p.name == "DPG-Trunk")
        assert trunk.vlan_id is None  # trunk VLAN range → None
        assert trunk.uplink_pnic_names == ("vmnic2",)  # override selects Uplink 1 → vmnic2

    def test_same_standard_name_across_hosts_is_scoped(self) -> None:
        # SA-Net is on the standalone host only; VM Network on host-20. Standard
        # port groups are host-scoped (host_name set) so names never collapse.
        pgs = [p for p in _inv().get_port_groups() if p.switch_type == VirtualSwitchType.STANDARD]
        assert all(p.host_name is not None for p in pgs)


class TestVmwareDiscoveryApi:
    def test_device_facts(self) -> None:
        facts = VmwareDiscoveryApi(_FixtureVsphereClient(), uuid4()).get_device_facts()
        assert facts.hostname == "vcenter.lab"
        assert facts.vendor_id == "vmware"
        assert facts.os_version == "8.0.2"
        assert facts.serial == "vc-instance-uuid-0001"

    def test_discover_one_object(self) -> None:
        objs = VmwareDiscoveryApi(_FixtureVsphereClient(), uuid4()).discover()
        assert len(objs) == 1
        assert objs[0].identifier == "vcenter.lab"
        assert objs[0].source_vendor == "vmware"


# ---------------------------------------------------------------------------
# No write capability declared (ADR-0051 §3 — conformance metadata case).
# ---------------------------------------------------------------------------

_WRITE_CAPABILITIES = frozenset(
    {
        Capability.CONFIG_RESTORE,
        Capability.CONFIG_DEPLOY,
        Capability.CONFIG_BACKUP,
        Capability.CONFIG_BACKUP_ARCHIVE,
        Capability.CONFIG_RESTORE_ARCHIVE,
        Capability.DDI_DNS,
        Capability.DDI_DHCP,
        Capability.DDI_IPAM,
    }
)


def test_vmware_declares_no_write_capability() -> None:
    assert VmwarePlugin.capabilities == frozenset(
        {Capability.DISCOVERY_API, Capability.VIRTUALIZATION_INVENTORY}
    )
    assert not (VmwarePlugin.capabilities & _WRITE_CAPABILITIES)
    # The plugin resolves neither a change-write nor an archive class.
    plugin = VmwarePlugin()
    for cap in _WRITE_CAPABILITIES:
        assert not plugin.supports(cap)


# ---------------------------------------------------------------------------
# Parser units (ADR-0051 §5.3).
# ---------------------------------------------------------------------------


class TestVmwareParsers:
    def test_map_power_state(self) -> None:
        assert _map_power_state("poweredOn") == VmPowerState.POWERED_ON
        assert _map_power_state("suspended") == VmPowerState.SUSPENDED
        assert _map_power_state(None) == VmPowerState.UNKNOWN
        assert _map_power_state("weird") == VmPowerState.UNKNOWN

    def test_map_connection_state(self) -> None:
        assert _map_connection_state("connected") == HostConnectionState.CONNECTED
        assert _map_connection_state("notResponding") == HostConnectionState.NOT_RESPONDING
        assert _map_connection_state(None) == HostConnectionState.UNKNOWN

    def test_standard_pnic_name(self) -> None:
        assert _standard_pnic_name("key-vim.host.PhysicalNic-vmnic0") == "vmnic0"
        assert _standard_pnic_name("vmnic1") == "vmnic1"


# ---------------------------------------------------------------------------
# pyVmomi fakes (contract tests + session lifecycle) — no vCenter needed.
# ---------------------------------------------------------------------------


class _FakeStub:
    """A minimal pyVmomi SOAP-stub double: serves property accessors + records methods.

    Lets a *real* ``vim`` ManagedObject (ContainerView / Datacenter / Folder) be
    used in the ``FilterSpec``/``ObjectSpec`` the production ``_retrieve`` builds,
    so that real pyVmomi call shape is exercised without a live vCenter.
    """

    def __init__(self, accessors: dict | None = None, cookie: str | None = _FAKE_COOKIE) -> None:
        self.cookie = cookie
        self.version = "vim.version.version12"
        self._accessors = accessors or {}
        self.methods: list[str] = []

    def InvokeAccessor(self, mo: object, info: object):
        return self._accessors.get(info.name)

    def InvokeMethod(self, mo: object, info: object, args: object):
        self.methods.append(info.name)
        return None


def _folder(moid: str):
    return vim.Folder(moid, _FakeStub())


def _datacenter_mo(name: str = _DC):
    stub = _FakeStub(
        {
            "name": name,
            "vmFolder": _folder("group-v1"),
            "hostFolder": _folder("group-h1"),
            "networkFolder": _folder("group-n1"),
        }
    )
    return vim.Datacenter("datacenter-1", stub)


def _container_view(view_objs: list):
    return vim.view.ContainerView("session[x]view", _FakeStub({"view": view_objs}))


class _FakeViewManager:
    def __init__(self, dc: object) -> None:
        self._dc = dc
        self.created: list[tuple] = []
        self.views: list = []

    def CreateContainerView(self, container: object, type: list, recursive: bool):  # noqa: A002
        self.created.append((container, tuple(type), recursive))
        view = _container_view([self._dc] if vim.Datacenter in type else [])
        self.views.append(view)
        return view


class _FakePropertyCollector:
    def __init__(self, batches: list[list], fail_first: bool = False) -> None:
        self._batches = batches
        self.fail_first = fail_first
        self.retrieve_calls = 0
        self.continue_calls = 0
        self.filter_specs: list = []

    def RetrievePropertiesEx(self, specs: list, options: object):
        self.retrieve_calls += 1
        self.filter_specs.append(specs)
        if self.fail_first:
            self.fail_first = False
            raise vim.fault.NotAuthenticated()
        return self._page(0)

    def ContinueRetrievePropertiesEx(self, token: str):
        self.continue_calls += 1
        return self._page(int(token))

    def _page(self, index: int):
        objs = self._batches[index]
        if not objs:
            return None
        kwargs: dict = {"objects": objs}
        if index + 1 < len(self._batches):
            kwargs["token"] = str(index + 1)
        return vmodl.query.PropertyCollector.RetrieveResult(**kwargs)


class _FakeContent:
    def __init__(self, pc: _FakePropertyCollector, vm: _FakeViewManager, about: object) -> None:
        self.propertyCollector = pc
        self.viewManager = vm
        self.rootFolder = _folder("group-root")
        self.about = about


class _FakeServiceInstance:
    def __init__(self, content: _FakeContent, cookie: str | None) -> None:
        self.content = content
        self._stub = _FakeStub(cookie=cookie)


def _oc(obj_type: type, moid: str, props: dict):
    return vmodl.query.PropertyCollector.ObjectContent(
        obj=obj_type(moid),
        propSet=[vmodl.DynamicProperty(name=k, val=v) for k, v in props.items()],
    )


def _make_si(
    batches: list[list], *, cookie: str | None = _FAKE_COOKIE, fail_first: bool = False, about=None
) -> _FakeServiceInstance:
    pc = _FakePropertyCollector(batches, fail_first=fail_first)
    vm = _FakeViewManager(_datacenter_mo(_DC))
    if about is None:
        about = vim.AboutInfo(
            name="vcenter.lab",
            fullName="VMware vCenter Server 8.0.2",
            version="8.0.2",
            instanceUuid="vc-instance-uuid-0001",
            apiType="VirtualCenter",
        )
    return _FakeServiceInstance(_FakeContent(pc, vm, about), cookie)


class TestVsphereClientContract:
    """Pin the real pyVmomi call shape (ADR-0051 §6) without a live vCenter."""

    def test_retrieve_with_continuation_paging(self) -> None:
        oc1 = _oc(vim.VirtualMachine, "vm-1", {"name": "web01", "runtime.powerState": "poweredOn"})
        oc2 = _oc(vim.VirtualMachine, "vm-2", {"name": "web02"})
        si = _make_si([[oc1], [oc2]])
        client = VsphereClient(
            host="vc.lab",
            username=_FAKE_USERNAME,
            password=_FAKE_PASSWORD,
            connect_fn=lambda: si,
            disconnect_fn=lambda _si: None,
        )
        batches = client.fetch_virtual_machines()
        assert [d["moref"] for batch in batches for d in batch] == ["vm-1", "vm-2"]
        first = batches[0][0]
        assert first["type"] == "VirtualMachine"
        assert first["datacenter"] == _DC
        assert first["properties"] == {"name": "web01", "runtime.powerState": "poweredOn"}
        pc = si.content.propertyCollector
        assert pc.retrieve_calls == 1  # one RetrievePropertiesEx
        assert pc.continue_calls == 1  # one ContinueRetrievePropertiesEx (2nd batch)
        # Container views for the Datacenter enumeration AND the VM type; all destroyed.
        types = [t for _c, t, _r in si.content.viewManager.created]
        assert (vim.Datacenter,) in types
        assert (vim.VirtualMachine,) in types
        assert all("Destroy" in v._stub.methods for v in si.content.viewManager.views)

    def test_fetch_about_returns_single_doc(self) -> None:
        si = _make_si([[]])
        client = VsphereClient(
            host="vc.lab",
            username=_FAKE_USERNAME,
            password=_FAKE_PASSWORD,
            connect_fn=lambda: si,
            disconnect_fn=lambda _si: None,
        )
        about = client.fetch_about()
        assert about["type"] == "AboutInfo"
        assert about["properties"]["version"] == "8.0.2"

    def test_disconnect_calls_pyvmomi_disconnect(self) -> None:
        disconnected: list = []
        si = _make_si([[]])
        client = VsphereClient(
            host="vc.lab",
            username=_FAKE_USERNAME,
            password=_FAKE_PASSWORD,
            connect_fn=lambda: si,
            disconnect_fn=disconnected.append,
        )
        client.fetch_about()  # lazily connects
        client.disconnect()
        assert disconnected == [si]

    def test_empty_result_is_empty_not_error(self) -> None:
        si = _make_si([[]])
        client = VsphereClient(
            host="vc.lab",
            username=_FAKE_USERNAME,
            password=_FAKE_PASSWORD,
            connect_fn=lambda: si,
            disconnect_fn=lambda _si: None,
        )
        assert client.fetch_virtual_machines() == []  # no PluginError


class TestVsphereClientSessionExpiry:
    """Mid-run NotAuthenticated → exactly one re-auth + retry (ADR-0051 §2)."""

    def test_reauth_once_then_success(self) -> None:
        connects: list[int] = []

        def connect() -> _FakeServiceInstance:
            connects.append(len(connects))
            # First session fails its RetrievePropertiesEx; the re-auth session succeeds.
            fail = len(connects) == 1
            oc = _oc(vim.VirtualMachine, "vm-1", {"name": "web01"})
            return _make_si([[oc]], fail_first=fail)

        client = VsphereClient(
            host="vc.lab",
            username=_FAKE_USERNAME,
            password=_FAKE_PASSWORD,
            connect_fn=connect,
            disconnect_fn=lambda _si: None,
        )
        batches = client.fetch_virtual_machines()
        assert [d["moref"] for batch in batches for d in batch] == ["vm-1"]
        assert len(connects) == 2  # initial login + exactly one re-auth

    def test_second_failure_raises_typed_error(self) -> None:
        connects: list[int] = []

        def connect() -> _FakeServiceInstance:
            connects.append(len(connects))
            oc = _oc(vim.VirtualMachine, "vm-1", {"name": "web01"})
            return _make_si([[oc]], fail_first=True)  # every session fails

        client = VsphereClient(
            host="vc.lab",
            username=_FAKE_USERNAME,
            password=_FAKE_PASSWORD,
            connect_fn=connect,
            disconnect_fn=lambda _si: None,
        )
        with pytest.raises(PluginError) as exc:
            client.fetch_virtual_machines()
        assert "re-authentication" in str(exc.value)
        assert len(connects) == 2  # one re-auth, then give up


class TestVmodlToJson:
    """Pin the generic vmodl→JSON serialization over constructed pyVmomi objects."""

    def test_scalars_enums_morefs(self) -> None:
        assert vmodl_to_json("x") == "x"
        assert vmodl_to_json(vim.VirtualMachine.PowerState.poweredOn) == "poweredOn"
        assert vmodl_to_json(vim.HostSystem("host-9")) == "host-9"

    def test_guest_nic_info(self) -> None:
        nic = vim.vm.GuestInfo.NicInfo(
            macAddress="00:50:56:aa:bb:cc",
            connected=True,
            deviceConfigId=4000,
            ipAddress=["10.0.0.5"],
            network="VM Network",
        )
        out = vmodl_to_json(nic)
        assert out["macAddress"] == "00:50:56:aa:bb:cc"
        assert out["ipAddress"] == ["10.0.0.5"]
        assert out["network"] == "VM Network"

    def test_trunk_vlan_spec(self) -> None:
        spec = vim.VmwareDistributedVirtualSwitch.TrunkVlanSpec(
            vlanId=[vim.NumericRange(start=100, end=200)]
        )
        out = vmodl_to_json(spec)
        assert out["vlanId"] == [{"start": 100, "end": 200}]


# ---------------------------------------------------------------------------
# Zero-plaintext-leakage — password + SOAP session cookie (ADR-0051 §2).
# ---------------------------------------------------------------------------


def _real_client(si: _FakeServiceInstance) -> VsphereClient:
    return VsphereClient(
        host="vc.lab",
        username=_FAKE_USERNAME,
        password=_FAKE_PASSWORD,
        connect_fn=lambda: si,
        disconnect_fn=lambda _si: None,
    )


def _forbidden() -> tuple[str, ...]:
    return (
        _FAKE_PASSWORD,
        urllib.parse.quote(_FAKE_PASSWORD, safe=""),
        _FAKE_COOKIE,
        urllib.parse.quote(_FAKE_COOKIE, safe=""),
        "FAKE-SOAP-SESSION-DO-NOT-LEAK",
    )


class TestVmwareSecretHygiene:
    def test_client_repr_hides_secrets(self) -> None:
        client = _real_client(_make_si([[]]))
        client.fetch_about()  # connect + register cookie
        r = repr(client)
        assert _FAKE_PASSWORD not in r
        assert _FAKE_COOKIE not in r
        assert "FAKE-SOAP-SESSION-DO-NOT-LEAK" not in r
        assert _FAKE_USERNAME not in r

    def test_no_secret_in_raw_artifacts(self) -> None:
        oc = _oc(
            vim.VirtualMachine,
            "vm-1",
            {"name": "web01", "runtime.powerState": "poweredOn"},
        )
        client = _real_client(_make_si([[oc]]))
        cap = VmwareVirtualizationInventory(client, uuid4())
        cap.get_virtual_machines()
        disc = VmwareDiscoveryApi(client, uuid4())
        disc.discover()
        for source in (cap, disc):
            for raw in source.raw_outputs:
                for needle in _forbidden():
                    assert needle not in raw.output
                    assert needle not in raw.command

    def test_no_secret_in_logs(self, caplog: pytest.LogCaptureFixture) -> None:
        client = _real_client(_make_si([[]]))
        client.fetch_about()  # registers the cookie in the redaction filter
        with caplog.at_level(logging.DEBUG):
            # Any SDK log record naming a secret is dropped before propagation.
            logging.getLogger("pyVmomi").info("soap cookie=%s", _FAKE_COOKIE)
            logging.getLogger("http.client").debug("login pwd=%s", _FAKE_PASSWORD)
        for record in caplog.records:
            message = record.getMessage()
            for needle in _forbidden():
                assert needle not in message, f"secret leaked in log: {message!r}"

    def test_invalid_login_error_hides_password(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # connect_fn=None exercises the real _default_connect error mapping (§2).
        client = VsphereClient(
            host="vc.lab",
            username=_FAKE_USERNAME,
            password=_FAKE_PASSWORD,
            disconnect_fn=lambda _si: None,
        )

        def _raise(**_kw: object) -> object:
            raise vim.fault.InvalidLogin()

        import pyVim.connect as connect_mod

        monkeypatch.setattr(connect_mod, "SmartConnect", _raise)
        with pytest.raises(PluginError) as exc:
            client.fetch_about()
        assert _FAKE_PASSWORD not in str(exc.value)
        assert _FAKE_USERNAME not in str(exc.value)
        assert "invalid credentials" in str(exc.value)

    @pytest.mark.parametrize(
        "raised",
        [vim.fault.HostConnectFault(), OSError("connection refused")],
        ids=["vimfault", "oserror"],
    )
    def test_connect_errors_are_credential_free(
        self, monkeypatch: pytest.MonkeyPatch, raised: Exception
    ) -> None:
        client = VsphereClient(
            host="vc.lab",
            username=_FAKE_USERNAME,
            password=_FAKE_PASSWORD,
            disconnect_fn=lambda _si: None,
        )

        def _raise(**_kw: object) -> object:
            raise raised

        import pyVim.connect as connect_mod

        monkeypatch.setattr(connect_mod, "SmartConnect", _raise)
        with pytest.raises(PluginError) as exc:
            client.fetch_about()
        for needle in _forbidden():
            assert needle not in str(exc.value)
        assert _FAKE_PASSWORD not in str(exc.value)

    def test_disconnect_logout_failure_is_nonfatal(self, caplog: pytest.LogCaptureFixture) -> None:
        def _boom(_si: object) -> None:
            raise RuntimeError("logout blew up")

        client = VsphereClient(
            host="vc.lab",
            username=_FAKE_USERNAME,
            password=_FAKE_PASSWORD,
            connect_fn=lambda: _make_si([[]]),
            disconnect_fn=_boom,
        )
        client.fetch_about()
        with caplog.at_level(logging.WARNING):
            client.disconnect()  # must not raise
        for record in caplog.records:
            for needle in _forbidden():
                assert needle not in record.getMessage()


# ---------------------------------------------------------------------------
# Plugin registration (ADR-0006 §5).
# ---------------------------------------------------------------------------


class TestVmwareRegistration:
    def test_iter_builtin_plugins_includes_vmware(self) -> None:
        from app.plugins.vendors import iter_builtin_plugins

        assert "vmware" in [p.vendor_id for p in iter_builtin_plugins()]

    def test_default_registry_contains_vmware(self) -> None:
        from app.plugins.registry import get_default_registry

        get_default_registry.cache_clear()
        try:
            assert "vmware" in get_default_registry().vendor_ids()
        finally:
            get_default_registry.cache_clear()

    def test_raw_artifacts_are_deterministic_json(self) -> None:
        cap = _inv()
        cap.get_virtual_machines()
        for raw in cap.raw_outputs:
            parsed = json.loads(raw.output)  # every raw artifact is valid JSON (§7)
            assert isinstance(parsed, list)
            # sort_keys determinism: re-dumping the parsed doc is stable.
            assert json.dumps(parsed, sort_keys=True) == raw.output
