"""W2-T2 pure derivation — the three automated sources (ADR-0052 §2/§3).

Every test drives :func:`derive_application_dependencies` with plain in-memory
ORM rows (no session, no I/O — the function is pure) and asserts the typed
:class:`DerivationPlan` it emits:

- **Source 1 (F5)** — one derived application per virtual server
  (``origin_ref = f5:<device_pg_id>:<vs_full_path>``), edges to reconciled
  member endpoints (interface-IP match → ``ip_address``, mgmt-IP match →
  ``device``), unreconcilable members counted and edge-less, the
  VS-leaf-name-as-FQDN seed heuristic.
- **Source 2 (VMware)** — the chain extender: app-linked VMs (member-IP ↔
  guest-IP, member-FQDN ↔ guest-hostname, manual tag on a VM endpoint) emit
  app → hypervisor-host *device* edges with the VM hop in provenance; a host
  that is not an inventory device emits **no** edge.
- **Source 3 (DNS)** — the M5 ``_AddressIndex`` reconciliation applied to
  caller-fetched records for each application's ``fqdns``, CNAME hops recorded
  in provenance; ``dns_records=None`` skips the pass entirely (a DDI outage
  must never look like "no dns evidence").
- **Determinism** — permuting every input sequence yields the identical plan.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from app.engines.topology.app_derivation import (
    DerivationPlan,
    PlannedDependency,
    ProvenanceStep,
    derive_application_dependencies,
)
from app.models.adc import NormalizedPoolRow, NormalizedVirtualServerRow
from app.models.applications import (
    Application,
    ApplicationDependency,
    ApplicationOrigin,
    DependencySource,
    DependencyTargetKind,
    stamp_derived_watermark,
)
from app.models.inventory import Device, NormalizedInterfaceRow
from app.models.virtualization import NormalizedHypervisorHostRow, NormalizedVirtualMachineRow
from app.schemas.normalized import (
    AdcAvailability,
    AdcProtocol,
    DnsRecordType,
    HostConnectionState,
    InterfaceAdminStatus,
    InterfaceOperStatus,
    NormalizedDnsRecord,
    VmPowerState,
)

COLLECTED_AT = datetime(2026, 7, 6, 12, 0, tzinfo=UTC)

F5_DEV = UUID("00000000-0000-0000-0000-00000000f501")
VC_DEV = UUID("00000000-0000-0000-0000-00000000ec01")
WEB1_DEV = UUID("00000000-0000-0000-0000-000000000d01")
WEB2_DEV = UUID("00000000-0000-0000-0000-000000000d02")
ESX1_DEV = UUID("00000000-0000-0000-0000-000000000d03")
IF_WEB1 = UUID("00000000-0000-0000-0000-000000000a01")
IF_CRM = UUID("00000000-0000-0000-0000-000000000a02")
VS_ROW = UUID("00000000-0000-0000-0000-000000000b01")
POOL_ROW = UUID("00000000-0000-0000-0000-000000000b02")
VM_APP = UUID("00000000-0000-0000-0000-000000000c01")
VM_WEB = UUID("00000000-0000-0000-0000-000000000c02")
VM_CRM = UUID("00000000-0000-0000-0000-000000000c03")
HOST_ESX1 = UUID("00000000-0000-0000-0000-000000000c11")
HOST_ESX2 = UUID("00000000-0000-0000-0000-000000000c12")
APP_CRM = UUID("00000000-0000-0000-0000-000000000e01")
DEP_CRM = UUID("00000000-0000-0000-0000-000000000e02")

PAYROLL_REF = f"f5:{F5_DEV}:/Common/payroll.corp.example.com"


def _provenance(device_id: UUID) -> dict[str, Any]:
    return {
        "device_id": device_id,
        "raw_artifact_id": uuid.uuid4(),
        "collected_at": COLLECTED_AT,
        "source_vendor": "f5_bigip",
    }


def make_device(hostname: str, mgmt_ip: str, *, device_id: UUID) -> Device:
    return Device(id=device_id, hostname=hostname, mgmt_ip=mgmt_ip, vendor_id="cisco_ios")


def make_interface(device_id: UUID, name: str, ip: str, *, row_id: UUID) -> NormalizedInterfaceRow:
    return NormalizedInterfaceRow(
        id=row_id,
        device_id=device_id,
        raw_artifact_id=uuid.uuid4(),
        collected_at=COLLECTED_AT,
        source_vendor="cisco_ios",
        name=name,
        admin_status=InterfaceAdminStatus.UP,
        oper_status=InterfaceOperStatus.UP,
        ip_address=ip,
    )


def make_vs(
    name: str,
    *,
    row_id: UUID = VS_ROW,
    pool_name: str | None = "/Common/payroll_pool",
    description: str | None = "payroll VIP",
) -> NormalizedVirtualServerRow:
    return NormalizedVirtualServerRow(
        id=row_id,
        **_provenance(F5_DEV),
        name=name,
        vip_address="192.0.2.10",
        port=443,
        protocol=AdcProtocol.TCP,
        enabled=True,
        availability=AdcAvailability.AVAILABLE,
        pool_name=pool_name,
        description=description,
    )


def member(
    name: str,
    address: str | None,
    port: int,
    *,
    fqdn: str | None = None,
    vrf: str | None = None,
) -> dict[str, Any]:
    return {
        "name": name,
        "address": address,
        "fqdn": fqdn,
        "port": port,
        "vrf": vrf,
        "admin_state": "enabled",
        "availability": "available",
    }


def make_pool(
    members: list[dict[str, Any]],
    *,
    name: str = "/Common/payroll_pool",
    row_id: UUID = POOL_ROW,
) -> NormalizedPoolRow:
    return NormalizedPoolRow(
        id=row_id,
        **_provenance(F5_DEV),
        name=name,
        monitors=["/Common/https"],
        availability=AdcAvailability.AVAILABLE,
        members=members,
    )


def make_vm(
    name: str,
    *,
    row_id: UUID,
    guest_ips: list[str],
    guest_hostname: str | None = None,
    host_name: str | None = "esx1.corp.example.com",
    datacenter: str | None = "dc1",
    is_template: bool = False,
) -> NormalizedVirtualMachineRow:
    return NormalizedVirtualMachineRow(
        id=row_id,
        **_provenance(VC_DEV),
        name=name,
        moref=f"vm-{str(row_id)[-4:]}",
        is_template=is_template,
        power_state=VmPowerState.POWERED_ON,
        guest_hostname=guest_hostname,
        guest_ip_addresses=guest_ips,
        host_name=host_name,
        cluster_name="prod",
        datacenter=datacenter,
        nics=[],
    )


def make_host(
    name: str,
    *,
    row_id: UUID,
    management_ip: str | None,
    datacenter: str | None = "dc1",
) -> NormalizedHypervisorHostRow:
    return NormalizedHypervisorHostRow(
        id=row_id,
        **_provenance(VC_DEV),
        name=name,
        moref=f"host-{str(row_id)[-4:]}",
        cluster_name="prod",
        datacenter=datacenter,
        connection_state=HostConnectionState.CONNECTED,
        in_maintenance_mode=False,
        management_ip=management_ip,
        pnics=[],
    )


def dns_record(name: str, record_type: DnsRecordType, value: str) -> NormalizedDnsRecord:
    return NormalizedDnsRecord(
        device_id=uuid.uuid4(),
        collected_at=COLLECTED_AT,
        source_vendor="infoblox",
        name=name,
        record_type=record_type,
        value=value,
        zone="corp.example.com",
    )


def make_crm_app() -> Application:
    app = Application(
        id=APP_CRM,
        name="CRM",
        origin=ApplicationOrigin.MANUAL,
        origin_ref=None,
        fqdns=["crm.corp.example.com", "missing.example.com"],
    )
    return app


def make_crm_manual_dep() -> ApplicationDependency:
    return ApplicationDependency(
        id=DEP_CRM,
        application_id=APP_CRM,
        target_kind=DependencyTargetKind.IP_ADDRESS,
        target_ref=str(IF_CRM),
        source=DependencySource.MANUAL,
        provenance=[{"kind": "user", "ref": str(uuid.uuid4())}],
        derived_at=COLLECTED_AT,
    )


def _inventory() -> tuple[list[Device], list[NormalizedInterfaceRow]]:
    devices = [
        make_device("f5-a", "10.9.9.9", device_id=F5_DEV),
        make_device("vcenter", "10.9.9.8", device_id=VC_DEV),
        make_device("web01", "10.0.0.10", device_id=WEB1_DEV),
        make_device("web02", "10.0.0.20", device_id=WEB2_DEV),
        make_device("esx1", "10.0.1.5", device_id=ESX1_DEV),
    ]
    interfaces = [
        make_interface(WEB1_DEV, "eth0", "10.0.0.11/24", row_id=IF_WEB1),
        make_interface(WEB1_DEV, "eth1", "10.0.0.40/24", row_id=IF_CRM),
    ]
    return devices, interfaces


def _derive(
    *,
    virtual_servers: list[NormalizedVirtualServerRow] | None = None,
    pools: list[NormalizedPoolRow] | None = None,
    virtual_machines: list[NormalizedVirtualMachineRow] | None = None,
    hypervisor_hosts: list[NormalizedHypervisorHostRow] | None = None,
    applications: list[Application] | None = None,
    dependencies: list[ApplicationDependency] | None = None,
    dns_records: list[NormalizedDnsRecord] | None = None,
) -> DerivationPlan:
    devices, interfaces = _inventory()
    return derive_application_dependencies(
        virtual_servers=virtual_servers or [],
        pools=pools or [],
        virtual_machines=virtual_machines or [],
        hypervisor_hosts=hypervisor_hosts or [],
        devices=devices,
        interfaces=interfaces,
        applications=applications or [],
        dependencies=dependencies or [],
        dns_records=dns_records,
    )


def _deps(plan: DerivationPlan, source: str) -> list[PlannedDependency]:
    return [d for d in plan.dependencies if d.source == source]


def _steps(dep: PlannedDependency) -> list[tuple[str, str]]:
    return [(step.kind, step.ref) for step in dep.provenance]


# ===========================================================================
# Source 1 — F5 VIP -> pool -> member
# ===========================================================================


def test_f5_derives_one_application_per_vs_with_reconciled_member_edges() -> None:
    plan = _derive(
        virtual_servers=[make_vs("/Common/payroll.corp.example.com")],
        pools=[
            make_pool(
                [
                    member("/Common/web01:80", "10.0.0.11", 80),
                    member("/Common/web02:80", "10.0.0.20", 80),
                ]
            )
        ],
    )

    assert len(plan.applications) == 1
    app = plan.applications[0]
    assert app.origin_ref == PAYROLL_REF
    assert app.application_id is None  # nothing existing -> create
    assert app.name == "payroll.corp.example.com"  # the full-path leaf
    assert app.description == "payroll VIP"

    f5 = _deps(plan, "f5")
    assert {(d.target_kind, d.target_ref) for d in f5} == {
        ("ip_address", str(IF_WEB1)),  # interface-IP reconciliation wins
        ("device", str(WEB2_DEV)),  # mgmt-IP fallback
    }
    assert all(d.app_origin_ref == PAYROLL_REF and d.application_id is None for d in f5)
    by_target = {d.target_ref: d for d in f5}
    assert _steps(by_target[str(IF_WEB1)]) == [
        ("virtual_server", str(VS_ROW)),
        ("pool", str(POOL_ROW)),
        ("member", "/Common/web01:80"),
        ("interface", str(IF_WEB1)),
    ]
    assert _steps(by_target[str(WEB2_DEV)]) == [
        ("virtual_server", str(VS_ROW)),
        ("pool", str(POOL_ROW)),
        ("member", "/Common/web02:80"),
        ("device", str(WEB2_DEV)),
    ]
    assert plan.stats.f5_applications == 1
    assert plan.stats.f5_edges == 2
    assert plan.stats.f5_members_unreconciled == 0


def test_f5_unreconcilable_member_emits_no_edge_but_is_counted() -> None:
    plan = _derive(
        virtual_servers=[make_vs("/Common/payroll.corp.example.com")],
        pools=[make_pool([member("/Common/ghost:80", "10.0.0.99", 80)])],
    )
    assert _deps(plan, "f5") == []
    assert plan.stats.f5_members_unreconciled == 1
    # The application itself still exists — the VS is the service identity.
    assert len(plan.applications) == 1


def test_f5_nondefault_route_domain_member_does_not_match_global_inventory() -> None:
    plan = _derive(
        virtual_servers=[make_vs("/Common/payroll.corp.example.com")],
        pools=[make_pool([member("/Common/rd2-web01:80", "10.0.0.11", 80, vrf="2")])],
    )

    assert _deps(plan, "f5") == []
    assert plan.stats.f5_members_unreconciled == 1


def test_f5_default_route_domain_variants_reconcile_global_inventory() -> None:
    absent = member("/Common/absent:80", "10.0.0.11", 80)
    absent.pop("vrf")
    variants = (
        absent,
        member("/Common/empty:80", "10.0.0.11", 80, vrf=""),
        member("/Common/zero:80", "10.0.0.11", 80, vrf="0"),
    )

    for entry in variants:
        plan = _derive(
            virtual_servers=[make_vs("/Common/payroll.corp.example.com")],
            pools=[make_pool([entry])],
        )
        (dep,) = _deps(plan, "f5")
        assert (dep.target_kind, dep.target_ref) == ("ip_address", str(IF_WEB1))
        assert plan.stats.f5_members_unreconciled == 0


def test_f5_fqdn_seed_heuristic_only_for_valid_fqdn_leaves() -> None:
    fqdn_vs = make_vs("/Common/payroll.corp.example.com", row_id=VS_ROW, pool_name=None)
    plain_vs = make_vs("/Common/vs_web", row_id=POOL_ROW, pool_name=None)
    plan = _derive(virtual_servers=[fqdn_vs, plain_vs])

    by_name = {app.name: app for app in plan.applications}
    assert by_name["payroll.corp.example.com"].fqdns == ("payroll.corp.example.com",)
    assert by_name["vs_web"].fqdns == ()


def test_f5_name_collision_attaches_case_insensitively_to_existing_manual_row() -> None:
    manual = Application(
        id=APP_CRM, name="Payroll.CORP.example.com", origin=ApplicationOrigin.MANUAL
    )
    plan = _derive(
        virtual_servers=[make_vs("/Common/payroll.corp.example.com")],
        pools=[make_pool([member("/Common/web01:80", "10.0.0.11", 80)])],
        applications=[manual],
    )

    assert len(plan.applications) == 1
    app = plan.applications[0]
    # Attach, never duplicate; the manual row stays manual (no origin_ref
    # transfer, no attribute takeover) — ADR-0052 §3.3.4.
    assert app.application_id == str(APP_CRM)
    assert app.record_origin_ref is False
    assert app.refresh_attributes is False
    (dep,) = _deps(plan, "f5")
    assert dep.application_id == str(APP_CRM)
    assert dep.app_origin_ref is None


def test_f5_name_collision_records_origin_ref_on_derived_row_lacking_one() -> None:
    derived = Application(
        id=APP_CRM,
        name="PAYROLL.corp.example.com",
        origin=ApplicationOrigin.DERIVED,
        origin_ref=None,
    )
    stamp_derived_watermark(derived)
    plan = _derive(virtual_servers=[make_vs("/Common/payroll.corp.example.com")])

    # Without the existing row: create.
    assert plan.applications[0].application_id is None

    plan = _derive(
        virtual_servers=[make_vs("/Common/payroll.corp.example.com")],
        applications=[derived],
    )
    app = plan.applications[0]
    assert app.application_id == str(APP_CRM)
    assert app.record_origin_ref is True  # first attach records the natural key
    assert app.refresh_attributes is True  # clean derived row stays refreshable


def test_f5_existing_origin_ref_wins_over_name_collision() -> None:
    owner = Application(
        id=APP_CRM,
        name="renamed-by-operator",
        origin=ApplicationOrigin.DERIVED,
        origin_ref=PAYROLL_REF,
    )
    other = Application(
        id=DEP_CRM, name="payroll.corp.example.com", origin=ApplicationOrigin.MANUAL
    )
    plan = _derive(
        virtual_servers=[make_vs("/Common/payroll.corp.example.com")],
        applications=[owner, other],
    )
    app = plan.applications[0]
    assert app.application_id == str(APP_CRM)  # identity by origin_ref, not name


def test_f5_within_pass_duplicate_leaf_names_collapse_to_one_application() -> None:
    vs_a = make_vs("/Common/payroll.corp.example.com", row_id=VS_ROW, pool_name=None)
    vs_b = make_vs("/PartitionB/payroll.corp.example.com", row_id=POOL_ROW, pool_name=None)
    plan = _derive(virtual_servers=[vs_a, vs_b])

    assert len(plan.applications) == 1
    # Deterministic winner: the lexically-smallest origin_ref.
    refs = sorted(
        [
            f"f5:{F5_DEV}:/Common/payroll.corp.example.com",
            f"f5:{F5_DEV}:/PartitionB/payroll.corp.example.com",
        ]
    )
    assert plan.applications[0].origin_ref == refs[0]


# ===========================================================================
# Source 2 — VMware VM -> host chain extender
# ===========================================================================


def test_vmware_member_ip_to_guest_ip_link_extends_chain_to_host_device() -> None:
    plan = _derive(
        virtual_servers=[make_vs("/Common/payroll.corp.example.com")],
        pools=[make_pool([member("/Common/web01:80", "10.0.0.11", 80)])],
        virtual_machines=[make_vm("web01vm", row_id=VM_WEB, guest_ips=["10.0.0.11"])],
        hypervisor_hosts=[
            make_host("esx1.corp.example.com", row_id=HOST_ESX1, management_ip="10.0.1.5")
        ],
    )

    (dep,) = _deps(plan, "vmware")
    assert dep.app_origin_ref == PAYROLL_REF
    assert (dep.target_kind, dep.target_ref) == ("device", str(ESX1_DEV))
    assert _steps(dep) == [
        ("virtual_server", str(VS_ROW)),
        ("pool", str(POOL_ROW)),
        ("member", "/Common/web01:80"),
        ("virtual_machine", str(VM_WEB)),
        ("hypervisor_host", str(HOST_ESX1)),
        ("device", str(ESX1_DEV)),
    ]
    assert plan.stats.vmware_edges == 1


def test_vmware_nondefault_route_domain_member_ip_does_not_match_guest_ip() -> None:
    plan = _derive(
        virtual_servers=[make_vs("/Common/payroll.corp.example.com")],
        pools=[make_pool([member("/Common/rd2-web01:80", "10.0.0.11", 80, vrf="2")])],
        virtual_machines=[make_vm("web01vm", row_id=VM_WEB, guest_ips=["10.0.0.11"])],
        hypervisor_hosts=[
            make_host("esx1.corp.example.com", row_id=HOST_ESX1, management_ip="10.0.1.5")
        ],
    )

    assert _deps(plan, "f5") == []
    assert plan.stats.f5_members_unreconciled == 1
    assert _deps(plan, "vmware") == []
    assert plan.stats.vmware_edges == 0


def test_vmware_fqdn_member_joins_guest_hostname_despite_no_address() -> None:
    """The spec fixture: an FQDN member (no IP — source-1 unreconcilable)
    still links the VM by guest hostname and extends to the host device."""
    plan = _derive(
        virtual_servers=[make_vs("/Common/payroll.corp.example.com")],
        pools=[make_pool([member("/Common/appvm:443", None, 443, fqdn="appvm.corp.example.com")])],
        virtual_machines=[
            make_vm(
                "appvm",
                row_id=VM_APP,
                guest_ips=["10.0.0.30"],
                guest_hostname="APPVM.corp.example.COM",  # case-insensitive join
            )
        ],
        hypervisor_hosts=[
            make_host("esx1.corp.example.com", row_id=HOST_ESX1, management_ip="10.0.1.5")
        ],
    )

    assert plan.stats.f5_members_unreconciled == 1  # no source-1 edge
    assert _deps(plan, "f5") == []
    (dep,) = _deps(plan, "vmware")
    assert (dep.target_kind, dep.target_ref) == ("device", str(ESX1_DEV))
    assert ("virtual_machine", str(VM_APP)) in _steps(dep)


def test_vmware_nondefault_route_domain_member_fqdn_still_matches_guest_hostname() -> None:
    plan = _derive(
        virtual_servers=[make_vs("/Common/payroll.corp.example.com")],
        pools=[
            make_pool(
                [
                    member(
                        "/Common/rd2-appvm:443",
                        "10.0.0.99",
                        443,
                        fqdn="appvm.corp.example.com",
                        vrf="2",
                    )
                ]
            )
        ],
        virtual_machines=[
            make_vm(
                "appvm",
                row_id=VM_APP,
                guest_ips=["192.0.2.44"],
                guest_hostname="APPVM.corp.example.COM",
            )
        ],
        hypervisor_hosts=[
            make_host("esx1.corp.example.com", row_id=HOST_ESX1, management_ip="10.0.1.5")
        ],
    )

    assert _deps(plan, "f5") == []
    assert plan.stats.f5_members_unreconciled == 1
    (dep,) = _deps(plan, "vmware")
    assert (dep.target_kind, dep.target_ref) == ("device", str(ESX1_DEV))
    assert _steps(dep) == [
        ("virtual_server", str(VS_ROW)),
        ("pool", str(POOL_ROW)),
        ("member", "/Common/rd2-appvm:443"),
        ("virtual_machine", str(VM_APP)),
        ("hypervisor_host", str(HOST_ESX1)),
        ("device", str(ESX1_DEV)),
    ]


def test_vmware_tools_less_vm_does_not_link_member() -> None:
    plan = _derive(
        virtual_servers=[make_vs("/Common/payroll.corp.example.com")],
        pools=[make_pool([member("/Common/web01:80", "10.0.0.11", 80)])],
        virtual_machines=[make_vm("web01vm", row_id=VM_WEB, guest_ips=[])],
        hypervisor_hosts=[
            make_host("esx1.corp.example.com", row_id=HOST_ESX1, management_ip="10.0.1.5")
        ],
    )

    assert _deps(plan, "vmware") == []
    assert plan.stats.vmware_edges == 0


def test_vmware_no_edge_when_host_not_an_inventory_device() -> None:
    plan = _derive(
        virtual_servers=[make_vs("/Common/payroll.corp.example.com")],
        pools=[make_pool([member("/Common/web01:80", "10.0.0.11", 80)])],
        virtual_machines=[
            make_vm(
                "web01vm",
                row_id=VM_WEB,
                guest_ips=["10.0.0.11"],
                host_name="esx9.corp.example.com",
            )
        ],
        hypervisor_hosts=[
            # Host row exists but reconciles to no inventory device.
            make_host("esx9.corp.example.com", row_id=HOST_ESX2, management_ip="203.0.113.9")
        ],
    )
    assert _deps(plan, "vmware") == []
    assert plan.stats.vmware_hosts_unmatched == 1

    # Same when the host row itself is missing.
    plan = _derive(
        virtual_servers=[make_vs("/Common/payroll.corp.example.com")],
        pools=[make_pool([member("/Common/web01:80", "10.0.0.11", 80)])],
        virtual_machines=[make_vm("web01vm", row_id=VM_WEB, guest_ips=["10.0.0.11"])],
        hypervisor_hosts=[],
    )
    assert _deps(plan, "vmware") == []
    assert plan.stats.vmware_hosts_unmatched == 1


def test_vmware_manual_tag_on_vm_endpoint_links_existing_application() -> None:
    plan = _derive(
        applications=[make_crm_app()],
        dependencies=[make_crm_manual_dep()],
        virtual_machines=[make_vm("crmvm", row_id=VM_CRM, guest_ips=["10.0.0.40"])],
        hypervisor_hosts=[
            make_host("esx1.corp.example.com", row_id=HOST_ESX1, management_ip="10.0.1.5")
        ],
    )

    (dep,) = _deps(plan, "vmware")
    assert dep.application_id == str(APP_CRM)
    assert (dep.target_kind, dep.target_ref) == ("device", str(ESX1_DEV))
    assert _steps(dep) == [
        ("dependency", str(DEP_CRM)),
        ("virtual_machine", str(VM_CRM)),
        ("hypervisor_host", str(HOST_ESX1)),
        ("device", str(ESX1_DEV)),
    ]


def test_vmware_templates_never_link() -> None:
    plan = _derive(
        applications=[make_crm_app()],
        dependencies=[make_crm_manual_dep()],
        virtual_machines=[
            make_vm("crm-template", row_id=VM_CRM, guest_ips=["10.0.0.40"], is_template=True)
        ],
        hypervisor_hosts=[
            make_host("esx1.corp.example.com", row_id=HOST_ESX1, management_ip="10.0.1.5")
        ],
    )
    assert _deps(plan, "vmware") == []


# ===========================================================================
# Source 3 — DNS linkage over caller-fetched records
# ===========================================================================


def test_dns_resolves_application_fqdns_through_cname_chains() -> None:
    records = [
        dns_record("crm.corp.example.com", DnsRecordType.CNAME, "crm-lb.corp.example.com"),
        dns_record("crm-lb.corp.example.com", DnsRecordType.A, "10.0.0.40"),
    ]
    plan = _derive(applications=[make_crm_app()], dns_records=records)

    assert plan.dns_pass_ran is True
    (dep,) = _deps(plan, "dns")
    assert dep.application_id == str(APP_CRM)
    assert (dep.target_kind, dep.target_ref) == ("ip_address", str(IF_CRM))
    assert _steps(dep) == [
        ("dns_record", "crm.corp.example.com|cname|crm-lb.corp.example.com"),
        ("dns_record", "crm-lb.corp.example.com|a|10.0.0.40"),
        ("interface", str(IF_CRM)),
    ]
    # "missing.example.com" resolved nothing.
    assert plan.stats.dns_names_unreconciled == 1
    assert plan.stats.dns_edges == 1


def test_dns_covers_fqdns_seeded_by_the_f5_pass_in_the_same_run() -> None:
    records = [dns_record("payroll.corp.example.com", DnsRecordType.A, "10.0.0.11")]
    plan = _derive(
        virtual_servers=[make_vs("/Common/payroll.corp.example.com", pool_name=None)],
        dns_records=records,
    )
    (dep,) = _deps(plan, "dns")
    assert dep.app_origin_ref == PAYROLL_REF
    assert (dep.target_kind, dep.target_ref) == ("ip_address", str(IF_WEB1))


def test_dns_none_skips_the_pass_entirely() -> None:
    plan = _derive(applications=[make_crm_app()], dns_records=None)
    assert plan.dns_pass_ran is False
    assert plan.stats.dns_skipped is True
    assert _deps(plan, "dns") == []


def test_dns_cname_loops_terminate() -> None:
    records = [
        dns_record("crm.corp.example.com", DnsRecordType.CNAME, "loop.corp.example.com"),
        dns_record("loop.corp.example.com", DnsRecordType.CNAME, "crm.corp.example.com"),
    ]
    plan = _derive(applications=[make_crm_app()], dns_records=records)
    assert _deps(plan, "dns") == []
    assert plan.stats.dns_names_unreconciled == 2


# ===========================================================================
# Cross-cutting invariants
# ===========================================================================


def _full_scenario_inputs() -> dict[str, Any]:
    return {
        "virtual_servers": [make_vs("/Common/payroll.corp.example.com")],
        "pools": [
            make_pool(
                [
                    member("/Common/web01:80", "10.0.0.11", 80),
                    member("/Common/web02:80", "10.0.0.20", 80),
                    member("/Common/ghost:80", "10.0.0.99", 80),
                    member("/Common/appvm:443", None, 443, fqdn="appvm.corp.example.com"),
                ]
            )
        ],
        "virtual_machines": [
            make_vm(
                "appvm",
                row_id=VM_APP,
                guest_ips=["10.0.0.30"],
                guest_hostname="appvm.corp.example.com",
            ),
            make_vm("crmvm", row_id=VM_CRM, guest_ips=["10.0.0.40"]),
        ],
        "hypervisor_hosts": [
            make_host("esx1.corp.example.com", row_id=HOST_ESX1, management_ip="10.0.1.5"),
            make_host("esx2.corp.example.com", row_id=HOST_ESX2, management_ip="203.0.113.9"),
        ],
        "applications": [make_crm_app()],
        "dependencies": [make_crm_manual_dep()],
        "dns_records": [
            dns_record("crm.corp.example.com", DnsRecordType.CNAME, "crm-lb.corp.example.com"),
            dns_record("crm-lb.corp.example.com", DnsRecordType.A, "10.0.0.40"),
            dns_record("payroll.corp.example.com", DnsRecordType.A, "10.0.0.11"),
        ],
    }


def test_output_is_independent_of_input_ordering() -> None:
    inputs = _full_scenario_inputs()
    baseline = _derive(**inputs)

    permuted = {
        key: (list(reversed(value)) if isinstance(value, list) else value)
        for key, value in _full_scenario_inputs().items()
    }
    assert _derive(**permuted) == baseline


def test_derivation_never_emits_manual_source_rows() -> None:
    plan = _derive(**_full_scenario_inputs())
    assert all(d.source in {"f5", "vmware", "dns"} for d in plan.dependencies)
    # And every provenance step references ids/natural keys, never row content.
    for dep in plan.dependencies:
        for step in dep.provenance:
            assert isinstance(step, ProvenanceStep)
            assert step.kind and step.ref


def test_duplicate_member_endpoints_dedupe_to_one_row() -> None:
    plan = _derive(
        virtual_servers=[make_vs("/Common/payroll.corp.example.com")],
        pools=[
            make_pool(
                [
                    member("/Common/web01:80", "10.0.0.11", 80),
                    member("/Common/web01:8443", "10.0.0.11", 8443),
                ]
            )
        ],
    )
    f5 = _deps(plan, "f5")
    assert len(f5) == 1  # one row per (app, target, source) natural key
    # Deterministic evidence: the first member in sorted order.
    assert ("member", "/Common/web01:80") in _steps(f5[0])


def test_duplicate_member_names_mixed_address_presence_do_not_crash() -> None:
    # Regression (PR #119 review): two pool members sharing a computed
    # member_name where one carries an address and the other is fqdn-only
    # (address=None). The pre-fix ``sorted(parsed)`` compared ``str`` vs
    # ``None`` on the tie-break tuple element and raised ``TypeError``, aborting
    # the whole derivation pass. The None-safe sort key must keep it ordered.
    plan = _derive(
        virtual_servers=[make_vs("/Common/payroll.corp.example.com")],
        pools=[
            make_pool(
                [
                    member("/Common/dup", "10.0.0.11", 80),
                    member("/Common/dup", None, 80, fqdn="dup.corp.example.com"),
                ]
            )
        ],
    )
    # No crash. The address-bearing member reconciles to its interface-IP edge;
    # the fqdn-only member has no address to resolve, so it is edge-less.
    f5 = _deps(plan, "f5")
    assert len(f5) == 1
