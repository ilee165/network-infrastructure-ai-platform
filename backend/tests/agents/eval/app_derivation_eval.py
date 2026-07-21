"""Canonical application-derivation corpus helpers (P4 W4-T2)."""

from __future__ import annotations

import json
from collections import defaultdict
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime
from fractions import Fraction
from pathlib import Path
from typing import Any
from uuid import UUID

from app.engines.topology.app_derivation import (
    DerivationPlan,
    derive_application_dependencies,
)
from app.knowledge.schema import LABEL_DEVICE, LABEL_IPADDRESS
from app.models.adc import NormalizedPoolRow, NormalizedVirtualServerRow
from app.models.applications import (
    Application,
    ApplicationDependency,
    ApplicationOrigin,
    DependencySource,
    DependencyTargetKind,
)
from app.models.inventory import Device, NormalizedInterfaceRow
from app.models.virtualization import NormalizedHypervisorHostRow, NormalizedVirtualMachineRow
from app.schemas.normalized import (
    NormalizedDnsRecord,
    NormalizedHypervisorHost,
    NormalizedInterface,
    NormalizedPool,
    NormalizedPoolMember,
    NormalizedVirtualMachine,
    NormalizedVirtualServer,
)

_FIXTURES = Path(__file__).with_name("fixtures")
_ESTATE = _FIXTURES / "p4_w4_app_derivation_estate.json"
_EXPECTED = _FIXTURES / "p4_w4_app_derivation_expected_graph.json"

_LABEL_BY_KIND = {
    DependencyTargetKind.DEVICE.value: LABEL_DEVICE,
    DependencyTargetKind.IP_ADDRESS.value: LABEL_IPADDRESS,
}


@dataclass(frozen=True)
class GraphEvaluation:
    """Endpoint precision/recall plus the full canonical-graph verdict."""

    precision: Fraction
    recall: Fraction
    graph_equal: bool

    @property
    def accepted(self) -> bool:
        """Whether the exact W4-T2 gate accepts the graph."""
        return (
            self.precision == Fraction(1, 1) and self.recall == Fraction(1, 1) and self.graph_equal
        )


def _endpoint_set(graph: dict[str, Any]) -> frozenset[tuple[str, str, str]]:
    """Canonical ``(application, target label, target key)`` edge identities."""
    return frozenset(
        (str(edge["app_key"]), str(edge["target_label"]), str(edge["target_key"]))
        for edge in graph.get("edges", [])
    )


def evaluate_graph(actual: dict[str, Any], expected: dict[str, Any]) -> GraphEvaluation:
    """Score one produced canonical graph against its independent contract fixture."""
    actual_endpoints = _endpoint_set(actual)
    expected_endpoints = _endpoint_set(expected)
    true_positives = len(actual_endpoints & expected_endpoints)
    precision = (
        Fraction(true_positives, len(actual_endpoints)) if actual_endpoints else Fraction(1, 1)
    )
    recall = (
        Fraction(true_positives, len(expected_endpoints)) if expected_endpoints else Fraction(1, 1)
    )
    return GraphEvaluation(precision, recall, actual == expected)


@dataclass(frozen=True)
class EstateRows:
    """The fixed JSON estate materialized as the derivation API's input types."""

    devices: tuple[Device, ...]
    interfaces: tuple[NormalizedInterfaceRow, ...]
    virtual_servers: tuple[NormalizedVirtualServerRow, ...]
    pools: tuple[NormalizedPoolRow, ...]
    virtual_machines: tuple[NormalizedVirtualMachineRow, ...]
    hypervisor_hosts: tuple[NormalizedHypervisorHostRow, ...]
    dns_records: tuple[NormalizedDnsRecord, ...]
    applications: tuple[Application, ...]
    manual_dependencies: tuple[ApplicationDependency, ...]
    t0: datetime
    t1: datetime
    projection_at: datetime


@dataclass(frozen=True)
class CorpusRun:
    """Pure derivation plan paired with its deterministic canonical graph."""

    rows: EstateRows
    plan: DerivationPlan
    graph: dict[str, Any]


def load_estate() -> dict[str, Any]:
    """Load a fresh copy of the independently authored synthetic estate."""
    return json.loads(_ESTATE.read_text(encoding="utf-8"))


def load_expected_graph() -> dict[str, Any]:
    """Load a fresh copy of the independently authored graph contract."""
    document = json.loads(_EXPECTED.read_text(encoding="utf-8"))
    return {"applications": document["applications"], "edges": document["edges"]}


def load_expected_contract() -> dict[str, Any]:
    """Load expected-only assertions kept deliberately outside the input estate."""
    document = json.loads(_EXPECTED.read_text(encoding="utf-8"))
    return document["_meta"]


def _timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:  # pragma: no cover - fixed fixtures are aware
        raise ValueError(f"fixture timestamp must be timezone-aware: {value}")
    return parsed


def build_estate_rows(estate: dict[str, Any]) -> EstateRows:
    """Adapt JSON-only contract data to rows without consulting runtime output."""
    meta = estate["_meta"]
    collected_at = _timestamp(meta["collected_at"])
    manual_derived_at = _timestamp(meta["manual_derived_at"])

    devices = tuple(
        Device(
            id=UUID(row["id"]),
            hostname=row["hostname"],
            mgmt_ip=row["mgmt_ip"],
            vendor_id=row["vendor_id"],
        )
        for row in estate["devices"]
    )
    normalized_interfaces = tuple(
        (
            row,
            NormalizedInterface(
                device_id=UUID(row["device_id"]),
                collected_at=collected_at,
                source_vendor=row["source_vendor"],
                name=row["name"],
                description=row["description"],
                admin_status=row["admin_status"],
                oper_status=row["oper_status"],
                mac_address=row["mac_address"],
                ip_address=row["ip_address"],
                mtu=row["mtu"],
                speed_mbps=row["speed_mbps"],
                duplex=row["duplex"],
                vlan_id=row["vlan_id"],
                input_errors=row["input_errors"],
                output_errors=row["output_errors"],
            ),
        )
        for row in estate["interfaces"]
    )
    interfaces = tuple(
        NormalizedInterfaceRow(
            id=UUID(row["id"]),
            device_id=record.device_id,
            raw_artifact_id=UUID(row["raw_artifact_id"]),
            collected_at=record.collected_at,
            source_vendor=record.source_vendor,
            name=record.name,
            description=record.description,
            admin_status=record.admin_status,
            oper_status=record.oper_status,
            mac_address=str(record.mac_address) if record.mac_address else None,
            ip_address=str(record.ip_address) if record.ip_address else None,
            mtu=record.mtu,
            speed_mbps=record.speed_mbps,
            duplex=record.duplex,
            vlan_id=record.vlan_id,
            input_errors=record.input_errors,
            output_errors=record.output_errors,
        )
        for row, record in normalized_interfaces
    )
    normalized_virtual_servers = tuple(
        (
            row,
            NormalizedVirtualServer(
                device_id=UUID(row["device_id"]),
                collected_at=collected_at,
                source_vendor=row["source_vendor"],
                name=row["name"],
                vip_address=row["vip_address"],
                port=row["port"],
                protocol=row["protocol"],
                vrf=row["vrf"],
                enabled=row["enabled"],
                availability=row["availability"],
                pool_name=row["pool_name"],
                description=row["description"],
            ),
        )
        for row in estate["virtual_servers"]
    )
    virtual_servers = tuple(
        NormalizedVirtualServerRow(
            id=UUID(row["id"]),
            device_id=record.device_id,
            raw_artifact_id=UUID(row["raw_artifact_id"]),
            collected_at=record.collected_at,
            source_vendor=record.source_vendor,
            name=record.name,
            vip_address=str(record.vip_address) if record.vip_address else None,
            port=record.port,
            protocol=record.protocol,
            vrf=record.vrf,
            enabled=record.enabled,
            availability=record.availability,
            pool_name=record.pool_name,
            description=record.description,
        )
        for row, record in normalized_virtual_servers
    )
    normalized_pools = tuple(
        (
            row,
            NormalizedPool(
                device_id=UUID(row["device_id"]),
                collected_at=collected_at,
                source_vendor=row["source_vendor"],
                name=row["name"],
                monitors=tuple(row["monitors"]),
                availability=row["availability"],
                members=tuple(NormalizedPoolMember(**member) for member in row["members"]),
                description=row["description"],
            ),
        )
        for row in estate["pools"]
    )
    pools = tuple(
        NormalizedPoolRow(
            id=UUID(row["id"]),
            device_id=record.device_id,
            raw_artifact_id=UUID(row["raw_artifact_id"]),
            collected_at=record.collected_at,
            source_vendor=record.source_vendor,
            name=record.name,
            monitors=list(record.monitors),
            availability=record.availability,
            members=[member.model_dump(mode="json") for member in record.members],
            description=record.description,
        )
        for row, record in normalized_pools
    )
    normalized_virtual_machines = tuple(
        (
            row,
            NormalizedVirtualMachine(
                device_id=UUID(row["device_id"]),
                collected_at=collected_at,
                source_vendor=row["source_vendor"],
                name=row["name"],
                moref=row["moref"],
                instance_uuid=row["instance_uuid"],
                is_template=row["is_template"],
                power_state=row["power_state"],
                guest_hostname=row["guest_hostname"],
                guest_ip_addresses=tuple(row["guest_ip_addresses"]),
                host_name=row["host_name"],
                cluster_name=row["cluster_name"],
                datacenter=row["datacenter"],
                nics=tuple(row["nics"]),
                description=row["description"],
            ),
        )
        for row in estate["virtual_machines"]
    )
    virtual_machines = tuple(
        NormalizedVirtualMachineRow(
            id=UUID(row["id"]),
            device_id=record.device_id,
            raw_artifact_id=UUID(row["raw_artifact_id"]),
            collected_at=record.collected_at,
            source_vendor=record.source_vendor,
            name=record.name,
            moref=record.moref,
            instance_uuid=record.instance_uuid,
            is_template=record.is_template,
            power_state=record.power_state,
            guest_hostname=record.guest_hostname,
            guest_ip_addresses=[str(ip) for ip in record.guest_ip_addresses],
            host_name=record.host_name,
            cluster_name=record.cluster_name,
            datacenter=record.datacenter,
            nics=[nic.model_dump(mode="json") for nic in record.nics],
            description=record.description,
        )
        for row, record in normalized_virtual_machines
    )
    normalized_hypervisor_hosts = tuple(
        (
            row,
            NormalizedHypervisorHost(
                device_id=UUID(row["device_id"]),
                collected_at=collected_at,
                source_vendor=row["source_vendor"],
                name=row["name"],
                moref=row["moref"],
                cluster_name=row["cluster_name"],
                datacenter=row["datacenter"],
                vendor=row["vendor"],
                model=row["model"],
                hypervisor_version=row["hypervisor_version"],
                connection_state=row["connection_state"],
                in_maintenance_mode=row["in_maintenance_mode"],
                management_ip=row["management_ip"],
                pnics=tuple(row["pnics"]),
            ),
        )
        for row in estate["hypervisor_hosts"]
    )
    hypervisor_hosts = tuple(
        NormalizedHypervisorHostRow(
            id=UUID(row["id"]),
            device_id=record.device_id,
            raw_artifact_id=UUID(row["raw_artifact_id"]),
            collected_at=record.collected_at,
            source_vendor=record.source_vendor,
            name=record.name,
            moref=record.moref,
            cluster_name=record.cluster_name,
            datacenter=record.datacenter,
            vendor=record.vendor,
            model=record.model,
            hypervisor_version=record.hypervisor_version,
            connection_state=record.connection_state,
            in_maintenance_mode=record.in_maintenance_mode,
            management_ip=str(record.management_ip) if record.management_ip else None,
            pnics=[pnic.model_dump(mode="json") for pnic in record.pnics],
        )
        for row, record in normalized_hypervisor_hosts
    )
    dns_records = tuple(
        NormalizedDnsRecord(
            device_id=UUID(row["device_id"]),
            collected_at=collected_at,
            source_vendor=row["source_vendor"],
            name=row["name"],
            record_type=row["record_type"],
            value=row["value"],
            zone=row["zone"],
        )
        for row in estate["dns_records"]
    )
    applications = tuple(
        Application(
            id=UUID(row["id"]),
            name=row["name"],
            description=row["description"],
            fqdns=list(row["fqdns"]),
            origin=ApplicationOrigin(row["origin"]),
            origin_ref=row["origin_ref"],
            owner=row["owner"],
            created_by=UUID(row["created_by"]) if row["created_by"] else None,
        )
        for row in estate["applications"]
    )
    manual_dependencies = tuple(
        ApplicationDependency(
            id=UUID(row["id"]),
            application_id=UUID(row["application_id"]),
            target_kind=DependencyTargetKind(row["target_kind"]),
            target_ref=row["target_ref"],
            source=DependencySource(row["source"]),
            provenance=deepcopy(row["provenance"]),
            derived_at=manual_derived_at,
            created_by=UUID(row["created_by"]) if row["created_by"] else None,
        )
        for row in estate["manual_dependencies"]
    )
    return EstateRows(
        devices=devices,
        interfaces=interfaces,
        virtual_servers=virtual_servers,
        pools=pools,
        virtual_machines=virtual_machines,
        hypervisor_hosts=hypervisor_hosts,
        dns_records=dns_records,
        applications=applications,
        manual_dependencies=manual_dependencies,
        t0=_timestamp(meta["t0"]),
        t1=_timestamp(meta["t1"]),
        projection_at=_timestamp(meta["projection_at"]),
    )


def _app_key(application: Application) -> str:
    if ApplicationOrigin(str(application.origin)) is ApplicationOrigin.MANUAL:
        return f"id:{application.id}"
    if application.origin_ref is None:
        raise ValueError(f"derived application {application.id} lacks origin_ref")
    return f"origin:{application.origin_ref}"


def _application_payload(application: Application, *, key: str | None = None) -> dict[str, Any]:
    return {
        "key": key or _app_key(application),
        "name": application.name,
        "description": application.description,
        "fqdns": sorted(application.fqdns or []),
        "origin": str(application.origin),
        "origin_ref": application.origin_ref,
        "owner": application.owner,
    }


def _canonical_graph(
    applications: list[dict[str, Any]],
    dependencies: list[tuple[str, str, str, str, list[dict[str, str]], datetime]],
) -> dict[str, Any]:
    """Collapse source rows into the exact projected edge representation."""
    grouped: dict[
        tuple[str, str, str],
        dict[str, tuple[list[dict[str, str]], datetime]],
    ] = defaultdict(dict)
    for app_key, target_label, target_key, source, provenance, derived_at in dependencies:
        grouped[(app_key, target_label, target_key)][source] = (provenance, derived_at)

    edges: list[dict[str, Any]] = []
    for (app_key, target_label, target_key), by_source in sorted(grouped.items()):
        sources = sorted(by_source)
        provenance_by_source = {source: by_source[source][0] for source in sources}
        edges.append(
            {
                "app_key": app_key,
                "target_label": target_label,
                "target_key": target_key,
                "sources": sources,
                "provenance_by_source": provenance_by_source,
                "compact_provenance": [
                    f"{source}:{step['kind']}:{step['ref']}"
                    for source in sources
                    for step in provenance_by_source[source]
                ],
                "derived_at": max(by_source[source][1] for source in sources).isoformat(),
            }
        )
    return {
        "applications": sorted(applications, key=lambda app: app["key"]),
        "edges": edges,
    }


def canonicalize_persisted_graph(
    applications: tuple[Application, ...] | list[Application],
    dependencies: tuple[ApplicationDependency, ...] | list[ApplicationDependency],
) -> dict[str, Any]:
    """Canonicalize reloaded PostgreSQL rows using ADR-0052 stable identities."""
    app_keys = {str(app.id): _app_key(app) for app in applications}
    canonical_dependencies = [
        (
            app_keys[str(dependency.application_id)],
            _LABEL_BY_KIND[str(dependency.target_kind)],
            dependency.target_ref,
            str(dependency.source),
            deepcopy(dependency.provenance),
            dependency.derived_at,
        )
        for dependency in dependencies
    ]
    return _canonical_graph(
        [_application_payload(app) for app in applications], canonical_dependencies
    )


def _canonicalize_plan(rows: EstateRows, plan: DerivationPlan) -> dict[str, Any]:
    current_by_id = {str(app.id): app for app in rows.applications}
    applications = [_application_payload(app) for app in rows.applications]
    app_key_by_id = {str(app.id): _app_key(app) for app in rows.applications}

    for planned in plan.applications:
        if planned.application_id is not None:
            current = current_by_id[planned.application_id]
            if planned.refresh_attributes:
                payload = {
                    "key": app_key_by_id[planned.application_id],
                    "name": planned.name,
                    "description": planned.description,
                    "fqdns": sorted(planned.fqdns),
                    "origin": str(current.origin),
                    "origin_ref": current.origin_ref,
                    "owner": current.owner,
                }
                applications = [
                    payload if app["key"] == payload["key"] else app for app in applications
                ]
            continue
        applications.append(
            {
                "key": f"origin:{planned.origin_ref}",
                "name": planned.name,
                "description": planned.description,
                "fqdns": sorted(planned.fqdns),
                "origin": ApplicationOrigin.DERIVED.value,
                "origin_ref": planned.origin_ref,
                "owner": None,
            }
        )

    canonical_dependencies: list[tuple[str, str, str, str, list[dict[str, str]], datetime]] = []
    for dependency in plan.dependencies:
        if dependency.application_id is not None:
            application_key = app_key_by_id[dependency.application_id]
        else:
            application_key = f"origin:{dependency.app_origin_ref}"
        canonical_dependencies.append(
            (
                application_key,
                _LABEL_BY_KIND[dependency.target_kind],
                dependency.target_ref,
                dependency.source,
                [step.model_dump(mode="json") for step in dependency.provenance],
                rows.t0,
            )
        )
    for manual_dependency in rows.manual_dependencies:
        canonical_dependencies.append(
            (
                app_key_by_id[str(manual_dependency.application_id)],
                _LABEL_BY_KIND[str(manual_dependency.target_kind)],
                manual_dependency.target_ref,
                str(manual_dependency.source),
                deepcopy(manual_dependency.provenance),
                manual_dependency.derived_at,
            )
        )
    return _canonical_graph(applications, canonical_dependencies)


def derive_corpus(estate: dict[str, Any]) -> CorpusRun:
    """Run the production pure derivation and canonicalize its desired graph."""
    rows = build_estate_rows(estate)
    plan = derive_application_dependencies(
        virtual_servers=rows.virtual_servers,
        pools=rows.pools,
        virtual_machines=rows.virtual_machines,
        hypervisor_hosts=rows.hypervisor_hosts,
        devices=rows.devices,
        interfaces=rows.interfaces,
        applications=rows.applications,
        dependencies=rows.manual_dependencies,
        dns_records=rows.dns_records,
    )
    return CorpusRun(rows=rows, plan=plan, graph=_canonicalize_plan(rows, plan))
