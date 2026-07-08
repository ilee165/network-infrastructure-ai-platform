"""Unit tests for the application-layer derivation (ADR-0052 §3.2/§5, W2-T1).

Pure-function tests over in-memory ORM rows — no session, no DB, no Neo4j.
The projection side (Cypher shape, MATCH-only endpoints, stale sweep) is
asserted in ``test_projector.py``; the PG constraint semantics in
``tests/pg/test_applications_pg.py``.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

from app.engines.topology.applications import derive_applications
from app.models.applications import (
    Application,
    ApplicationDependency,
    ApplicationOrigin,
    DependencySource,
    DependencyTargetKind,
)

T0 = datetime(2026, 7, 6, 12, 0, tzinfo=UTC)
T1 = T0 + timedelta(minutes=5)

APP_A = UUID("00000000-0000-0000-0000-00000000f0a1")
APP_B = UUID("00000000-0000-0000-0000-00000000f0a2")
DEV = UUID("00000000-0000-0000-0000-00000000d001")
IP = UUID("00000000-0000-0000-0000-00000000a001")


def _app(app_id: UUID, name: str, **overrides: object) -> Application:
    values: dict = {
        "id": app_id,
        "name": name,
        "origin": ApplicationOrigin.DERIVED,
        "origin_ref": f"f5:test:{name}",
        "fqdns": [f"{name}.corp.example.com"],
        "description": None,
        "owner": None,
    }
    values.update(overrides)
    return Application(**values)


def _dep(
    app_id: UUID,
    kind: DependencyTargetKind,
    target_ref: str,
    source: DependencySource,
    *,
    derived_at: datetime = T0,
    provenance: list[dict[str, str]] | None = None,
) -> ApplicationDependency:
    return ApplicationDependency(
        application_id=app_id,
        target_kind=kind,
        target_ref=target_ref,
        source=source,
        provenance=provenance if provenance is not None else [],
        derived_at=derived_at,
    )


def test_union_edge_per_pair_sources_sorted_newest_derived_at() -> None:
    """Per-source PG rows collapse to ONE projected edge per (app, target)
    carrying sorted sources and the newest derived_at (ADR-0052 §3.2)."""
    deps = [
        _dep(
            APP_A,
            DependencyTargetKind.DEVICE,
            str(DEV),
            DependencySource.MANUAL,
            derived_at=T0,
            provenance=[{"kind": "user", "ref": "u-1"}],
        ),
        _dep(
            APP_A,
            DependencyTargetKind.DEVICE,
            str(DEV),
            DependencySource.F5,
            derived_at=T1,
            provenance=[{"kind": "virtual_server", "ref": "vs-1"}, {"kind": "pool", "ref": "p-1"}],
        ),
    ]
    derived = derive_applications(
        [_app(APP_A, "payroll")],
        deps,
        device_keys={str(DEV)},
        ip_address_keys=set(),
    )
    assert len(derived.depends_on) == 1
    edge = derived.depends_on[0]
    assert edge.application_pg_id == str(APP_A)
    assert edge.target_label == "Device"
    assert edge.target_key == str(DEV)
    assert edge.sources == ("f5", "manual")  # sorted, deduped
    assert edge.derived_at == T1  # newest across the asserting sources
    # Compact provenance: rows sorted by source, steps in stored order (§3.2).
    assert edge.provenance == (
        "f5:virtual_server:vs-1",
        "f5:pool:p-1",
        "manual:user:u-1",
    )


def test_target_kinds_map_to_projected_labels() -> None:
    derived = derive_applications(
        [_app(APP_A, "payroll")],
        [
            _dep(APP_A, DependencyTargetKind.DEVICE, str(DEV), DependencySource.F5),
            _dep(APP_A, DependencyTargetKind.IP_ADDRESS, str(IP), DependencySource.DNS),
        ],
        device_keys={str(DEV)},
        ip_address_keys={str(IP)},
    )
    assert {(e.target_label, e.target_key) for e in derived.depends_on} == {
        ("Device", str(DEV)),
        ("IPAddress", str(IP)),
    }


def test_unprojected_targets_emit_no_edge() -> None:
    """A dependency row whose target key is not among the pass's projected
    Device/IPAddress keys derives NO edge (no phantom endpoints, §5) — and the
    snapshot counts therefore stay equal to what the graph will hold."""
    derived = derive_applications(
        [_app(APP_A, "payroll")],
        [
            _dep(APP_A, DependencyTargetKind.DEVICE, str(DEV), DependencySource.F5),
            _dep(APP_A, DependencyTargetKind.IP_ADDRESS, str(IP), DependencySource.DNS),
        ],
        device_keys={str(DEV)},
        ip_address_keys=set(),  # the IP target was not projected this pass
    )
    assert [(e.target_label, e.target_key) for e in derived.depends_on] == [("Device", str(DEV))]


def test_dependencies_of_unknown_applications_are_dropped() -> None:
    derived = derive_applications(
        [_app(APP_A, "payroll")],
        [_dep(APP_B, DependencyTargetKind.DEVICE, str(DEV), DependencySource.F5)],
        device_keys={str(DEV)},
        ip_address_keys=set(),
    )
    assert derived.depends_on == ()


def test_nodes_sorted_case_insensitively_and_deduped_by_pg_id() -> None:
    apps = [
        _app(APP_B, "Zeta", origin_ref="ref-z"),
        _app(APP_A, "alpha", origin_ref="ref-a"),
        _app(APP_A, "alpha", origin_ref="ref-a"),  # duplicate row: deduped by key
    ]
    derived = derive_applications(apps, [], device_keys=set(), ip_address_keys=set())
    assert [n.name for n in derived.applications] == ["alpha", "Zeta"]
    assert [str(n.pg_id) for n in derived.applications] == [str(APP_A), str(APP_B)]


def test_output_is_independent_of_input_ordering() -> None:
    apps = [_app(APP_A, "payroll"), _app(APP_B, "billing", origin_ref="ref-b")]
    deps = [
        _dep(APP_A, DependencyTargetKind.DEVICE, str(DEV), DependencySource.F5),
        _dep(APP_A, DependencyTargetKind.IP_ADDRESS, str(IP), DependencySource.DNS),
        _dep(APP_B, DependencyTargetKind.DEVICE, str(DEV), DependencySource.MANUAL),
    ]
    keys = {"device_keys": {str(DEV)}, "ip_address_keys": {str(IP)}}
    forward = derive_applications(apps, deps, **keys)
    backward = derive_applications(list(reversed(apps)), list(reversed(deps)), **keys)
    assert forward == backward


def test_node_properties_project_fqdns_as_list_and_origin_as_string() -> None:
    derived = derive_applications(
        [_app(APP_A, "payroll", owner="team-a")],
        [],
        device_keys=set(),
        ip_address_keys=set(),
    )
    node = derived.applications[0]
    props = node.neo4j_properties(T0)
    assert props["pg_id"] == str(APP_A)
    assert props["origin"] == "derived"
    assert props["owner"] == "team-a"
    assert props["fqdns"] == ["payroll.corp.example.com"]
    assert props["last_projected_at"] == T0


def test_malformed_provenance_steps_are_skipped_defensively() -> None:
    dep = _dep(
        APP_A,
        DependencyTargetKind.DEVICE,
        str(DEV),
        DependencySource.F5,
        provenance=[{"kind": "vs", "ref": "v-1"}, "not-a-dict"],  # type: ignore[list-item]
    )
    derived = derive_applications(
        [_app(APP_A, "payroll")], [dep], device_keys={str(DEV)}, ip_address_keys=set()
    )
    assert derived.depends_on[0].provenance == ("f5:vs:v-1",)
