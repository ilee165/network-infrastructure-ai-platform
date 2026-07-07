"""Real-PostgreSQL assertions for the W2-T2 derivation write path (ADR-0052 §3.3/§4).

The unit suite proves the applier's logic on SQLite; this module re-asserts
the semantics that only real PostgreSQL exercises (P4-PLAN §0a "SQLite hides
PG semantics") through the REAL migrated schema:

- **Idempotent re-derivation is a no-op** through the server round-trip: the
  ``timestamptz`` values written by the §3.3.3 watermark stamp must compare
  equal after a real flush/reload, or every re-run would misread rows as
  operator-edited (frozen metadata) or rewrite them (audit churn).
- **Natural-key diff-replace never violates**
  ``uq_application_dependencies_natural_key`` — and per-source rows for the
  SAME (application, target) pair coexist (§3.3.1).
- **``origin_ref`` MERGE stability against the partial-unique index**: the
  re-run updates in place (stable UUID) instead of tripping
  ``uq_applications_origin_ref``, and the applier's create path satisfies the
  ``lower(name)`` expression unique index via §3.3.4 collision-attach.
- **Per-source ownership + manual untouchability** and the skipped-dns-pass
  preservation rule, byte-for-byte on the production backend.
- **Dirty tracking through the applier**: a real operator UPDATE (house
  ``onupdate`` moving ``updated_at`` off the watermark) permanently locks
  attributes while edges keep diff-replacing.

Inventory/ADC/VM inputs are plain in-memory rows (the derivation is pure —
only the ``applications`` tables are written), reusing the unit-suite
builders so both suites drive the exact same call shape.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.engines.topology.app_derivation import (
    DerivationPlan,
    derive_application_dependencies,
)
from app.engines.topology.app_derivation_store import (
    DerivationApplyStats,
    apply_derivation_plan,
)
from app.models.applications import (
    Application,
    ApplicationDependency,
    ApplicationOrigin,
    DependencySource,
    DependencyTargetKind,
)
from tests.engines.topology.test_app_derivation import (
    IF_CRM,
    IF_WEB1,
    PAYROLL_REF,
    WEB2_DEV,
    _inventory,
    make_pool,
    make_vs,
    member,
)

#: Selected by the blocking ``pg-integration`` CI job (``pytest -m integration``);
#: without it this file is DESELECTED (not skipped) and its PG-semantics
#: assertions run in no CI job at all (PR #119 review).
pytestmark = pytest.mark.integration

NOW1 = datetime(2026, 7, 6, 12, 0, tzinfo=UTC)
NOW2 = datetime(2026, 7, 6, 13, 0, tzinfo=UTC)


async def _derive_and_apply(
    session: AsyncSession,
    *,
    now: datetime,
    virtual_servers: Sequence[Any] = (),
    pools: Sequence[Any] = (),
    dns_records: Sequence[Any] | None = None,
) -> tuple[DerivationPlan, DerivationApplyStats]:
    """The production call shape: load rows, derive (pure), apply, commit."""
    devices, interfaces = _inventory()
    applications = list((await session.execute(select(Application))).scalars())
    dependencies = list((await session.execute(select(ApplicationDependency))).scalars())
    plan = derive_application_dependencies(
        virtual_servers=list(virtual_servers),
        pools=list(pools),
        virtual_machines=[],
        hypervisor_hosts=[],
        devices=devices,
        interfaces=interfaces,
        applications=applications,
        dependencies=dependencies,
        dns_records=dns_records,
    )
    stats = await apply_derivation_plan(session, plan, now=now)
    await session.commit()
    return plan, stats


def _two_member_inputs(description: str = "payroll VIP") -> dict[str, Any]:
    return {
        "virtual_servers": [make_vs("/Common/payroll.corp.example.com", description=description)],
        "pools": [
            make_pool(
                [
                    member("/Common/web01:80", "10.0.0.11", 80),
                    member("/Common/web02:80", "10.0.0.20", 80),
                ]
            )
        ],
    }


async def _rows(
    session: AsyncSession,
) -> tuple[list[Application], list[ApplicationDependency]]:
    apps = list((await session.execute(select(Application).order_by(Application.name))).scalars())
    deps = list(
        (
            await session.execute(
                select(ApplicationDependency).order_by(
                    ApplicationDependency.source, ApplicationDependency.target_ref
                )
            )
        ).scalars()
    )
    return apps, deps


# ---------------------------------------------------------------------------
# Idempotency + origin_ref MERGE stability (ADR-0052 §4) — the timestamptz
# round-trip and the partial-unique index are exactly what SQLite mismodels.
# ---------------------------------------------------------------------------


async def test_rerun_on_unchanged_inputs_is_a_noop_under_real_pg(
    pg_session: AsyncSession,
) -> None:
    _, stats1 = await _derive_and_apply(pg_session, now=NOW1, **_two_member_inputs())
    assert stats1.applications_created == 1
    assert stats1.f5.inserted == 2

    apps, deps = await _rows(pg_session)
    (app,) = apps
    app_id = app.id
    # The watermark stamp survives the server round-trip exactly equal —
    # the §3.3.3 "still derivation-managed" state.
    assert app.updated_at == app.derived_watermark == NOW1
    first_dep_ids = {d.id for d in deps}

    _, stats2 = await _derive_and_apply(pg_session, now=NOW2, **_two_member_inputs())
    assert stats2.applications_created == 0
    assert stats2.applications_updated == 0
    assert stats2.applications_deleted == 0
    assert (stats2.f5.inserted, stats2.f5.updated, stats2.f5.deleted) == (0, 0, 0)

    apps, deps = await _rows(pg_session)
    assert apps[0].id == app_id  # MERGE on origin_ref against the partial-unique index
    assert apps[0].updated_at == NOW1  # zero updated_at churn
    assert {d.id for d in deps} == first_dep_ids  # no rewrite, no duplicates
    assert all(d.derived_at == NOW1 for d in deps)


async def test_attribute_refresh_keeps_uuid_and_watermark_in_lockstep(
    pg_session: AsyncSession,
) -> None:
    await _derive_and_apply(pg_session, now=NOW1, **_two_member_inputs())
    apps, _ = await _rows(pg_session)
    app_id = apps[0].id

    _, stats = await _derive_and_apply(
        pg_session, now=NOW2, **_two_member_inputs(description="payroll VIP v2")
    )
    assert stats.applications_updated == 1

    apps, _ = await _rows(pg_session)
    assert apps[0].id == app_id  # stable UUID across a real UPDATE
    assert apps[0].description == "payroll VIP v2"
    # Re-stamped: still derivation-managed after the real onupdate cycle.
    assert apps[0].updated_at == apps[0].derived_watermark == NOW2


# ---------------------------------------------------------------------------
# Natural-key semantics through the applier (ADR-0052 §4 / §3.3.1)
# ---------------------------------------------------------------------------


async def test_diff_replace_coexists_with_other_sources_on_the_same_pair(
    pg_session: AsyncSession,
) -> None:
    """The natural key includes ``source``: an f5 re-derivation upserting the
    SAME (application, target) pair a manual row asserts must neither violate
    ``uq_application_dependencies_natural_key`` nor touch the manual row."""
    await _derive_and_apply(pg_session, now=NOW1, **_two_member_inputs())
    apps, _ = await _rows(pg_session)
    app_id = apps[0].id

    manual = ApplicationDependency(
        application_id=app_id,
        target_kind=DependencyTargetKind.IP_ADDRESS,
        target_ref=str(IF_WEB1),  # the exact pair the f5 pass asserts
        source=DependencySource.MANUAL,
        provenance=[{"kind": "user", "ref": str(uuid4())}],
        derived_at=NOW1,
    )
    pg_session.add(manual)
    await pg_session.commit()
    manual_updated_at = manual.updated_at

    _, stats = await _derive_and_apply(pg_session, now=NOW2, **_two_member_inputs())
    assert (stats.f5.inserted, stats.f5.updated, stats.f5.deleted) == (0, 0, 0)

    _, deps = await _rows(pg_session)
    pair_rows = [d for d in deps if d.target_ref == str(IF_WEB1)]
    assert {str(d.source) for d in pair_rows} == {"f5", "manual"}  # per-source rows
    kept = next(d for d in pair_rows if str(d.source) == "manual")
    assert kept.id == manual.id
    assert kept.updated_at == manual_updated_at  # never touched by the pass


async def test_skipped_dns_pass_preserves_source3_rows_fetched_pass_diffs_them(
    pg_session: AsyncSession,
) -> None:
    app = Application(
        name="crm",
        origin=ApplicationOrigin.MANUAL,
        fqdns=["crm.corp.example.com"],
    )
    pg_session.add(app)
    await pg_session.flush()
    dns_row = ApplicationDependency(
        application_id=app.id,
        target_kind=DependencyTargetKind.IP_ADDRESS,
        target_ref=str(IF_CRM),
        source=DependencySource.DNS,
        provenance=[{"kind": "dns_record", "ref": "crm.corp.example.com|a|10.0.0.40"}],
        derived_at=NOW1,
    )
    pg_session.add(dns_row)
    await pg_session.commit()

    # dns_records=None (DDI unreachable): source-3 results persist untouched.
    _, stats = await _derive_and_apply(pg_session, now=NOW2, dns_records=None)
    assert stats.dns is None
    _, deps = await _rows(pg_session)
    assert [d.id for d in deps if str(d.source) == "dns"] == [dns_row.id]
    assert deps[0].derived_at == NOW1

    # A fetched-but-empty record set is a legitimate diff: the row retracts.
    _, stats = await _derive_and_apply(pg_session, now=NOW2, dns_records=[])
    assert stats.dns is not None and stats.dns.deleted == 1
    _, deps = await _rows(pg_session)
    assert [d for d in deps if str(d.source) == "dns"] == []


# ---------------------------------------------------------------------------
# Collision-attach against the lower(name) unique index (ADR-0052 §3.3.4)
# ---------------------------------------------------------------------------


async def test_collision_attach_respects_the_case_insensitive_unique_index(
    pg_session: AsyncSession,
) -> None:
    """A derived application whose name collides case-insensitively with an
    existing row must ATTACH (the create path would trip the real
    ``lower(name)`` expression index — the semantics SQLite's expression
    index support can mask)."""
    manual = Application(name="Payroll.CORP.example.com", origin=ApplicationOrigin.MANUAL)
    pg_session.add(manual)
    await pg_session.commit()

    _, stats = await _derive_and_apply(pg_session, now=NOW1, **_two_member_inputs())
    assert stats.applications_created == 0  # attach, no duplicate row

    apps, deps = await _rows(pg_session)
    (app,) = apps
    assert app.id == manual.id
    assert app.origin is ApplicationOrigin.MANUAL  # stays user-owned
    assert app.origin_ref is None  # no lifecycle transfer (§3.3.4)
    assert {d.target_ref for d in deps} == {str(IF_WEB1), str(WEB2_DEV)}

    # Source object gone: the manual application survives, its derived edge
    # rows retract (§3.3.5) — under the real FK/cascade schema.
    _, stats = await _derive_and_apply(pg_session, now=NOW2)
    assert stats.applications_deleted == 0
    apps, deps = await _rows(pg_session)
    assert len(apps) == 1 and apps[0].id == manual.id
    assert deps == []


async def test_derived_lifecycle_delete_leaves_no_orphan_rows(
    pg_session: AsyncSession,
) -> None:
    await _derive_and_apply(pg_session, now=NOW1, **_two_member_inputs())
    apps, deps = await _rows(pg_session)
    assert len(apps) == 1 and len(deps) == 2
    assert apps[0].origin_ref == PAYROLL_REF

    _, stats = await _derive_and_apply(pg_session, now=NOW2)
    assert stats.applications_deleted == 1
    apps, deps = await _rows(pg_session)
    assert apps == [] and deps == []  # row + every dependency row gone


# ---------------------------------------------------------------------------
# Manual-wins dirty tracking through the applier (ADR-0052 §3.3.3)
# ---------------------------------------------------------------------------


async def test_operator_edit_locks_attributes_while_edges_keep_diffing(
    pg_session: AsyncSession,
) -> None:
    await _derive_and_apply(pg_session, now=NOW1, **_two_member_inputs())
    apps, _ = await _rows(pg_session)
    app_id = apps[0].id

    # A real operator UPDATE: the house onupdate moves updated_at off the
    # watermark on the server round-trip — the exact semantics an in-memory
    # check would mismodel.
    row = (
        await pg_session.execute(select(Application).where(Application.id == app_id))
    ).scalar_one()
    row.name = "operator-owned-name"
    row.fqdns = ["operator.example.com"]
    await pg_session.commit()

    shrunk = {
        "virtual_servers": [make_vs("/Common/payroll.corp.example.com")],
        "pools": [make_pool([member("/Common/web01:80", "10.0.0.11", 80)])],
    }
    _, stats = await _derive_and_apply(pg_session, now=NOW2, **shrunk)
    assert stats.applications_updated == 0  # refresh refused (manual wins)
    assert stats.f5.deleted == 1  # edges remain derivation-owned

    apps, deps = await _rows(pg_session)
    assert apps[0].id == app_id
    assert apps[0].name == "operator-owned-name"
    assert apps[0].fqdns == ["operator.example.com"]
    assert len(deps) == 1 and deps[0].target_ref == str(IF_WEB1)
