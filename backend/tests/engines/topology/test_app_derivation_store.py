"""W2-T2 applier — diff-replace per source, MERGE on origin_ref, manual-wins.

End-to-end over in-memory SQLite: each scenario loads the CURRENT table
contents, runs the pure :func:`derive_application_dependencies`, applies the
plan via :func:`apply_derivation_plan`, and asserts the ADR-0052 §3.3/§4
write-path invariants:

- idempotent re-derivation is a byte-for-byte **no-op** (no ``updated_at`` /
  ``derived_at`` churn, stable row UUIDs);
- diff-replace touches only actual differences, per source;
- a pass for source *S* never touches another source's rows and NEVER touches
  ``manual`` rows; a skipped dns pass (``dns_records=None``) preserves the
  persisted source-3 results;
- derived applications are lifecycle-owned: the row disappears when its
  ``origin_ref`` source object disappears, while a collision-attached
  ``manual`` application only loses the derived edge rows;
- operator-edited attributes are never clobbered (edges still refresh).

The same invariants are re-asserted against real PostgreSQL in
``tests/pg/test_app_derivation_pg.py`` (the blocking ``pg-integration`` job).
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Sequence
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import pytest
from sqlalchemy import event, select
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.engines.topology.app_derivation import (
    DerivationPlan,
    derive_application_dependencies,
)
from app.engines.topology.app_derivation_store import (
    DerivationApplyStats,
    apply_derivation_plan,
)
from app.models import Base
from app.models.applications import (
    Application,
    ApplicationDependency,
    ApplicationOrigin,
    DependencySource,
    DependencyTargetKind,
)
from tests.engines.topology.test_app_derivation import (
    APP_CRM,
    IF_CRM,
    IF_WEB1,
    PAYROLL_REF,
    WEB2_DEV,
    _inventory,
    make_crm_app,
    make_crm_manual_dep,
    make_pool,
    make_vs,
    member,
)

NOW1 = datetime(2026, 7, 6, 12, 0, tzinfo=UTC)
NOW2 = datetime(2026, 7, 6, 13, 0, tzinfo=UTC)
NOW3 = datetime(2026, 7, 6, 14, 0, tzinfo=UTC)


@pytest.fixture()
async def engine() -> AsyncIterator[AsyncEngine]:
    engine = create_async_engine("sqlite+aiosqlite://")

    @event.listens_for(engine.sync_engine, "connect")
    def _enable_sqlite_fks(dbapi_connection: Any, _record: Any) -> None:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()


@pytest.fixture()
async def session(engine: AsyncEngine) -> AsyncIterator[AsyncSession]:
    maker = async_sessionmaker(engine, expire_on_commit=False)
    async with maker() as session:
        yield session


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


def _two_member_inputs() -> dict[str, Any]:
    return {
        "virtual_servers": [make_vs("/Common/payroll.corp.example.com")],
        "pools": [
            make_pool(
                [
                    member("/Common/web01:80", "10.0.0.11", 80),
                    member("/Common/web02:80", "10.0.0.20", 80),
                ]
            )
        ],
    }


async def _rows(session: AsyncSession) -> tuple[list[Application], list[ApplicationDependency]]:
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
# Create + idempotent re-run (ADR-0052 §4)
# ---------------------------------------------------------------------------


async def test_apply_creates_rows_and_rerun_on_unchanged_inputs_is_a_noop(
    session: AsyncSession,
) -> None:
    _, stats1 = await _derive_and_apply(session, now=NOW1, **_two_member_inputs())
    assert stats1.applications_created == 1
    assert stats1.f5.inserted == 2

    apps, deps = await _rows(session)
    (app,) = apps
    assert app.origin is ApplicationOrigin.DERIVED
    assert app.origin_ref == PAYROLL_REF
    assert app.updated_at == app.derived_watermark == NOW1
    assert {d.target_ref for d in deps} == {str(IF_WEB1), str(WEB2_DEV)}
    assert all(d.derived_at == NOW1 for d in deps)
    first_ids = {d.id for d in deps}

    # Re-run against unchanged inputs: nothing written, nothing re-stamped.
    _, stats2 = await _derive_and_apply(session, now=NOW2, **_two_member_inputs())
    assert stats2.applications_created == 0
    assert stats2.applications_updated == 0
    assert stats2.applications_deleted == 0
    assert (stats2.f5.inserted, stats2.f5.updated, stats2.f5.deleted) == (0, 0, 0)

    apps, deps = await _rows(session)
    assert apps[0].id == app.id  # origin_ref MERGE: stable UUID
    assert apps[0].updated_at == NOW1  # no updated_at churn
    assert all(d.derived_at == NOW1 for d in deps)
    assert {d.id for d in deps} == first_ids  # no rewrite, no duplicates


async def test_diff_replace_deletes_only_vanished_rows(session: AsyncSession) -> None:
    await _derive_and_apply(session, now=NOW1, **_two_member_inputs())

    shrunk = {
        "virtual_servers": [make_vs("/Common/payroll.corp.example.com")],
        "pools": [make_pool([member("/Common/web01:80", "10.0.0.11", 80)])],
    }
    _, stats = await _derive_and_apply(session, now=NOW2, **shrunk)
    assert (stats.f5.inserted, stats.f5.updated, stats.f5.deleted) == (0, 0, 1)

    _, deps = await _rows(session)
    (survivor,) = deps
    assert survivor.target_ref == str(IF_WEB1)
    assert survivor.derived_at == NOW1  # untouched, not rewritten


async def test_provenance_change_updates_in_place_without_duplicates(
    session: AsyncSession,
) -> None:
    await _derive_and_apply(session, now=NOW1, **_two_member_inputs())
    _, before = await _rows(session)
    row_ids = {d.target_ref: d.id for d in before}

    renamed = {
        "virtual_servers": [make_vs("/Common/payroll.corp.example.com")],
        "pools": [
            make_pool(
                [
                    member("/Common/web01:8080", "10.0.0.11", 8080),  # new member name
                    member("/Common/web02:80", "10.0.0.20", 80),
                ]
            )
        ],
    }
    _, stats = await _derive_and_apply(session, now=NOW2, **renamed)
    assert (stats.f5.inserted, stats.f5.updated, stats.f5.deleted) == (0, 1, 0)

    _, deps = await _rows(session)
    changed = next(d for d in deps if d.target_ref == str(IF_WEB1))
    untouched = next(d for d in deps if d.target_ref == str(WEB2_DEV))
    assert changed.id == row_ids[str(IF_WEB1)]  # same row, updated in place
    assert changed.derived_at == NOW2
    assert any(step["ref"] == "/Common/web01:8080" for step in changed.provenance)
    assert untouched.derived_at == NOW1


# ---------------------------------------------------------------------------
# Per-source ownership + manual untouchability (ADR-0052 §3.3.1)
# ---------------------------------------------------------------------------


async def test_pass_owns_only_its_source_rows_and_never_manual(
    session: AsyncSession,
) -> None:
    crm = make_crm_app()
    manual_dep = make_crm_manual_dep()
    dns_row = ApplicationDependency(
        application_id=APP_CRM,
        target_kind=DependencyTargetKind.IP_ADDRESS,
        target_ref=str(IF_CRM),
        source=DependencySource.DNS,
        provenance=[{"kind": "dns_record", "ref": "crm.corp.example.com|a|10.0.0.40"}],
        derived_at=NOW1,
    )
    session.add_all([crm, manual_dep, dns_row])
    await session.commit()
    manual_updated_at = manual_dep.updated_at
    dns_updated_at = dns_row.updated_at

    # An f5+vmware pass with dns UNFETCHABLE (None): dns rows must survive —
    # a DDI outage never deletes persisted source-3 results (§2 intro).
    _, stats = await _derive_and_apply(session, now=NOW2, dns_records=None, **_two_member_inputs())
    assert stats.dns is None
    _, deps = await _rows(session)
    kept_manual = next(d for d in deps if str(d.source) == "manual")
    kept_dns = next(d for d in deps if str(d.source) == "dns")
    assert kept_manual.updated_at == manual_updated_at
    assert kept_manual.id == manual_dep.id
    assert kept_dns.updated_at == dns_updated_at
    assert kept_dns.derived_at == NOW1

    # A FETCHED-but-empty record set is a legitimate dns diff: rows retract.
    _, stats = await _derive_and_apply(session, now=NOW3, dns_records=[], **_two_member_inputs())
    assert stats.dns is not None
    assert stats.dns.deleted == 1
    _, deps = await _rows(session)
    assert [str(d.source) for d in deps if str(d.source) == "dns"] == []
    # The manual row is untouchable by EVERY pass.
    assert any(d.id == manual_dep.id for d in deps)


# ---------------------------------------------------------------------------
# Derived-application lifecycle (ADR-0052 §3.3.5)
# ---------------------------------------------------------------------------


async def test_derived_application_disappears_with_its_source_object(
    session: AsyncSession,
) -> None:
    await _derive_and_apply(session, now=NOW1, **_two_member_inputs())
    apps, deps = await _rows(session)
    assert len(apps) == 1 and len(deps) == 2

    # VS vanished: next pass deletes the derived application and its rows.
    _, stats = await _derive_and_apply(session, now=NOW2)
    assert stats.applications_deleted == 1
    apps, deps = await _rows(session)
    assert apps == [] and deps == []


async def test_collision_attached_manual_application_survives_source_removal(
    session: AsyncSession,
) -> None:
    manual = Application(
        id=uuid4(), name="payroll.CORP.example.com", origin=ApplicationOrigin.MANUAL
    )
    session.add(manual)
    await session.commit()

    _, stats = await _derive_and_apply(session, now=NOW1, **_two_member_inputs())
    assert stats.applications_created == 0  # attach, never duplicate (§3.3.4)
    apps, deps = await _rows(session)
    assert len(apps) == 1
    assert apps[0].origin is ApplicationOrigin.MANUAL
    assert apps[0].origin_ref is None  # no lifecycle transfer to a manual row
    assert len(deps) == 2 and all(str(d.source) == "f5" for d in deps)

    # Source object gone: only the derived edge rows retract (§3.3.5).
    _, stats = await _derive_and_apply(session, now=NOW2)
    assert stats.applications_deleted == 0
    apps, deps = await _rows(session)
    assert len(apps) == 1 and apps[0].name == "payroll.CORP.example.com"
    assert deps == []


# ---------------------------------------------------------------------------
# Manual-wins dirty tracking through the applier (ADR-0052 §3.3.3)
# ---------------------------------------------------------------------------


async def test_operator_edited_attributes_survive_while_edges_refresh(
    session: AsyncSession,
) -> None:
    await _derive_and_apply(session, now=NOW1, **_two_member_inputs())
    apps, _ = await _rows(session)
    app_id = apps[0].id

    # Operator edit (the API write path): plain attribute write + commit.
    row = (await session.execute(select(Application).where(Application.id == app_id))).scalar_one()
    row.name = "operator-owned-name"
    await session.commit()

    shrunk = {
        "virtual_servers": [make_vs("/Common/payroll.corp.example.com")],
        "pools": [make_pool([member("/Common/web01:80", "10.0.0.11", 80)])],
    }
    _, stats = await _derive_and_apply(session, now=NOW2, **shrunk)
    assert stats.f5.deleted == 1  # edges are still derivation-owned

    apps, deps = await _rows(session)
    assert apps[0].id == app_id  # origin_ref identity outlives the rename
    assert apps[0].name == "operator-owned-name"  # never clobbered
    assert len(deps) == 1


async def test_clean_derived_metadata_is_refreshed_not_frozen(
    session: AsyncSession,
) -> None:
    await _derive_and_apply(session, now=NOW1, **_two_member_inputs())

    refreshed = {
        "virtual_servers": [
            make_vs("/Common/payroll.corp.example.com", description="payroll VIP v2")
        ],
        "pools": [
            make_pool(
                [
                    member("/Common/web01:80", "10.0.0.11", 80),
                    member("/Common/web02:80", "10.0.0.20", 80),
                ]
            )
        ],
    }
    _, stats = await _derive_and_apply(session, now=NOW2, **refreshed)
    assert stats.applications_updated == 1

    apps, _ = await _rows(session)
    assert apps[0].description == "payroll VIP v2"
    assert apps[0].updated_at == apps[0].derived_watermark == NOW2  # still clean
