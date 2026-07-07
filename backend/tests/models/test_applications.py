"""Model tests for the application-dependency system of record (ADR-0052 §1/§3.3.3).

SQLite-level checks of the schema shape (constraints exist and bite where
SQLite supports them) plus the manual-wins dirty-tracking mechanism through a
real flush (the ``onupdate`` refresh is what an in-memory-only check would
mismodel). The authoritative PG-semantics assertions — partial-unique index,
case-insensitive unique, CHECK constraints, natural-key upsert, and BOTH
dirty-tracking directions under real PostgreSQL — live in
``tests/pg/test_applications_pg.py`` (the blocking ``pg-integration`` job).
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.applications import (
    Application,
    ApplicationDependency,
    ApplicationOrigin,
    DependencySource,
    DependencyTargetKind,
    apply_derived_attributes,
    derived_attributes_clean,
    stamp_derived_watermark,
)

DERIVED_AT = datetime(2026, 7, 6, 12, 0, tzinfo=UTC)


def _application(**overrides: object) -> Application:
    values: dict = {
        "name": "payroll",
        "origin": ApplicationOrigin.DERIVED,
        "origin_ref": "f5:dev-1:/Common/payroll",
        "fqdns": ["payroll.corp.example.com"],
    }
    values.update(overrides)
    return Application(**values)


def _dependency(application: Application, **overrides: object) -> ApplicationDependency:
    values: dict = {
        "application_id": application.id,
        "target_kind": DependencyTargetKind.DEVICE,
        "target_ref": str(uuid4()),
        "source": DependencySource.F5,
        "provenance": [{"kind": "virtual_server", "ref": "vs-1"}],
        "derived_at": DERIVED_AT,
    }
    values.update(overrides)
    return ApplicationDependency(**values)


# ---------------------------------------------------------------------------
# Schema shape (ADR-0052 §1)
# ---------------------------------------------------------------------------


async def test_application_roundtrip_defaults_and_enums(session: AsyncSession) -> None:
    app = _application(description="the payroll service", owner="platform")
    session.add(app)
    await session.commit()

    loaded = (await session.execute(select(Application))).scalar_one()
    assert loaded.name == "payroll"
    assert loaded.origin is ApplicationOrigin.DERIVED
    assert loaded.origin_ref == "f5:dev-1:/Common/payroll"
    assert loaded.fqdns == ["payroll.corp.example.com"]
    assert loaded.created_by is None
    assert loaded.derived_watermark is None
    assert loaded.created_at.tzinfo is not None


async def test_dependency_roundtrip_and_provenance_json(session: AsyncSession) -> None:
    app = _application()
    session.add(app)
    await session.flush()
    dep = _dependency(app, source=DependencySource.MANUAL, created_by=None)
    session.add(dep)
    await session.commit()

    loaded = (await session.execute(select(ApplicationDependency))).scalar_one()
    assert loaded.application_id == app.id
    assert loaded.target_kind is DependencyTargetKind.DEVICE
    assert loaded.source is DependencySource.MANUAL
    assert loaded.provenance == [{"kind": "virtual_server", "ref": "vs-1"}]
    assert loaded.derived_at == DERIVED_AT


async def test_name_uniqueness_is_case_insensitive(session: AsyncSession) -> None:
    session.add(_application(name="Payroll", origin_ref="ref-a"))
    await session.commit()
    session.add(_application(name="payroll", origin_ref="ref-b"))
    with pytest.raises(IntegrityError):
        await session.commit()
    await session.rollback()


async def test_origin_ref_unique_where_not_null_allows_many_nulls(
    session: AsyncSession,
) -> None:
    session.add(_application(name="a1", origin=ApplicationOrigin.MANUAL, origin_ref=None))
    session.add(_application(name="a2", origin=ApplicationOrigin.MANUAL, origin_ref=None))
    await session.commit()  # two NULL origin_refs coexist (partial index)

    session.add(_application(name="a3", origin_ref="dup-ref"))
    await session.commit()
    session.add(_application(name="a4", origin_ref="dup-ref"))
    with pytest.raises(IntegrityError):
        await session.commit()
    await session.rollback()


async def test_dependency_natural_key_unique_but_per_source_rows_coexist(
    session: AsyncSession,
) -> None:
    app = _application()
    session.add(app)
    await session.flush()
    target = str(uuid4())
    session.add(_dependency(app, target_ref=target, source=DependencySource.F5))
    # Same (app, kind, target) from ANOTHER source is a distinct row (§3.3.1).
    session.add(_dependency(app, target_ref=target, source=DependencySource.DNS))
    await session.commit()

    # The SAME source asserting the same pair again violates the natural key.
    session.add(_dependency(app, target_ref=target, source=DependencySource.F5))
    with pytest.raises(IntegrityError):
        await session.commit()
    await session.rollback()


async def test_deleting_application_cascades_to_dependency_rows(
    session: AsyncSession,
) -> None:
    app = _application()
    session.add(app)
    await session.flush()
    session.add(_dependency(app))
    await session.commit()

    await session.execute(delete(Application).where(Application.id == app.id))
    await session.commit()
    remaining = list((await session.execute(select(ApplicationDependency))).scalars())
    assert remaining == []


# ---------------------------------------------------------------------------
# Manual-wins dirty tracking (ADR-0052 §3.3.3) — mechanism semantics
# ---------------------------------------------------------------------------


async def test_clean_derived_row_accepts_attribute_refresh_no_freeze(
    session: AsyncSession,
) -> None:
    """Direction 2 (never freeze): while untouched by operators, every
    re-derivation may refresh the derived metadata — repeatedly."""
    app = _application()
    stamp_derived_watermark(app)
    session.add(app)
    await session.commit()

    loaded = (await session.execute(select(Application))).scalar_one()
    assert derived_attributes_clean(loaded)
    assert apply_derived_attributes(
        loaded, name="payroll-v2", description="renamed", owner=None, fqdns=["p2.example.com"]
    )
    await session.commit()

    reloaded = (await session.execute(select(Application))).scalar_one()
    assert reloaded.name == "payroll-v2"
    assert reloaded.fqdns == ["p2.example.com"]
    # Re-stamped: STILL derivation-managed, so a THIRD pass may refresh again.
    assert derived_attributes_clean(reloaded)
    assert apply_derived_attributes(
        reloaded, name="payroll-v3", description=None, owner=None, fqdns=[]
    )


async def test_operator_edit_locks_attributes_against_derivation(
    session: AsyncSession,
) -> None:
    """Direction 1 (never clobber): an operator edit refreshes ``updated_at``
    (house onupdate) without moving the watermark — derivation must then leave
    name/description/owner/fqdns alone."""
    app = _application(description="derived description")
    stamp_derived_watermark(app)
    session.add(app)
    await session.commit()

    # Operator edit: a plain attribute write + commit (the API write path).
    edited = (await session.execute(select(Application))).scalar_one()
    edited.name = "operator-name"
    await session.commit()

    locked = (await session.execute(select(Application))).scalar_one()
    assert not derived_attributes_clean(locked)
    assert not apply_derived_attributes(
        locked, name="derived-name", description="x", owner="x", fqdns=["x.example.com"]
    )
    await session.commit()

    final = (await session.execute(select(Application))).scalar_one()
    assert final.name == "operator-name"
    assert final.description == "derived description"
    assert final.fqdns == ["payroll.corp.example.com"]


def test_manual_origin_rows_are_never_attribute_refreshed() -> None:
    """§3.3.4: derivation may attach edges to a manual application it collided
    with by name, but never takes over the attributes (or the lifecycle)."""
    app = _application(origin=ApplicationOrigin.MANUAL, origin_ref=None)
    stamp_derived_watermark(app)  # even a (wrongly) stamped manual row refuses
    assert not derived_attributes_clean(app)
    assert not apply_derived_attributes(
        app, name="derived-name", description=None, owner=None, fqdns=[]
    )
    assert app.name == "payroll"


def test_unstamped_derived_row_is_not_refreshable() -> None:
    """No watermark -> conservative: never clobber on ambiguity."""
    app = _application()
    assert not derived_attributes_clean(app)
    assert not apply_derived_attributes(
        app, name="derived-name", description=None, owner=None, fqdns=[]
    )
