"""Real-PostgreSQL assertions for the application-dependency tables (W2-T1).

ADR-0052 §1/§3.3.3/§4 semantics that SQLite mismodels or that must be proven
on the production backend (P4-PLAN §0a "SQLite hides PG semantics"):

- the case-insensitive unique ``lower(name)`` expression index,
- the partial-unique ``origin_ref WHERE origin_ref IS NOT NULL`` index,
- the ``origin``/``source``/``target_kind`` CHECK constraints (String-plus-
  CHECK enum discipline — asserted with raw SQL so the app-layer StrEnum
  validation cannot mask a missing DB constraint),
- the natural-key unique ``(application_id, target_kind, target_ref, source)``
  (what idempotent re-derivation diff-upserts against),
- ``ON DELETE CASCADE`` from ``applications`` to its dependency rows, and
- the §3.3.3 manual-wins dirty-tracking invariant in BOTH directions —
  derivation refresh never clobbers operator-edited attributes, and derived
  metadata never freezes while the row is untouched — through real flushes
  (the ``onupdate`` + timestamptz round-trip is exactly what an in-memory
  check would mismodel).

The schema comes from the REAL ``alembic upgrade head`` (conftest), so these
tests also prove migration 0018 produces the constraints it claims.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from sqlalchemy import delete, select, text
from sqlalchemy.exc import DBAPIError, IntegrityError
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
        "name": f"app-{uuid4().hex[:12]}",
        "origin": ApplicationOrigin.DERIVED,
        "origin_ref": f"f5:test:{uuid4().hex[:12]}",
        "fqdns": ["svc.corp.example.com"],
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
# Unique / partial-unique / CHECK semantics (ADR-0052 §1, §4)
# ---------------------------------------------------------------------------


async def test_lower_name_unique_index_bites_case_insensitively(
    pg_session: AsyncSession,
) -> None:
    pg_session.add(_application(name="Payroll"))
    await pg_session.commit()
    pg_session.add(_application(name="payroll"))
    with pytest.raises(IntegrityError):
        await pg_session.commit()
    await pg_session.rollback()


async def test_origin_ref_partial_unique_allows_nulls_blocks_duplicates(
    pg_session: AsyncSession,
) -> None:
    # Many manual rows without an origin_ref coexist (partial index scope).
    pg_session.add(_application(origin=ApplicationOrigin.MANUAL, origin_ref=None))
    pg_session.add(_application(origin=ApplicationOrigin.MANUAL, origin_ref=None))
    await pg_session.commit()

    pg_session.add(_application(origin_ref="f5:dev-1:/Common/dup"))
    await pg_session.commit()
    pg_session.add(_application(origin_ref="f5:dev-1:/Common/dup"))
    with pytest.raises(IntegrityError):
        await pg_session.commit()
    await pg_session.rollback()


async def test_check_constraints_reject_invalid_values_at_the_db_layer(
    pg_session: AsyncSession,
) -> None:
    """Raw SQL bypasses the app-layer StrEnum validation, so a pass here proves
    the DATABASE constraint exists (String-plus-CHECK, ADR-0052 §1)."""
    bad_origin = text(
        "INSERT INTO applications (id, name, fqdns, origin, created_at, updated_at) "
        "VALUES (:id, :name, '[]', 'bogus', now(), now())"
    )
    with pytest.raises((IntegrityError, DBAPIError)):
        await pg_session.execute(bad_origin, {"id": uuid4(), "name": f"x-{uuid4().hex[:8]}"})
    await pg_session.rollback()

    app = _application()
    pg_session.add(app)
    await pg_session.commit()
    app_id = app.id  # scalar snapshot: rollbacks below expire the instance
    for column, value in (("target_kind", "subnet"), ("source", "netflow")):
        bad_dep = text(
            "INSERT INTO application_dependencies "
            "(id, application_id, target_kind, target_ref, source, provenance, derived_at, "
            " created_at, updated_at) "
            "VALUES (:id, :app_id, :target_kind, :target_ref, :source, '[]', now(), "
            "now(), now())"
        )
        params = {
            "id": uuid4(),
            "app_id": app_id,
            "target_kind": "device",
            "target_ref": str(uuid4()),
            "source": "f5",
        }
        params[column] = value
        with pytest.raises((IntegrityError, DBAPIError)):
            await pg_session.execute(bad_dep, params)
        await pg_session.rollback()


async def test_natural_key_unique_but_per_source_rows_coexist(
    pg_session: AsyncSession,
) -> None:
    """The §4 idempotency key: the SAME source re-asserting a pair violates;
    ANOTHER source asserting the same pair is a distinct row (§3.3.1)."""
    app = _application()
    pg_session.add(app)
    await pg_session.flush()
    target = str(uuid4())
    pg_session.add(_dependency(app, target_ref=target, source=DependencySource.F5))
    pg_session.add(_dependency(app, target_ref=target, source=DependencySource.DNS))
    pg_session.add(_dependency(app, target_ref=target, source=DependencySource.MANUAL))
    await pg_session.commit()

    pg_session.add(_dependency(app, target_ref=target, source=DependencySource.F5))
    with pytest.raises(IntegrityError):
        await pg_session.commit()
    await pg_session.rollback()


async def test_deleting_application_cascades_to_dependency_rows(
    pg_session: AsyncSession,
) -> None:
    app = _application()
    pg_session.add(app)
    await pg_session.flush()
    pg_session.add(_dependency(app))
    pg_session.add(_dependency(app, source=DependencySource.DNS))
    await pg_session.commit()

    await pg_session.execute(delete(Application).where(Application.id == app.id))
    await pg_session.commit()
    remaining = list(
        (
            await pg_session.execute(
                select(ApplicationDependency).where(ApplicationDependency.application_id == app.id)
            )
        ).scalars()
    )
    assert remaining == []


# ---------------------------------------------------------------------------
# Manual-wins dirty tracking (ADR-0052 §3.3.3) — BOTH directions on real PG
# ---------------------------------------------------------------------------


async def test_dirty_tracking_direction_1_operator_edit_is_never_clobbered(
    pg_session: AsyncSession,
) -> None:
    """Operator edits name → onupdate moves ``updated_at`` off the watermark →
    every later derivation refresh refuses; the operator's values survive."""
    app = _application(description="derived description", owner="derived-owner")
    stamp_derived_watermark(app)
    pg_session.add(app)
    await pg_session.commit()
    app_id = app.id

    # Operator edit (the API write path): plain attribute write + commit.
    edited = (
        await pg_session.execute(select(Application).where(Application.id == app_id))
    ).scalar_one()
    edited.name = "operator-chosen-name"
    edited.fqdns = ["operator.example.com"]
    await pg_session.commit()

    locked = (
        await pg_session.execute(select(Application).where(Application.id == app_id))
    ).scalar_one()
    assert not derived_attributes_clean(locked)
    assert not apply_derived_attributes(
        locked,
        name="derivation-name",
        description="derivation description",
        owner="derivation-owner",
        fqdns=["derivation.example.com"],
    )
    await pg_session.commit()

    final = (
        await pg_session.execute(select(Application).where(Application.id == app_id))
    ).scalar_one()
    assert final.name == "operator-chosen-name"
    assert final.fqdns == ["operator.example.com"]
    assert final.description == "derived description"
    assert final.owner == "derived-owner"
    # A second derivation attempt refuses too — the lock is permanent.
    assert not apply_derived_attributes(
        final, name="derivation-name-2", description=None, owner=None, fqdns=[]
    )


async def test_dirty_tracking_direction_2_derived_metadata_never_freezes(
    pg_session: AsyncSession,
) -> None:
    """While no operator has touched the row, EVERY re-derivation may refresh
    the attributes — the watermark re-stamps on each write, so the timestamptz
    round-trip must keep ``updated_at == derived_watermark`` exactly."""
    app = _application(description="v1")
    stamp_derived_watermark(app)
    pg_session.add(app)
    await pg_session.commit()
    app_id = app.id

    for version in ("v2", "v3"):
        row = (
            await pg_session.execute(select(Application).where(Application.id == app_id))
        ).scalar_one()
        assert derived_attributes_clean(row), f"row froze before applying {version}"
        assert apply_derived_attributes(
            row,
            name=row.name,
            description=version,
            owner="derived-owner",
            fqdns=[f"{version}.example.com"],
        )
        await pg_session.commit()

    final = (
        await pg_session.execute(select(Application).where(Application.id == app_id))
    ).scalar_one()
    assert final.description == "v3"
    assert final.fqdns == ["v3.example.com"]
    assert derived_attributes_clean(final)  # still derivation-managed


async def test_dirty_tracking_manual_origin_rows_refuse_attribute_transfer(
    pg_session: AsyncSession,
) -> None:
    """§3.3.4: a manual application a derivation collided with by name keeps
    user-owned attributes even when (wrongly) stamped."""
    app = _application(origin=ApplicationOrigin.MANUAL, origin_ref=None, name="user-app")
    stamp_derived_watermark(app)
    pg_session.add(app)
    await pg_session.commit()

    loaded = (
        await pg_session.execute(select(Application).where(Application.id == app.id))
    ).scalar_one()
    assert not derived_attributes_clean(loaded)
    assert not apply_derived_attributes(
        loaded, name="derived-name", description=None, owner=None, fqdns=[]
    )
    assert loaded.name == "user-app"
