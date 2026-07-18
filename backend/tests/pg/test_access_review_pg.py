"""Access review report on REAL PostgreSQL (P4 W3-T4; ADR-0053 §7.3).

Last-login/dormancy/break-glass derivation is aggregation over the partitioned
``audit_log`` plus joins over ``users``/``roles`` — exactly the query class
SQLite can mismodel (P4-PLAN §0a), so every report query re-asserts here
against the migrated schema: the MAX/GROUP BY last-login aggregation with its
period-end cutoff, the dormancy window boundary, the CLOSED-OPEN break-glass
extraction, a mixed local/OIDC estate (partial-unique federated identity
rows), and the empty period. The credential-adjacent-column exclusion
(no ``password_hash``, no ``refresh_sessions``) is proven per-statement in
``tests/engines/reports/test_boundary.py``.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.engines.reports.access_review import (
    BREAK_GLASS_ACTION,
    CLASS_ACTIVE,
    CLASS_DORMANT,
    CLASS_NEVER_LOGGED_IN,
    CLASS_NEW_ACCOUNT,
    NEVER_TOKEN,
    NOTE_NO_BREAK_GLASS,
    PROVIDER_LOCAL_BREAK_GLASS,
    PROVIDER_LOCAL_FENCED,
    PROVIDER_OIDC,
    SECTION_BREAK_GLASS,
    SECTION_ROLE_SUMMARY,
    SECTION_USERS,
    build_access_review_sections,
)
from app.engines.reports.payloads import ReportSection
from app.models import AuditLog, Role, User

pytestmark = pytest.mark.integration

# Monthly period: July 2026, CLOSED-OPEN [start, end); 90-day window from 05-03.
_PERIOD_START = datetime(2026, 7, 1, tzinfo=UTC)
_PERIOD_END = datetime(2026, 8, 1, tzinfo=UTC)
_WINDOW_START = datetime(2026, 5, 3, tzinfo=UTC)

_ALICE = uuid.UUID("00000000-0000-0000-0000-00000000ee01")
_BOB = uuid.UUID("00000000-0000-0000-0000-00000000ee02")
_CAROL = uuid.UUID("00000000-0000-0000-0000-00000000ee03")
_DAVE = uuid.UUID("00000000-0000-0000-0000-00000000ee04")
_SVC = uuid.UUID("00000000-0000-0000-0000-00000000ee06")

_ISSUER = "https://idp.example.test"


def _settings() -> Settings:
    """Pinned settings: OIDC enabled, 90-day dormancy window (kwargs beat env)."""
    return Settings(
        _env_file=None,
        oidc_issuer=_ISSUER,
        oidc_client_id="netops-platform",
        oidc_client_secret_ref="vault:ref-oidc-client",  # a REFERENCE handle, never a value
        oidc_group_role_map={"netops-engineers": "engineer"},
        oidc_allow_admin=False,
        report_access_review_dormant_days=90,
    )


async def _role_ids(session: AsyncSession) -> dict[str, uuid.UUID]:
    """The migration-seeded RBAC roles (never truncated by the PG harness)."""
    rows = (await session.execute(select(Role.name, Role.id))).all()
    return {name: role_id for name, role_id in rows}


def _user(
    user_id: uuid.UUID,
    username: str,
    role_id: uuid.UUID,
    *,
    created_at: datetime,
    is_active: bool = True,
    idp_subject: str | None = None,
) -> User:
    return User(
        id=user_id,
        username=username,
        password_hash="x",  # never readable from engines/reports (layer 1)
        role_id=role_id,
        is_active=is_active,
        created_at=created_at,
        updated_at=created_at,
        idp_iss=_ISSUER if idp_subject is not None else None,
        idp_subject=idp_subject,
    )


def _login(
    action: str,
    user_id: uuid.UUID,
    at: datetime,
    *,
    actor: str,
    request_id: uuid.UUID | None = None,
) -> AuditLog:
    return AuditLog(
        actor=actor,
        action=action,
        target_type="user",
        target_id=str(user_id),
        created_at=at,
        request_id=request_id,
    )


async def _seed_estate(session: AsyncSession) -> None:
    """Mixed local/OIDC estate mirroring the unit scenario's semantics."""
    roles = await _role_ids(session)
    session.add_all(
        [
            _user(
                _ALICE, "alice.admin", roles["admin"], created_at=datetime(2026, 1, 5, tzinfo=UTC)
            ),
            _user(
                _BOB,
                "bob-engineer",
                roles["engineer"],
                created_at=datetime(2026, 3, 10, tzinfo=UTC),
                idp_subject="bob-sub",
            ),
            _user(
                _CAROL,
                "carol-operator",
                roles["operator"],
                created_at=datetime(2026, 1, 20, tzinfo=UTC),
                idp_subject="carol-sub",
            ),
            _user(
                _DAVE, "dave-new", roles["engineer"], created_at=datetime(2026, 7, 20, tzinfo=UTC)
            ),
            _user(
                _SVC, "svc-scanner", roles["viewer"], created_at=datetime(2025, 12, 1, tzinfo=UTC)
            ),
        ]
    )
    await session.commit()


def _section(sections: tuple[ReportSection, ...], title: str) -> ReportSection:
    return next(s for s in sections if s.title == title)


async def _build(
    session: AsyncSession,
) -> tuple[tuple[ReportSection, ...], tuple[str, ...]]:
    return await build_access_review_sections(
        session,
        period_start=_PERIOD_START,
        period_end=_PERIOD_END,
        settings=_settings(),
    )


async def test_last_login_aggregation_and_dormancy_on_pg(pg_session: AsyncSession) -> None:
    """MAX/GROUP BY last-login on the partitioned audit spine, cutoff at period end.

    Includes the window boundary (a login exactly at ``end - window`` is
    active), the excluded post-period login, and a failed login that must
    never count.
    """
    await _seed_estate(pg_session)
    pg_session.add_all(
        [
            # alice: multiple logins across actions — the newest pre-end wins.
            _login(
                "auth.login", _ALICE, datetime(2026, 2, 1, 9, tzinfo=UTC), actor="user:alice.admin"
            ),
            _login(
                BREAK_GLASS_ACTION,
                _ALICE,
                datetime(2026, 7, 15, 11, 30, tzinfo=UTC),
                actor="user:alice.admin",
            ),
            # alice also logs in AFTER the period — must not count.
            _login(
                "auth.login", _ALICE, datetime(2026, 8, 2, 8, tzinfo=UTC), actor="user:alice.admin"
            ),
            # bob: exactly at the window start — inclusive boundary → active.
            _login(
                "auth.oidc.login_succeeded",
                _BOB,
                _WINDOW_START,
                actor=f"oidc:{_ISSUER}#bob-sub",
            ),
            # carol: one second before the window start → dormant.
            _login(
                "auth.oidc.login_succeeded",
                _CAROL,
                datetime(2026, 5, 2, 23, 59, 59, tzinfo=UTC),
                actor=f"oidc:{_ISSUER}#carol-sub",
            ),
            # svc: a FAILED login is not a login.
            _login(
                "auth.login_failed",
                _SVC,
                datetime(2026, 7, 10, tzinfo=UTC),
                actor="user:svc-scanner",
            ),
        ]
    )
    await pg_session.commit()

    sections, _ = await _build(pg_session)

    by_name = {row[0]: row for row in _section(sections, SECTION_USERS).rows}
    assert by_name["alice.admin"][5] == "2026-07-15T11:30:00+00:00"
    assert by_name["alice.admin"][6] == CLASS_ACTIVE
    assert by_name["bob-engineer"][5] == _WINDOW_START.isoformat()
    assert by_name["bob-engineer"][6] == CLASS_ACTIVE
    assert by_name["carol-operator"][6] == CLASS_DORMANT
    assert by_name["dave-new"][5] == NEVER_TOKEN
    assert by_name["dave-new"][6] == CLASS_NEW_ACCOUNT
    assert by_name["svc-scanner"][5] == NEVER_TOKEN
    assert by_name["svc-scanner"][6] == CLASS_NEVER_LOGGED_IN


async def test_break_glass_extraction_is_period_bounded_on_pg(pg_session: AsyncSession) -> None:
    """CLOSED-OPEN period selection over the partitioned audit table."""
    await _seed_estate(pg_session)
    request_id = uuid.UUID("00000000-0000-0000-0000-00000000fe01")
    pg_session.add_all(
        [
            _login(
                BREAK_GLASS_ACTION,
                _ALICE,
                datetime(2026, 6, 20, 7, 45, tzinfo=UTC),  # pre-period: excluded
                actor="user:alice.admin",
            ),
            _login(
                BREAK_GLASS_ACTION,
                _ALICE,
                datetime(2026, 7, 3, 9, tzinfo=UTC),
                actor="user:alice.admin",
            ),
            _login(
                BREAK_GLASS_ACTION,
                _ALICE,
                datetime(2026, 7, 15, 11, 30, tzinfo=UTC),
                actor="user:alice.admin",
                request_id=request_id,
            ),
            _login(
                BREAK_GLASS_ACTION,
                _ALICE,
                _PERIOD_END,  # exactly at end: excluded (closed-open)
                actor="user:alice.admin",
            ),
        ]
    )
    await pg_session.commit()

    sections, notes = await _build(pg_session)

    assert _section(sections, SECTION_BREAK_GLASS).rows == (
        ("2026-07-03T09:00:00+00:00", "user:alice.admin", str(_ALICE), "none"),
        ("2026-07-15T11:30:00+00:00", "user:alice.admin", str(_ALICE), str(request_id)),
    )
    assert NOTE_NO_BREAK_GLASS not in notes


async def test_mixed_local_oidc_estate_labels_on_pg(pg_session: AsyncSession) -> None:
    """Provider labels + the roles join + the rank-ordered role summary on PG."""
    await _seed_estate(pg_session)

    sections, _ = await _build(pg_session)

    by_name = {row[0]: row for row in _section(sections, SECTION_USERS).rows}
    assert by_name["alice.admin"][2] == PROVIDER_LOCAL_BREAK_GLASS
    assert by_name["bob-engineer"][2] == PROVIDER_OIDC
    assert by_name["carol-operator"][2] == PROVIDER_OIDC
    assert by_name["dave-new"][2] == PROVIDER_LOCAL_FENCED
    assert by_name["svc-scanner"][2] == PROVIDER_LOCAL_FENCED
    # Rank order over the migration-seeded roles; counts are measured.
    assert _section(sections, SECTION_ROLE_SUMMARY).rows == (
        ("viewer", "1", "1", "0"),
        ("operator", "1", "1", "0"),
        ("engineer", "2", "2", "0"),
        ("admin", "1", "1", "0"),
    )


async def test_empty_period_renders_honest_roster_on_pg(pg_session: AsyncSession) -> None:
    """No logins at all: every account classifies honestly; break-glass is empty."""
    await _seed_estate(pg_session)

    sections, notes = await _build(pg_session)

    rows = _section(sections, SECTION_USERS).rows
    assert len(rows) == 5  # nobody is silently excluded
    assert {row[5] for row in rows} == {NEVER_TOKEN}
    assert _section(sections, SECTION_BREAK_GLASS).rows == ()
    assert NOTE_NO_BREAK_GLASS in notes


async def test_zero_user_estate_keeps_seeded_roles_visible_on_pg(
    pg_session: AsyncSession,
) -> None:
    """With users truncated, the migration-seeded roles still render zeros."""
    sections, _ = await _build(pg_session)

    assert _section(sections, SECTION_USERS).rows == ()
    summary = {row[0]: row[1:] for row in _section(sections, SECTION_ROLE_SUMMARY).rows}
    for name in ("viewer", "operator", "engineer", "admin"):
        assert summary[name] == ("0", "0", "0")
