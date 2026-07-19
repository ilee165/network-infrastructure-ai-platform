"""Access review builder (P4 W3-T4; ADR-0053 §7.3) — unit suite.

The access-review report is the highest-sensitivity report (admin floor at
generation AND download, its own downloads audited — asserted in
``tests/api/test_reports.py``). This suite covers the payload builder:

* roster rows for local + OIDC accounts with role assignment, provider,
  status, creation and last-login timestamps, and an HONEST activity
  classification (active / dormant / never-logged-in / new account) — service
  and bootstrap accounts surface, never silently excluded;
* last login derived from the platform's own audit login events, anchored at
  the period end (a login after the period end does not count);
* dormancy window boundary semantics (configurable days, inclusive at the
  cutoff instant);
* break-glass completeness: every ``auth.local.breakglass_login`` audit entry
  in the CLOSED-OPEN period appears — none outside it;
* IdP group→role mapping rows with the ADR-0028 admin cap surfaced, and the
  OIDC federation posture section;
* zero credential-adjacent data: pinned headers clear the deny class, the real
  payload passes the redaction choke point, planted secrets fail closed;
* naive period inputs are pinned as UTC (the W3-T1 phantom-run-id class);
* the golden CSV/PDF structure fixture for W4-T3's conformance checks.

Every aggregation query re-asserts on real PostgreSQL in
``tests/pg/test_access_review_pg.py``.
"""

from __future__ import annotations

import csv
import io
import json
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.config import Settings
from app.engines.reports import RedactionViolationError, build_payload, render_artifacts
from app.engines.reports.access_review import (
    BREAK_GLASS_ACTION,
    BREAK_GLASS_COLUMNS,
    CLASS_ACTIVE,
    CLASS_DORMANT,
    CLASS_NEVER_LOGGED_IN,
    CLASS_NEW_ACCOUNT,
    CLASS_POST_PERIOD_ACCOUNT,
    IDP_MAPPING_COLUMNS,
    LOGIN_ACTIONS,
    NEVER_TOKEN,
    NOTE_LOCAL_ONLY,
    NOTE_NO_BREAK_GLASS,
    OIDC_POSTURE_COLUMNS,
    PROVIDER_LOCAL,
    PROVIDER_LOCAL_BREAK_GLASS,
    PROVIDER_LOCAL_FENCED,
    PROVIDER_OIDC,
    ROLE_SUMMARY_COLUMNS,
    SECTION_BREAK_GLASS,
    SECTION_IDP_MAPPINGS,
    SECTION_OIDC_POSTURE,
    SECTION_ROLE_SUMMARY,
    SECTION_USERS,
    USER_COLUMNS,
    build_access_review_sections,
)
from app.engines.reports.payloads import ReportSection
from app.engines.reports.regime_mapping import MAPPING_VERSION_TAG
from app.models import AuditLog, Base, Role, User
from app.models.reports import ReportKind

_GOLDEN = Path(__file__).resolve().parent / "golden" / "access_review_golden.json"

# Monthly period: July 2026, CLOSED-OPEN [start, end).
_PERIOD_START = datetime(2026, 7, 1, tzinfo=UTC)
_PERIOD_END = datetime(2026, 8, 1, tzinfo=UTC)
_GENERATED_AT = datetime(2026, 8, 1, 0, 5, tzinfo=UTC)
# 90-day dormancy window ending at the period end.
_WINDOW_START = datetime(2026, 5, 3, tzinfo=UTC)

_ROLE_IDS = {
    "viewer": uuid.UUID("00000000-0000-0000-0000-0000000000a1"),
    "operator": uuid.UUID("00000000-0000-0000-0000-0000000000a2"),
    "engineer": uuid.UUID("00000000-0000-0000-0000-0000000000a3"),
    "admin": uuid.UUID("00000000-0000-0000-0000-0000000000a4"),
}

_ALICE = uuid.UUID("00000000-0000-0000-0000-00000000ee01")
_BOB = uuid.UUID("00000000-0000-0000-0000-00000000ee02")
_CAROL = uuid.UUID("00000000-0000-0000-0000-00000000ee03")
_DAVE = uuid.UUID("00000000-0000-0000-0000-00000000ee04")
_EVE = uuid.UUID("00000000-0000-0000-0000-00000000ee05")
_SVC = uuid.UUID("00000000-0000-0000-0000-00000000ee06")

_ISSUER = "https://idp.example.test"
_REQUEST_ID = uuid.UUID("00000000-0000-0000-0000-00000000fe01")


# ---------------------------------------------------------------------------
# Fixtures + seed helpers
# ---------------------------------------------------------------------------


@pytest.fixture()
async def session(tmp_path: Path) -> AsyncIterator[AsyncSession]:
    """File-backed SQLite schema + one AsyncSession (T1 harness pattern)."""
    url = f"sqlite+aiosqlite:///{tmp_path / 'access_review.sqlite'}"
    engine = create_async_engine(url)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    maker = async_sessionmaker(engine, expire_on_commit=False)
    async with maker() as db_session:
        yield db_session
    await engine.dispose()


def _settings(**overrides: Any) -> Settings:
    """Pinned, deterministic settings: OIDC enabled, 90-day dormancy window."""
    defaults: dict[str, Any] = {
        "oidc_issuer": _ISSUER,
        "oidc_client_id": "netops-platform",
        # A vault credential REFERENCE handle (never a value) — required for
        # the ``oidc_enabled`` derivation, never read by the builder.
        "oidc_client_secret_ref": "vault:ref-oidc-client",
        "oidc_groups_claim": "groups",
        "oidc_group_role_map": {
            "netops-engineers": "engineer",
            "netops-admins": "admin",
        },
        "oidc_allow_admin": False,
        "report_access_review_dormant_days": 90,
    }
    defaults.update(overrides)
    return Settings(_env_file=None, **defaults)


def _roles() -> list[Role]:
    return [Role(id=role_id, name=name) for name, role_id in _ROLE_IDS.items()]


def _user(
    user_id: uuid.UUID,
    username: str,
    role: str,
    *,
    created_at: datetime,
    is_active: bool = True,
    idp_subject: str | None = None,
) -> User:
    return User(
        id=user_id,
        username=username,
        password_hash="x",  # never readable from engines/reports (layer 1)
        role_id=_ROLE_IDS[role],
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


def _scenario() -> list[Any]:
    """Deterministic mixed local/OIDC estate for July 2026 (window from 05-03).

    * alice.admin — local admin: break-glass logins 06-20 (pre-period),
      07-03, 07-15 (in period) → active; the 07-15 login is her last.
    * bob-engineer — OIDC: login 07-06 → active.
    * carol-operator — OIDC: login 04-15 (before the window) → dormant.
    * dave-new — local, created 07-20 inside the window, no login → new.
    * eve-disabled — local viewer, disabled, login 06-30 → active + disabled.
    * svc-scanner — local viewer, never logged in, older than the window →
      never-logged-in (dormant): the honest service-account surface.
    """
    return [
        *_roles(),
        _user(_ALICE, "alice.admin", "admin", created_at=datetime(2026, 1, 5, 8, tzinfo=UTC)),
        _user(
            _BOB,
            "bob-engineer",
            "engineer",
            created_at=datetime(2026, 3, 10, 12, tzinfo=UTC),
            idp_subject="bob-sub",
        ),
        _user(
            _CAROL,
            "carol-operator",
            "operator",
            created_at=datetime(2026, 1, 20, 9, 30, tzinfo=UTC),
            idp_subject="carol-sub",
        ),
        _user(_DAVE, "dave-new", "engineer", created_at=datetime(2026, 7, 20, 14, tzinfo=UTC)),
        _user(
            _EVE,
            "eve-disabled",
            "viewer",
            created_at=datetime(2026, 2, 14, 10, tzinfo=UTC),
            is_active=False,
        ),
        _user(_SVC, "svc-scanner", "viewer", created_at=datetime(2025, 12, 1, tzinfo=UTC)),
        # Login history (audit spine). alice's early login predates OIDC.
        _login("auth.login", _ALICE, datetime(2026, 2, 1, 9, tzinfo=UTC), actor="user:alice.admin"),
        _login(
            BREAK_GLASS_ACTION,
            _ALICE,
            datetime(2026, 6, 20, 7, 45, tzinfo=UTC),
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
            request_id=_REQUEST_ID,
        ),
        _login(
            "auth.oidc.login_succeeded",
            _BOB,
            datetime(2026, 7, 6, 10, 15, tzinfo=UTC),
            actor=f"oidc:{_ISSUER}#bob-sub",
        ),
        _login(
            "auth.oidc.login_succeeded",
            _CAROL,
            datetime(2026, 4, 15, 8, tzinfo=UTC),
            actor=f"oidc:{_ISSUER}#carol-sub",
        ),
        _login(
            "auth.login", _EVE, datetime(2026, 6, 30, 16, tzinfo=UTC), actor="user:eve-disabled"
        ),
        # A failed login is NOT a login: must never count toward last-login.
        _login(
            "auth.login_failed",
            _SVC,
            datetime(2026, 7, 10, 3, tzinfo=UTC),
            actor="user:svc-scanner",
        ),
    ]


async def _seed(session: AsyncSession, instances: list[Any]) -> None:
    session.add_all(instances)
    await session.commit()


def _section(sections: tuple[ReportSection, ...], title: str) -> ReportSection:
    return next(s for s in sections if s.title == title)


async def _build(
    session: AsyncSession,
    start: datetime = _PERIOD_START,
    end: datetime = _PERIOD_END,
    settings: Settings | None = None,
) -> tuple[tuple[ReportSection, ...], tuple[str, ...]]:
    return await build_access_review_sections(
        session,
        period_start=start,
        period_end=end,
        settings=settings if settings is not None else _settings(),
    )


# ---------------------------------------------------------------------------
# Section structure
# ---------------------------------------------------------------------------


async def test_sections_and_columns_are_stable(session: AsyncSession) -> None:
    """Five sections with pinned titles/columns (golden + W4-T3 ride these)."""
    await _seed(session, _scenario())
    sections, _ = await _build(session)

    assert [s.title for s in sections] == [
        SECTION_USERS,
        SECTION_ROLE_SUMMARY,
        SECTION_OIDC_POSTURE,
        SECTION_IDP_MAPPINGS,
        SECTION_BREAK_GLASS,
    ]
    assert _section(sections, SECTION_USERS).columns == USER_COLUMNS
    assert _section(sections, SECTION_ROLE_SUMMARY).columns == ROLE_SUMMARY_COLUMNS
    assert _section(sections, SECTION_OIDC_POSTURE).columns == OIDC_POSTURE_COLUMNS
    assert _section(sections, SECTION_IDP_MAPPINGS).columns == IDP_MAPPING_COLUMNS
    assert _section(sections, SECTION_BREAK_GLASS).columns == BREAK_GLASS_COLUMNS


# ---------------------------------------------------------------------------
# Roster: last login, dormancy, honest classification
# ---------------------------------------------------------------------------


async def test_roster_rows_classify_and_stamp_last_login(session: AsyncSession) -> None:
    await _seed(session, _scenario())
    sections, _ = await _build(session)

    assert _section(sections, SECTION_USERS).rows == (
        (
            "alice.admin",
            "admin",
            PROVIDER_LOCAL_BREAK_GLASS,
            "enabled",
            "2026-01-05T08:00:00+00:00",
            "2026-07-15T11:30:00+00:00",
            CLASS_ACTIVE,
        ),
        (
            "bob-engineer",
            "engineer",
            PROVIDER_OIDC,
            "enabled",
            "2026-03-10T12:00:00+00:00",
            "2026-07-06T10:15:00+00:00",
            CLASS_ACTIVE,
        ),
        (
            "carol-operator",
            "operator",
            PROVIDER_OIDC,
            "enabled",
            "2026-01-20T09:30:00+00:00",
            "2026-04-15T08:00:00+00:00",
            CLASS_DORMANT,
        ),
        (
            "dave-new",
            "engineer",
            PROVIDER_LOCAL_FENCED,
            "enabled",
            "2026-07-20T14:00:00+00:00",
            NEVER_TOKEN,
            CLASS_NEW_ACCOUNT,
        ),
        (
            "eve-disabled",
            "viewer",
            PROVIDER_LOCAL_FENCED,
            "disabled",
            "2026-02-14T10:00:00+00:00",
            "2026-06-30T16:00:00+00:00",
            CLASS_ACTIVE,
        ),
        (
            "svc-scanner",
            "viewer",
            PROVIDER_LOCAL_FENCED,
            "enabled",
            "2025-12-01T00:00:00+00:00",
            NEVER_TOKEN,
            CLASS_NEVER_LOGGED_IN,
        ),
    )


async def test_dormancy_window_boundary_is_inclusive_at_cutoff(session: AsyncSession) -> None:
    """A login exactly at ``end - window`` is active; one second earlier is not."""
    await _seed(
        session,
        [
            *_roles(),
            _user(_ALICE, "on-cutoff", "viewer", created_at=datetime(2026, 1, 1, tzinfo=UTC)),
            _user(_BOB, "just-before", "viewer", created_at=datetime(2026, 1, 1, tzinfo=UTC)),
            _login("auth.login", _ALICE, _WINDOW_START, actor="user:on-cutoff"),
            _login(
                "auth.login",
                _BOB,
                datetime(2026, 5, 2, 23, 59, 59, tzinfo=UTC),
                actor="user:just-before",
            ),
        ],
    )
    sections, _ = await _build(session)

    by_name = {row[0]: row for row in _section(sections, SECTION_USERS).rows}
    assert by_name["on-cutoff"][6] == CLASS_ACTIVE
    assert by_name["just-before"][6] == CLASS_DORMANT


async def test_login_after_period_end_does_not_count(session: AsyncSession) -> None:
    """Classification is as-of period end: a later login must not rewrite it."""
    await _seed(
        session,
        [
            *_roles(),
            _user(_ALICE, "late-login", "viewer", created_at=datetime(2026, 1, 1, tzinfo=UTC)),
            _login(
                "auth.login", _ALICE, datetime(2026, 8, 2, 9, tzinfo=UTC), actor="user:late-login"
            ),
        ],
    )
    sections, _ = await _build(session)

    row = _section(sections, SECTION_USERS).rows[0]
    assert row[5] == NEVER_TOKEN
    assert row[6] == CLASS_NEVER_LOGGED_IN


async def test_account_created_after_period_end_gets_the_honest_post_period_label(
    session: AsyncSession,
) -> None:
    """An account created AFTER the reviewed period (e.g. a roster generated
    for a past period) is NOT excluded and is NOT mislabeled as a new account
    of THIS period — it earns its own honest classification (PR #166 F2)."""
    await _seed(
        session,
        [
            *_roles(),
            _user(
                _ALICE,
                "future-onboard",
                "viewer",
                created_at=datetime(2026, 8, 15, tzinfo=UTC),  # after _PERIOD_END
            ),
        ],
    )
    sections, _ = await _build(session)

    row = _section(sections, SECTION_USERS).rows[0]
    assert row[5] == NEVER_TOKEN
    assert row[6] == CLASS_POST_PERIOD_ACCOUNT
    assert row[6] != CLASS_NEW_ACCOUNT


async def test_dormancy_window_is_configurable(session: AsyncSession) -> None:
    """A 30-day window reclassifies carol's 04-15 login-holder AND bob stays active."""
    await _seed(session, _scenario())
    sections, notes = await _build(
        session, settings=_settings(report_access_review_dormant_days=30)
    )

    by_name = {row[0]: row for row in _section(sections, SECTION_USERS).rows}
    # 30-day window starts 2026-07-02: alice (07-15) + bob (07-06) active,
    # eve's 06-30 login now falls outside the window → dormant.
    assert by_name["alice.admin"][6] == CLASS_ACTIVE
    assert by_name["bob-engineer"][6] == CLASS_ACTIVE
    assert by_name["eve-disabled"][6] == CLASS_DORMANT
    assert any("30 days" in note for note in notes)


async def test_never_logged_in_accounts_surface_never_silently_excluded(
    session: AsyncSession,
) -> None:
    """Service/bootstrap accounts are classified honestly, not dropped."""
    await _seed(session, _scenario())
    sections, notes = await _build(session)

    usernames = [row[0] for row in _section(sections, SECTION_USERS).rows]
    assert "svc-scanner" in usernames
    assert "dave-new" in usernames
    assert any("silently excluded" in note.casefold() for note in notes)


# ---------------------------------------------------------------------------
# Break-glass completeness
# ---------------------------------------------------------------------------


async def test_break_glass_rows_are_complete_and_period_bounded(session: AsyncSession) -> None:
    await _seed(session, _scenario())
    sections, notes = await _build(session)

    assert _section(sections, SECTION_BREAK_GLASS).rows == (
        ("2026-07-03T09:00:00+00:00", "user:alice.admin", str(_ALICE), "none"),
        ("2026-07-15T11:30:00+00:00", "user:alice.admin", str(_ALICE), str(_REQUEST_ID)),
    )
    assert any("breakglass_login" in note for note in notes)


async def test_break_glass_empty_period_renders_explicit_note(session: AsyncSession) -> None:
    await _seed(
        session,
        [
            *_roles(),
            _user(_ALICE, "alice.admin", "admin", created_at=datetime(2026, 1, 5, tzinfo=UTC)),
            _login(
                BREAK_GLASS_ACTION,
                _ALICE,
                datetime(2026, 6, 20, 7, 45, tzinfo=UTC),  # pre-period only
                actor="user:alice.admin",
            ),
        ],
    )
    sections, notes = await _build(session)

    assert _section(sections, SECTION_BREAK_GLASS).rows == ()
    assert NOTE_NO_BREAK_GLASS in notes


# ---------------------------------------------------------------------------
# Role summary
# ---------------------------------------------------------------------------


async def test_role_summary_counts_in_rank_order(session: AsyncSession) -> None:
    await _seed(session, _scenario())
    sections, _ = await _build(session)

    assert _section(sections, SECTION_ROLE_SUMMARY).rows == (
        ("viewer", "2", "1", "1"),
        ("operator", "1", "1", "0"),
        ("engineer", "2", "2", "0"),
        ("admin", "1", "1", "0"),
    )


async def test_role_with_no_accounts_renders_measured_zero(session: AsyncSession) -> None:
    await _seed(session, _roles())
    sections, _ = await _build(session)

    assert _section(sections, SECTION_ROLE_SUMMARY).rows == (
        ("viewer", "0", "0", "0"),
        ("operator", "0", "0", "0"),
        ("engineer", "0", "0", "0"),
        ("admin", "0", "0", "0"),
    )
    assert _section(sections, SECTION_USERS).rows == ()


# ---------------------------------------------------------------------------
# OIDC posture + IdP mapping config (ADR-0028)
# ---------------------------------------------------------------------------


async def test_idp_mappings_surface_the_admin_cap(session: AsyncSession) -> None:
    await _seed(session, _scenario())
    sections, _ = await _build(session)

    assert _section(sections, SECTION_IDP_MAPPINGS).rows == (
        ("netops-admins", "admin", "engineer (capped: admin via OIDC not enabled)"),
        ("netops-engineers", "engineer", "engineer"),
    )


async def test_idp_mapping_admin_opt_in_is_uncapped(session: AsyncSession) -> None:
    await _seed(session, _scenario())
    sections, _ = await _build(session, settings=_settings(oidc_allow_admin=True))

    rows = {
        group: effective for group, _, effective in _section(sections, SECTION_IDP_MAPPINGS).rows
    }
    assert rows["netops-admins"] == "admin"


async def test_misconfigured_mapping_surfaces_honestly(session: AsyncSession) -> None:
    """An unknown role name is a visible misconfiguration, never dropped."""
    await _seed(session, _scenario())
    sections, _ = await _build(
        session, settings=_settings(oidc_group_role_map={"grp-x": "superuser"})
    )

    assert _section(sections, SECTION_IDP_MAPPINGS).rows == (
        ("grp-x", "superuser", "invalid role name (denied at login)"),
    )


async def test_oidc_posture_section_rows(session: AsyncSession) -> None:
    await _seed(session, _scenario())
    sections, _ = await _build(session)

    rows = dict(_section(sections, SECTION_OIDC_POSTURE).rows)
    assert rows["OIDC federation"] == "enabled"
    assert rows["Groups claim"] == "groups"
    assert rows["Admin via OIDC"] == "not permitted (capped at engineer)"
    assert rows["Local login while OIDC enabled"] == "break-glass admin only"
    assert rows["Dormancy window (days)"] == "90"


async def test_oidc_disabled_estate_is_local_only(session: AsyncSession) -> None:
    """With OIDC off: providers are plain local, mappings empty, note explicit."""
    await _seed(
        session,
        [
            *_roles(),
            _user(_ALICE, "alice.admin", "admin", created_at=datetime(2026, 1, 5, tzinfo=UTC)),
            _login(
                "auth.login", _ALICE, datetime(2026, 7, 3, 9, tzinfo=UTC), actor="user:alice.admin"
            ),
        ],
    )
    local = _settings(
        oidc_issuer=None, oidc_client_id=None, oidc_client_secret_ref=None, oidc_group_role_map={}
    )
    sections, notes = await _build(session, settings=local)

    assert _section(sections, SECTION_USERS).rows[0][2] == PROVIDER_LOCAL
    assert _section(sections, SECTION_IDP_MAPPINGS).rows == ()
    posture = dict(_section(sections, SECTION_OIDC_POSTURE).rows)
    assert posture["OIDC federation"] == "disabled (local accounts only)"
    assert NOTE_LOCAL_ONLY in notes


# ---------------------------------------------------------------------------
# Naive-period regression (W3 sibling bug class)
# ---------------------------------------------------------------------------


async def test_naive_period_inputs_are_pinned_as_utc(session: AsyncSession) -> None:
    await _seed(session, _scenario())
    aware_sections, aware_notes = await _build(session)
    naive_sections, naive_notes = await _build(session, datetime(2026, 7, 1), datetime(2026, 8, 1))

    assert naive_sections == aware_sections
    assert naive_notes == aware_notes


# ---------------------------------------------------------------------------
# Engine wiring + redaction sanity
# ---------------------------------------------------------------------------


async def test_build_payload_wires_access_review_off_the_skeleton(
    session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.engines.reports import access_review

    monkeypatch.setattr(access_review, "get_settings", _settings)
    await _seed(session, _scenario())

    payload = await build_payload(
        session,
        kind=ReportKind.ACCESS_REVIEW,
        period_start=_PERIOD_START,
        period_end=_PERIOD_END,
        generated_at=_GENERATED_AT,
    )

    assert payload.kind == "access_review"
    assert payload.regime_tags == (
        "soc2:CC6.1",
        "soc2:CC6.2",
        "soc2:CC6.3",
        MAPPING_VERSION_TAG,
    )
    titles = [s.title for s in payload.sections]
    assert SECTION_USERS in titles
    assert SECTION_BREAK_GLASS in titles
    assert not any("skeleton" in note for note in payload.notes)


async def test_access_review_payload_passes_the_redaction_choke_point(
    session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The real payload renders through the SINGLE path (redaction runs first)."""
    from app.engines.reports import access_review, render

    monkeypatch.setattr(access_review, "get_settings", _settings)
    monkeypatch.setattr(render, "_render_pdf", lambda payload: b"%PDF-1.7 stub")
    await _seed(session, _scenario())
    payload = await build_payload(
        session,
        kind=ReportKind.ACCESS_REVIEW,
        period_start=_PERIOD_START,
        period_end=_PERIOD_END,
        generated_at=_GENERATED_AT,
    )

    artifacts = render_artifacts(payload)

    assert sorted(a.format.value for a in artifacts) == ["csv", "pdf"]


async def test_planted_secret_value_in_access_review_payload_fails_closed(
    session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.engines.reports import access_review

    monkeypatch.setattr(access_review, "get_settings", _settings)
    await _seed(session, _scenario())
    payload = await build_payload(
        session,
        kind=ReportKind.ACCESS_REVIEW,
        period_start=_PERIOD_START,
        period_end=_PERIOD_END,
        generated_at=_GENERATED_AT,
    )
    # Assembled at runtime so secret scanners never see a literal PEM header.
    pem_header = "-----BEGIN " + "RSA PRIVATE " + "KEY-----"
    planted = payload.model_copy(
        update={
            "sections": (
                *payload.sections,
                ReportSection(title="Planted", columns=("Value",), rows=((pem_header,),)),
            )
        }
    )

    with pytest.raises(RedactionViolationError):
        render_artifacts(planted)


async def test_planted_deny_class_column_in_access_review_payload_fails_closed(
    session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.engines.reports import access_review

    monkeypatch.setattr(access_review, "get_settings", _settings)
    await _seed(session, _scenario())
    payload = await build_payload(
        session,
        kind=ReportKind.ACCESS_REVIEW,
        period_start=_PERIOD_START,
        period_end=_PERIOD_END,
        generated_at=_GENERATED_AT,
    )
    planted = payload.model_copy(
        update={
            "sections": (
                *payload.sections,
                ReportSection(title="Planted", columns=("Password hash",), rows=()),
            )
        }
    )

    with pytest.raises(RedactionViolationError):
        render_artifacts(planted)


def test_section_headers_and_tokens_clear_the_deny_class() -> None:
    """No pinned header/token may trip the deny-class name filter (fail-closed)."""
    from app.engines.reports.redaction import DENY_FIELD_NAME_TOKENS

    for columns in (
        USER_COLUMNS,
        ROLE_SUMMARY_COLUMNS,
        OIDC_POSTURE_COLUMNS,
        IDP_MAPPING_COLUMNS,
        BREAK_GLASS_COLUMNS,
    ):
        for header in columns:
            lowered = header.casefold()
            assert not any(token in lowered for token in DENY_FIELD_NAME_TOKENS), header


# ---------------------------------------------------------------------------
# Pinned vocabularies stay in sync with their sources of truth
# ---------------------------------------------------------------------------


def test_login_action_vocabulary_matches_audit_service() -> None:
    from app.services.audit import service as audit_actions

    assert frozenset(LOGIN_ACTIONS) == frozenset(
        {
            audit_actions.AUTH_LOGIN,
            audit_actions.AUTH_LOCAL_BREAKGLASS_LOGIN,
            audit_actions.AUTH_OIDC_LOGIN_SUCCEEDED,
        }
    )
    assert BREAK_GLASS_ACTION == audit_actions.AUTH_LOCAL_BREAKGLASS_LOGIN


# ---------------------------------------------------------------------------
# Golden CSV/PDF structure fixture (W4-T3 rides this file)
# ---------------------------------------------------------------------------


async def test_golden_csv_and_pdf_structure(
    session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The deterministic scenario renders EXACTLY the committed golden structure.

    CSV: parsed rows compare exactly (deterministic payload → deterministic
    bytes). PDF: structure-stable, not byte-golden (ADR-0053 §1) — the rendered
    HTML that WeasyPrint consumes must carry every golden section title and
    column header. W4-T3's conformance checks assert against the same fixture.
    """
    from app.engines.reports import access_review, render

    monkeypatch.setattr(access_review, "get_settings", _settings)
    monkeypatch.setattr(render, "_render_pdf", lambda payload: b"%PDF-1.7 stub")
    await _seed(session, _scenario())
    payload = await build_payload(
        session,
        kind=ReportKind.ACCESS_REVIEW,
        period_start=_PERIOD_START,
        period_end=_PERIOD_END,
        generated_at=_GENERATED_AT,
    )

    golden = json.loads(_GOLDEN.read_text(encoding="utf-8"))

    artifacts = render_artifacts(payload)
    csv_artifact = next(a for a in artifacts if a.format.value == "csv")
    parsed_rows = list(csv.reader(io.StringIO(csv_artifact.content.decode("utf-8"))))
    assert parsed_rows == golden["csv_rows"]

    html_source = render._jinja_env().get_template("report_base.html").render(payload=payload)
    for section in golden["pdf_structure"]["sections"]:
        assert f"<h2>{section['title']}</h2>" in html_source
        for column in section["columns"]:
            assert f"<th>{column}</th>" in html_source
    # The golden fixture must carry zero credential-adjacent surface: only the
    # planted-secret NEGATIVE tests ever see secret-shaped strings.
    golden_text = _GOLDEN.read_text(encoding="utf-8")
    assert "BEGIN RSA" not in golden_text
    assert "password_hash" not in golden_text
