"""Access review report builder (P4 W3-T4; ADR-0053 §7.3).

The highest-sensitivity report: users (local + OIDC), role assignments, IdP
group→role mapping configuration (ADR-0028 §4), last login per user, dormant
accounts, and **every break-glass local login in the period** — monthly
evidence for periodic access reviews (SOC 2 CC6-series). The admin floor at
generation AND download, and the auditing of this report's own downloads, are
engine/API contracts (ADR-0053 §3) asserted in ``tests/api/test_reports.py``.

Honesty contracts this module owns:

* **Dormant/service/break-glass accounts are classified, never silently
  excluded.** Every account row carries an explicit activity classification as
  of the period end: :data:`CLASS_ACTIVE` (a login inside the configurable
  dormancy window), :data:`CLASS_DORMANT` (a login exists, but none inside the
  window), :data:`CLASS_NEVER_LOGGED_IN` (no login ever — the honest surface
  for service/bootstrap accounts, which a reviewer must see, not lose), or
  :data:`CLASS_NEW_ACCOUNT` (created inside the window with no login yet — a
  new account is not a dormant one), or :data:`CLASS_POST_PERIOD_ACCOUNT`
  (created AFTER the period end, e.g. a roster generated for a past period —
  distinct from a new account created inside the window; it is still listed,
  never excluded).
* **Login-derived columns are anchored at the period end** (reproducible
  review evidence): last login is the newest audit login event strictly before
  ``period_end``; roster/role/mapping state is generation-time state — the
  platform keeps no role-assignment history, and the report says so.
* **Break-glass completeness (ADR-0028 §5):** every
  ``auth.local.breakglass_login`` audit entry in the CLOSED-OPEN period
  appears; an empty section carries an explicit note.

Zero credential-adjacent data (ADR-0053 §6 layer 1): this module reads ONLY
explicit secret-free columns — usernames/roles/mappings/flags/timestamps from
``users``/``roles``, login events from the audit spine, and mapping config
from :class:`~app.core.config.Settings`. ``users.password_hash`` and the
``refresh_sessions`` table are never selected — enforced by the no-SELECT
deny-set runtime proof (``tests/engines/reports/test_boundary.py``) on top of
the import-linter contract.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta
from typing import Final

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, get_settings
from app.core.security import Role as RbacRole
from app.engines.reports.idempotency import coerce_utc
from app.engines.reports.payloads import ReportSection
from app.models.audit import AuditLog
from app.models.identity import Role, User

__all__ = [
    "BREAK_GLASS_ACTION",
    "BREAK_GLASS_COLUMNS",
    "CLASS_ACTIVE",
    "CLASS_DORMANT",
    "CLASS_NEVER_LOGGED_IN",
    "CLASS_NEW_ACCOUNT",
    "CLASS_POST_PERIOD_ACCOUNT",
    "IDP_MAPPING_COLUMNS",
    "LOGIN_ACTIONS",
    "NEVER_TOKEN",
    "NOTE_LOCAL_ONLY",
    "NOTE_NO_BREAK_GLASS",
    "OIDC_POSTURE_COLUMNS",
    "PROVIDER_LOCAL",
    "PROVIDER_LOCAL_BREAK_GLASS",
    "PROVIDER_LOCAL_FENCED",
    "PROVIDER_OIDC",
    "ROLE_SUMMARY_COLUMNS",
    "SECTION_BREAK_GLASS",
    "SECTION_IDP_MAPPINGS",
    "SECTION_OIDC_POSTURE",
    "SECTION_ROLE_SUMMARY",
    "SECTION_USERS",
    "USER_COLUMNS",
    "build_access_review_sections",
]

#: Successful-login audit actions (the last-login sources). Pinned locally so
#: the report engine imports no service layer; the unit suite asserts these
#: equal the canonical ``app.services.audit.service`` constants.
LOGIN_ACTIONS: Final[tuple[str, ...]] = (
    "auth.login",
    "auth.local.breakglass_login",
    "auth.oidc.login_succeeded",
)

#: The alerted, audited break-glass local-admin login (ADR-0028 §5).
BREAK_GLASS_ACTION: Final = "auth.local.breakglass_login"

SECTION_USERS: Final = "User accounts and role assignments"
SECTION_ROLE_SUMMARY: Final = "Role assignment summary"
SECTION_OIDC_POSTURE: Final = "OIDC federation posture"
SECTION_IDP_MAPPINGS: Final = "IdP group-to-role assignments"
SECTION_BREAK_GLASS: Final = "Break-glass local logins in period"

USER_COLUMNS: Final = (
    "Username",
    "Role",
    "Provider",
    "Status",
    "Created (UTC)",
    "Last login (UTC)",
    "Classification",
)
ROLE_SUMMARY_COLUMNS: Final = ("Role", "Accounts", "Enabled", "Disabled")
OIDC_POSTURE_COLUMNS: Final = ("Field", "Value")
IDP_MAPPING_COLUMNS: Final = ("IdP group", "Mapped role", "Effective role")
BREAK_GLASS_COLUMNS: Final = ("Time (UTC)", "Actor", "User id", "Request id")

#: Activity classification tokens (as of the period end; see module docstring).
CLASS_ACTIVE: Final = "active"
CLASS_DORMANT: Final = "dormant"
CLASS_NEVER_LOGGED_IN: Final = "never-logged-in (dormant)"
CLASS_NEW_ACCOUNT: Final = "never-logged-in (new account)"
CLASS_POST_PERIOD_ACCOUNT: Final = "never-logged-in (created after period end)"

#: Provider tokens. While OIDC is enabled the local-login path is fenced to
#: break-glass admin only (ADR-0028 §5) — the roster says so per account
#: instead of leaving a reviewer to derive it.
PROVIDER_LOCAL: Final = "local"
PROVIDER_OIDC: Final = "oidc"
PROVIDER_LOCAL_BREAK_GLASS: Final = "local (break-glass)"
PROVIDER_LOCAL_FENCED: Final = "local (fenced while OIDC enabled)"

#: Rendered when an account has no recorded login at or before the period end.
NEVER_TOKEN: Final = "never"

#: Placeholder for absent metadata dimensions (matches the sibling reports).
_NONE: Final = "none"

NOTE_SCOPE: Final = (
    "Roster, role assignments, and IdP group-to-role assignments reflect platform state "
    "at generation time (the platform keeps no role-assignment history); login-derived "
    "columns are anchored at the period end for reproducible review evidence."
)
NOTE_LAST_LOGIN: Final = (
    "Last login is derived from the platform's own audit login events (auth.login, "
    "auth.local.breakglass_login, auth.oidc.login_succeeded) strictly before the period "
    "end; 'never' means no such event exists for the account."
)
NOTE_BREAK_GLASS: Final = (
    "Break-glass completeness (ADR-0028 §5): every auth.local.breakglass_login audit "
    "entry in the period appears in this report — the alerted, audited local-admin "
    "recovery path; this report is its periodic review surface."
)
NOTE_NO_BREAK_GLASS: Final = "No break-glass local logins were recorded in this period."
NOTE_MINIMIZATION: Final = (
    "Data minimization (ADR-0053 §6 layer 1): this report carries account names, role "
    "assignments, mapping configuration, and timestamps only — no authentication "
    "material of any kind is readable from the report engine's allowlisted sources."
)
NOTE_LOCAL_ONLY: Final = (
    "OIDC federation is disabled: every account is local and no IdP group-to-role "
    "assignments are in force."
)
NOTE_DENY_DEFAULT_MAP: Final = (
    "OIDC is enabled with an empty group-to-role map: deny-default applies — every "
    "federated login is denied a role until a mapping is configured (ADR-0028 §4)."
)


def _dormancy_note(days: int) -> str:
    """The dormancy-honesty note, carrying the window actually in force."""
    return (
        f"Dormancy window: {days} days ending at the period end. Accounts with no "
        "recorded login inside the window classify as dormant; accounts that never "
        "logged in (including service/bootstrap accounts) carry an explicit "
        "never-logged-in classification and are never silently excluded; accounts "
        "created inside the window with no login yet classify as new accounts, not "
        "dormant; accounts created AFTER the period end (e.g. a roster generated for "
        "a past period) classify distinctly as post-period accounts, never as new "
        "accounts of this period."
    )


# ---------------------------------------------------------------------------
# Queries (allowlisted, explicit secret-free columns ONLY; re-asserted on real
# PG in tests/pg/test_access_review_pg.py)
# ---------------------------------------------------------------------------


async def _load_accounts(
    session: AsyncSession,
) -> list[tuple[uuid.UUID, str, bool, datetime, str | None, str]]:
    """Every account row: explicit columns only — never the full ``users`` row.

    Selecting the ORM entity would drag ``password_hash`` into the SQL; this
    projection keeps credential-adjacent columns structurally unqueried
    (ADR-0053 §6 layer 1 — what is never queried can never leak).
    """
    stmt = (
        select(User.id, User.username, User.is_active, User.created_at, User.idp_iss, Role.name)
        .join(Role, Role.id == User.role_id)
        .order_by(User.username, User.id)
    )
    return [tuple(row) for row in (await session.execute(stmt)).all()]


async def _last_login_by_user(session: AsyncSession, end: datetime) -> dict[str, datetime]:
    """``{user id string: newest login instant strictly before *end*}``."""
    stmt = (
        select(AuditLog.target_id, func.max(AuditLog.created_at))
        .where(
            AuditLog.action.in_(LOGIN_ACTIONS),
            AuditLog.target_type == "user",
            AuditLog.created_at < end,
        )
        .group_by(AuditLog.target_id)
    )
    return {
        target_id: coerce_utc(latest)
        for target_id, latest in (await session.execute(stmt)).all()
        if target_id is not None and latest is not None
    }


async def _role_account_counts(session: AsyncSession) -> dict[str, dict[bool, int]]:
    """``{role name: {is_active: account count}}`` — zero-account roles included."""
    stmt = (
        select(Role.name, User.is_active, func.count(User.id))
        .select_from(Role)
        .join(User, User.role_id == Role.id, isouter=True)
        .group_by(Role.name, User.is_active)
    )
    counts: dict[str, dict[bool, int]] = {}
    for name, is_active, count in (await session.execute(stmt)).all():
        bucket = counts.setdefault(name, {})
        if is_active is None:  # outer-join row for a role with no accounts
            continue
        bucket[bool(is_active)] = count
    return counts


async def _break_glass_logins(
    session: AsyncSession, start: datetime, end: datetime
) -> list[tuple[datetime, str, str | None, uuid.UUID | None]]:
    """Every break-glass login audit entry in the CLOSED-OPEN ``[start, end)``."""
    stmt = (
        select(AuditLog.created_at, AuditLog.actor, AuditLog.target_id, AuditLog.request_id)
        .where(
            AuditLog.action == BREAK_GLASS_ACTION,
            AuditLog.created_at >= start,
            AuditLog.created_at < end,
        )
        .order_by(AuditLog.created_at, AuditLog.seq.asc().nulls_last())
    )
    return [tuple(row) for row in (await session.execute(stmt)).all()]


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------


def _classify(
    last_login: datetime | None,
    created_at: datetime,
    *,
    window_start: datetime,
    period_end: datetime,
) -> str:
    """The honest activity classification for one account (module docstring).

    *period_end* distinguishes an account created strictly AFTER the
    reviewed period (e.g. a roster generated for a past period) from one
    created inside the dormancy window — both have no login yet, but only
    the latter is honestly "new" relative to THIS review period (PR #166
    F2). Neither is ever excluded from the roster (module docstring / NOTE_SCOPE).
    """
    if last_login is not None and last_login >= window_start:
        return CLASS_ACTIVE
    if last_login is not None:
        return CLASS_DORMANT
    created = coerce_utc(created_at)
    if created >= period_end:
        return CLASS_POST_PERIOD_ACCOUNT
    if created >= window_start:
        return CLASS_NEW_ACCOUNT
    return CLASS_NEVER_LOGGED_IN


def _provider(idp_iss: str | None, role_name: str, *, oidc_enabled: bool) -> str:
    """The provider label, naming the ADR-0028 §5 fence state per local account."""
    if idp_iss is not None:
        return PROVIDER_OIDC
    if not oidc_enabled:
        return PROVIDER_LOCAL
    if role_name == RbacRole.ADMIN.value:
        return PROVIDER_LOCAL_BREAK_GLASS
    return PROVIDER_LOCAL_FENCED


def _role_sort_key(name: str) -> tuple[int, int, str]:
    """RBAC roles in rank order (viewer→admin); unknown names after, sorted."""
    role = RbacRole.from_name(name)
    if role is None:
        return (1, 0, name)
    return (0, role.rank, name)


def _effective_mapped_role(role_name: str, *, allow_admin: bool) -> str:
    """The role a group mapping actually grants at login (ADR-0028 §4)."""
    role = RbacRole.from_name(role_name)
    if role is None:
        return "invalid role name (denied at login)"
    if role is RbacRole.ADMIN and not allow_admin:
        return "engineer (capped: admin via OIDC not enabled)"
    return role.value


# ---------------------------------------------------------------------------
# The builder
# ---------------------------------------------------------------------------


async def build_access_review_sections(
    session: AsyncSession,
    *,
    period_start: datetime,
    period_end: datetime,
    settings: Settings | None = None,
) -> tuple[tuple[ReportSection, ...], tuple[str, ...]]:
    """Assemble the ADR-0053 §7.3 access-review sections for one period.

    Naive period bounds are pinned as UTC (:func:`coerce_utc`) — the W3 sibling
    bug class: every boundary must interpret the same wall-clock period
    identically regardless of host timezone. Break-glass selection is
    CLOSED-OPEN over ``audit_log.created_at``; last-login/dormancy are
    anchored at the period end.

    *settings* carries the mapping config and dormancy window; ``None`` reads
    the process settings (the worker path). Tests inject a pinned instance.

    Returns the five sections (stable titles/columns — the golden fixture and
    W4-T3 assert this structure) plus the payload notes.
    """
    cfg = settings if settings is not None else get_settings()
    start = coerce_utc(period_start)
    end = coerce_utc(period_end)
    window_days = cfg.report_access_review_dormant_days
    window_start = end - timedelta(days=window_days)
    oidc_enabled = cfg.oidc_enabled

    accounts = await _load_accounts(session)
    last_login = await _last_login_by_user(session, end)

    user_rows = tuple(
        (
            username,
            role_name,
            _provider(idp_iss, role_name, oidc_enabled=oidc_enabled),
            "enabled" if is_active else "disabled",
            coerce_utc(created_at).isoformat(),
            latest.isoformat() if latest is not None else NEVER_TOKEN,
            _classify(latest, created_at, window_start=window_start, period_end=end),
        )
        for user_id, username, is_active, created_at, idp_iss, role_name in accounts
        for latest in (last_login.get(str(user_id)),)
    )

    role_counts = await _role_account_counts(session)
    role_rows = tuple(
        (
            name,
            str(role_counts[name].get(True, 0) + role_counts[name].get(False, 0)),
            str(role_counts[name].get(True, 0)),
            str(role_counts[name].get(False, 0)),
        )
        for name in sorted(role_counts, key=_role_sort_key)
    )

    posture_rows = (
        ("OIDC federation", "enabled" if oidc_enabled else "disabled (local accounts only)"),
        ("Groups claim", cfg.oidc_groups_claim),
        (
            "Admin via OIDC",
            "permitted (opt-in)" if cfg.oidc_allow_admin else "not permitted (capped at engineer)",
        ),
        (
            "Local login while OIDC enabled",
            "break-glass admin only" if oidc_enabled else "all local accounts (OIDC disabled)",
        ),
        ("Dormancy window (days)", str(window_days)),
    )

    allow_admin = cfg.oidc_allow_admin
    mapping_rows = tuple(
        (
            group,
            cfg.oidc_group_role_map[group],
            _effective_mapped_role(cfg.oidc_group_role_map[group], allow_admin=allow_admin),
        )
        for group in sorted(cfg.oidc_group_role_map)
    )

    break_glass = await _break_glass_logins(session, start, end)
    break_glass_rows = tuple(
        (
            coerce_utc(at).isoformat(),
            actor,
            target_id if target_id is not None else _NONE,
            str(request_id) if request_id is not None else _NONE,
        )
        for at, actor, target_id, request_id in break_glass
    )

    sections = (
        ReportSection(title=SECTION_USERS, columns=USER_COLUMNS, rows=user_rows),
        ReportSection(title=SECTION_ROLE_SUMMARY, columns=ROLE_SUMMARY_COLUMNS, rows=role_rows),
        ReportSection(title=SECTION_OIDC_POSTURE, columns=OIDC_POSTURE_COLUMNS, rows=posture_rows),
        ReportSection(title=SECTION_IDP_MAPPINGS, columns=IDP_MAPPING_COLUMNS, rows=mapping_rows),
        ReportSection(
            title=SECTION_BREAK_GLASS, columns=BREAK_GLASS_COLUMNS, rows=break_glass_rows
        ),
    )

    notes: list[str] = [
        NOTE_SCOPE,
        NOTE_LAST_LOGIN,
        _dormancy_note(window_days),
        NOTE_BREAK_GLASS if break_glass_rows else NOTE_NO_BREAK_GLASS,
        NOTE_MINIMIZATION,
    ]
    if not oidc_enabled:
        notes.append(NOTE_LOCAL_ONLY)
    elif not cfg.oidc_group_role_map:
        notes.append(NOTE_DENY_DEFAULT_MAP)
    return sections, tuple(notes)
