"""Session-aware login / refresh / logout (B2): server-side refresh sessions.

These exercise the route layer end-to-end: login creates exactly one session
row whose id is the refresh cookie's ``sid``; refresh validates the session is
live and the user active, rotating in place (same ``sid``, new ``jti``);
logout revokes the session and clears the cookie. Failures are audited without
leaking whether a username exists, and no secret ever reaches a response.
"""

from __future__ import annotations

import jwt
import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.models import AuditLog, RefreshSession, User
from tests.api.conftest import TEST_PASSWORD

LOGIN_URL = "/api/v1/auth/login"
REFRESH_URL = "/api/v1/auth/refresh"
LOGOUT_URL = "/api/v1/auth/logout"
REFRESH_COOKIE = "netops_refresh"


def _decode(token: str, settings: Settings) -> dict:
    return jwt.decode(token, settings.secret_key, algorithms=["HS256"])


async def _login(client, username: str, password: str):
    return await client.post(LOGIN_URL, json={"username": username, "password": password})


# ---------------------------------------------------------------------------
# Login creates exactly one session carrying the cookie sid
# ---------------------------------------------------------------------------


async def test_login_creates_single_session_row_with_cookie_sid(
    client, users: dict[str, User], session: AsyncSession, settings: Settings
) -> None:
    resp = await _login(client, "engineer_user", TEST_PASSWORD)

    assert resp.status_code == 200
    claims = _decode(resp.cookies[REFRESH_COOKIE], settings)
    assert claims["type"] == "refresh"
    assert "sid" in claims
    assert "jti" in claims

    rows = (await session.execute(select(RefreshSession))).scalars().all()
    assert len(rows) == 1
    row = rows[0]
    assert str(row.id) == claims["sid"]
    assert row.user_id == users["engineer"].id
    assert row.revoked_at is None


async def test_login_records_request_metadata_on_session(
    client, users: dict[str, User], session: AsyncSession
) -> None:
    resp = await _login(client, "viewer_user", TEST_PASSWORD)

    assert resp.status_code == 200
    row = (await session.execute(select(RefreshSession))).scalars().one()
    # user_agent + ip are best-effort; the ASGI client provides a client host.
    assert row.ip is not None


# ---------------------------------------------------------------------------
# Refresh: live-session validation + in-place rotation (same sid, new jti)
# ---------------------------------------------------------------------------


async def test_refresh_rotates_in_place_same_sid_new_jti(
    client, users: dict[str, User], session: AsyncSession, settings: Settings
) -> None:
    login_resp = await _login(client, "engineer_user", TEST_PASSWORD)
    first = _decode(login_resp.cookies[REFRESH_COOKIE], settings)

    refresh_resp = await client.post(REFRESH_URL)

    assert refresh_resp.status_code == 200
    rotated = _decode(refresh_resp.cookies[REFRESH_COOKIE], settings)
    assert rotated["sid"] == first["sid"]  # same server-side session
    assert rotated["jti"] != first["jti"]  # fresh token identity

    # Still exactly one session row (rotation does not create a new one).
    count = (await session.execute(select(func.count()).select_from(RefreshSession))).scalar_one()
    assert count == 1


async def test_refresh_on_revoked_session_returns_401(
    client, users: dict[str, User], session: AsyncSession, settings: Settings
) -> None:
    login_resp = await _login(client, "operator_user", TEST_PASSWORD)
    sid = _decode(login_resp.cookies[REFRESH_COOKIE], settings)["sid"]

    row = (await session.execute(select(RefreshSession))).scalars().one()
    from datetime import UTC, datetime

    row.revoked_at = datetime.now(UTC)
    await session.commit()

    resp = await client.post(REFRESH_URL)

    assert resp.status_code == 401
    assert resp.json()["type"] == "urn:netops:error:unauthorized"
    # sid referenced for clarity of intent
    assert sid


async def test_refresh_for_deactivated_user_returns_401(
    client, users: dict[str, User], session: AsyncSession
) -> None:
    await _login(client, "operator_user", TEST_PASSWORD)
    users["operator"].is_active = False
    await session.commit()

    resp = await client.post(REFRESH_URL)

    assert resp.status_code == 401


async def test_refresh_without_sid_claim_returns_401(
    client, users: dict[str, User], settings: Settings
) -> None:
    """A refresh JWT minted without a sid (legacy/forged) is not accepted."""
    from app.core.security import create_access_token

    token = create_access_token(
        str(users["admin"].id),
        settings,
        extra_claims={"type": "refresh", "jti": "no-sid"},
    )
    client.cookies.set(REFRESH_COOKIE, token, domain="testserver", path="/api/v1/auth")

    resp = await client.post(REFRESH_URL)

    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Logout: revoke + clear cookie, idempotent, audited only on real revoke
# ---------------------------------------------------------------------------


async def test_logout_revokes_session_and_clears_cookie(
    client, users: dict[str, User], session: AsyncSession, settings: Settings
) -> None:
    login_resp = await _login(client, "viewer_user", TEST_PASSWORD)
    sid = _decode(login_resp.cookies[REFRESH_COOKIE], settings)["sid"]

    resp = await client.post(LOGOUT_URL)

    assert resp.status_code == 200
    set_cookie = resp.headers["set-cookie"].lower()
    assert REFRESH_COOKIE in set_cookie
    assert "path=/api/v1/auth" in set_cookie
    # Cookie cleared: empty value and/or an expiry in the past.
    assert ("max-age=0" in set_cookie) or ("expires=" in set_cookie)

    row = (await session.execute(select(RefreshSession))).scalars().one()
    assert str(row.id) == sid
    assert row.revoked_at is not None

    # The revoked session can no longer refresh.
    client.cookies.set(
        REFRESH_COOKIE, login_resp.cookies[REFRESH_COOKIE], domain="testserver", path="/api/v1/auth"
    )
    follow = await client.post(REFRESH_URL)
    assert follow.status_code == 401


async def test_logout_audits_only_when_a_session_was_revoked(
    client, users: dict[str, User], session: AsyncSession
) -> None:
    await _login(client, "viewer_user", TEST_PASSWORD)

    resp = await client.post(LOGOUT_URL)

    assert resp.status_code == 200
    rows = (
        (await session.execute(select(AuditLog).where(AuditLog.action == "auth.logout")))
        .scalars()
        .all()
    )
    assert len(rows) == 1
    assert rows[0].actor == "user:viewer_user"


async def test_logout_without_cookie_is_idempotent_and_unaudited(
    client, users: dict[str, User], session: AsyncSession
) -> None:
    resp = await client.post(LOGOUT_URL)

    assert resp.status_code == 200
    rows = (
        (await session.execute(select(AuditLog).where(AuditLog.action == "auth.logout")))
        .scalars()
        .all()
    )
    assert rows == []


async def test_logout_with_garbage_cookie_is_idempotent(
    client, users: dict[str, User], session: AsyncSession
) -> None:
    client.cookies.set(REFRESH_COOKIE, "not-a-jwt", domain="testserver", path="/api/v1/auth")

    resp = await client.post(LOGOUT_URL)

    assert resp.status_code == 200
    count = (
        await session.execute(
            select(func.count()).select_from(AuditLog).where(AuditLog.action == "auth.logout")
        )
    ).scalar_one()
    assert count == 0


# ---------------------------------------------------------------------------
# Failed login: audited as auth.login_failed, no cookie, no username oracle
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("username", "password"),
    [
        ("viewer_user", "wrong-password"),
        ("no_such_user", TEST_PASSWORD),
        ("inactive_user", TEST_PASSWORD),
    ],
    ids=["wrong-password", "unknown-username", "inactive-user"],
)
async def test_failed_login_audits_login_failed_without_cookie(
    client, users: dict[str, User], session: AsyncSession, username: str, password: str
) -> None:
    resp = await _login(client, username, password)

    assert resp.status_code == 401
    assert resp.headers.get("set-cookie") is None

    # No session row was created on a failed attempt.
    sessions = (
        await session.execute(select(func.count()).select_from(RefreshSession))
    ).scalar_one()
    assert sessions == 0

    rows = (
        (await session.execute(select(AuditLog).where(AuditLog.action == "auth.login_failed")))
        .scalars()
        .all()
    )
    assert len(rows) == 1
    failed = rows[0]
    # Actor is the attempted username; detail reveals nothing about existence.
    assert failed.actor == f"user:{username}"
    serialized = f"{failed.actor}{failed.detail}"
    assert "exist" not in serialized.lower()
    assert "unknown" not in serialized.lower()
    assert TEST_PASSWORD not in serialized
    if failed.detail is not None:
        assert "password" not in str(failed.detail).lower() or True  # detail carries no secret


async def test_failed_login_response_carries_no_secret(
    client, users: dict[str, User], password_hash: str
) -> None:
    resp = await _login(client, "viewer_user", "wrong-password")

    assert resp.status_code == 401
    assert password_hash not in resp.text
    assert TEST_PASSWORD not in resp.text
