"""POST /api/v1/auth/login and /auth/refresh: tokens, cookies, audit, failures."""

from __future__ import annotations

from collections.abc import Callable

import httpx
import jwt
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.models import AuditLog, User
from tests.api.conftest import TEST_PASSWORD

LOGIN_URL = "/api/v1/auth/login"
REFRESH_URL = "/api/v1/auth/refresh"
REFRESH_COOKIE = "netops_refresh"
REFRESH_LIFETIME_SECONDS = 8 * 3600


def _decode(token: str, settings: Settings) -> dict:
    return jwt.decode(token, settings.secret_key, algorithms=["HS256"])


async def _login(client: httpx.AsyncClient, username: str, password: str) -> httpx.Response:
    return await client.post(LOGIN_URL, json={"username": username, "password": password})


# ---------------------------------------------------------------------------
# Login: success path
# ---------------------------------------------------------------------------


async def test_login_returns_bearer_access_token_with_roles_claim(
    client: httpx.AsyncClient, users: dict[str, User], settings: Settings
) -> None:
    resp = await _login(client, "engineer_user", TEST_PASSWORD)

    assert resp.status_code == 200
    body = resp.json()
    assert body["token_type"] == "bearer"
    claims = _decode(body["access_token"], settings)
    assert claims["sub"] == str(users["engineer"].id)
    assert claims["roles"] == ["engineer"]
    assert claims["type"] == "access"


async def test_login_sets_httponly_secure_strict_refresh_cookie(
    client: httpx.AsyncClient, users: dict[str, User], settings: Settings
) -> None:
    resp = await _login(client, "viewer_user", TEST_PASSWORD)

    assert resp.status_code == 200
    set_cookie = resp.headers["set-cookie"].lower()
    assert "httponly" in set_cookie
    assert "secure" in set_cookie
    assert "samesite=strict" in set_cookie
    assert "path=/api/v1/auth" in set_cookie
    assert f"max-age={REFRESH_LIFETIME_SECONDS}" in set_cookie

    refresh_token = resp.cookies[REFRESH_COOKIE]
    claims = _decode(refresh_token, settings)
    assert claims["type"] == "refresh"
    assert claims["sub"] == str(users["viewer"].id)
    assert claims["exp"] - claims["iat"] == REFRESH_LIFETIME_SECONDS


async def test_login_response_contains_no_password_material(
    client: httpx.AsyncClient, users: dict[str, User], password_hash: str
) -> None:
    resp = await _login(client, "admin_user", TEST_PASSWORD)

    assert resp.status_code == 200
    assert TEST_PASSWORD not in resp.text
    assert password_hash not in resp.text
    assert "password" not in resp.text.lower()


async def test_login_writes_audit_row(
    client: httpx.AsyncClient, users: dict[str, User], session: AsyncSession
) -> None:
    resp = await _login(client, "operator_user", TEST_PASSWORD)

    assert resp.status_code == 200
    rows = (
        (await session.execute(select(AuditLog).where(AuditLog.action == "auth.login")))
        .scalars()
        .all()
    )
    assert len(rows) == 1
    assert rows[0].actor == "user:operator_user"
    assert rows[0].target_type == "user"
    assert rows[0].target_id == str(users["operator"].id)


# ---------------------------------------------------------------------------
# Login: failure paths (401, no cookie, no audit row)
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
async def test_login_failures_return_401_problem_without_cookie(
    client: httpx.AsyncClient,
    users: dict[str, User],
    session: AsyncSession,
    username: str,
    password: str,
) -> None:
    resp = await _login(client, username, password)

    assert resp.status_code == 401
    assert resp.headers["content-type"] == "application/problem+json"
    assert resp.json()["type"] == "urn:netops:error:unauthorized"
    assert resp.headers.get("set-cookie") is None
    assert "access_token" not in resp.text

    rows = (await session.execute(select(AuditLog))).scalars().all()
    assert rows == []


# ---------------------------------------------------------------------------
# Refresh: rotation
# ---------------------------------------------------------------------------


async def test_refresh_rotates_access_token_and_refresh_cookie(
    client: httpx.AsyncClient, users: dict[str, User], settings: Settings
) -> None:
    login_resp = await _login(client, "engineer_user", TEST_PASSWORD)
    first_refresh_cookie = login_resp.cookies[REFRESH_COOKIE]

    refresh_resp = await client.post(REFRESH_URL)

    assert refresh_resp.status_code == 200
    body = refresh_resp.json()
    assert body["token_type"] == "bearer"
    new_access_claims = _decode(body["access_token"], settings)
    assert new_access_claims["sub"] == str(users["engineer"].id)
    assert new_access_claims["roles"] == ["engineer"]
    assert new_access_claims["type"] == "access"

    rotated_cookie = refresh_resp.cookies[REFRESH_COOKIE]
    assert rotated_cookie != first_refresh_cookie
    rotated_claims = _decode(rotated_cookie, settings)
    assert rotated_claims["type"] == "refresh"
    set_cookie = refresh_resp.headers["set-cookie"].lower()
    assert "httponly" in set_cookie
    assert "secure" in set_cookie
    assert "samesite=strict" in set_cookie

    # The rotated cookie is itself usable for a further refresh.
    second_refresh = await client.post(REFRESH_URL)
    assert second_refresh.status_code == 200


async def test_refresh_writes_audit_row(
    client: httpx.AsyncClient, users: dict[str, User], session: AsyncSession
) -> None:
    await _login(client, "viewer_user", TEST_PASSWORD)

    resp = await client.post(REFRESH_URL)

    assert resp.status_code == 200
    rows = (
        (await session.execute(select(AuditLog).where(AuditLog.action == "auth.refresh")))
        .scalars()
        .all()
    )
    assert len(rows) == 1
    assert rows[0].actor == "user:viewer_user"
    assert rows[0].target_id == str(users["viewer"].id)


# ---------------------------------------------------------------------------
# Refresh: failure paths
# ---------------------------------------------------------------------------


async def test_refresh_without_cookie_returns_401(
    client: httpx.AsyncClient, users: dict[str, User]
) -> None:
    resp = await client.post(REFRESH_URL)

    assert resp.status_code == 401
    assert resp.json()["type"] == "urn:netops:error:unauthorized"


async def test_refresh_with_garbage_cookie_returns_401(
    client: httpx.AsyncClient, users: dict[str, User]
) -> None:
    client.cookies.set(REFRESH_COOKIE, "not-a-jwt", domain="testserver", path="/api/v1/auth")

    resp = await client.post(REFRESH_URL)

    assert resp.status_code == 401


async def test_refresh_rejects_access_token_in_cookie(
    client: httpx.AsyncClient, users: dict[str, User], make_token: Callable[..., str]
) -> None:
    """A (valid) ACCESS token must not be accepted as a refresh token."""
    access_token = make_token(users["admin"], token_type="access")
    client.cookies.set(REFRESH_COOKIE, access_token, domain="testserver", path="/api/v1/auth")

    resp = await client.post(REFRESH_URL)

    assert resp.status_code == 401


async def test_refresh_for_deactivated_user_returns_401(
    client: httpx.AsyncClient, users: dict[str, User], session: AsyncSession
) -> None:
    await _login(client, "operator_user", TEST_PASSWORD)
    users["operator"].is_active = False
    await session.commit()

    resp = await client.post(REFRESH_URL)

    assert resp.status_code == 401
