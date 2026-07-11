"""Account / profile endpoints + forced-password-change guard (B3).

These exercise the self-service account surface under ``/api/v1/auth``:
``GET/PATCH /me``, ``POST /me/password``, ``GET /sessions``,
``DELETE /sessions/{sid}``, ``POST /sessions/revoke-all`` — plus the
``get_active_user`` dependency that blocks the app while
``must_change_password`` is set. Invariants under test: the ``/me`` shape never
carries ``password_hash``; PATCH rejects an email already owned by another user
(409); a password change verifies the current password, clears the flag, and
revokes every *other* live session while keeping the caller's; session
list/revoke enforce per-user ownership; and the forced-change guard raises for
a flagged user but passes everyone else.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Annotated

import pytest
from fastapi import Depends, FastAPI
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api import deps
from app.core.errors import ForbiddenError
from app.core.security import hash_password, verify_password
from app.models import AuditLog, RefreshSession, User
from tests.api.conftest import TEST_PASSWORD

ME_URL = "/api/v1/auth/me"
PASSWORD_URL = "/api/v1/auth/me/password"
SESSIONS_URL = "/api/v1/auth/sessions"
REVOKE_ALL_URL = "/api/v1/auth/sessions/revoke-all"
LOGIN_URL = "/api/v1/auth/login"
REFRESH_COOKIE = "netops_refresh"


async def _login(client, username: str, password: str = TEST_PASSWORD):
    return await client.post(LOGIN_URL, json={"username": username, "password": password})


async def _make_session(
    session: AsyncSession, user: User, *, ua: str | None = "agent", ip: str | None = "10.0.0.1"
) -> RefreshSession:
    row = RefreshSession(user_id=user.id, user_agent=ua, ip=ip)
    session.add(row)
    await session.flush()
    return row


# ---------------------------------------------------------------------------
# GET /me — UserMe shape, no secret material
# ---------------------------------------------------------------------------


async def test_me_returns_user_shape_without_password_hash(
    client, users: dict[str, User], auth_headers: Callable[[str], dict[str, str]]
) -> None:
    resp = await client.get(ME_URL, headers=auth_headers("engineer"))

    assert resp.status_code == 200
    body = resp.json()
    assert body["username"] == "engineer_user"
    assert body["role"] == "engineer"
    assert body["is_active"] is True
    assert body["must_change_password"] is False
    assert set(body) == {
        "id",
        "username",
        "email",
        "display_name",
        "role",
        "is_active",
        "must_change_password",
    }
    assert "password_hash" not in body


async def test_me_response_never_leaks_hash(
    client,
    users: dict[str, User],
    auth_headers: Callable[[str], dict[str, str]],
    password_hash: str,
) -> None:
    resp = await client.get(ME_URL, headers=auth_headers("viewer"))

    assert resp.status_code == 200
    assert password_hash not in resp.text
    assert TEST_PASSWORD not in resp.text


async def test_me_requires_authentication(client, users: dict[str, User]) -> None:
    resp = await client.get(ME_URL)
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# PATCH /me — update own fields, email-conflict 409, audit user.updated
# ---------------------------------------------------------------------------


async def test_patch_me_updates_email_and_display_name(
    client,
    users: dict[str, User],
    session: AsyncSession,
    auth_headers: Callable[[str], dict[str, str]],
) -> None:
    resp = await client.patch(
        ME_URL,
        headers=auth_headers("operator"),
        json={"email": "op@example.com", "display_name": "Op Erator"},
    )

    assert resp.status_code == 200
    body = resp.json()
    assert body["email"] == "op@example.com"
    assert body["display_name"] == "Op Erator"

    await session.refresh(users["operator"])
    assert users["operator"].email == "op@example.com"
    assert users["operator"].display_name == "Op Erator"


async def test_patch_me_audits_user_updated(
    client,
    users: dict[str, User],
    session: AsyncSession,
    auth_headers: Callable[[str], dict[str, str]],
) -> None:
    resp = await client.patch(
        ME_URL, headers=auth_headers("operator"), json={"display_name": "Renamed"}
    )

    assert resp.status_code == 200
    rows = (
        (await session.execute(select(AuditLog).where(AuditLog.action == "user.updated")))
        .scalars()
        .all()
    )
    assert len(rows) == 1
    assert rows[0].actor == "user:operator_user"
    assert rows[0].target_id == str(users["operator"].id)


async def test_patch_me_rejects_email_owned_by_another_user(
    client,
    users: dict[str, User],
    session: AsyncSession,
    auth_headers: Callable[[str], dict[str, str]],
) -> None:
    users["admin"].email = "taken@example.com"
    await session.commit()

    resp = await client.patch(
        ME_URL, headers=auth_headers("operator"), json={"email": "taken@example.com"}
    )

    assert resp.status_code == 409


async def test_patch_me_allows_keeping_own_email(
    client,
    users: dict[str, User],
    session: AsyncSession,
    auth_headers: Callable[[str], dict[str, str]],
) -> None:
    users["operator"].email = "mine@example.com"
    await session.commit()

    resp = await client.patch(
        ME_URL,
        headers=auth_headers("operator"),
        json={"email": "mine@example.com", "display_name": "Still Me"},
    )

    assert resp.status_code == 200
    assert resp.json()["email"] == "mine@example.com"


# ---------------------------------------------------------------------------
# POST /me/password — verify current, clear flag, revoke OTHER sessions
# ---------------------------------------------------------------------------


async def test_password_change_verifies_current_and_sets_new_hash(
    client,
    users: dict[str, User],
    session: AsyncSession,
    auth_headers: Callable[[str], dict[str, str]],
) -> None:
    resp = await client.post(
        PASSWORD_URL,
        headers=auth_headers("engineer"),
        json={"current_password": TEST_PASSWORD, "new_password": "brand-new-secret"},
    )

    assert resp.status_code == 200
    await session.refresh(users["engineer"])
    assert verify_password("brand-new-secret", users["engineer"].password_hash)
    assert not verify_password(TEST_PASSWORD, users["engineer"].password_hash)


async def test_password_change_rejects_wrong_current_password_generically(
    client,
    users: dict[str, User],
    session: AsyncSession,
    auth_headers: Callable[[str], dict[str, str]],
) -> None:
    resp = await client.post(
        PASSWORD_URL,
        headers=auth_headers("engineer"),
        json={"current_password": "not-my-password", "new_password": "brand-new-secret"},
    )

    assert resp.status_code == 400
    # The original hash is untouched.
    await session.refresh(users["engineer"])
    assert verify_password(TEST_PASSWORD, users["engineer"].password_hash)


async def test_password_change_enforces_min_length(
    client, users: dict[str, User], auth_headers: Callable[[str], dict[str, str]]
) -> None:
    resp = await client.post(
        PASSWORD_URL,
        headers=auth_headers("engineer"),
        json={"current_password": TEST_PASSWORD, "new_password": "short"},
    )
    assert resp.status_code == 422


async def test_password_change_clears_must_change_flag(
    client,
    users: dict[str, User],
    session: AsyncSession,
    auth_headers: Callable[[str], dict[str, str]],
) -> None:
    users["engineer"].must_change_password = True
    await session.commit()

    resp = await client.post(
        PASSWORD_URL,
        headers=auth_headers("engineer"),
        json={"current_password": TEST_PASSWORD, "new_password": "brand-new-secret"},
    )

    assert resp.status_code == 200
    await session.refresh(users["engineer"])
    assert users["engineer"].must_change_password is False


async def test_password_change_revokes_other_sessions_keeps_current(
    client, users: dict[str, User], session: AsyncSession, settings
) -> None:
    import jwt

    # Establish the current session via real login (sets the refresh cookie).
    login_resp = await _login(client, "engineer_user")
    current_sid = jwt.decode(
        login_resp.cookies[REFRESH_COOKIE], settings.secret_key, algorithms=["HS256"]
    )["sid"]
    access = login_resp.json()["access_token"]

    # A second, unrelated live session for the same user.
    other = await _make_session(session, users["engineer"])
    await session.commit()

    resp = await client.post(
        PASSWORD_URL,
        headers={"Authorization": f"Bearer {access}"},
        json={"current_password": TEST_PASSWORD, "new_password": "brand-new-secret"},
    )

    assert resp.status_code == 200
    await session.refresh(other)
    assert other.revoked_at is not None  # other session revoked

    import uuid

    current = (
        await session.execute(
            select(RefreshSession).where(RefreshSession.id == uuid.UUID(current_sid))
        )
    ).scalar_one()
    assert current.revoked_at is None  # caller's own session stays live


async def test_password_change_audits_password_changed(
    client,
    users: dict[str, User],
    session: AsyncSession,
    auth_headers: Callable[[str], dict[str, str]],
) -> None:
    resp = await client.post(
        PASSWORD_URL,
        headers=auth_headers("engineer"),
        json={"current_password": TEST_PASSWORD, "new_password": "brand-new-secret"},
    )

    assert resp.status_code == 200
    rows = (
        (await session.execute(select(AuditLog).where(AuditLog.action == "auth.password_changed")))
        .scalars()
        .all()
    )
    assert len(rows) == 1
    assert rows[0].actor == "user:engineer_user"


async def test_password_change_response_carries_no_secret(
    client,
    users: dict[str, User],
    auth_headers: Callable[[str], dict[str, str]],
    password_hash: str,
) -> None:
    resp = await client.post(
        PASSWORD_URL,
        headers=auth_headers("engineer"),
        json={"current_password": TEST_PASSWORD, "new_password": "brand-new-secret"},
    )

    assert resp.status_code == 200
    assert "brand-new-secret" not in resp.text
    assert password_hash not in resp.text


# ---------------------------------------------------------------------------
# GET /sessions — own sessions only, is_current flags the cookie sid
# ---------------------------------------------------------------------------


async def test_sessions_lists_only_own_sessions(
    client, users: dict[str, User], session: AsyncSession, settings
) -> None:
    login_resp = await _login(client, "engineer_user")
    access = login_resp.json()["access_token"]

    # A session belonging to a different user must never appear.
    await _make_session(session, users["viewer"])
    await session.commit()

    resp = await client.get(SESSIONS_URL, headers={"Authorization": f"Bearer {access}"})

    assert resp.status_code == 200
    body = resp.json()
    assert all(s["sid"] for s in body)
    # Only the engineer's own (login) session.
    assert len(body) == 1


async def test_sessions_marks_current_session(
    client, users: dict[str, User], session: AsyncSession, settings
) -> None:
    import jwt

    login_resp = await _login(client, "engineer_user")
    access = login_resp.json()["access_token"]
    current_sid = jwt.decode(
        login_resp.cookies[REFRESH_COOKIE], settings.secret_key, algorithms=["HS256"]
    )["sid"]

    # An additional non-current session for the same user.
    await _make_session(session, users["engineer"])
    await session.commit()

    resp = await client.get(SESSIONS_URL, headers={"Authorization": f"Bearer {access}"})

    assert resp.status_code == 200
    body = resp.json()
    current = [s for s in body if s["is_current"]]
    assert len(current) == 1
    assert current[0]["sid"] == current_sid


# ---------------------------------------------------------------------------
# DELETE /sessions/{sid} — own-only, 404 otherwise, audited
# ---------------------------------------------------------------------------


async def test_delete_session_revokes_own_session(
    client, users: dict[str, User], session: AsyncSession, auth_headers
) -> None:
    row = await _make_session(session, users["engineer"])
    await session.commit()

    resp = await client.delete(f"{SESSIONS_URL}/{row.id}", headers=auth_headers("engineer"))

    assert resp.status_code in (200, 204)
    await session.refresh(row)
    assert row.revoked_at is not None

    rows = (
        (await session.execute(select(AuditLog).where(AuditLog.action == "auth.session_revoked")))
        .scalars()
        .all()
    )
    assert len(rows) == 1
    assert rows[0].actor == "user:engineer_user"


async def test_delete_session_owned_by_other_user_is_404(
    client, users: dict[str, User], session: AsyncSession, auth_headers
) -> None:
    row = await _make_session(session, users["viewer"])
    await session.commit()

    resp = await client.delete(f"{SESSIONS_URL}/{row.id}", headers=auth_headers("engineer"))

    assert resp.status_code == 404
    # The other user's session is untouched.
    await session.refresh(row)
    assert row.revoked_at is None


async def test_delete_unknown_session_is_404(client, users: dict[str, User], auth_headers) -> None:
    import uuid

    resp = await client.delete(f"{SESSIONS_URL}/{uuid.uuid4()}", headers=auth_headers("engineer"))
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# POST /sessions/revoke-all — every own session, audited
# ---------------------------------------------------------------------------


async def test_revoke_all_revokes_every_own_session(
    client, users: dict[str, User], session: AsyncSession, auth_headers
) -> None:
    a = await _make_session(session, users["engineer"])
    b = await _make_session(session, users["engineer"])
    other = await _make_session(session, users["viewer"])
    await session.commit()

    resp = await client.post(REVOKE_ALL_URL, headers=auth_headers("engineer"))

    assert resp.status_code == 200
    for row in (a, b):
        await session.refresh(row)
        assert row.revoked_at is not None
    # Another user's session is never touched.
    await session.refresh(other)
    assert other.revoked_at is None

    count = (
        await session.execute(
            select(func.count())
            .select_from(AuditLog)
            .where(AuditLog.action == "auth.session_revoked")
        )
    ).scalar_one()
    assert count == 1


# ---------------------------------------------------------------------------
# get_active_user — forced-change guard
# ---------------------------------------------------------------------------


@pytest.fixture()
def guarded_app(app: FastAPI) -> FastAPI:
    """The base app with one probe route gated by ``get_active_user``."""

    @app.get("/active-probe")
    async def _probe(user: Annotated[User, Depends(deps.get_active_user)]) -> dict[str, str]:
        return {"username": user.username}

    return app


@pytest.fixture()
async def guarded_client(guarded_app: FastAPI):
    import httpx

    transport = httpx.ASGITransport(app=guarded_app)
    async with httpx.AsyncClient(transport=transport, base_url="https://testserver") as test_client:
        yield test_client


async def test_get_active_user_blocks_when_flag_set(
    guarded_client, users: dict[str, User], session: AsyncSession, auth_headers
) -> None:
    users["engineer"].must_change_password = True
    await session.commit()

    resp = await guarded_client.get("/active-probe", headers=auth_headers("engineer"))

    assert resp.status_code == 403
    assert resp.json()["detail"] == "password_change_required"


async def test_get_active_user_passes_when_flag_clear(
    guarded_client, users: dict[str, User], auth_headers
) -> None:
    resp = await guarded_client.get("/active-probe", headers=auth_headers("engineer"))

    assert resp.status_code == 200
    assert resp.json()["username"] == "engineer_user"


def test_get_active_user_raises_forbidden_directly() -> None:
    """The dependency body raises a distinct ForbiddenError when flagged."""

    class _U:
        must_change_password = True

    with pytest.raises(ForbiddenError) as exc:
        deps._require_password_current(_U())  # type: ignore[arg-type]
    assert exc.value.detail == "password_change_required"


async def test_flagged_user_blocked_on_real_protected_route(
    client, users: dict[str, User], session: AsyncSession, auth_headers
) -> None:
    """A must_change_password user is 403'd on a real require_role route.

    Guards against the guard going dead again: ``require_role``'s ``_enforce``
    must resolve through ``get_active_user``, not bare ``get_current_user``.
    """
    users["engineer"].must_change_password = True
    await session.commit()

    resp = await client.get("/api/v1/devices", headers=auth_headers("engineer"))

    assert resp.status_code == 403
    assert resp.json()["detail"] == "password_change_required"


async def test_flagged_user_keeps_self_service_escape_hatches(
    client, users: dict[str, User], session: AsyncSession, auth_headers
) -> None:
    """A flagged user can still read /me and change the password (documented exceptions)."""
    users["engineer"].must_change_password = True
    await session.commit()

    me = await client.get(ME_URL, headers=auth_headers("engineer"))
    assert me.status_code == 200
    assert me.json()["must_change_password"] is True

    changed = await client.post(
        PASSWORD_URL,
        headers=auth_headers("engineer"),
        json={"current_password": TEST_PASSWORD, "new_password": "N3w-Str0ng-Passw0rd!"},
    )
    assert changed.status_code == 200

    # Flag cleared → the protected route opens back up.
    resp = await client.get("/api/v1/devices", headers=auth_headers("engineer"))
    assert resp.status_code == 200


def test_hash_password_roundtrip_helper() -> None:
    """Sanity check the helper imported for password assertions."""
    h = hash_password("some-password")
    assert verify_password("some-password", h)
