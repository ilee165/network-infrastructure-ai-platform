"""Admin user-management endpoints + last-admin guard (B4).

These exercise the admin-only user surface under ``/api/v1/auth/users``:
``GET/POST /users``, ``GET/PATCH /users/{id}``,
``POST /users/{id}/reset-password`` and ``POST /users/{id}/revoke-sessions``.

Invariants under test (every one of them security-load-bearing):

- Every ``/users`` route is gated by ``require_role("admin")``: a viewer or
  engineer gets 403, an unauthenticated caller 401.
- No list/detail/create/patch/reset response ever carries ``password_hash``.
- ``POST /users`` returns the generated temp password exactly once and sets
  ``must_change_password``; the temp password is bcrypt-hashed in the DB and
  never appears in any audit ``detail``.
- The last-admin guard blocks both deactivating AND demoting the final active
  admin (lockout prevention), but allows it while another active admin exists.
- Deactivating a user revokes that user's live sessions; reset-password sets a
  forced-change temp password and revokes the target's sessions.
"""

from __future__ import annotations

from collections.abc import Callable

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import verify_password
from app.models import AuditLog, RefreshSession, Role, User
from tests.api.conftest import TEST_PASSWORD

USERS_URL = "/api/v1/auth/users"


def _admin(auth_headers: Callable[[str], dict[str, str]]) -> dict[str, str]:
    return auth_headers("admin")


async def _make_session(
    session: AsyncSession, user: User, *, ua: str | None = "agent", ip: str | None = "10.0.0.1"
) -> RefreshSession:
    row = RefreshSession(user_id=user.id, user_agent=ua, ip=ip)
    session.add(row)
    await session.flush()
    return row


async def _audit_rows(session: AsyncSession, action: str) -> list[AuditLog]:
    return list(
        (await session.execute(select(AuditLog).where(AuditLog.action == action))).scalars().all()
    )


# ---------------------------------------------------------------------------
# RBAC — every /users route is admin-only
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("role", ["viewer", "operator", "engineer"])
async def test_list_users_forbidden_for_non_admin(
    client, users: dict[str, User], auth_headers: Callable[[str], dict[str, str]], role: str
) -> None:
    resp = await client.get(USERS_URL, headers=auth_headers(role))
    assert resp.status_code == 403


@pytest.mark.parametrize("role", ["viewer", "engineer"])
async def test_create_user_forbidden_for_non_admin(
    client, users: dict[str, User], auth_headers: Callable[[str], dict[str, str]], role: str
) -> None:
    resp = await client.post(
        USERS_URL, headers=auth_headers(role), json={"username": "nope", "role": "viewer"}
    )
    assert resp.status_code == 403


@pytest.mark.parametrize("role", ["viewer", "engineer"])
async def test_get_user_forbidden_for_non_admin(
    client, users: dict[str, User], auth_headers: Callable[[str], dict[str, str]], role: str
) -> None:
    target = users["operator"].id
    resp = await client.get(f"{USERS_URL}/{target}", headers=auth_headers(role))
    assert resp.status_code == 403


@pytest.mark.parametrize("role", ["viewer", "engineer"])
async def test_patch_user_forbidden_for_non_admin(
    client, users: dict[str, User], auth_headers: Callable[[str], dict[str, str]], role: str
) -> None:
    target = users["operator"].id
    resp = await client.patch(
        f"{USERS_URL}/{target}", headers=auth_headers(role), json={"is_active": False}
    )
    assert resp.status_code == 403


@pytest.mark.parametrize("role", ["viewer", "engineer"])
async def test_reset_password_forbidden_for_non_admin(
    client, users: dict[str, User], auth_headers: Callable[[str], dict[str, str]], role: str
) -> None:
    target = users["operator"].id
    resp = await client.post(
        f"{USERS_URL}/{target}/reset-password", headers=auth_headers(role), json={}
    )
    assert resp.status_code == 403


@pytest.mark.parametrize("role", ["viewer", "engineer"])
async def test_revoke_sessions_forbidden_for_non_admin(
    client, users: dict[str, User], auth_headers: Callable[[str], dict[str, str]], role: str
) -> None:
    target = users["operator"].id
    resp = await client.post(
        f"{USERS_URL}/{target}/revoke-sessions", headers=auth_headers(role), json={}
    )
    assert resp.status_code == 403


async def test_list_users_requires_authentication(client, users: dict[str, User]) -> None:
    resp = await client.get(USERS_URL)
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# GET /users — listing shape, no hashes
# ---------------------------------------------------------------------------


async def test_list_users_returns_all_without_hashes(
    client,
    users: dict[str, User],
    auth_headers: Callable[[str], dict[str, str]],
    password_hash: str,
) -> None:
    resp = await client.get(USERS_URL, headers=_admin(auth_headers))

    assert resp.status_code == 200
    body = resp.json()
    # viewer/operator/engineer/admin/inactive == 5 seeded users.
    assert len(body) == 5
    for entry in body:
        assert set(entry) == {
            "id",
            "username",
            "email",
            "display_name",
            "role",
            "is_active",
            "must_change_password",
        }
        assert "password_hash" not in entry
    assert password_hash not in resp.text


# ---------------------------------------------------------------------------
# POST /users — create, temp password once, forced change, audit, no leak
# ---------------------------------------------------------------------------


async def test_create_user_returns_temp_password_once_and_forces_change(
    client,
    users: dict[str, User],
    session: AsyncSession,
    auth_headers: Callable[[str], dict[str, str]],
) -> None:
    resp = await client.post(
        USERS_URL,
        headers=_admin(auth_headers),
        json={"username": "newbie", "role": "operator", "email": "new@example.com"},
    )

    assert resp.status_code == 201
    body = resp.json()
    assert body["user"]["username"] == "newbie"
    assert body["user"]["role"] == "operator"
    assert body["user"]["email"] == "new@example.com"
    assert body["user"]["must_change_password"] is True
    assert "password_hash" not in body["user"]

    temp = body["temp_password"]
    assert isinstance(temp, str)
    assert len(temp) >= 16

    created = (await session.execute(select(User).where(User.username == "newbie"))).scalar_one()
    assert created.must_change_password is True
    # The DB stores a bcrypt hash that verifies against the returned temp password,
    # and never the plaintext itself.
    assert created.password_hash != temp
    assert verify_password(temp, created.password_hash)


async def test_create_user_with_explicit_temp_password(
    client,
    users: dict[str, User],
    session: AsyncSession,
    auth_headers: Callable[[str], dict[str, str]],
) -> None:
    resp = await client.post(
        USERS_URL,
        headers=_admin(auth_headers),
        json={"username": "chosen", "role": "viewer", "temp_password": "explicit-temp-pass-123"},
    )

    assert resp.status_code == 201
    assert resp.json()["temp_password"] == "explicit-temp-pass-123"
    created = (await session.execute(select(User).where(User.username == "chosen"))).scalar_one()
    assert verify_password("explicit-temp-pass-123", created.password_hash)


async def test_create_user_audits_user_created_without_password(
    client,
    users: dict[str, User],
    session: AsyncSession,
    auth_headers: Callable[[str], dict[str, str]],
) -> None:
    resp = await client.post(
        USERS_URL,
        headers=_admin(auth_headers),
        json={"username": "audited", "role": "viewer"},
    )

    assert resp.status_code == 201
    temp = resp.json()["temp_password"]
    rows = await _audit_rows(session, "user.created")
    assert len(rows) == 1
    assert rows[0].actor == "user:admin_user"
    # The generated temp password must never reach an audit detail.
    detail_text = "" if rows[0].detail is None else str(rows[0].detail)
    assert temp not in detail_text


async def test_create_user_duplicate_username_is_409(
    client, users: dict[str, User], auth_headers: Callable[[str], dict[str, str]]
) -> None:
    resp = await client.post(
        USERS_URL,
        headers=_admin(auth_headers),
        json={"username": "operator_user", "role": "viewer"},
    )
    assert resp.status_code == 409


async def test_create_user_duplicate_email_is_409(
    client,
    users: dict[str, User],
    session: AsyncSession,
    auth_headers: Callable[[str], dict[str, str]],
) -> None:
    users["operator"].email = "dup@example.com"
    await session.commit()

    resp = await client.post(
        USERS_URL,
        headers=_admin(auth_headers),
        json={"username": "freshname", "role": "viewer", "email": "dup@example.com"},
    )
    assert resp.status_code == 409


async def test_create_user_unknown_role_is_rejected(
    client, users: dict[str, User], auth_headers: Callable[[str], dict[str, str]]
) -> None:
    resp = await client.post(
        USERS_URL,
        headers=_admin(auth_headers),
        json={"username": "weird", "role": "superuser"},
    )
    assert resp.status_code in (400, 422)


async def test_create_user_response_never_leaks_hash(
    client, users: dict[str, User], auth_headers: Callable[[str], dict[str, str]]
) -> None:
    resp = await client.post(
        USERS_URL,
        headers=_admin(auth_headers),
        json={"username": "leaktest", "role": "viewer"},
    )
    assert resp.status_code == 201
    assert "password_hash" not in resp.text
    assert "$2b$" not in resp.text


# ---------------------------------------------------------------------------
# GET /users/{id}
# ---------------------------------------------------------------------------


async def test_get_user_returns_target(
    client, users: dict[str, User], auth_headers: Callable[[str], dict[str, str]]
) -> None:
    target = users["viewer"]
    resp = await client.get(f"{USERS_URL}/{target.id}", headers=_admin(auth_headers))

    assert resp.status_code == 200
    body = resp.json()
    assert body["username"] == "viewer_user"
    assert body["role"] == "viewer"
    assert "password_hash" not in body


async def test_get_unknown_user_is_404(
    client, users: dict[str, User], auth_headers: Callable[[str], dict[str, str]]
) -> None:
    import uuid

    resp = await client.get(f"{USERS_URL}/{uuid.uuid4()}", headers=_admin(auth_headers))
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# PATCH /users/{id} — role/active/email/display_name + audit selection
# ---------------------------------------------------------------------------


async def test_patch_user_changes_role_and_audits_role_changed(
    client,
    users: dict[str, User],
    session: AsyncSession,
    auth_headers: Callable[[str], dict[str, str]],
) -> None:
    target = users["viewer"]
    resp = await client.patch(
        f"{USERS_URL}/{target.id}", headers=_admin(auth_headers), json={"role": "engineer"}
    )

    assert resp.status_code == 200
    assert resp.json()["role"] == "engineer"
    await session.refresh(target)
    assert target.role.name == "engineer"

    rows = await _audit_rows(session, "user.role_changed")
    assert len(rows) == 1
    assert rows[0].target_id == str(target.id)


async def test_patch_user_non_role_change_audits_user_updated(
    client,
    users: dict[str, User],
    session: AsyncSession,
    auth_headers: Callable[[str], dict[str, str]],
) -> None:
    target = users["viewer"]
    resp = await client.patch(
        f"{USERS_URL}/{target.id}",
        headers=_admin(auth_headers),
        json={"display_name": "Vee", "email": "vee@example.com"},
    )

    assert resp.status_code == 200
    assert await _audit_rows(session, "user.role_changed") == []
    rows = await _audit_rows(session, "user.updated")
    assert len(rows) == 1


async def test_patch_user_unknown_role_is_rejected(
    client, users: dict[str, User], auth_headers: Callable[[str], dict[str, str]]
) -> None:
    target = users["viewer"]
    resp = await client.patch(
        f"{USERS_URL}/{target.id}", headers=_admin(auth_headers), json={"role": "ceo"}
    )
    assert resp.status_code in (400, 422)


async def test_patch_user_duplicate_email_is_409(
    client,
    users: dict[str, User],
    session: AsyncSession,
    auth_headers: Callable[[str], dict[str, str]],
) -> None:
    users["operator"].email = "owned@example.com"
    await session.commit()

    resp = await client.patch(
        f"{USERS_URL}/{users['viewer'].id}",
        headers=_admin(auth_headers),
        json={"email": "owned@example.com"},
    )
    assert resp.status_code == 409


async def test_deactivating_user_revokes_their_sessions(
    client,
    users: dict[str, User],
    session: AsyncSession,
    auth_headers: Callable[[str], dict[str, str]],
) -> None:
    target = users["engineer"]
    s1 = await _make_session(session, target)
    s2 = await _make_session(session, target)
    await session.commit()

    resp = await client.patch(
        f"{USERS_URL}/{target.id}", headers=_admin(auth_headers), json={"is_active": False}
    )

    assert resp.status_code == 200
    await session.refresh(target)
    assert target.is_active is False
    for row in (s1, s2):
        await session.refresh(row)
        assert row.revoked_at is not None


# ---------------------------------------------------------------------------
# Last-admin guard
# ---------------------------------------------------------------------------


async def test_cannot_deactivate_final_active_admin(
    client,
    users: dict[str, User],
    session: AsyncSession,
    auth_headers: Callable[[str], dict[str, str]],
) -> None:
    # Only one active admin exists in the seed set.
    admin = users["admin"]
    resp = await client.patch(
        f"{USERS_URL}/{admin.id}", headers=_admin(auth_headers), json={"is_active": False}
    )

    assert resp.status_code == 409
    await session.refresh(admin)
    assert admin.is_active is True


async def test_cannot_demote_final_active_admin(
    client,
    users: dict[str, User],
    session: AsyncSession,
    auth_headers: Callable[[str], dict[str, str]],
) -> None:
    admin = users["admin"]
    resp = await client.patch(
        f"{USERS_URL}/{admin.id}", headers=_admin(auth_headers), json={"role": "engineer"}
    )

    assert resp.status_code == 409
    await session.refresh(admin)
    assert admin.role.name == "admin"


async def test_can_demote_admin_when_another_active_admin_exists(
    client,
    users: dict[str, User],
    session: AsyncSession,
    auth_headers: Callable[[str], dict[str, str]],
) -> None:
    # Promote the engineer to admin so two active admins exist.
    admin_role = (await session.execute(select(Role).where(Role.name == "admin"))).scalar_one()
    users["engineer"].role = admin_role
    await session.commit()

    resp = await client.patch(
        f"{USERS_URL}/{users['admin'].id}",
        headers=_admin(auth_headers),
        json={"role": "engineer"},
    )

    assert resp.status_code == 200
    await session.refresh(users["admin"])
    assert users["admin"].role.name == "engineer"


async def test_can_deactivate_admin_when_another_active_admin_exists(
    client,
    users: dict[str, User],
    session: AsyncSession,
    auth_headers: Callable[[str], dict[str, str]],
) -> None:
    admin_role = (await session.execute(select(Role).where(Role.name == "admin"))).scalar_one()
    users["engineer"].role = admin_role
    await session.commit()

    resp = await client.patch(
        f"{USERS_URL}/{users['admin'].id}",
        headers=_admin(auth_headers),
        json={"is_active": False},
    )

    assert resp.status_code == 200
    await session.refresh(users["admin"])
    assert users["admin"].is_active is False


# ---------------------------------------------------------------------------
# POST /users/{id}/reset-password
# ---------------------------------------------------------------------------


async def test_reset_password_sets_temp_and_forces_change(
    client,
    users: dict[str, User],
    session: AsyncSession,
    auth_headers: Callable[[str], dict[str, str]],
) -> None:
    target = users["operator"]
    resp = await client.post(
        f"{USERS_URL}/{target.id}/reset-password", headers=_admin(auth_headers), json={}
    )

    assert resp.status_code == 200
    temp = resp.json()["temp_password"]
    assert len(temp) >= 16

    await session.refresh(target)
    assert target.must_change_password is True
    assert verify_password(temp, target.password_hash)
    assert not verify_password(TEST_PASSWORD, target.password_hash)


async def test_reset_password_explicit_value(
    client,
    users: dict[str, User],
    session: AsyncSession,
    auth_headers: Callable[[str], dict[str, str]],
) -> None:
    target = users["operator"]
    resp = await client.post(
        f"{USERS_URL}/{target.id}/reset-password",
        headers=_admin(auth_headers),
        json={"temp_password": "set-by-admin-12345"},
    )

    assert resp.status_code == 200
    assert resp.json()["temp_password"] == "set-by-admin-12345"
    await session.refresh(target)
    assert verify_password("set-by-admin-12345", target.password_hash)


async def test_reset_password_revokes_target_sessions_and_audits(
    client,
    users: dict[str, User],
    session: AsyncSession,
    auth_headers: Callable[[str], dict[str, str]],
) -> None:
    target = users["operator"]
    s1 = await _make_session(session, target)
    await session.commit()

    resp = await client.post(
        f"{USERS_URL}/{target.id}/reset-password", headers=_admin(auth_headers), json={}
    )

    assert resp.status_code == 200
    await session.refresh(s1)
    assert s1.revoked_at is not None

    rows = await _audit_rows(session, "user.password_reset")
    assert len(rows) == 1
    assert rows[0].target_id == str(target.id)
    detail_text = "" if rows[0].detail is None else str(rows[0].detail)
    assert resp.json()["temp_password"] not in detail_text


async def test_reset_password_unknown_user_is_404(
    client, users: dict[str, User], auth_headers: Callable[[str], dict[str, str]]
) -> None:
    import uuid

    resp = await client.post(
        f"{USERS_URL}/{uuid.uuid4()}/reset-password", headers=_admin(auth_headers), json={}
    )
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# POST /users/{id}/revoke-sessions
# ---------------------------------------------------------------------------


async def test_revoke_sessions_revokes_all_target_sessions_and_audits(
    client,
    users: dict[str, User],
    session: AsyncSession,
    auth_headers: Callable[[str], dict[str, str]],
) -> None:
    target = users["engineer"]
    s1 = await _make_session(session, target)
    s2 = await _make_session(session, target)
    other = await _make_session(session, users["viewer"])
    await session.commit()

    resp = await client.post(
        f"{USERS_URL}/{target.id}/revoke-sessions", headers=_admin(auth_headers), json={}
    )

    assert resp.status_code == 200
    for row in (s1, s2):
        await session.refresh(row)
        assert row.revoked_at is not None
    # Another user's session is untouched.
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


async def test_revoke_sessions_unknown_user_is_404(
    client, users: dict[str, User], auth_headers: Callable[[str], dict[str, str]]
) -> None:
    import uuid

    resp = await client.post(
        f"{USERS_URL}/{uuid.uuid4()}/revoke-sessions", headers=_admin(auth_headers), json={}
    )
    assert resp.status_code == 404
