"""Server-side refresh-session service: create, lookup, touch, revoke (B2).

Flush-only semantics (the caller owns the commit), live-session validation
(missing / revoked / user-mismatch all read as "not live"), and idempotent
revocation. No secret material is ever read or written by this service.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import RefreshSession, Role, User
from app.models.mixins import utcnow
from app.services.auth_sessions import service as auth_sessions


async def _get_viewer_role(session: AsyncSession) -> Role:
    """Fetch the shared ``viewer`` role, creating it once (name is unique)."""
    role = (await session.execute(select(Role).where(Role.name == "viewer"))).scalar_one_or_none()
    if role is None:
        role = Role(name="viewer")
        session.add(role)
        await session.flush()
    return role


async def _make_user(
    session: AsyncSession, *, username: str = "alice", password_hash: str = "x"
) -> User:
    role = await _get_viewer_role(session)
    user = User(username=username, password_hash=password_hash, role=role)
    session.add(user)
    await session.flush()
    return user


async def test_create_session_persists_row_for_user(session: AsyncSession) -> None:
    user = await _make_user(session)

    created = await auth_sessions.create_session(
        session, user=user, user_agent="pytest-agent", ip="203.0.113.7"
    )

    assert created.user_id == user.id
    assert created.user_agent == "pytest-agent"
    assert created.ip == "203.0.113.7"
    assert created.revoked_at is None
    assert created.id is not None  # flushed → id assigned

    rows = (await session.execute(select(RefreshSession))).scalars().all()
    assert len(rows) == 1
    assert rows[0].id == created.id


async def test_create_session_flushes_but_does_not_commit(session: AsyncSession) -> None:
    user = await _make_user(session)

    await auth_sessions.create_session(session, user=user, user_agent=None, ip=None)

    # Caller owns the transaction boundary: a rollback must discard the row.
    await session.rollback()
    count = (await session.execute(select(func.count()).select_from(RefreshSession))).scalar_one()
    assert count == 0


async def test_get_live_session_returns_live_row(session: AsyncSession) -> None:
    user = await _make_user(session)
    created = await auth_sessions.create_session(session, user=user, user_agent=None, ip=None)

    found = await auth_sessions.get_live_session(session, sid=created.id, user_id=user.id)

    assert found is not None
    assert found.id == created.id


async def test_get_live_session_none_when_missing(session: AsyncSession) -> None:
    user = await _make_user(session)

    found = await auth_sessions.get_live_session(session, sid=uuid.uuid4(), user_id=user.id)

    assert found is None


async def test_get_live_session_none_when_revoked(session: AsyncSession) -> None:
    user = await _make_user(session)
    created = await auth_sessions.create_session(session, user=user, user_agent=None, ip=None)
    await auth_sessions.revoke(session, sid=created.id)

    found = await auth_sessions.get_live_session(session, sid=created.id, user_id=user.id)

    assert found is None


async def test_get_live_session_none_on_user_mismatch(session: AsyncSession) -> None:
    user = await _make_user(session, username="alice")
    other = await _make_user(session, username="bob")
    created = await auth_sessions.create_session(session, user=user, user_agent=None, ip=None)

    found = await auth_sessions.get_live_session(session, sid=created.id, user_id=other.id)

    assert found is None


async def test_touch_advances_last_used_at(session: AsyncSession) -> None:
    user = await _make_user(session)
    created = await auth_sessions.create_session(session, user=user, user_agent=None, ip=None)
    before = created.last_used_at

    # Force a measurable gap independent of wall-clock resolution.
    created.last_used_at = before.replace(year=2000)
    await auth_sessions.touch(session, created)

    assert created.last_used_at > before.replace(year=2000)
    assert created.last_used_at >= before


async def test_revoke_sets_revoked_at_and_returns_true(session: AsyncSession) -> None:
    user = await _make_user(session)
    created = await auth_sessions.create_session(session, user=user, user_agent=None, ip=None)

    result = await auth_sessions.revoke(session, sid=created.id)

    assert result is True
    reloaded = (
        await session.execute(
            select(RefreshSession)
            .where(RefreshSession.id == created.id)
            .execution_options(populate_existing=True)
        )
    ).scalar_one()
    assert reloaded.revoked_at is not None


async def test_revoke_unknown_sid_returns_false(session: AsyncSession) -> None:
    result = await auth_sessions.revoke(session, sid=uuid.uuid4())
    assert result is False


async def test_revoke_is_idempotent_keeps_first_timestamp(session: AsyncSession) -> None:
    user = await _make_user(session)
    created = await auth_sessions.create_session(session, user=user, user_agent=None, ip=None)
    await auth_sessions.revoke(session, sid=created.id)
    first = created.revoked_at

    result = await auth_sessions.revoke(session, sid=created.id)

    assert result is False  # already revoked → no new revocation
    reloaded = (
        await session.execute(
            select(RefreshSession)
            .where(RefreshSession.id == created.id)
            .execution_options(populate_existing=True)
        )
    ).scalar_one()
    assert reloaded.revoked_at == first


async def test_revoke_all_for_user_revokes_only_live_own_sessions(session: AsyncSession) -> None:
    user = await _make_user(session, username="alice")
    other = await _make_user(session, username="bob")
    s1 = await auth_sessions.create_session(session, user=user, user_agent=None, ip=None)
    s2 = await auth_sessions.create_session(session, user=user, user_agent=None, ip=None)
    already = await auth_sessions.create_session(session, user=user, user_agent=None, ip=None)
    already.revoked_at = utcnow()
    foreign = await auth_sessions.create_session(session, user=other, user_agent=None, ip=None)
    await session.flush()

    count = await auth_sessions.revoke_all_for_user(session, user_id=user.id)

    assert count == 2  # s1 + s2; the already-revoked one is not re-counted
    live_for_user = (
        (
            await session.execute(
                select(RefreshSession).where(
                    RefreshSession.user_id == user.id,
                    RefreshSession.revoked_at.is_(None),
                )
            )
        )
        .scalars()
        .all()
    )
    assert live_for_user == []
    # Another user's session is untouched.
    foreign_reloaded = (
        await session.execute(
            select(RefreshSession)
            .where(RefreshSession.id == foreign.id)
            .execution_options(populate_existing=True)
        )
    ).scalar_one()
    assert foreign_reloaded.revoked_at is None
    assert {s1.id, s2.id}  # referenced for clarity


@pytest.mark.parametrize("secret", ["$2b$12$unguessablehash", "super-secret-hash"])
async def test_service_never_reads_password_hash(session: AsyncSession, secret: str) -> None:
    """The session rows carry no credential material — only metadata."""
    user = await _make_user(session, username="carol", password_hash=secret)

    created = await auth_sessions.create_session(
        session, user=user, user_agent="agent", ip="198.51.100.2"
    )

    # No attribute on the session row exposes the hash.
    assert secret not in repr(created)
    assert not hasattr(created, "password_hash")
