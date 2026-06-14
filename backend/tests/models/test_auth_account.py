"""Auth & Account UI models (B1): User auth columns, RefreshSession, SystemSetting."""

from __future__ import annotations

from datetime import UTC

import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Base, RefreshSession, Role, SystemSetting, User


async def _make_user(session: AsyncSession, username: str = "isaac") -> User:
    role = Role(name=f"role-{username}")
    session.add(role)
    await session.flush()
    user = User(username=username, password_hash="$2b$12$notarealhash", role_id=role.id)
    session.add(user)
    await session.flush()
    return user


# ---------------------------------------------------------------------------
# User: new auth columns
# ---------------------------------------------------------------------------


async def test_user_email_display_name_optional(session: AsyncSession) -> None:
    """email and display_name are nullable and roundtrip when set."""
    user = await _make_user(session)
    assert user.email is None
    assert user.display_name is None

    user.email = "isaac@example.com"
    user.display_name = "Isaac Lee"
    await session.commit()

    reloaded = (
        await session.execute(
            select(User).where(User.id == user.id).execution_options(populate_existing=True)
        )
    ).scalar_one()
    assert reloaded.email == "isaac@example.com"
    assert reloaded.display_name == "Isaac Lee"


async def test_user_email_unique(session: AsyncSession) -> None:
    """Two users cannot share the same email."""
    first = await _make_user(session, username="a")
    first.email = "dup@example.com"
    await session.flush()

    second = await _make_user(session, username="b")
    second.email = "dup@example.com"
    with pytest.raises(IntegrityError):
        await session.flush()
    await session.rollback()


async def test_user_must_change_password_defaults_false(session: AsyncSession) -> None:
    """must_change_password is NOT NULL and defaults to False."""
    user = await _make_user(session)
    assert user.must_change_password is False


# ---------------------------------------------------------------------------
# RefreshSession
# ---------------------------------------------------------------------------


async def test_refresh_session_roundtrip(session: AsyncSession) -> None:
    """A server-side refresh session persists with its user FK and timestamps."""
    user = await _make_user(session)
    rs = RefreshSession(user_id=user.id, user_agent="pytest/1.0", ip="192.0.2.10")
    session.add(rs)
    await session.commit()

    reloaded = (
        await session.execute(
            select(RefreshSession)
            .where(RefreshSession.id == rs.id)
            .execution_options(populate_existing=True)
        )
    ).scalar_one()
    assert reloaded.user_id == user.id
    assert reloaded.user_agent == "pytest/1.0"
    assert reloaded.ip == "192.0.2.10"
    assert reloaded.revoked_at is None
    assert reloaded.created_at.tzinfo == UTC
    assert reloaded.last_used_at.tzinfo == UTC


async def test_refresh_session_nullable_metadata(session: AsyncSession) -> None:
    """user_agent and ip are optional; revoked_at starts unset."""
    user = await _make_user(session)
    rs = RefreshSession(user_id=user.id)
    session.add(rs)
    await session.flush()
    assert rs.user_agent is None
    assert rs.ip is None
    assert rs.revoked_at is None


async def test_refresh_session_requires_user(session: AsyncSession) -> None:
    """user_id is NOT NULL."""
    session.add(RefreshSession(user_id=None))  # type: ignore[arg-type]
    with pytest.raises(IntegrityError):
        await session.flush()
    await session.rollback()


# ---------------------------------------------------------------------------
# SystemSetting
# ---------------------------------------------------------------------------


async def test_system_setting_defaults_local_profile(session: AsyncSession) -> None:
    """The single settings row defaults llm_profile to 'local' with empty role map."""
    setting = SystemSetting()
    session.add(setting)
    await session.flush()
    assert setting.llm_profile == "local"
    assert setting.llm_role_reasoning is None
    assert setting.llm_role_fast is None


async def test_system_setting_roundtrip(session: AsyncSession) -> None:
    """Profile and role map persist and reload intact."""
    setting = SystemSetting(
        llm_profile="openai",
        llm_role_reasoning="gpt-reasoner",
        llm_role_fast="gpt-fast",
    )
    session.add(setting)
    await session.commit()

    reloaded = (
        await session.execute(
            select(SystemSetting)
            .where(SystemSetting.id == setting.id)
            .execution_options(populate_existing=True)
        )
    ).scalar_one()
    assert reloaded.llm_profile == "openai"
    assert reloaded.llm_role_reasoning == "gpt-reasoner"
    assert reloaded.llm_role_fast == "gpt-fast"


# ---------------------------------------------------------------------------
# Metadata registration
# ---------------------------------------------------------------------------


def test_new_tables_registered() -> None:
    """Importing app.models registers the B1 tables on Base.metadata."""
    assert {"refresh_sessions", "system_settings"} <= set(Base.metadata.tables)


def test_refresh_session_user_id_indexed_with_fk() -> None:
    """refresh_sessions.user_id is a real FK to users.id and is indexed."""
    table = Base.metadata.tables["refresh_sessions"]
    column = table.columns["user_id"]
    assert {fk.target_fullname for fk in column.foreign_keys} == {"users.id"}
    indexed = {c.name for index in table.indexes for c in index.columns}
    assert "user_id" in indexed
