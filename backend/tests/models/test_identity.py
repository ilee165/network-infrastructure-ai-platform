"""Role / User roundtrips and uniqueness (D10)."""

from __future__ import annotations

import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Role, User


async def _make_role(session: AsyncSession, name: str = "admin") -> Role:
    role = Role(name=name)
    session.add(role)
    await session.flush()
    return role


async def test_role_user_roundtrip(session: AsyncSession) -> None:
    """A user persists with its role FK and eager-loads the role on query."""
    role = await _make_role(session)
    user = User(username="isaac", password_hash="$2b$12$notarealhash", role_id=role.id)
    session.add(user)
    await session.commit()

    reloaded = (
        await session.execute(
            select(User).where(User.username == "isaac").execution_options(populate_existing=True)
        )
    ).scalar_one()
    assert reloaded.role_id == role.id
    assert reloaded.role.name == "admin"
    assert reloaded.password_hash == "$2b$12$notarealhash"


async def test_user_is_active_defaults_true(session: AsyncSession) -> None:
    role = await _make_role(session, name="viewer")
    user = User(username="probe", password_hash="x", role_id=role.id)
    session.add(user)
    await session.flush()
    assert user.is_active is True


async def test_role_name_unique(session: AsyncSession) -> None:
    await _make_role(session, name="engineer")
    session.add(Role(name="engineer"))
    with pytest.raises(IntegrityError):
        await session.flush()
    await session.rollback()


async def test_username_unique(session: AsyncSession) -> None:
    role = await _make_role(session, name="operator")
    session.add(User(username="dup", password_hash="a", role_id=role.id))
    await session.flush()
    session.add(User(username="dup", password_hash="b", role_id=role.id))
    with pytest.raises(IntegrityError):
        await session.flush()
    await session.rollback()
