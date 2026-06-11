"""get_session dependency: one AsyncSession per request, closed afterwards."""

from __future__ import annotations

from collections.abc import AsyncIterator

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

import app.db as db


@pytest.fixture()
async def _patched_sessionmaker(
    monkeypatch: pytest.MonkeyPatch,
) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    engine = create_async_engine("sqlite+aiosqlite://")
    maker = async_sessionmaker(engine, expire_on_commit=False)
    monkeypatch.setattr(db, "_sessionmaker", maker)
    yield maker
    await engine.dispose()


async def test_get_session_yields_usable_session(
    _patched_sessionmaker: async_sessionmaker[AsyncSession],
) -> None:
    generator = db.get_session()
    session = await anext(generator)
    assert isinstance(session, AsyncSession)
    assert (await session.execute(text("SELECT 1"))).scalar_one() == 1

    with pytest.raises(StopAsyncIteration):
        await anext(generator)
    assert not session.is_active or not session.in_transaction()


async def test_get_session_yields_distinct_sessions_per_call(
    _patched_sessionmaker: async_sessionmaker[AsyncSession],
) -> None:
    first_gen = db.get_session()
    second_gen = db.get_session()
    first = await anext(first_gen)
    second = await anext(second_gen)
    assert first is not second
    for generator in (first_gen, second_gen):
        with pytest.raises(StopAsyncIteration):
            await anext(generator)
