"""Fixtures for service-layer tests: in-memory aiosqlite, no Postgres/Docker/network.

``Base.metadata.create_all`` is forbidden outside tests (D4); here it is the
sanctioned schema bootstrap for the unit suite.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

import pytest
from sqlalchemy import event
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.models import Base

# The agent-session lifecycle tests (test_agent_session_service.py) live in this
# services subtree but exercise the agent framework, so they reuse its test
# doubles. Re-export the two fixtures from tests/agents/conftest.py (out of this
# subtree's fixture scope) so pytest can resolve them here.
from tests.agents.conftest import (  # noqa: F401  (re-exported as pytest fixtures)
    audit_sink,
    specialist_factory,
)


@pytest.fixture()
async def engine() -> AsyncIterator[AsyncEngine]:
    """In-memory async SQLite engine with the full model schema created."""
    engine = create_async_engine("sqlite+aiosqlite://")

    @event.listens_for(engine.sync_engine, "connect")
    def _enable_sqlite_fks(dbapi_connection: Any, _record: Any) -> None:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()


@pytest.fixture()
async def session(engine: AsyncEngine) -> AsyncIterator[AsyncSession]:
    """An :class:`AsyncSession` bound to the in-memory test engine."""
    maker = async_sessionmaker(engine, expire_on_commit=False)
    async with maker() as session:
        yield session
