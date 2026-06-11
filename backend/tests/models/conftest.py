"""Fixtures for ORM model tests: in-memory aiosqlite, no Postgres/Docker/network.

``Base.metadata.create_all`` is forbidden outside tests (D4); here it is the
sanctioned schema bootstrap for the unit suite. Postgres-only behavior
(partition DDL, REVOKE grants) is exercised by ``integration``-marked tests.
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

from app.models import Base, Device


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


@pytest.fixture()
async def device(session: AsyncSession) -> Device:
    """A persisted device for rows that need a ``devices.id`` foreign key."""
    dev = Device(hostname="lab-sw-01", mgmt_ip="192.0.2.10", vendor_id="cisco_ios")
    session.add(dev)
    await session.flush()
    return dev
