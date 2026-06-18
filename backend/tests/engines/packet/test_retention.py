"""pcap ingest + retention/tombstone engine tests (M5; ADR-0023 §3/§4).

In-memory aiosqlite (FKs off — device/user FKs not exercised here), no Celery,
no filesystem. Verifies the retention worklist (expired & un-tombstoned) and
that tombstoning preserves the row (never deletes the audit fact).
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import event, select
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.engines.packet import (
    expired_capture_ids,
    ingest_capture,
    tombstone_capture,
)
from app.models import Base, PcapMetadata


@pytest.fixture()
async def engine() -> AsyncIterator[AsyncEngine]:
    engine = create_async_engine("sqlite+aiosqlite://")

    @event.listens_for(engine.sync_engine, "connect")
    def _no_fks(dbapi_connection: Any, _record: Any) -> None:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=OFF")
        cursor.close()

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()


@pytest.fixture()
async def session(engine: AsyncEngine) -> AsyncIterator[AsyncSession]:
    maker = async_sessionmaker(engine, expire_on_commit=False)
    async with maker() as session:
        yield session


async def test_ingest_capture_sets_retention_clock(session: AsyncSession) -> None:
    started = datetime(2026, 6, 1, 0, 0, tzinfo=UTC)
    capture_id = uuid.uuid4()
    meta = await ingest_capture(
        session,
        capture_id=capture_id,
        requester_id=uuid.uuid4(),
        interface="eth0",
        storage_path="/data/pcaps/a.pcap",
        sha256="a" * 64,
        byte_count=4096,
        packet_count=42,
        started_at=started,
        ended_at=started + timedelta(seconds=300),
        device_id=None,
        capture_filter="tcp port 443",
        retention_days=30,
    )
    await session.commit()
    assert meta.retention_expires_at == started + timedelta(days=30)
    assert meta.device_id is None  # worker-side tcpdump
    assert meta.tombstoned_at is None


async def test_expired_worklist_excludes_future_and_tombstoned(session: AsyncSession) -> None:
    now = datetime(2026, 7, 1, 0, 0, tzinfo=UTC)
    expired_id = uuid.uuid4()
    fresh_id = uuid.uuid4()
    already_tombstoned = uuid.uuid4()
    # expired, not tombstoned → in worklist
    await ingest_capture(
        session,
        capture_id=expired_id,
        requester_id=uuid.uuid4(),
        interface="eth0",
        storage_path="/data/pcaps/old.pcap",
        sha256="b" * 64,
        byte_count=1,
        packet_count=1,
        started_at=now - timedelta(days=40),
        ended_at=None,
        retention_days=30,
    )
    # fresh → not in worklist
    await ingest_capture(
        session,
        capture_id=fresh_id,
        requester_id=uuid.uuid4(),
        interface="eth0",
        storage_path="/data/pcaps/new.pcap",
        sha256="c" * 64,
        byte_count=1,
        packet_count=1,
        started_at=now - timedelta(days=1),
        ended_at=None,
        retention_days=30,
    )
    # expired but already tombstoned → not in worklist
    tomb = await ingest_capture(
        session,
        capture_id=already_tombstoned,
        requester_id=uuid.uuid4(),
        interface="eth0",
        storage_path="/data/pcaps/gone.pcap",
        sha256="d" * 64,
        byte_count=1,
        packet_count=1,
        started_at=now - timedelta(days=40),
        ended_at=None,
        retention_days=30,
    )
    tomb.tombstoned_at = now
    tomb.tombstoned_reason = "retention_expired"
    await session.commit()

    worklist = await expired_capture_ids(session, now=now)
    assert expired_id in worklist
    assert fresh_id not in worklist
    assert already_tombstoned not in worklist


async def test_tombstone_preserves_row_and_path(session: AsyncSession) -> None:
    started = datetime(2026, 6, 1, 0, 0, tzinfo=UTC)
    capture_id = uuid.uuid4()
    await ingest_capture(
        session,
        capture_id=capture_id,
        requester_id=uuid.uuid4(),
        interface="eth0",
        storage_path="/data/pcaps/old.pcap",
        sha256="e" * 64,
        byte_count=1,
        packet_count=1,
        started_at=started,
        ended_at=None,
        retention_days=30,
    )
    await session.commit()

    purged_at = datetime(2026, 7, 5, 0, 0, tzinfo=UTC)
    row = await tombstone_capture(
        session, capture_id=capture_id, reason="retention_expired", now=purged_at
    )
    await session.commit()
    assert row is not None

    reloaded = (
        await session.execute(
            select(PcapMetadata).where(PcapMetadata.capture_id == capture_id)
        )
    ).scalar_one()
    # The row survives (audit fact); only the file is removed elsewhere.
    assert reloaded.tombstoned_at == purged_at
    assert reloaded.tombstoned_reason == "retention_expired"
    assert reloaded.storage_path == "/data/pcaps/old.pcap"


async def test_tombstone_twice_is_idempotent(session: AsyncSession) -> None:
    started = datetime(2026, 6, 1, 0, 0, tzinfo=UTC)
    capture_id = uuid.uuid4()
    await ingest_capture(
        session,
        capture_id=capture_id,
        requester_id=uuid.uuid4(),
        interface="eth0",
        storage_path="/data/pcaps/old.pcap",
        sha256="f" * 64,
        byte_count=1,
        packet_count=1,
        started_at=started,
        ended_at=None,
        retention_days=30,
    )
    await session.commit()
    assert await tombstone_capture(session, capture_id=capture_id) is not None
    await session.commit()
    # Second attempt finds no un-tombstoned row → None (no double-purge).
    assert await tombstone_capture(session, capture_id=capture_id) is None
