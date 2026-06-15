"""Snapshot capture engine (M4; ADR-0017) — content-addressing + dedup.

Covers the storage decisions ADR-0017 §1 fixes: the content hash is the SHA-256
of the *normalized* text (so transport CR/LF or trailing-whitespace noise never
shows up as drift), an unchanged re-capture stores no new blob (only the
observation timestamp advances), and a changed config produces a second row
keyed by its own hash. In-memory aiosqlite, no Celery, no network.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from typing import Any

import pytest
from sqlalchemy import event, func, select
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.engines.config_mgmt.capture import (
    capture_snapshot,
    hash_config,
    normalize_config,
)
from app.models import Base, ConfigSnapshot, ConfigSource

RUNNING_CONFIG = "hostname lab-sw-01\n!\ninterface Gi0/1\n description uplink\n!\nend\n"


@pytest.fixture()
async def engine() -> AsyncIterator[AsyncEngine]:
    engine = create_async_engine("sqlite+aiosqlite://")

    @event.listens_for(engine.sync_engine, "connect")
    def _enable_sqlite_fks(dbapi_connection: Any, _record: Any) -> None:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=OFF")  # device FK not exercised here
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


async def _count(session: AsyncSession) -> int:
    result = await session.execute(select(func.count()).select_from(ConfigSnapshot))
    return int(result.scalar_one())


# ---------------------------------------------------------------------------
# normalization + hashing
# ---------------------------------------------------------------------------


def test_normalize_collapses_line_endings_and_trailing_whitespace() -> None:
    crlf = "hostname r1  \r\ninterface Gi0/1\r\n description x \r\n"
    assert normalize_config(crlf) == "hostname r1\ninterface Gi0/1\n description x\n"


def test_normalize_is_idempotent() -> None:
    once = normalize_config(RUNNING_CONFIG)
    assert normalize_config(once) == once


def test_normalize_guarantees_single_trailing_newline() -> None:
    assert normalize_config("end\n\n\n") == "end\n"
    assert normalize_config("end") == "end\n"
    assert normalize_config("") == ""


def test_hash_is_invariant_to_transport_noise() -> None:
    lf = "hostname r1\nend\n"
    crlf_with_trailing = "hostname r1 \r\nend\r\n\n"
    assert hash_config(normalize_config(lf)) == hash_config(normalize_config(crlf_with_trailing))


# ---------------------------------------------------------------------------
# capture persistence + content-addressed dedup
# ---------------------------------------------------------------------------


async def test_first_capture_stores_verbatim_content_addressed_row(session: AsyncSession) -> None:
    device_id = uuid.uuid4()
    result = await capture_snapshot(
        session, device_id=device_id, raw_config=RUNNING_CONFIG, source=ConfigSource.ON_DEMAND
    )
    await session.commit()

    assert result.created is True
    assert result.content_hash == hash_config(normalize_config(RUNNING_CONFIG))
    assert result.snapshot.content == normalize_config(RUNNING_CONFIG)
    assert result.snapshot.source is ConfigSource.ON_DEMAND
    assert result.snapshot.baseline is False
    assert await _count(session) == 1


async def test_unchanged_recapture_stores_no_new_blob_but_advances_observation(
    session: AsyncSession,
) -> None:
    device_id = uuid.uuid4()
    first = await capture_snapshot(
        session, device_id=device_id, raw_config=RUNNING_CONFIG, source=ConfigSource.SCHEDULED
    )
    await session.commit()
    first_captured_at = first.snapshot.captured_at

    # Re-capture the same config (transport noise differs only) → dedup.
    noisy = RUNNING_CONFIG.replace("\n", "\r\n") + "   \r\n"
    second = await capture_snapshot(
        session, device_id=device_id, raw_config=noisy, source=ConfigSource.SCHEDULED
    )
    await session.commit()

    assert second.created is False
    assert second.snapshot.id == first.snapshot.id
    assert second.snapshot.captured_at >= first_captured_at
    assert await _count(session) == 1


async def test_changed_config_inserts_a_second_row(session: AsyncSession) -> None:
    device_id = uuid.uuid4()
    await capture_snapshot(
        session, device_id=device_id, raw_config=RUNNING_CONFIG, source=ConfigSource.SCHEDULED
    )
    changed = RUNNING_CONFIG.replace("description uplink", "description CHANGED")
    second = await capture_snapshot(
        session, device_id=device_id, raw_config=changed, source=ConfigSource.SCHEDULED
    )
    await session.commit()

    assert second.created is True
    assert await _count(session) == 2


async def test_same_config_on_two_devices_are_distinct_rows(session: AsyncSession) -> None:
    config = RUNNING_CONFIG
    a = await capture_snapshot(
        session, device_id=uuid.uuid4(), raw_config=config, source=ConfigSource.SCHEDULED
    )
    b = await capture_snapshot(
        session, device_id=uuid.uuid4(), raw_config=config, source=ConfigSource.SCHEDULED
    )
    await session.commit()

    assert a.content_hash == b.content_hash
    assert a.snapshot.id != b.snapshot.id
    assert await _count(session) == 2


async def test_capture_run_id_is_recorded_when_provided(session: AsyncSession) -> None:
    run_id = uuid.uuid4()
    result = await capture_snapshot(
        session,
        device_id=uuid.uuid4(),
        raw_config=RUNNING_CONFIG,
        source=ConfigSource.SCHEDULED,
        capture_run_id=run_id,
    )
    await session.commit()
    assert result.snapshot.capture_run_id == run_id
