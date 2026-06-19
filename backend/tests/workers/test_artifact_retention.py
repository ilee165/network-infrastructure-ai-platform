"""M5-T19 raw-artifact retention beat (``discovery.purge_expired_artifacts``).

ADR-0023 §4 tombstones pcaps; ``raw_artifacts`` (verbatim device output captured
during discovery — potentially credential-bearing CLI text, D11) instead are
**hard-deleted** once past the retention window, because — unlike a pcap whose
metadata row is the audit fact — a raw artifact *is* the captured payload and has
no separate tombstone row. Each purge run is summarized in one audit entry
(actor = system/retention, action = ``raw_artifact.purged``, the deleted count
and the cutoff) so the fact "N artifacts past retention were removed" survives.

Same harness as the packet/discovery task tests: file-backed aiosqlite (each
task opens its own ``asyncio.run`` loop), ``task_always_eager``, the engine seam
monkeypatched. No Postgres, no network.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.models import AuditLog, Base, Device, DeviceStatus, RawArtifact
from app.workers.celery_app import celery_app
from app.workers.tasks import discovery as tasks


@pytest.fixture()
def eager_celery() -> Iterator[None]:
    previous = celery_app.conf.task_always_eager
    celery_app.conf.task_always_eager = True
    yield
    celery_app.conf.task_always_eager = previous


@pytest.fixture()
def db_url(tmp_path: Any, monkeypatch: pytest.MonkeyPatch) -> str:
    url = f"sqlite+aiosqlite:///{tmp_path / 'artifacts.sqlite'}"

    async def _create_schema() -> None:
        engine = create_async_engine(url)
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        await engine.dispose()

    asyncio.run(_create_schema())
    monkeypatch.setattr(tasks, "_make_engine", lambda: create_async_engine(url))
    return url


def _fetch_all(db_url: str, orm_cls: type) -> list[Any]:
    async def _go() -> list[Any]:
        engine = create_async_engine(db_url)
        maker = async_sessionmaker(engine, expire_on_commit=False)
        async with maker() as session:
            rows = list((await session.execute(select(orm_cls))).scalars())
        await engine.dispose()
        return rows

    return asyncio.run(_go())


def _seed(db_url: str, *, created_at: datetime, raw_text: str = "show run") -> uuid.UUID:
    """Seed one device + one raw artifact captured at *created_at*; return its id."""

    async def _go() -> uuid.UUID:
        engine = create_async_engine(db_url)
        maker = async_sessionmaker(engine, expire_on_commit=False)
        artifact_id = uuid.uuid4()
        async with maker() as session:
            device = Device(
                hostname="r1",
                mgmt_ip=f"10.0.0.{uuid.uuid4().int % 250 + 1}",
                status=DeviceStatus.REACHABLE,
            )
            session.add(device)
            await session.flush()
            session.add(
                RawArtifact(
                    id=artifact_id,
                    created_at=created_at,
                    device_id=device.id,
                    command="show running-config",
                    raw_text=raw_text,
                )
            )
            await session.commit()
        await engine.dispose()
        return artifact_id

    return asyncio.run(_go())


def test_purge_expired_artifacts_deletes_old_rows_and_audits(
    eager_celery: None, db_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(tasks._settings(), "raw_artifact_retention_days", 30)
    old_id = _seed(db_url, created_at=datetime.now(UTC) - timedelta(days=45))

    result = tasks.purge_expired_artifacts()

    assert result["purged"] == 1
    # The verbatim device output (the sensitive payload) is gone.
    remaining = _fetch_all(db_url, RawArtifact)
    assert all(row.id != old_id for row in remaining)
    assert remaining == []
    purge_audits = [a for a in _fetch_all(db_url, AuditLog) if a.action == "raw_artifact.purged"]
    assert purge_audits and purge_audits[0].detail["purged"] == 1
    # The audit must never echo the captured device text.
    assert "raw_text" not in purge_audits[0].detail


def test_purge_expired_artifacts_keeps_fresh_rows(
    eager_celery: None, db_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(tasks._settings(), "raw_artifact_retention_days", 30)
    fresh_id = _seed(db_url, created_at=datetime.now(UTC) - timedelta(days=1))

    result = tasks.purge_expired_artifacts()

    assert result["purged"] == 0
    remaining = _fetch_all(db_url, RawArtifact)
    assert [row.id for row in remaining] == [fresh_id]


def test_purge_expired_artifacts_disabled_when_retention_zero(
    eager_celery: None, db_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A retention of 0 days disables artifact purging (keep-forever policy)."""
    monkeypatch.setattr(tasks._settings(), "raw_artifact_retention_days", 0)
    _seed(db_url, created_at=datetime.now(UTC) - timedelta(days=999))

    result = tasks.purge_expired_artifacts()

    assert result["purged"] == 0
    assert result.get("disabled") is True
    assert len(_fetch_all(db_url, RawArtifact)) == 1
