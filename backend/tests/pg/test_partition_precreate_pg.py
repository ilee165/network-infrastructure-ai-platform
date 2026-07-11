"""Monthly-partition pre-creation against REAL PostgreSQL (H4, 2026-07-10 review).

The migrations ship explicit monthly partitions only through ``2026_07`` plus a
DEFAULT partition; ``system.ensure_partitions`` is the beat task that keeps the
window rolling. Range partitioning does not exist on SQLite, so the DDL is
asserted here on the real backend:

* the task creates ``<parent>_<suffix>`` partitions for all four partitioned
  parents, attached as real partitions (``pg_class.relispartition``);
* the DDL is idempotent — a second run recreates nothing and does not raise
  (redelivery-safe per the system-queue rationale in ``celery_app.py``).
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from app.core.config import Settings
from app.workers.tasks import maintenance
from tests.pg.conftest import _async_url

pytestmark = pytest.mark.integration

#: A far-future month so the partitions cannot collide with migration-created
#: ones; also exercises the December year-rollover on real DDL.
_FIXED_NOW = datetime(2031, 12, 5, tzinfo=UTC)
_EXPECTED_SUFFIXES = ("2031_12", "2032_01")


async def _partition_names(engine: AsyncEngine) -> set[str]:
    async with engine.connect() as conn:
        rows = await conn.execute(
            text(
                "SELECT c.relname FROM pg_class c "
                "WHERE c.relispartition AND c.relname LIKE '%_203%'"
            )
        )
        return {row[0] for row in rows}


async def _drop_created(engine: AsyncEngine) -> None:
    async with engine.begin() as conn:
        for parent in maintenance.PARTITIONED_TABLES:
            for suffix in _EXPECTED_SUFFIXES:
                await conn.execute(text(f"DROP TABLE IF EXISTS {parent}_{suffix}"))


async def test_ensure_partitions_creates_and_is_idempotent(
    pg_engine: AsyncEngine, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        maintenance,
        "get_settings",
        lambda: Settings(_env_file=None, database_url=_async_url()),  # type: ignore[call-arg]
    )
    windows = maintenance.month_windows(_FIXED_NOW)
    assert [w[0] for w in windows] == list(_EXPECTED_SUFFIXES)

    try:
        created = await maintenance._ensure_partitions(windows)
        expected = {
            f"{parent}_{suffix}"
            for parent in maintenance.PARTITIONED_TABLES
            for suffix in _EXPECTED_SUFFIXES
        }
        assert set(created) == expected

        names = await _partition_names(pg_engine)
        assert expected <= names, f"missing partitions: {expected - names}"

        # Idempotent re-run (redelivery / next day's beat): no raise, same set.
        again = await maintenance._ensure_partitions(windows)
        assert set(again) == expected
    finally:
        await _drop_created(pg_engine)
