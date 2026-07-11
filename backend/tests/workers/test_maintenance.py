"""Unit tests for the monthly-partition pre-creation beat task (H4).

The PG-semantics half (real CREATE TABLE ... PARTITION OF DDL, idempotent
re-run, catalog assertions) lives in ``tests/pg/test_partition_precreate_pg.py``
— range partitioning does not exist on SQLite. Here: the window math and the
non-PostgreSQL no-op guard.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from app.core.config import Settings
from app.workers.tasks import maintenance


class TestMonthWindows:
    def test_current_and_next_month(self) -> None:
        windows = maintenance.month_windows(datetime(2026, 7, 11, tzinfo=UTC))
        assert windows == [
            ("2026_07", "2026-07-01 00:00:00+00", "2026-08-01 00:00:00+00"),
            ("2026_08", "2026-08-01 00:00:00+00", "2026-09-01 00:00:00+00"),
        ]

    def test_december_rolls_over_the_year(self) -> None:
        windows = maintenance.month_windows(datetime(2026, 12, 31, tzinfo=UTC))
        assert windows == [
            ("2026_12", "2026-12-01 00:00:00+00", "2027-01-01 00:00:00+00"),
            ("2027_01", "2027-01-01 00:00:00+00", "2027-02-01 00:00:00+00"),
        ]

    def test_windows_match_migration_shape(self) -> None:
        """Suffix/bounds format is byte-identical to the 0001/0004 migrations'
        _PARTITION_WINDOWS entries (explicit +00 offsets, zero-padded month)."""
        windows = maintenance.month_windows(datetime(2026, 6, 1, tzinfo=UTC), count=2)
        assert windows[0] == ("2026_06", "2026-06-01 00:00:00+00", "2026-07-01 00:00:00+00")
        assert windows[1] == ("2026_07", "2026-07-01 00:00:00+00", "2026-08-01 00:00:00+00")


class TestEnsurePartitionsTask:
    def test_noop_on_non_postgresql_backend(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """On SQLite (the unpartitioned-migration backends) the task skips."""
        monkeypatch.setattr(
            maintenance,
            "get_settings",
            lambda: Settings(  # type: ignore[call-arg]
                _env_file=None, database_url="sqlite+aiosqlite://"
            ),
        )
        result = maintenance.ensure_partitions()
        assert result == {"ensured": [], "skipped": True}

    def test_task_registered_and_scheduled(self) -> None:
        from app.workers.celery_app import celery_app

        assert "system.ensure_partitions" in celery_app.tasks
        beat = celery_app.conf.beat_schedule
        assert beat["partition-precreate"]["task"] == "system.ensure_partitions"
