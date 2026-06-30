"""Migration 0013 (P3-W2): config_backup_runs idempotency guard table + single head.

Unit tests drive ``alembic upgrade head --sql`` in-process against the PostgreSQL
dialect (no DB/Docker/network) and assert the emitted DDL creates the
``config_backup_runs`` table with the expected columns. ``alembic heads`` is
asserted to be the SINGLE head ``0013`` chaining after ``0012``.

This table is the DB-level idempotency guard for ``config.nightly_backup``:
a redelivered task (``task_acks_late`` + ``task_reject_on_worker_lost``)
INSERTs ON CONFLICT DO NOTHING and skips the fan-out + audit emit when the
row already exists (ADR-0043 §6 / ADR-0008 §5).
"""

from __future__ import annotations

import io
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory

from app.core.config import get_settings

BACKEND_DIR = Path(__file__).resolve().parents[2]


def _alembic_config(output_buffer: io.StringIO | None = None) -> Config:
    """Programmatic Config: no ini file, so env.py skips fileConfig (caplog-safe)."""
    cfg = Config(output_buffer=output_buffer) if output_buffer is not None else Config()
    cfg.set_main_option("script_location", str(BACKEND_DIR / "alembic"))
    return cfg


def _offline_sql_0013(direction: str) -> str:
    """Render ``alembic <direction> --sql`` for revision 0013 in isolation."""
    buffer = io.StringIO()
    if direction == "upgrade":
        command.upgrade(_alembic_config(buffer), "0012:0013", sql=True)
    else:
        command.downgrade(_alembic_config(buffer), "0013:0012", sql=True)
    return buffer.getvalue()


@pytest.fixture()
def _postgres_dialect_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(
        "NETOPS_DATABASE_URL", "postgresql+asyncpg://netops:netops@127.0.0.1:5432/netops"
    )
    get_settings.cache_clear()
    yield  # type: ignore[misc]
    get_settings.cache_clear()


# ---------------------------------------------------------------------------
# Single head + revision wiring
# ---------------------------------------------------------------------------


def test_single_head_is_0013() -> None:
    """`alembic heads` resolves to exactly one head, revision 0013 (no branch)."""
    script = ScriptDirectory.from_config(_alembic_config())
    heads = script.get_heads()
    assert heads == ["0013"], f"expected single head 0013, got {heads}"


def test_0013_revises_0012() -> None:
    script = ScriptDirectory.from_config(_alembic_config())
    rev = script.get_revision("0013")
    assert rev.down_revision == "0012"


# ---------------------------------------------------------------------------
# Offline SQL (no database required)
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("_postgres_dialect_env")
def test_offline_sql_creates_config_backup_runs_table() -> None:
    """Upgrade DDL creates the config_backup_runs table with all required columns."""
    sql = _offline_sql_0013("upgrade")

    # Table creation
    assert "config_backup_runs" in sql

    # Required columns
    for column in ("run_uuid", "scheduled_slot", "status", "started_at"):
        assert column in sql, f"expected column {column!r} in upgrade DDL"

    # finished_at is nullable (no NOT NULL)
    for line in sql.splitlines():
        if "finished_at" in line and "ADD" in line.upper():
            assert "NOT NULL" not in line, "finished_at must be nullable"


@pytest.mark.usefixtures("_postgres_dialect_env")
def test_offline_downgrade_drops_config_backup_runs_table() -> None:
    """Downgrade DDL drops the config_backup_runs table."""
    sql = _offline_sql_0013("downgrade")
    assert "config_backup_runs" in sql
    # The downgrade should DROP the table (and its index)
    assert "DROP" in sql.upper()
