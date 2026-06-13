"""Migration 0004 (M3 agent sessions + reasoning traces): offline SQL + real run.

Unit tests drive ``alembic upgrade head --sql`` in-process against the
PostgreSQL dialect — no database, no Docker, no network — and assert on the
emitted DDL (the new tables, monthly partitioning of ``reasoning_traces`` and
``reasoning_trace_steps``, the ``audit_log.reasoning_trace_id`` link column).
The ``integration``-marked test runs a real upgrade against
``NETOPS_DATABASE_URL`` and skips cleanly when Postgres is unreachable.
"""

from __future__ import annotations

import asyncio
import io
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import NullPool

from app.core.config import get_settings

BACKEND_DIR = Path(__file__).resolve().parents[2]

#: Tables migration 0004 must create (M3-01).
NEW_TABLES: tuple[str, ...] = ("agent_sessions", "reasoning_traces", "reasoning_trace_steps")

#: New tables that are range-partitioned monthly by ``created_at`` (ADR-0011).
PARTITIONED_TABLES: tuple[str, ...] = ("reasoning_traces", "reasoning_trace_steps")


def _alembic_config(output_buffer: io.StringIO | None = None) -> Config:
    """Programmatic Config: no ini file, so env.py skips fileConfig (caplog-safe)."""
    cfg = Config(output_buffer=output_buffer) if output_buffer is not None else Config()
    cfg.set_main_option("script_location", str(BACKEND_DIR / "alembic"))
    return cfg


def _offline_upgrade_sql() -> str:
    """Render ``alembic upgrade head --sql`` and return the generated SQL."""
    buffer = io.StringIO()
    command.upgrade(_alembic_config(buffer), "head", sql=True)
    return buffer.getvalue()


@pytest.fixture()
def _postgres_dialect_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pin a PostgreSQL-dialect URL so offline rendering is deterministic."""
    monkeypatch.setenv(
        "NETOPS_DATABASE_URL", "postgresql+asyncpg://netops:netops@127.0.0.1:5432/netops"
    )
    get_settings.cache_clear()


# ---------------------------------------------------------------------------
# Unit: offline SQL generation (no database required)
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("_postgres_dialect_env")
def test_offline_sql_creates_agent_session_and_trace_tables() -> None:
    sql = _offline_upgrade_sql()
    for table in NEW_TABLES:
        assert f"CREATE TABLE {table} (" in sql, f"missing CREATE TABLE for {table}"


@pytest.mark.usefixtures("_postgres_dialect_env")
def test_offline_sql_partitions_traces_monthly() -> None:
    sql = _offline_upgrade_sql()
    for parent in PARTITIONED_TABLES:
        assert f"CREATE TABLE {parent} (" in sql
        assert "PARTITION BY RANGE (created_at)" in sql
        # Same monthly windows + DEFAULT as the audit_log baseline precedent.
        assert f"CREATE TABLE {parent}_2026_06 PARTITION OF {parent}" in sql
        assert f"CREATE TABLE {parent}_2026_07 PARTITION OF {parent}" in sql
        assert f"CREATE TABLE {parent}_default PARTITION OF {parent} DEFAULT" in sql


@pytest.mark.usefixtures("_postgres_dialect_env")
def test_offline_sql_adds_audit_log_reasoning_trace_link() -> None:
    sql = _offline_upgrade_sql()
    assert "ALTER TABLE audit_log ADD COLUMN reasoning_trace_id" in sql


# ---------------------------------------------------------------------------
# Integration: real upgrade against NETOPS_DATABASE_URL
# ---------------------------------------------------------------------------


def _postgres_reachable(url: str) -> bool:
    async def probe() -> bool:
        engine = create_async_engine(url, poolclass=NullPool, connect_args={"timeout": 3})
        try:
            async with engine.connect():
                return True
        finally:
            await engine.dispose()

    try:
        return asyncio.run(probe())
    except Exception:
        return False


async def _partitioned_relations(url: str) -> set[str]:
    engine = create_async_engine(url, poolclass=NullPool)
    try:
        async with engine.connect() as conn:
            return set(
                (
                    await conn.execute(text("SELECT relname FROM pg_class WHERE relkind = 'p'"))
                ).scalars()
            )
    finally:
        await engine.dispose()


async def _table_names(url: str) -> set[str]:
    engine = create_async_engine(url, poolclass=NullPool)
    try:
        async with engine.connect() as conn:
            return set(
                (
                    await conn.execute(
                        text("SELECT tablename FROM pg_tables WHERE schemaname = current_schema()")
                    )
                ).scalars()
            )
    finally:
        await engine.dispose()


@pytest.mark.integration
def test_migration_0004_creates_partitioned_traces_real_postgres() -> None:
    url = get_settings().database_url
    if not url.startswith("postgresql") or not _postgres_reachable(url):
        pytest.skip("PostgreSQL unreachable at NETOPS_DATABASE_URL; skipping integration test")

    cfg = _alembic_config()
    command.downgrade(cfg, "base")
    command.upgrade(cfg, "head")
    try:
        tables = asyncio.run(_table_names(url))
        partitioned = asyncio.run(_partitioned_relations(url))
    finally:
        command.downgrade(cfg, "base")

    assert set(NEW_TABLES) <= tables
    assert set(PARTITIONED_TABLES) <= partitioned
    for parent in PARTITIONED_TABLES:
        for suffix in ("2026_06", "2026_07", "default"):
            assert f"{parent}_{suffix}" in tables, f"missing partition {parent}_{suffix}"

    remaining = asyncio.run(_table_names(url))
    assert not set(NEW_TABLES) & remaining, "downgrade must drop every M3 table"
