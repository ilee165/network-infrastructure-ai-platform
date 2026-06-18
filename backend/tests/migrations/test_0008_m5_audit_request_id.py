"""Migration 0008 (M5 review fix): audit_log.request_id correlation column.

ADR-0020 §4 names ``request id`` as a required dimension of every ChangeRequest
transition audit entry. Migration 0008 adds a nullable, plain indexed
``request_id`` UUID to ``audit_log`` (no FK — there is no request table, and
``audit_log`` is partitioned, cf. ``reasoning_trace_id`` in 0004). Unit tests
drive ``alembic upgrade head --sql`` in-process against the PostgreSQL dialect —
no database, no Docker, no network — and assert on the emitted DDL. The
``integration``-marked test runs a real upgrade/downgrade against
``NETOPS_DATABASE_URL`` and skips cleanly when Postgres is unreachable.
"""

from __future__ import annotations

import asyncio
import io
from collections.abc import Generator
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import NullPool

from app.core.config import get_settings

BACKEND_DIR = Path(__file__).resolve().parents[2]


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
def _postgres_dialect_env(monkeypatch: pytest.MonkeyPatch) -> Generator[None, None, None]:
    """Pin a PostgreSQL-dialect URL so offline rendering is deterministic."""
    monkeypatch.setenv(
        "NETOPS_DATABASE_URL", "postgresql+asyncpg://netops:netops@127.0.0.1:5432/netops"
    )
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


# ---------------------------------------------------------------------------
# Unit: offline SQL generation (no database required)
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("_postgres_dialect_env")
def test_offline_sql_adds_audit_log_request_id_column() -> None:
    sql = _offline_upgrade_sql()
    assert "ALTER TABLE audit_log ADD COLUMN request_id" in sql


@pytest.mark.usefixtures("_postgres_dialect_env")
def test_offline_sql_indexes_audit_log_request_id() -> None:
    sql = _offline_upgrade_sql()
    assert "ix_audit_log_request_id" in sql


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


async def _audit_log_columns(url: str) -> set[str]:
    engine = create_async_engine(url, poolclass=NullPool)
    try:
        async with engine.connect() as conn:
            return set(
                (
                    await conn.execute(
                        text(
                            "SELECT column_name FROM information_schema.columns "
                            "WHERE table_name = 'audit_log' "
                            "AND table_schema = current_schema()"
                        )
                    )
                ).scalars()
            )
    finally:
        await engine.dispose()


@pytest.mark.integration
def test_migration_0008_adds_and_drops_request_id() -> None:
    url = get_settings().database_url
    if not url.startswith("postgresql") or not _postgres_reachable(url):
        pytest.skip("PostgreSQL unreachable at NETOPS_DATABASE_URL; skipping integration test")

    cfg = _alembic_config()
    command.downgrade(cfg, "0007")
    command.upgrade(cfg, "head")
    try:
        assert "request_id" in asyncio.run(_audit_log_columns(url))
    finally:
        command.downgrade(cfg, "0007")
    assert "request_id" not in asyncio.run(_audit_log_columns(url))
