"""Migration 0005 (Auth & Account UI): offline SQL + real round-trip.

Unit tests drive ``alembic upgrade head --sql`` in-process against the
PostgreSQL dialect — no database, no Docker, no network — and assert on the
emitted DDL (the new ``users`` auth columns and the ``refresh_sessions`` /
``system_settings`` tables). The ``integration``-marked test runs a real
upgrade+downgrade round-trip against ``NETOPS_DATABASE_URL`` and skips cleanly
when Postgres is unreachable.
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

#: Tables migration 0005 must create (B1).
NEW_TABLES: tuple[str, ...] = ("refresh_sessions", "system_settings")

#: Columns migration 0005 must add to ``users`` (B1).
NEW_USER_COLUMNS: tuple[str, ...] = ("email", "display_name", "must_change_password")


def _alembic_config(output_buffer: io.StringIO | None = None) -> Config:
    """Programmatic Config: no ini file, so env.py skips fileConfig (caplog-safe)."""
    cfg = Config(output_buffer=output_buffer) if output_buffer is not None else Config()
    cfg.set_main_option("script_location", str(BACKEND_DIR / "alembic"))
    return cfg


def _offline_sql(direction: str) -> str:
    """Render ``alembic <direction> --sql`` for revision 0005 and return the SQL."""
    buffer = io.StringIO()
    if direction == "upgrade":
        command.upgrade(_alembic_config(buffer), "0004:0005", sql=True)
    else:
        command.downgrade(_alembic_config(buffer), "0005:0004", sql=True)
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
def test_offline_sql_creates_new_tables() -> None:
    sql = _offline_sql("upgrade")
    for table in NEW_TABLES:
        assert f"CREATE TABLE {table} (" in sql, f"missing CREATE TABLE for {table}"


@pytest.mark.usefixtures("_postgres_dialect_env")
def test_offline_sql_adds_user_auth_columns() -> None:
    sql = _offline_sql("upgrade")
    for column in NEW_USER_COLUMNS:
        assert f"ALTER TABLE users ADD COLUMN {column}" in sql, f"missing users.{column}"


@pytest.mark.usefixtures("_postgres_dialect_env")
def test_offline_sql_refresh_sessions_links_user() -> None:
    sql = _offline_sql("upgrade")
    assert "FOREIGN KEY(user_id) REFERENCES users (id)" in sql
    assert "CREATE INDEX ix_refresh_sessions_user_id" in sql


@pytest.mark.usefixtures("_postgres_dialect_env")
def test_offline_downgrade_reverses_upgrade() -> None:
    sql = _offline_sql("downgrade")
    for table in NEW_TABLES:
        assert f"DROP TABLE {table}" in sql, f"downgrade must drop {table}"
    for column in NEW_USER_COLUMNS:
        assert f"ALTER TABLE users DROP COLUMN {column}" in sql, f"downgrade must drop {column}"


# ---------------------------------------------------------------------------
# Integration: real upgrade+downgrade round-trip against NETOPS_DATABASE_URL
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


async def _user_columns(url: str) -> set[str]:
    engine = create_async_engine(url, poolclass=NullPool)
    try:
        async with engine.connect() as conn:
            return set(
                (
                    await conn.execute(
                        text(
                            "SELECT column_name FROM information_schema.columns "
                            "WHERE table_name = 'users'"
                        )
                    )
                ).scalars()
            )
    finally:
        await engine.dispose()


@pytest.mark.integration
def test_migration_0005_roundtrip_real_postgres() -> None:
    url = get_settings().database_url
    if not url.startswith("postgresql") or not _postgres_reachable(url):
        pytest.skip("PostgreSQL unreachable at NETOPS_DATABASE_URL; skipping integration test")

    cfg = _alembic_config()
    command.downgrade(cfg, "base")
    command.upgrade(cfg, "head")
    try:
        tables = asyncio.run(_table_names(url))
        user_columns = asyncio.run(_user_columns(url))
        command.downgrade(cfg, "0004")
        tables_after = asyncio.run(_table_names(url))
        user_columns_after = asyncio.run(_user_columns(url))
    finally:
        command.downgrade(cfg, "base")

    assert set(NEW_TABLES) <= tables
    assert set(NEW_USER_COLUMNS) <= user_columns
    # Downgrade to 0004 must remove everything 0005 added.
    assert not set(NEW_TABLES) & tables_after
    assert not set(NEW_USER_COLUMNS) & user_columns_after
