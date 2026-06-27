"""Migration 0011 (ADR-0038 audit hash chain): offline SQL + round-trip + single head.

Unit tests drive ``alembic upgrade head --sql`` in-process against the PostgreSQL
dialect (no DB/Docker/network) and assert the emitted DDL adds the two BYTEA chain
columns to ``audit_log`` and creates the ``audit_chain_checkpoint`` watermark
table. A real SQLite round-trip (NullPool) proves up→down→up is clean, and
``alembic heads`` is asserted to be the SINGLE head ``0011``.
"""

from __future__ import annotations

import asyncio
import io
from collections.abc import Generator
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
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
    buffer = io.StringIO()
    command.upgrade(_alembic_config(buffer), "head", sql=True)
    return buffer.getvalue()


def _offline_sql(direction: str) -> str:
    """Render ``alembic <direction> --sql`` for revision 0011 in isolation."""
    buffer = io.StringIO()
    if direction == "upgrade":
        command.upgrade(_alembic_config(buffer), "0010:0011", sql=True)
    else:
        command.downgrade(_alembic_config(buffer), "0011:0010", sql=True)
    return buffer.getvalue()


@pytest.fixture()
def _postgres_dialect_env(monkeypatch: pytest.MonkeyPatch) -> Generator[None, None, None]:
    monkeypatch.setenv(
        "NETOPS_DATABASE_URL", "postgresql+asyncpg://netops:netops@127.0.0.1:5432/netops"
    )
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


# ---------------------------------------------------------------------------
# Single head + revision wiring
# ---------------------------------------------------------------------------


def test_single_head_is_0011() -> None:
    """`alembic heads` resolves to exactly one head, revision 0011 (no branch)."""
    script = ScriptDirectory.from_config(_alembic_config())
    heads = script.get_heads()
    assert heads == ["0011"], f"expected single head 0011, got {heads}"


def test_0011_revises_0010() -> None:
    script = ScriptDirectory.from_config(_alembic_config())
    rev = script.get_revision("0011")
    assert rev.down_revision == "0010"


# ---------------------------------------------------------------------------
# Offline SQL (no database required)
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("_postgres_dialect_env")
def test_offline_sql_adds_bytea_chain_columns() -> None:
    sql = _offline_upgrade_sql()
    # Both columns are added to audit_log as BYTEA (raw digest — no hex variant).
    assert "ALTER TABLE audit_log ADD COLUMN prev_hash BYTEA" in sql
    assert "ALTER TABLE audit_log ADD COLUMN entry_hash BYTEA" in sql


@pytest.mark.usefixtures("_postgres_dialect_env")
def test_offline_sql_creates_checkpoint_table() -> None:
    sql = _offline_upgrade_sql()
    assert "CREATE TABLE audit_chain_checkpoint (" in sql
    assert "entry_hash BYTEA NOT NULL" in sql


@pytest.mark.usefixtures("_postgres_dialect_env")
def test_offline_downgrade_reverses_upgrade() -> None:
    """The downgrade drops both chain columns and the checkpoint table."""
    sql = _offline_sql("downgrade")
    assert "ALTER TABLE audit_log DROP COLUMN entry_hash" in sql
    assert "ALTER TABLE audit_log DROP COLUMN prev_hash" in sql
    assert "DROP TABLE audit_chain_checkpoint" in sql


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


async def _audit_log_columns(url: str) -> set[str]:
    engine = create_async_engine(url, poolclass=NullPool)
    try:
        async with engine.connect() as conn:
            return set(
                (
                    await conn.execute(
                        text(
                            "SELECT column_name FROM information_schema.columns "
                            "WHERE table_name = 'audit_log'"
                        )
                    )
                ).scalars()
            )
    finally:
        await engine.dispose()


@pytest.mark.integration
def test_migration_0011_round_trip_real_postgres() -> None:
    """upgrade head → downgrade 0010 → upgrade head, asserting the chain columns."""
    url = get_settings().database_url
    if not url.startswith("postgresql") or not _postgres_reachable(url):
        pytest.skip("PostgreSQL unreachable at NETOPS_DATABASE_URL; skipping integration test")

    cfg = _alembic_config()
    command.upgrade(cfg, "head")
    try:
        after_up = asyncio.run(_audit_log_columns(url))
        assert {"prev_hash", "entry_hash"} <= after_up

        command.downgrade(cfg, "0010")
        after_down = asyncio.run(_audit_log_columns(url))
        assert not ({"prev_hash", "entry_hash"} & after_down), "downgrade must drop chain columns"
    finally:
        command.upgrade(cfg, "head")
