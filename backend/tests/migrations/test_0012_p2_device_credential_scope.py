"""Migration 0012 (ADR-0040): device-credential scope columns + single head.

Unit tests drive ``alembic upgrade head --sql`` in-process against the PostgreSQL
dialect (no DB/Docker/network) and assert the emitted DDL adds the three nullable
scope columns to ``device_credentials``. A real PostgreSQL round-trip (NullPool,
skipped when unreachable) proves up->down->up is clean, and ``alembic heads`` is
asserted to be the SINGLE head ``0012`` chaining after W4-T1's ``0011``.
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

_SCOPE_COLUMNS = {"scope_site", "scope_role", "scope_device_group"}
_DEVICE_COLUMNS = {"role", "device_group"}


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
    """Render ``alembic <direction> --sql`` for revision 0012 in isolation."""
    buffer = io.StringIO()
    if direction == "upgrade":
        command.upgrade(_alembic_config(buffer), "0011:0012", sql=True)
    else:
        command.downgrade(_alembic_config(buffer), "0012:0011", sql=True)
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


def test_single_head_is_0012() -> None:
    """`alembic heads` resolves to exactly one head, revision 0012 (no branch)."""
    script = ScriptDirectory.from_config(_alembic_config())
    heads = script.get_heads()
    assert heads == ["0012"], f"expected single head 0012, got {heads}"


def test_0012_revises_0011() -> None:
    script = ScriptDirectory.from_config(_alembic_config())
    rev = script.get_revision("0012")
    assert rev.down_revision == "0011"


# ---------------------------------------------------------------------------
# Offline SQL (no database required)
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("_postgres_dialect_env")
def test_offline_sql_adds_nullable_scope_columns() -> None:
    sql = _offline_upgrade_sql()
    # All three scope dimensions are added to device_credentials, nullable (a NULL
    # dimension means "matches any" — an all-NULL credential is unscoped, ADR-0040).
    for column in _SCOPE_COLUMNS:
        assert f"ALTER TABLE device_credentials ADD COLUMN {column} VARCHAR" in sql
        # Nullable: the ADD COLUMN must NOT carry a NOT NULL clause for the scope cols.
        for line in sql.splitlines():
            if f"ADD COLUMN {column} " in line:
                assert "NOT NULL" not in line


@pytest.mark.usefixtures("_postgres_dialect_env")
def test_offline_sql_adds_device_scope_attributes() -> None:
    sql = _offline_upgrade_sql()
    # The device gains the attributes a scoped credential is matched against, so the
    # session-open check is a real structural comparison (ADR-0040 §2).
    for column in _DEVICE_COLUMNS:
        assert f"ALTER TABLE devices ADD COLUMN {column} VARCHAR" in sql


@pytest.mark.usefixtures("_postgres_dialect_env")
def test_offline_downgrade_drops_scope_columns() -> None:
    sql = _offline_sql("downgrade")
    for column in _SCOPE_COLUMNS:
        assert f"ALTER TABLE device_credentials DROP COLUMN {column}" in sql
    for column in _DEVICE_COLUMNS:
        assert f"ALTER TABLE devices DROP COLUMN {column}" in sql


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


async def _device_credential_columns(url: str) -> set[str]:
    engine = create_async_engine(url, poolclass=NullPool)
    try:
        async with engine.connect() as conn:
            return set(
                (
                    await conn.execute(
                        text(
                            "SELECT column_name FROM information_schema.columns "
                            "WHERE table_name = 'device_credentials'"
                        )
                    )
                ).scalars()
            )
    finally:
        await engine.dispose()


@pytest.mark.integration
def test_migration_0012_round_trip_real_postgres() -> None:
    """upgrade head -> downgrade 0011 -> upgrade head, asserting the scope columns."""
    url = get_settings().database_url
    if not url.startswith("postgresql") or not _postgres_reachable(url):
        pytest.skip("PostgreSQL unreachable at NETOPS_DATABASE_URL; skipping integration test")

    cfg = _alembic_config()
    command.upgrade(cfg, "head")
    try:
        after_up = asyncio.run(_device_credential_columns(url))
        assert after_up >= _SCOPE_COLUMNS

        command.downgrade(cfg, "0011")
        after_down = asyncio.run(_device_credential_columns(url))
        assert not (_SCOPE_COLUMNS & after_down), "downgrade must drop scope columns"
    finally:
        command.upgrade(cfg, "head")
