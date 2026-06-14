"""Migration 0001 (M1 baseline): offline SQL generation + real-Postgres run.

Unit tests drive ``alembic upgrade head --sql`` in-process against the
PostgreSQL dialect — no database, no Docker, no network — and assert on the
emitted DDL/DML (partitioning, append-only REVOKE, every table, seeds).
The ``integration``-marked test runs a real upgrade/downgrade cycle against
``NETOPS_DATABASE_URL`` and skips cleanly when Postgres is unreachable.
"""

from __future__ import annotations

import asyncio
import io
import logging
import os
import re
from pathlib import Path
from typing import Any

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import NullPool

from app.core.config import get_settings
from app.core.security import verify_password

BACKEND_DIR = Path(__file__).resolve().parents[2]

#: Every table migration 0001 must create (M1-01 models, ADR-0011).
EXPECTED_TABLES: tuple[str, ...] = (
    "roles",
    "users",
    "device_credentials",
    "devices",
    "discovery_runs",
    "audit_log",
    "raw_artifacts",
    "normalized_interfaces",
    "normalized_routes",
    "normalized_neighbors",
)

PARTITIONED_TABLES: tuple[str, ...] = ("audit_log", "raw_artifacts")

_BCRYPT_HASH_RE = re.compile(r"\$2[abxy]\$\d{2}\$[./A-Za-z0-9]{53}")


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
def test_offline_sql_creates_every_m1_table() -> None:
    sql = _offline_upgrade_sql()
    for table in EXPECTED_TABLES:
        assert f"CREATE TABLE {table} (" in sql, f"missing CREATE TABLE for {table}"


@pytest.mark.usefixtures("_postgres_dialect_env")
def test_offline_sql_partitions_audit_log_and_raw_artifacts() -> None:
    sql = _offline_upgrade_sql()
    assert "PARTITION BY RANGE (created_at)" in sql
    for parent in PARTITIONED_TABLES:
        # Tie the partitions to this specific parent table so the assertion
        # stays correct as later migrations add their own partitioned tables
        # to the upgrade-head SQL (e.g. 0004 reasoning traces).
        assert f"CREATE TABLE {parent}_2026_06 PARTITION OF {parent}" in sql
        assert f"CREATE TABLE {parent}_2026_07 PARTITION OF {parent}" in sql
        assert f"CREATE TABLE {parent}_default PARTITION OF {parent} DEFAULT" in sql


@pytest.mark.usefixtures("_postgres_dialect_env")
def test_offline_sql_revokes_update_delete_on_audit_log() -> None:
    sql = _offline_upgrade_sql()
    assert "REVOKE UPDATE, DELETE ON audit_log FROM PUBLIC" in sql


@pytest.mark.usefixtures("_postgres_dialect_env")
def test_offline_sql_seeds_four_roles_and_admin_user() -> None:
    sql = _offline_upgrade_sql()
    assert "INSERT INTO roles " in sql
    for role in ("viewer", "operator", "engineer", "admin"):
        assert f"'{role}'" in sql, f"role {role} not seeded"
    assert "INSERT INTO users " in sql


@pytest.mark.usefixtures("_postgres_dialect_env")
def test_admin_seed_defaults_password_with_warning(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.delenv("NETOPS_ADMIN_PASSWORD", raising=False)
    with caplog.at_level(logging.WARNING):
        sql = _offline_upgrade_sql()
    warnings = [
        record
        for record in caplog.records
        if record.levelno >= logging.WARNING and "NETOPS_ADMIN_PASSWORD" in record.getMessage()
    ]
    assert warnings, "expected a migration warning when NETOPS_ADMIN_PASSWORD is unset"
    match = _BCRYPT_HASH_RE.search(sql)
    assert match is not None, "seeded admin user must carry a bcrypt hash"
    assert verify_password("admin", match.group(0))


@pytest.mark.usefixtures("_postgres_dialect_env")
def test_admin_seed_uses_env_password_without_leaking_plaintext(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    password = "unit-test-Adm1n-pass"
    monkeypatch.setenv("NETOPS_ADMIN_PASSWORD", password)
    with caplog.at_level(logging.WARNING):
        sql = _offline_upgrade_sql()
    assert not [
        record
        for record in caplog.records
        if record.levelno >= logging.WARNING and "NETOPS_ADMIN_PASSWORD" in record.getMessage()
    ], "no default-password warning expected when NETOPS_ADMIN_PASSWORD is set"
    assert password not in sql, "plaintext admin password leaked into migration SQL"
    match = _BCRYPT_HASH_RE.search(sql)
    assert match is not None
    assert verify_password(password, match.group(0))


# ---------------------------------------------------------------------------
# Integration: real upgrade/downgrade against NETOPS_DATABASE_URL
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
            result = await conn.execute(
                text("SELECT tablename FROM pg_tables WHERE schemaname = current_schema()")
            )
            return set(result.scalars())
    finally:
        await engine.dispose()


async def _snapshot(url: str) -> dict[str, Any]:
    engine = create_async_engine(url, poolclass=NullPool)
    try:
        async with engine.connect() as conn:
            tables = set(
                (
                    await conn.execute(
                        text("SELECT tablename FROM pg_tables WHERE schemaname = current_schema()")
                    )
                ).scalars()
            )
            partitioned = set(
                (
                    await conn.execute(text("SELECT relname FROM pg_class WHERE relkind = 'p'"))
                ).scalars()
            )
            roles = sorted((await conn.execute(text("SELECT name FROM roles"))).scalars())
            admin = (
                await conn.execute(
                    text(
                        "SELECT u.password_hash, r.name FROM users u "
                        "JOIN roles r ON r.id = u.role_id WHERE u.username = 'admin'"
                    )
                )
            ).one()
            return {
                "tables": tables,
                "partitioned": partitioned,
                "roles": roles,
                "admin_hash": admin[0],
                "admin_role": admin[1],
            }
    finally:
        await engine.dispose()


@pytest.mark.integration
def test_migration_0001_upgrades_and_downgrades_real_postgres() -> None:
    url = get_settings().database_url
    if not url.startswith("postgresql") or not _postgres_reachable(url):
        pytest.skip("PostgreSQL unreachable at NETOPS_DATABASE_URL; skipping integration test")

    cfg = _alembic_config()
    # Reset any state a previous (possibly failed) run left behind.
    command.downgrade(cfg, "base")
    command.upgrade(cfg, "head")
    try:
        state = asyncio.run(_snapshot(url))
    finally:
        command.downgrade(cfg, "base")

    assert set(EXPECTED_TABLES) <= state["tables"]
    assert set(PARTITIONED_TABLES) <= state["partitioned"]
    for parent in PARTITIONED_TABLES:
        for suffix in ("2026_06", "2026_07", "default"):
            assert f"{parent}_{suffix}" in state["tables"]
    assert state["roles"] == ["admin", "engineer", "operator", "viewer"]
    assert state["admin_role"] == "admin"
    expected_password = os.environ.get("NETOPS_ADMIN_PASSWORD") or "admin"
    assert verify_password(expected_password, state["admin_hash"])

    remaining = asyncio.run(_table_names(url))
    assert not set(EXPECTED_TABLES) & remaining, "downgrade must drop every M1 table"
