"""Migration 0006 (M4 config + docs schema): offline SQL + real run.

Unit tests drive ``alembic upgrade head --sql`` in-process against the
PostgreSQL dialect — no database, no Docker, no network — and assert on the
emitted DDL (the four new tables, the pgvector extension + ``vector`` column +
HNSW/cosine index, the content-addressed and per-version unique constraints).
The ``integration``-marked test runs a real upgrade against
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

#: Tables migration 0006 must create (M4 schema).
NEW_TABLES: tuple[str, ...] = (
    "config_snapshots",
    "compliance_policies",
    "documents",
    "embeddings",
)


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
def test_offline_sql_creates_m4_tables() -> None:
    sql = _offline_upgrade_sql()
    for table in NEW_TABLES:
        assert f"CREATE TABLE {table} (" in sql, f"missing CREATE TABLE for {table}"


@pytest.mark.usefixtures("_postgres_dialect_env")
def test_offline_sql_enables_pgvector_and_vector_column() -> None:
    sql = _offline_upgrade_sql()
    assert "CREATE EXTENSION IF NOT EXISTS vector" in sql
    # The embedding column is a fixed-dimension pgvector column (768 = nomic).
    assert "VECTOR(768)" in sql


@pytest.mark.usefixtures("_postgres_dialect_env")
def test_offline_sql_creates_hnsw_cosine_index() -> None:
    sql = _offline_upgrade_sql()
    assert "USING hnsw (embedding vector_cosine_ops)" in sql, (
        "missing HNSW/cosine index on embeddings.embedding (ADR-0004 §3)"
    )


@pytest.mark.usefixtures("_postgres_dialect_env")
def test_offline_sql_declares_uniqueness_constraints() -> None:
    sql = _offline_upgrade_sql()
    # Content-addressed dedup, per-version policy, per-chunk embedding.
    assert "uq_config_snapshots_device_hash" in sql
    assert "uq_compliance_policies_policy_version" in sql
    assert "uq_embeddings_document_chunk" in sql


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


async def _index_names(url: str) -> set[str]:
    engine = create_async_engine(url, poolclass=NullPool)
    try:
        async with engine.connect() as conn:
            return set(
                (
                    await conn.execute(
                        text("SELECT indexname FROM pg_indexes WHERE schemaname = current_schema()")
                    )
                ).scalars()
            )
    finally:
        await engine.dispose()


@pytest.mark.integration
def test_migration_0006_creates_m4_schema_real_postgres() -> None:
    url = get_settings().database_url
    if not url.startswith("postgresql") or not _postgres_reachable(url):
        pytest.skip("PostgreSQL unreachable at NETOPS_DATABASE_URL; skipping integration test")

    cfg = _alembic_config()
    command.downgrade(cfg, "base")
    command.upgrade(cfg, "head")
    try:
        tables = asyncio.run(_table_names(url))
        indexes = asyncio.run(_index_names(url))
    finally:
        command.downgrade(cfg, "base")

    assert set(NEW_TABLES) <= tables
    assert "ix_embeddings_embedding_hnsw" in indexes, "missing HNSW index on real Postgres"

    remaining = asyncio.run(_table_names(url))
    assert not set(NEW_TABLES) & remaining, "downgrade must drop every M4 table"
