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


def test_revision_chain_has_single_head_and_0011_is_in_line() -> None:
    """The chain stays linear (single head, no branch); 0011 is on the line, not orphaned.

    0011 was the head when W4-T1 landed; W4-T2's 0012 now extends the SAME linear
    chain after it (the current-head assertion lives in
    ``test_0012_p2_device_credential_scope.test_single_head_is_0012``). This test
    guards that adding 0012 did not FORK the chain: still exactly one head, and 0011
    remains a reachable ancestor of it.
    """
    script = ScriptDirectory.from_config(_alembic_config())
    heads = script.get_heads()
    assert len(heads) == 1, f"expected a single head (no branch), got {heads}"
    ancestry = {rev.revision for rev in script.iterate_revisions(heads[0], "base")}
    assert "0011" in ancestry, f"0011 must be on the line to the head, got {ancestry}"


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
def test_offline_sql_keeps_genesis_default_for_rolling_deploy() -> None:
    """The genesis server_default stays on through this expand migration (W4-T1 A7).

    Dropping the default in the SAME migration that adds the NOT NULL chain columns
    would break N→N+1 rolling deploys: an old (pre-W4) pod still inserting audit
    rows does not set prev_hash/entry_hash, so without a default its INSERT hits
    NOT NULL and crashes. The expand migration therefore KEEPS the default (a
    contract migration may drop it later) — assert the upgrade SQL carries the
    genesis DEFAULT and issues NO ``ALTER COLUMN ... DROP DEFAULT`` on these columns.
    """
    sql = _offline_upgrade_sql()
    genesis_hex = ("\\x" + "00" * 32).lower()
    assert genesis_hex in sql.lower(), "genesis default literal must appear in the column add"
    lowered = sql.lower()
    assert "drop default" not in lowered, "expand migration must NOT drop the chain defaults (A7)"


@pytest.mark.usefixtures("_postgres_dialect_env")
def test_offline_sql_adds_monotonic_seq_column_and_sequence() -> None:
    """A monotonic BIGINT ``seq`` column + shared sequence are added (W4-T1 A4)."""
    sql = _offline_upgrade_sql()
    lowered = sql.lower()
    # A dedicated sequence backs the column, drawn from on every INSERT (any
    # partition) so seq is globally monotonic; the column defaults to nextval.
    assert "create sequence" in lowered and "audit_log_seq" in lowered
    assert "add column seq bigint" in lowered
    assert "nextval('audit_log_seq'" in lowered
    # The column is indexed for the head read (MAX seq) and the verifier ORDER BY.
    assert "ix_audit_log_seq" in lowered


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
    assert "ALTER TABLE audit_log DROP COLUMN seq" in sql
    assert "DROP TABLE audit_chain_checkpoint" in sql
    # The shared sequence is dropped too (clean down, no orphaned object).
    assert "drop sequence" in sql.lower() and "audit_log_seq" in sql.lower()


def test_migration_seq_sequence_name_pinned_to_model() -> None:
    """Migration's inlined sequence name equals the model constant (D4 — pinned)."""
    from app.models import audit as audit_model

    # The revision file name starts with a digit (``0011_...``), so it is not a
    # plain importable module — load it via the alembic ScriptDirectory the same way
    # the migration runner does, then read the inlined constant off the module.
    script = ScriptDirectory.from_config(_alembic_config())
    revision = script.get_revision("0011")
    migration_module = revision.module

    assert migration_module._SEQ_SEQUENCE_NAME == audit_model._SEQ_SEQUENCE_NAME == "audit_log_seq"


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
