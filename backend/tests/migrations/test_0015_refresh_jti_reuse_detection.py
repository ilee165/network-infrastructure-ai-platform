"""Migration 0015 (audit Wave 2 item 3): refresh-reuse jti hash column + single head.

Unit tests drive ``alembic upgrade --sql`` in-process against the PostgreSQL
dialect (no DB/Docker/network) and assert the emitted DDL adds the additive,
NULLABLE ``refresh_sessions.current_jti_hash`` column (the Wave 2 rollback plan
depends on the column being nullable: a code revert leaves a harmless column,
no emergency down-migration). ``alembic heads`` is asserted to be the SINGLE
head ``0015`` chaining after ``0014`` (this is the LATEST migration, so it owns
the single-head invariant).

The column stores only the SHA-256 hex of the current refresh ``jti`` — never
token material; the live reuse-detection behaviour is covered by
``tests/api/test_auth_refresh.py`` and the real-Postgres shape by
``tests/pg/test_refresh_reuse.py``.
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


def _offline_sql_0015(direction: str) -> str:
    """Render ``alembic <direction> --sql`` for revision 0015 in isolation."""
    buffer = io.StringIO()
    if direction == "upgrade":
        command.upgrade(_alembic_config(buffer), "0014:0015", sql=True)
    else:
        command.downgrade(_alembic_config(buffer), "0015:0014", sql=True)
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


def test_single_head_no_branch() -> None:
    """`alembic heads` resolves to exactly one head (no branch).

    The single-head invariant now belongs to the LATEST migration
    (``tests/migrations/test_0016_config_archives.py``); 0015 no longer owns the
    head but must remain on the single, unbranched chain.
    """
    script = ScriptDirectory.from_config(_alembic_config())
    heads = script.get_heads()
    assert len(heads) == 1, f"expected a single unbranched head, got {heads}"
    # 0015 must still be a reachable ancestor of that head.
    ancestry = {rev.revision for rev in script.walk_revisions("base", heads[0])}
    assert "0015" in ancestry


def test_0015_revises_0014() -> None:
    script = ScriptDirectory.from_config(_alembic_config())
    rev = script.get_revision("0015")
    assert rev.down_revision == "0014"


# ---------------------------------------------------------------------------
# Offline SQL (no database required)
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("_postgres_dialect_env")
def test_offline_sql_adds_nullable_current_jti_hash_column() -> None:
    """Upgrade DDL adds refresh_sessions.current_jti_hash as NULLABLE varchar(64)."""
    sql = _offline_sql_0015("upgrade")

    alter_lines = [
        line
        for line in sql.splitlines()
        if "ALTER TABLE" in line.upper() and "refresh_sessions" in line
    ]
    assert len(alter_lines) == 1, f"expected one ALTER TABLE refresh_sessions, got {alter_lines}"
    line = alter_lines[0]
    assert "current_jti_hash" in line
    assert "VARCHAR(64)" in line.upper()
    # Additive + nullable is the Wave 2 rollback contract: pre-0015 rows stay
    # valid and a code revert leaves a harmless column.
    assert "NOT NULL" not in line.upper(), "current_jti_hash must be nullable"


@pytest.mark.usefixtures("_postgres_dialect_env")
def test_offline_downgrade_drops_current_jti_hash_column() -> None:
    """Downgrade DDL drops exactly the current_jti_hash column (never the table)."""
    sql = _offline_sql_0015("downgrade")
    assert any(
        "DROP COLUMN" in line.upper() and "current_jti_hash" in line for line in sql.splitlines()
    ), "downgrade DDL must DROP COLUMN current_jti_hash"
    assert not any(
        "DROP TABLE" in line.upper() and "refresh_sessions" in line for line in sql.splitlines()
    ), "downgrade must never drop the refresh_sessions table"
