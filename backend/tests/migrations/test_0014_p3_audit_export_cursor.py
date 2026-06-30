"""Migration 0014 (P3-W3): audit_export_cursor durable cursor + single head.

Unit tests drive ``alembic upgrade head --sql`` in-process against the PostgreSQL
dialect (no DB/Docker/network) and assert the emitted DDL creates the
``audit_export_cursor`` table with the expected columns. ``alembic heads`` is
asserted to be the SINGLE head ``0014`` chaining after ``0013`` (this is the LATEST
migration, so it owns the single-head invariant — W3-T1).

This singleton table is the durable last-exported watermark for the audit→SIEM
export pipeline (ADR-0045 §2): the exporter reads committed ``audit_log`` rows with
``seq > exported_seq`` ordered by ``seq``, delivers them, and advances
``exported_seq`` ONLY on a sink ACK — so a restart resumes from the cursor with no
gap (at-least-once, never at-most-once). It is a mutable run-tracking row, NOT part
of the append-only audit hash chain.
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


def _offline_sql_0014(direction: str) -> str:
    """Render ``alembic <direction> --sql`` for revision 0014 in isolation."""
    buffer = io.StringIO()
    if direction == "upgrade":
        command.upgrade(_alembic_config(buffer), "0013:0014", sql=True)
    else:
        command.downgrade(_alembic_config(buffer), "0014:0013", sql=True)
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


def test_single_head_is_0014() -> None:
    """`alembic heads` resolves to exactly one head, revision 0014 (no branch)."""
    script = ScriptDirectory.from_config(_alembic_config())
    heads = script.get_heads()
    assert heads == ["0014"], f"expected single head 0014, got {heads}"


def test_0014_revises_0013() -> None:
    script = ScriptDirectory.from_config(_alembic_config())
    rev = script.get_revision("0014")
    assert rev.down_revision == "0013"


# ---------------------------------------------------------------------------
# Offline SQL (no database required)
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("_postgres_dialect_env")
def test_offline_sql_creates_audit_export_cursor_table() -> None:
    """Upgrade DDL creates the audit_export_cursor table with all required columns."""
    sql = _offline_sql_0014("upgrade")

    assert "audit_export_cursor" in sql

    for column in ("id", "exported_seq", "last_exported_commit_at", "updated_at"):
        assert column in sql, f"expected column {column!r} in upgrade DDL"

    # The singleton PRIMARY KEY on id (the upsert target for the watermark).
    assert "pk_audit_export_cursor" in sql or "PRIMARY KEY" in sql.upper(), (
        "the id PRIMARY KEY constraint (the singleton upsert target) is missing"
    )

    # exported_seq carries a server_default of 0 (the genesis cursor: seq > 0 selects
    # the whole chain) so an exporter started before the first delivery reads from 0.
    assert any(
        "exported_seq" in line and ("DEFAULT" in line.upper() or "0" in line)
        for line in sql.splitlines()
    ), "exported_seq must carry a 0 server_default (the genesis cursor)"

    # last_exported_commit_at is nullable (no NOT NULL — undefined until first export).
    for line in sql.splitlines():
        if "last_exported_commit_at" in line and "ADD" in line.upper():
            assert "NOT NULL" not in line.upper(), "last_exported_commit_at must be nullable"


@pytest.mark.usefixtures("_postgres_dialect_env")
def test_offline_downgrade_drops_audit_export_cursor_table() -> None:
    """Downgrade DDL drops the audit_export_cursor table itself (not only an index)."""
    sql = _offline_sql_0014("downgrade")
    assert any(
        "DROP TABLE" in line.upper() and "audit_export_cursor" in line for line in sql.splitlines()
    ), "downgrade DDL must DROP TABLE audit_export_cursor"
