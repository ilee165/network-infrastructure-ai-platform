"""Migration 0013 (P3-W2): config_backup_runs idempotency guard table + single head.

Unit tests drive ``alembic upgrade head --sql`` in-process against the PostgreSQL
dialect (no DB/Docker/network) and assert the emitted DDL creates the
``config_backup_runs`` table with the expected columns. Revision ``0013`` chains
after ``0012`` (the single-head invariant is now owned by the LATEST migration's
test — ``test_0014_p3_audit_export_cursor.py`` — since 0014 superseded 0013 as head).

This table is the DB-level idempotency guard for ``config.nightly_backup``:
a redelivered task (``task_acks_late`` + ``task_reject_on_worker_lost``)
INSERTs ON CONFLICT DO NOTHING and skips the fan-out + audit emit when the
row already exists (ADR-0043 §6 / ADR-0008 §5).
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


def _offline_sql_0013(direction: str) -> str:
    """Render ``alembic <direction> --sql`` for revision 0013 in isolation."""
    buffer = io.StringIO()
    if direction == "upgrade":
        command.upgrade(_alembic_config(buffer), "0012:0013", sql=True)
    else:
        command.downgrade(_alembic_config(buffer), "0013:0012", sql=True)
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
# Revision wiring (the single-head invariant moved to the 0014 test — see header).
# ---------------------------------------------------------------------------


def test_0013_revises_0012() -> None:
    script = ScriptDirectory.from_config(_alembic_config())
    rev = script.get_revision("0013")
    assert rev.down_revision == "0012"


def test_0013_is_an_ancestor_of_the_single_head() -> None:
    """0013 stays on the single linear chain below the current head (no branch)."""
    script = ScriptDirectory.from_config(_alembic_config())
    heads = script.get_heads()
    assert len(heads) == 1, f"expected a single head, got {heads}"
    # 0013 must be reachable walking down from the single head — it is still on the
    # one linear chain (0014 chained onto it), never orphaned by a branch.
    chain = {rev.revision for rev in script.walk_revisions("base", heads[0])}
    assert "0013" in chain


# ---------------------------------------------------------------------------
# Offline SQL (no database required)
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("_postgres_dialect_env")
def test_offline_sql_creates_config_backup_runs_table() -> None:
    """Upgrade DDL creates the config_backup_runs table with all required columns."""
    sql = _offline_sql_0013("upgrade")

    # Table creation
    assert "config_backup_runs" in sql

    # Required columns
    for column in ("run_uuid", "scheduled_slot", "status", "started_at"):
        assert column in sql, f"expected column {column!r} in upgrade DDL"

    # The PRIMARY KEY constraint on run_uuid is the idempotency guard (ON CONFLICT
    # targets it); without it the column names would still appear but the dedup
    # would be broken at the DDL level (F-mig-95).
    assert "pk_config_backup_runs" in sql or "PRIMARY KEY" in sql.upper(), (
        "the run_uuid PRIMARY KEY constraint (the ON CONFLICT idempotency target) "
        "is missing from the upgrade DDL"
    )

    # finished_at is nullable (no NOT NULL)
    for line in sql.splitlines():
        if "finished_at" in line and "ADD" in line.upper():
            assert "NOT NULL" not in line, "finished_at must be nullable"


@pytest.mark.usefixtures("_postgres_dialect_env")
def test_offline_downgrade_drops_config_backup_runs_table() -> None:
    """Downgrade DDL drops the config_backup_runs table."""
    sql = _offline_sql_0013("downgrade")
    assert "config_backup_runs" in sql
    # The downgrade must DROP THE TABLE itself, not merely its index: a generic
    # "DROP" check passes on the index drop alone even if the table drop were
    # removed, leaving the table behind (F-mig-103).
    assert any(
        "DROP TABLE" in line.upper() and "config_backup_runs" in line for line in sql.splitlines()
    ), "downgrade DDL must DROP TABLE config_backup_runs (not only its index)"
