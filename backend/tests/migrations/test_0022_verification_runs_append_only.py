"""Migration 0022 (PR #166 F3): verification-history append-only parity.

Unit tests drive ``alembic upgrade --sql`` in-process against the PostgreSQL
dialect (no DB/Docker/network) and assert the revision mirrors BOTH existing
append-only controls onto ``audit_chain_verification_runs``: the 0001-style
``REVOKE UPDATE, DELETE ... FROM PUBLIC`` and the 0009-style ``BEFORE UPDATE
OR DELETE`` guard trigger that RAISES. The behavioral proof — a real UPDATE/
DELETE REFUSED on live PostgreSQL — lives in
``tests/pg/test_audit_integrity_pg.py::test_verification_history_is_append_only_on_pg``.
``alembic heads`` is asserted to be the SINGLE head ``0022`` after ``0021``.
"""

from __future__ import annotations

import io
import re
from collections.abc import Iterator
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory

from app.core.config import get_settings

BACKEND_DIR = Path(__file__).resolve().parents[2]


def _alembic_config(output_buffer: io.StringIO | None = None) -> Config:
    cfg = Config(output_buffer=output_buffer) if output_buffer is not None else Config()
    cfg.set_main_option("script_location", str(BACKEND_DIR / "alembic"))
    return cfg


def _offline_sql(direction: str) -> str:
    """Render ``alembic <direction> --sql`` for revision 0022 in isolation."""
    buffer = io.StringIO()
    if direction == "upgrade":
        command.upgrade(_alembic_config(buffer), "0021:0022", sql=True)
    else:
        command.downgrade(_alembic_config(buffer), "0022:0021", sql=True)
    return buffer.getvalue()


@pytest.fixture()
def _postgres_dialect_env(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setenv(
        "NETOPS_DATABASE_URL", "postgresql+asyncpg://netops:netops@127.0.0.1:5432/netops"
    )
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


# ---------------------------------------------------------------------------
# Single head + revision wiring
# ---------------------------------------------------------------------------


def test_single_head_is_0024() -> None:
    script = ScriptDirectory.from_config(_alembic_config())
    heads = script.get_heads()
    assert heads == ["0024"], f"expected single head 0024, got {heads}"


def test_0022_revises_0021() -> None:
    script = ScriptDirectory.from_config(_alembic_config())
    rev = script.get_revision("0022")
    assert rev.down_revision == "0021"


# ---------------------------------------------------------------------------
# Offline SQL (no database required)
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("_postgres_dialect_env")
def test_offline_sql_revokes_and_creates_append_only_guard() -> None:
    """Both controls land: the PUBLIC REVOKE and the RAISE-ing guard trigger."""
    sql = _offline_sql("upgrade")
    assert re.search(r"REVOKE UPDATE, DELETE ON audit_chain_verification_runs FROM PUBLIC", sql), (
        sql
    )
    assert re.search(r"CREATE FUNCTION enforce_verification_runs_append_only\(\)", sql), sql
    assert re.search(r"RAISE EXCEPTION", sql), sql
    assert re.search(
        r"CREATE TRIGGER trg_verification_runs_append_only\s+"
        r"BEFORE UPDATE OR DELETE ON audit_chain_verification_runs",
        sql,
    ), sql


@pytest.mark.usefixtures("_postgres_dialect_env")
def test_offline_sql_touches_no_other_table() -> None:
    """The revision only guards the history table — no DDL on anything else."""
    sql = _offline_sql("upgrade")
    assert not re.search(r"\bALTER TABLE\b", sql), sql
    assert not re.search(r"\bDROP TABLE\b", sql), sql
    assert not re.search(r"\bCREATE TABLE\b", sql), sql


@pytest.mark.usefixtures("_postgres_dialect_env")
def test_offline_sql_downgrade_drops_trigger_and_function() -> None:
    sql = _offline_sql("downgrade")
    assert re.search(
        r"DROP TRIGGER IF EXISTS trg_verification_runs_append_only\s+"
        r"ON audit_chain_verification_runs",
        sql,
    ), sql
    assert re.search(r"DROP FUNCTION IF EXISTS enforce_verification_runs_append_only\(\)", sql), sql
