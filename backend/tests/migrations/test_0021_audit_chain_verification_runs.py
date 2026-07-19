"""Migration 0021 (P4 W3-T5, ADR-0053 §7.4): audit chain verification history.

Unit tests drive ``alembic upgrade --sql`` in-process against the PostgreSQL
dialect (no DB/Docker/network) and assert the ONE expand-only revision creates
``audit_chain_verification_runs`` — the persisted per-run outcome of the daily
ADR-0038 chain-verification CronJob (started/finished, verified range,
clean|break outcome, checkpoint hex before/after, daily grant-attestation
outcome) — with the report's period index, and that the downgrade drops it.
``alembic heads`` is asserted to be the SINGLE head ``0021`` after ``0020``.
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
    """Render ``alembic <direction> --sql`` for revision 0021 in isolation."""
    buffer = io.StringIO()
    if direction == "upgrade":
        command.upgrade(_alembic_config(buffer), "0020:0021", sql=True)
    else:
        command.downgrade(_alembic_config(buffer), "0021:0020", sql=True)
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


def test_single_head() -> None:
    # The exact-head pin moved to test_0022 (the newest revision's test file);
    # this keeps the no-branch invariant, matching the 0019/0020 convention.
    script = ScriptDirectory.from_config(_alembic_config())
    heads = script.get_heads()
    assert len(heads) == 1, f"expected a single head (no branch), got {heads}"


def test_0021_revises_0020() -> None:
    script = ScriptDirectory.from_config(_alembic_config())
    rev = script.get_revision("0021")
    assert rev.down_revision == "0020"


# ---------------------------------------------------------------------------
# Offline SQL (no database required)
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("_postgres_dialect_env")
def test_offline_sql_creates_history_table_with_spec_columns() -> None:
    """The expand revision creates the §7.4 table: run window, range, outcome,
    checkpoint hex before/after, and the daily grant-attestation outcome."""
    sql = _offline_sql("upgrade")
    assert re.search(r"CREATE TABLE audit_chain_verification_runs\b", sql)
    for column in (
        "started_at",
        "finished_at",
        "outcome",
        "entries_checked",
        "range_from_entry_id",
        "range_to_entry_id",
        "checkpoint_before_hash",
        "checkpoint_after_hash",
        "grant_check_outcome",
    ):
        assert re.search(rf"\b{column}\b", sql), f"missing column {column!r} in:\n{sql}"
    # The audit-integrity report selects the CLOSED-OPEN period over started_at.
    assert re.search(r"CREATE INDEX ix_audit_chain_verification_runs_started_at\b", sql), sql


@pytest.mark.usefixtures("_postgres_dialect_env")
def test_offline_sql_is_expand_only() -> None:
    """No ALTER/DROP of any existing table — the revision only ADDS (expand)."""
    sql = _offline_sql("upgrade")
    assert not re.search(r"\bALTER TABLE (?!audit_chain_verification_runs\b)", sql), sql
    assert not re.search(r"\bDROP TABLE\b", sql), sql


@pytest.mark.usefixtures("_postgres_dialect_env")
def test_offline_sql_downgrade_drops_the_table() -> None:
    sql = _offline_sql("downgrade")
    assert re.search(r"DROP INDEX ix_audit_chain_verification_runs_started_at\b", sql)
    assert re.search(r"DROP TABLE audit_chain_verification_runs\b", sql)
