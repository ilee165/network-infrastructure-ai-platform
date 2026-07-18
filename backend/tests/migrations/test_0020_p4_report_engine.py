"""Migration 0020 (P4 W3-T1, ADR-0053 §1/§7.2): report engine + trend history.

Unit tests drive ``alembic upgrade --sql`` in-process against the PostgreSQL
dialect (no DB/Docker/network) and assert the ONE expand-only revision creates
all four ADR-0053 tables — ``report_runs`` / ``report_artifacts`` (§1) AND
``compliance_runs`` / ``compliance_run_findings`` (§7.2, same revision per the
ADR) — with the claim-guard unique constraint, the bytea artifact columns, and
NO evidence-excerpt column on the findings history (§6 layer 3).
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
    """Render ``alembic <direction> --sql`` for revision 0020 in isolation."""
    buffer = io.StringIO()
    if direction == "upgrade":
        command.upgrade(_alembic_config(buffer), "0019:0020", sql=True)
    else:
        command.downgrade(_alembic_config(buffer), "0020:0019", sql=True)
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


def test_single_head_no_branch() -> None:
    """`alembic heads` resolves to exactly one head (no branch).

    0020 was the head when W3-T1 landed; P4 W3-T5's 0021 now extends the same
    linear chain. Current-head assertion lives in
    ``test_0021_audit_chain_verification_runs.test_single_head_is_0021``.
    """
    script = ScriptDirectory.from_config(_alembic_config())
    heads = script.get_heads()
    assert len(heads) == 1, f"expected a single head (no branch), got {heads}"
    ancestry = {rev.revision for rev in script.iterate_revisions(heads[0], "base")}
    assert "0020" in ancestry, f"0020 must be on the line to the head, got {ancestry}"


def test_0020_revises_0019() -> None:
    script = ScriptDirectory.from_config(_alembic_config())
    rev = script.get_revision("0020")
    assert rev.down_revision == "0019"


# ---------------------------------------------------------------------------
# Offline SQL (no database required)
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("_postgres_dialect_env")
def test_offline_sql_creates_all_four_adr0053_tables_in_one_revision() -> None:
    """§7.2 lands in the SAME expand-only revision as the report model."""
    sql = _offline_sql("upgrade").upper()
    for table in (
        "REPORT_RUNS",
        "REPORT_ARTIFACTS",
        "COMPLIANCE_RUNS",
        "COMPLIANCE_RUN_FINDINGS",
    ):
        assert f"CREATE TABLE {table}" in sql, f"missing CREATE TABLE {table}"
    # Expand-only: this revision drops/alters nothing pre-existing.
    assert "DROP TABLE" not in sql
    assert "ALTER TABLE" not in sql.replace("ALTER TABLE REPORT", "").replace(
        "ALTER TABLE COMPLIANCE", ""
    )


@pytest.mark.usefixtures("_postgres_dialect_env")
def test_offline_sql_report_runs_claim_guard_and_artifact_columns() -> None:
    sql = _offline_sql("upgrade")
    upper = sql.upper()
    # DB-level idempotency guard beneath the deterministic claim UUID (§2).
    assert "UQ_REPORT_RUNS_KIND_PERIOD" in upper
    # Artifact integrity + retention columns (§1/§4): bytea + sha256 + expiry.
    artifacts_ddl = upper.split("CREATE TABLE REPORT_ARTIFACTS", 1)[1].split(";", 1)[0]
    assert "BYTEA" in artifacts_ddl
    assert "SHA256" in artifacts_ddl
    assert "EXPIRES_AT" in artifacts_ddl
    assert "IX_REPORT_ARTIFACTS_EXPIRES_AT" in upper
    # Typed failure class column — never free-form text (§1/§6).
    assert "ERROR_CLASS" in upper


@pytest.mark.usefixtures("_postgres_dialect_env")
def test_offline_sql_findings_history_is_secret_free_by_construction() -> None:
    """§6 layer 3: the findings table persists status/severity ONLY."""
    sql = _offline_sql("upgrade").upper()
    findings_ddl = sql.split("CREATE TABLE COMPLIANCE_RUN_FINDINGS", 1)[1].split(";", 1)[0]
    assert "STATUS" in findings_ddl
    assert "SEVERITY" in findings_ddl
    # Deliberately NO evidence/excerpt/content column exists to leak into.
    for banned in ("EVIDENCE", "EXCERPT", "CONTENT", "RAW_CONFIG"):
        assert banned not in findings_ddl, f"findings history must not carry {banned}"


@pytest.mark.usefixtures("_postgres_dialect_env")
def test_offline_sql_downgrade_drops_all_four_tables() -> None:
    sql = _offline_sql("downgrade").upper()
    for table in (
        "REPORT_RUNS",
        "REPORT_ARTIFACTS",
        "COMPLIANCE_RUNS",
        "COMPLIANCE_RUN_FINDINGS",
    ):
        assert re.search(rf"DROP TABLE {table}\b", sql), f"downgrade must drop {table}"
