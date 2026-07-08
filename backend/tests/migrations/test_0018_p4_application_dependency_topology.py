"""Migration 0018 (P4 W2-T1, ADR-0052 §1): application-dependency tables +
single head.

Unit tests drive ``alembic upgrade --sql`` in-process against the PostgreSQL
dialect (no DB/Docker/network) and assert the emitted DDL creates the two
tables (``applications``, ``application_dependencies``) with their key
columns, CHECK constraints, the case-insensitive unique name index, the
partial-unique ``origin_ref`` index, the natural-key unique constraint, and
the reverse ``(target_kind, target_ref)`` index. This is an **expand-only**
migration (two new tables, no edits to existing ones). ``alembic heads`` is
asserted to be the SINGLE head ``0018`` chaining after ``0017``.
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
    cfg = Config(output_buffer=output_buffer) if output_buffer is not None else Config()
    cfg.set_main_option("script_location", str(BACKEND_DIR / "alembic"))
    return cfg


def _offline_sql_0018(direction: str) -> str:
    """Render ``alembic <direction> --sql`` for revision 0018 in isolation."""
    buffer = io.StringIO()
    if direction == "upgrade":
        command.upgrade(_alembic_config(buffer), "0017:0018", sql=True)
    else:
        command.downgrade(_alembic_config(buffer), "0018:0017", sql=True)
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


def test_single_head_is_0018() -> None:
    """`alembic heads` resolves to exactly one head, revision 0018 (no branch)."""
    script = ScriptDirectory.from_config(_alembic_config())
    heads = script.get_heads()
    assert heads == ["0018"], f"expected single head 0018, got {heads}"


def test_0018_revises_0017() -> None:
    script = ScriptDirectory.from_config(_alembic_config())
    rev = script.get_revision("0018")
    assert rev.down_revision == "0017"


# ---------------------------------------------------------------------------
# Offline SQL (no database required)
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("_postgres_dialect_env")
def test_offline_sql_creates_both_tables_with_adr_0052_columns() -> None:
    sql = _offline_sql_0018("upgrade").upper()

    assert "CREATE TABLE APPLICATIONS" in sql
    apps_segment = sql[sql.index("CREATE TABLE APPLICATIONS") :]
    apps_segment = apps_segment[: apps_segment.index("CREATE TABLE APPLICATION_DEPENDENCIES")]
    for column in (
        "NAME",
        "DESCRIPTION",
        "FQDNS",
        "ORIGIN",
        "ORIGIN_REF",
        "OWNER",
        "CREATED_BY",
        "DERIVED_WATERMARK",
    ):
        assert column in apps_segment, f"missing column {column} on APPLICATIONS"
    # String-plus-CHECK enum discipline (ADR-0052 §1) + non-empty name.
    assert "ORIGIN IN ('MANUAL', 'DERIVED')" in apps_segment
    assert "LENGTH(NAME) > 0" in apps_segment

    deps_segment = sql[sql.index("CREATE TABLE APPLICATION_DEPENDENCIES") :]
    for column in (
        "APPLICATION_ID",
        "TARGET_KIND",
        "TARGET_REF",
        "SOURCE",
        "PROVENANCE",
        "DERIVED_AT",
        "CREATED_BY",
    ):
        assert column in deps_segment, f"missing column {column} on APPLICATION_DEPENDENCIES"
    assert "TARGET_KIND IN ('DEVICE', 'IP_ADDRESS')" in deps_segment
    assert "SOURCE IN ('F5', 'VMWARE', 'DNS', 'MANUAL')" in deps_segment
    # Natural key + ON DELETE CASCADE (ADR-0052 §1).
    assert "UQ_APPLICATION_DEPENDENCIES_NATURAL_KEY" in deps_segment
    assert "ON DELETE CASCADE" in deps_segment


@pytest.mark.usefixtures("_postgres_dialect_env")
def test_offline_sql_creates_the_three_special_indexes() -> None:
    sql = _offline_sql_0018("upgrade").upper()
    # Case-insensitive unique name (expression index).
    assert "UQ_APPLICATIONS_LOWER_NAME" in sql
    assert "LOWER(NAME)" in sql
    # Partial-unique origin_ref where not null.
    assert "UQ_APPLICATIONS_ORIGIN_REF" in sql
    assert "ORIGIN_REF IS NOT NULL" in sql
    # Reverse ("what depends on X") read index.
    assert "IX_APPLICATION_DEPENDENCIES_TARGET" in sql


@pytest.mark.usefixtures("_postgres_dialect_env")
def test_offline_sql_is_expand_only() -> None:
    """New tables only — the DDL never ALTERs or DROPs an existing object
    (ADR-0004 / N-2 upgrade discipline)."""
    sql = _offline_sql_0018("upgrade").upper()
    assert "ALTER TABLE" not in sql.replace("ALTER TABLE APPLICATIONS", "").replace(
        "ALTER TABLE APPLICATION_DEPENDENCIES", ""
    )
    assert "DROP TABLE" not in sql
    assert "DROP COLUMN" not in sql


@pytest.mark.usefixtures("_postgres_dialect_env")
def test_offline_downgrade_drops_both_tables() -> None:
    sql = _offline_sql_0018("downgrade").upper()
    assert "DROP TABLE APPLICATION_DEPENDENCIES" in sql
    assert "DROP TABLE APPLICATIONS" in sql
