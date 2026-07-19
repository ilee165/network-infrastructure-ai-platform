"""Migration 0019 (Settings T1.3): device_credentials.disabled_at soft-disable.

Unit tests drive ``alembic upgrade --sql`` in-process against the PostgreSQL
dialect (no DB/Docker/network) and assert the emitted DDL adds nullable
``disabled_at`` to ``device_credentials``. Expand-only (no crypto columns).
``alembic heads`` is asserted to be the SINGLE head ``0019`` after ``0018``.
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


def _offline_sql(direction: str) -> str:
    """Render ``alembic <direction> --sql`` for revision 0019 in isolation."""
    buffer = io.StringIO()
    if direction == "upgrade":
        command.upgrade(_alembic_config(buffer), "0018:0019", sql=True)
    else:
        command.downgrade(_alembic_config(buffer), "0019:0018", sql=True)
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

    0019 was the head when Settings T1.3 landed; P4 W3-T1's 0020 now extends
    the same linear chain. Current-head assertion lives in
    ``test_0020_p4_report_engine.test_single_head_is_0020``.
    """
    script = ScriptDirectory.from_config(_alembic_config())
    heads = script.get_heads()
    assert len(heads) == 1, f"expected a single head (no branch), got {heads}"
    ancestry = {rev.revision for rev in script.iterate_revisions(heads[0], "base")}
    assert "0019" in ancestry, f"0019 must be on the line to the head, got {ancestry}"


def test_0019_revises_0018() -> None:
    script = ScriptDirectory.from_config(_alembic_config())
    rev = script.get_revision("0019")
    assert rev.down_revision == "0018"


# ---------------------------------------------------------------------------
# Offline SQL (no database required)
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("_postgres_dialect_env")
def test_offline_sql_adds_nullable_disabled_at() -> None:
    sql = _offline_sql("upgrade")
    upper = sql.upper()
    assert "DEVICE_CREDENTIALS" in upper
    assert "DISABLED_AT" in upper
    assert "ADD COLUMN" in upper
    # Nullable expand: no NOT NULL on the new column.
    # Alembic emits TIMESTAMP (WITH TIME ZONE) for DateTime(timezone=True).
    assert "NOT NULL" not in upper.split("DISABLED_AT", 1)[1].split("\n", 1)[0]


@pytest.mark.usefixtures("_postgres_dialect_env")
def test_offline_sql_downgrade_drops_disabled_at() -> None:
    sql = _offline_sql("downgrade").upper()
    assert "DROP COLUMN" in sql
    assert "DISABLED_AT" in sql
