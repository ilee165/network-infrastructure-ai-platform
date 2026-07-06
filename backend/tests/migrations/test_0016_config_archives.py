"""Migration 0016 (P4 W1-T1, ADR-0050 §7.3): config_archives table + single head.

Unit tests drive ``alembic upgrade --sql`` in-process against the PostgreSQL
dialect (no DB/Docker/network) and assert the emitted DDL creates the
``config_archives`` table with the second (platform) envelope columns
(``ciphertext`` / ``nonce`` / ``wrapped_dek`` / ``dek_nonce`` / ``kek_version``)
alongside the log-safe metadata (device, format, size, sha256, passphrase_ref).
This is an **expand-only** migration (a new table, no edits to existing ones).
``0016`` chains after ``0015``; the single-head invariant now belongs to
``0017`` (see ``test_0017_p4_adc_virtualization_inventory.py``).
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


def _offline_sql_0016(direction: str) -> str:
    """Render ``alembic <direction> --sql`` for revision 0016 in isolation."""
    buffer = io.StringIO()
    if direction == "upgrade":
        command.upgrade(_alembic_config(buffer), "0015:0016", sql=True)
    else:
        command.downgrade(_alembic_config(buffer), "0016:0015", sql=True)
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


def test_0016_is_an_ancestor_of_the_single_head() -> None:
    """0016 stays on the single linear chain below the current head (no branch).

    The single-head invariant now belongs to the LATEST migration
    (``tests/migrations/test_0017_p4_adc_virtualization_inventory.py``); 0016 no
    longer owns the head but must remain on the single, unbranched chain.
    """
    script = ScriptDirectory.from_config(_alembic_config())
    heads = script.get_heads()
    assert len(heads) == 1, f"expected a single unbranched head, got {heads}"
    ancestry = {rev.revision for rev in script.walk_revisions("base", heads[0])}
    assert "0016" in ancestry


def test_0016_revises_0015() -> None:
    script = ScriptDirectory.from_config(_alembic_config())
    rev = script.get_revision("0016")
    assert rev.down_revision == "0015"


# ---------------------------------------------------------------------------
# Offline SQL (no database required)
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("_postgres_dialect_env")
def test_offline_sql_creates_config_archives_table() -> None:
    sql = _offline_sql_0016("upgrade").upper()
    assert "CREATE TABLE CONFIG_ARCHIVES" in sql
    # The at-rest double-envelope columns (parity with device_credentials).
    for column in ("CIPHERTEXT", "NONCE", "WRAPPED_DEK", "DEK_NONCE", "KEK_VERSION"):
        assert column in sql, f"missing envelope column {column}"
    # Log-safe metadata columns.
    for column in ("SIZE_BYTES", "SHA256", "PASSPHRASE_REF", "ARCHIVE_FORMAT"):
        assert column in sql, f"missing metadata column {column}"


@pytest.mark.usefixtures("_postgres_dialect_env")
def test_offline_downgrade_drops_config_archives_table() -> None:
    sql = _offline_sql_0016("downgrade").upper()
    assert "DROP TABLE CONFIG_ARCHIVES" in sql
