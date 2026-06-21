"""Migration 0010 (ADR-0028 OIDC): offline SQL for the federated-identity schema.

Drives ``alembic upgrade/downgrade --sql`` in-process against the PostgreSQL
dialect — no database, no Docker, no network — and asserts on the emitted DDL:
the two nullable ``users`` anchor columns and the partial UNIQUE index that
backs the one-federated-identity-⇒-one-row invariant (ADR-0028 §6).
"""

from __future__ import annotations

import io
from collections.abc import Generator
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config

from app.core.config import get_settings

BACKEND_DIR = Path(__file__).resolve().parents[2]

NEW_USER_COLUMNS: tuple[str, ...] = ("idp_iss", "idp_subject")


def _alembic_config(output_buffer: io.StringIO | None = None) -> Config:
    cfg = Config(output_buffer=output_buffer) if output_buffer is not None else Config()
    cfg.set_main_option("script_location", str(BACKEND_DIR / "alembic"))
    return cfg


def _offline_sql(direction: str) -> str:
    buffer = io.StringIO()
    if direction == "upgrade":
        command.upgrade(_alembic_config(buffer), "0009:0010", sql=True)
    else:
        command.downgrade(_alembic_config(buffer), "0010:0009", sql=True)
    return buffer.getvalue()


@pytest.fixture()
def _postgres_dialect_env(monkeypatch: pytest.MonkeyPatch) -> Generator[None, None, None]:
    monkeypatch.setenv(
        "NETOPS_DATABASE_URL", "postgresql+asyncpg://netops:netops@127.0.0.1:5432/netops"
    )
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.mark.usefixtures("_postgres_dialect_env")
def test_offline_sql_adds_idp_anchor_columns() -> None:
    sql = _offline_sql("upgrade")
    for column in NEW_USER_COLUMNS:
        assert f"ALTER TABLE users ADD COLUMN {column}" in sql, f"missing users.{column}"


@pytest.mark.usefixtures("_postgres_dialect_env")
def test_offline_sql_creates_partial_unique_index() -> None:
    sql = _offline_sql("upgrade")
    assert "CREATE UNIQUE INDEX uq_users_idp_identity" in sql
    # Partial predicate exempts local users (NULL anchor) — the 1:1 backstop.
    assert "WHERE idp_subject IS NOT NULL" in sql


@pytest.mark.usefixtures("_postgres_dialect_env")
def test_offline_downgrade_reverses_upgrade() -> None:
    sql = _offline_sql("downgrade")
    assert "DROP INDEX uq_users_idp_identity" in sql
    for column in NEW_USER_COLUMNS:
        assert f"ALTER TABLE users DROP COLUMN {column}" in sql, f"downgrade must drop {column}"
