"""Migration 0023 schema conformance for the durable report dispatch outbox."""

from __future__ import annotations

import io
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


@pytest.fixture()
def _postgres_dialect_env(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setenv(
        "NETOPS_DATABASE_URL", "postgresql+asyncpg://netops:netops@127.0.0.1:5432/netops"
    )
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.mark.usefixtures("_postgres_dialect_env")
def test_0023_payload_and_consumer_ownership_match_postgresql_orm_contract() -> None:
    buffer = io.StringIO()
    command.upgrade(_alembic_config(buffer), "0022:0023", sql=True)
    sql = buffer.getvalue().upper()
    table = sql.split("CREATE TABLE DISPATCH_OUTBOX", 1)[1].split(";", 1)[0]
    assert "PAYLOAD_JSON JSONB" in table
    for column in (
        "CONSUMER_STATE",
        "CONSUMER_OWNER",
        "CONSUMER_CLAIMED_AT",
        "CONSUMER_FINISHED_AT",
        "CONSUMER_ERROR_CODE",
    ):
        assert column in table


def test_single_head_is_0024() -> None:
    script = ScriptDirectory.from_config(_alembic_config())
    assert script.get_heads() == ["0024"]
