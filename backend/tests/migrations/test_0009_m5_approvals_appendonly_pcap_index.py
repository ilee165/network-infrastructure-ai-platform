"""Migration 0009 (approvals append-only guard + pcap retention index).

Unit tests render ``alembic upgrade head --sql`` in-process against the
PostgreSQL dialect — no database, no Docker, no network — and assert on the
emitted DDL (the new ``retention_expires_at`` index, the append-only guard
function + ``BEFORE UPDATE OR DELETE`` trigger). The ``integration``-marked test
runs a real upgrade against ``NETOPS_DATABASE_URL`` and asserts the security
behavior end to end: an ``UPDATE`` or ``DELETE`` of an ``approvals`` row RAISES,
while ``INSERT`` still succeeds (the append-only audit guarantee, ADR-0020 §2).

It skips cleanly when Postgres is unreachable. Mirrors the 0007 four-eyes
migration test harness.
"""

from __future__ import annotations

import asyncio
import io
import uuid
from collections.abc import Generator
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import NullPool

from app.core.config import get_settings

BACKEND_DIR = Path(__file__).resolve().parents[2]


def _alembic_config(output_buffer: io.StringIO | None = None) -> Config:
    """Programmatic Config: no ini file, so env.py skips fileConfig (caplog-safe)."""
    cfg = Config(output_buffer=output_buffer) if output_buffer is not None else Config()
    cfg.set_main_option("script_location", str(BACKEND_DIR / "alembic"))
    return cfg


def _offline_upgrade_sql() -> str:
    """Render ``alembic upgrade head --sql`` and return the generated SQL."""
    buffer = io.StringIO()
    command.upgrade(_alembic_config(buffer), "head", sql=True)
    return buffer.getvalue()


@pytest.fixture()
def _postgres_dialect_env(monkeypatch: pytest.MonkeyPatch) -> Generator[None, None, None]:
    """Pin a PostgreSQL-dialect URL so offline rendering is deterministic."""
    monkeypatch.setenv(
        "NETOPS_DATABASE_URL", "postgresql+asyncpg://netops:netops@127.0.0.1:5432/netops"
    )
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


# ---------------------------------------------------------------------------
# Unit: offline SQL generation (no database required)
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("_postgres_dialect_env")
def test_offline_sql_indexes_retention_expires_at() -> None:
    """The purge column gets an index so retention scans don't full-scan."""
    sql = _offline_upgrade_sql()
    assert "ix_pcap_metadata_retention_expires_at" in sql
    assert "retention_expires_at" in sql


@pytest.mark.usefixtures("_postgres_dialect_env")
def test_offline_sql_creates_append_only_guard() -> None:
    """approvals gets a BEFORE UPDATE OR DELETE guard that raises (ADR-0020 §2)."""
    sql = _offline_upgrade_sql()
    assert (
        "CREATE FUNCTION enforce_approvals_append_only" in sql
        or "CREATE OR REPLACE FUNCTION enforce_approvals_append_only" in sql
    )
    assert "trg_approvals_append_only" in sql
    assert "BEFORE UPDATE OR DELETE ON approvals" in sql
    assert "RAISE EXCEPTION" in sql


# ---------------------------------------------------------------------------
# Integration: real upgrade against NETOPS_DATABASE_URL
# ---------------------------------------------------------------------------


def _postgres_reachable(url: str) -> bool:
    async def probe() -> bool:
        engine = create_async_engine(url, poolclass=NullPool, connect_args={"timeout": 3})
        try:
            async with engine.connect():
                return True
        finally:
            await engine.dispose()

    try:
        return asyncio.run(probe())
    except Exception:
        return False


async def _seed_user(conn: object, username: str) -> uuid.UUID:  # pragma: no cover - integration
    role_id = uuid.uuid4()
    user_id = uuid.uuid4()
    await conn.execute(  # type: ignore[attr-defined]
        text(
            "INSERT INTO roles (id, name, created_at, updated_at) VALUES (:id, :name, now(), now())"
        ),
        {"id": role_id, "name": f"role-{username}"},
    )
    await conn.execute(  # type: ignore[attr-defined]
        text(
            "INSERT INTO users (id, username, password_hash, role_id, is_active, "
            "must_change_password, created_at, updated_at) "
            "VALUES (:id, :username, 'x', :role_id, true, false, now(), now())"
        ),
        {"id": user_id, "username": username, "role_id": role_id},
    )
    return user_id


@pytest.mark.integration
def test_migration_0009_approvals_are_append_only() -> None:
    """An UPDATE or DELETE of an approvals row RAISES; INSERT still works."""
    url = get_settings().database_url
    if not url.startswith("postgresql") or not _postgres_reachable(url):
        pytest.skip("PostgreSQL unreachable at NETOPS_DATABASE_URL; skipping integration test")

    cfg = _alembic_config()
    command.downgrade(cfg, "0006")
    command.upgrade(cfg, "head")

    async def exercise() -> None:
        engine = create_async_engine(url, poolclass=NullPool)
        try:
            # Seed a requester, a different approver, a CR, and one approval row.
            async with engine.begin() as conn:
                requester = await _seed_user(conn, f"req-{uuid.uuid4().hex[:8]}")
                approver = await _seed_user(conn, f"app-{uuid.uuid4().hex[:8]}")
                cr_id = uuid.uuid4()
                await conn.execute(
                    text(
                        "INSERT INTO change_requests (id, state, kind, requester_id, "
                        "four_eyes_required, created_at, updated_at) "
                        "VALUES (:id, 'draft', 'config', :req, true, now(), now())"
                    ),
                    {"id": cr_id, "req": requester},
                )
                approval_id = uuid.uuid4()
                await conn.execute(
                    text(
                        "INSERT INTO approvals (id, change_request_id, actor_id, decision, "
                        "comment, created_at) VALUES (:id, :cr, :actor, 'approve', 'c', now())"
                    ),
                    {"id": approval_id, "cr": cr_id, "actor": approver},
                )

            # UPDATE must raise.
            update_raised = False
            try:
                async with engine.begin() as conn:
                    await conn.execute(
                        text("UPDATE approvals SET comment = 'tampered' WHERE id = :id"),
                        {"id": approval_id},
                    )
            except DBAPIError:
                update_raised = True
            assert update_raised, "UPDATE of an approvals row must be rejected (append-only)"

            # DELETE must raise.
            delete_raised = False
            try:
                async with engine.begin() as conn:
                    await conn.execute(
                        text("DELETE FROM approvals WHERE id = :id"), {"id": approval_id}
                    )
            except DBAPIError:
                delete_raised = True
            assert delete_raised, "DELETE of an approvals row must be rejected (append-only)"

            # The row is intact (neither tampered nor removed).
            async with engine.connect() as conn:
                count = (
                    await conn.execute(
                        text("SELECT count(*) FROM approvals WHERE id = :id AND comment = 'c'"),
                        {"id": approval_id},
                    )
                ).scalar_one()
            assert count == 1, "the original approval row must survive the blocked mutations"
        finally:
            await engine.dispose()

    try:
        asyncio.run(exercise())
    finally:
        command.downgrade(cfg, "0006")
