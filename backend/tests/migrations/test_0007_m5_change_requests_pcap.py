"""Migration 0007 (M5 ChangeRequest spine + pcap metadata): offline SQL + real run.

Unit tests drive ``alembic upgrade head --sql`` in-process against the
PostgreSQL dialect — no database, no Docker, no network — and assert on the
emitted DDL (the three new tables, the four-eyes *constraint trigger* and its
guard function, the uniqueness constraints, the conditional ``four_eyes_required``
predicate). The ``integration``-marked test runs a real upgrade against
``NETOPS_DATABASE_URL`` and exercises the security-critical behavior end to end:

- four_eyes_required = true  → an ``approve`` row with actor == requester RAISES,
- four_eyes_required = false → the same self-approval is ALLOWED (and still
  produces a distinct, audited ``approvals`` row),
- a ``reject`` self-decision is always allowed (only ``approve`` is constrained).

It skips cleanly when Postgres is unreachable. This is the DB backstop behind the
ChangeRequest service guard (ADR-0020 §2/§3; M5 exit criterion #2).
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

#: Tables migration 0007 must create (M5 task #2).
NEW_TABLES: tuple[str, ...] = ("change_requests", "approvals", "pcap_metadata")


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
def test_offline_sql_creates_m5_tables() -> None:
    sql = _offline_upgrade_sql()
    for table in NEW_TABLES:
        assert f"CREATE TABLE {table} (" in sql, f"missing CREATE TABLE for {table}"


@pytest.mark.usefixtures("_postgres_dialect_env")
def test_offline_sql_creates_four_eyes_constraint_trigger() -> None:
    """The four-eyes backstop is a CONSTRAINT TRIGGER + guard function (ADR-0020 §2).

    A single-row CHECK cannot reach ``change_requests.requester_id`` from an
    ``approvals`` row, so the cross-table rule is a constraint trigger.
    """
    sql = _offline_upgrade_sql()
    assert (
        "CREATE FUNCTION enforce_four_eyes" in sql
        or "CREATE OR REPLACE FUNCTION enforce_four_eyes" in sql
    )
    assert "CREATE CONSTRAINT TRIGGER" in sql
    # PL/pgSQL guard raises on a violation.
    assert "RAISE EXCEPTION" in sql


@pytest.mark.usefixtures("_postgres_dialect_env")
def test_offline_sql_four_eyes_is_conditional_on_flag() -> None:
    """The trigger raises ONLY when four_eyes_required is true (Wave-0 critical fix).

    An unconditional trigger would reject the very self-approval the documented
    ``four_eyes_required = false`` mode is meant to allow, making that mode
    unbuildable (ADR-0020 §2). So the guard reads the CR's flag and is scoped to
    decision = 'approved' / 'approve'.
    """
    sql = _offline_upgrade_sql()
    assert "four_eyes_required" in sql, "trigger guard must read four_eyes_required"


@pytest.mark.usefixtures("_postgres_dialect_env")
def test_offline_sql_declares_uniqueness_constraints() -> None:
    sql = _offline_upgrade_sql()
    assert "uq_pcap_metadata_capture_id" in sql


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


async def _table_names(url: str) -> set[str]:
    engine = create_async_engine(url, poolclass=NullPool)
    try:
        async with engine.connect() as conn:
            return set(
                (
                    await conn.execute(
                        text("SELECT tablename FROM pg_tables WHERE schemaname = current_schema()")
                    )
                ).scalars()
            )
    finally:
        await engine.dispose()


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


async def _create_cr(
    conn: object, requester_id: uuid.UUID, *, four_eyes_required: bool
) -> uuid.UUID:  # pragma: no cover - integration
    cr_id = uuid.uuid4()
    await conn.execute(  # type: ignore[attr-defined]
        text(
            "INSERT INTO change_requests (id, state, kind, requester_id, "
            "four_eyes_required, created_at, updated_at) "
            "VALUES (:id, 'draft', 'config', :req, :fer, now(), now())"
        ),
        {"id": cr_id, "req": requester_id, "fer": four_eyes_required},
    )
    return cr_id


async def _insert_approval(
    conn: object, cr_id: uuid.UUID, actor_id: uuid.UUID, decision: str
) -> None:  # pragma: no cover - integration
    await conn.execute(  # type: ignore[attr-defined]
        text(
            "INSERT INTO approvals (id, change_request_id, actor_id, decision, "
            "comment, created_at) VALUES (:id, :cr, :actor, :decision, 'c', now())"
        ),
        {"id": uuid.uuid4(), "cr": cr_id, "actor": actor_id, "decision": decision},
    )


@pytest.mark.integration
def test_migration_0007_creates_m5_schema_real_postgres() -> None:
    url = get_settings().database_url
    if not url.startswith("postgresql") or not _postgres_reachable(url):
        pytest.skip("PostgreSQL unreachable at NETOPS_DATABASE_URL; skipping integration test")

    cfg = _alembic_config()
    command.downgrade(cfg, "0006")
    command.upgrade(cfg, "head")
    try:
        tables = asyncio.run(_table_names(url))
    finally:
        command.downgrade(cfg, "0006")
    assert set(NEW_TABLES) <= tables

    remaining = asyncio.run(_table_names(url))
    assert not set(NEW_TABLES) & remaining, "downgrade must drop every M5 table"


@pytest.mark.integration
def test_migration_0007_four_eyes_constraint_trigger_behavior() -> None:
    """The DB constraint trigger enforces conditional four-eyes (ADR-0020 §2).

    enabled  → self-approval (actor == requester, decision approve) RAISES;
    disabled → the same self-approval is ALLOWED and recorded;
    reject self-decision is always allowed (only approve is constrained).
    """
    url = get_settings().database_url
    if not url.startswith("postgresql") or not _postgres_reachable(url):
        pytest.skip("PostgreSQL unreachable at NETOPS_DATABASE_URL; skipping integration test")

    cfg = _alembic_config()
    command.downgrade(cfg, "0006")
    command.upgrade(cfg, "head")

    async def exercise() -> None:
        engine = create_async_engine(url, poolclass=NullPool)
        try:
            async with engine.begin() as conn:
                requester = await _seed_user(conn, f"req-{uuid.uuid4().hex[:8]}")
                approver = await _seed_user(conn, f"app-{uuid.uuid4().hex[:8]}")

                # 1. four_eyes_required = true: a DIFFERENT approver is fine.
                cr_enabled = await _create_cr(conn, requester, four_eyes_required=True)
                await _insert_approval(conn, cr_enabled, approver, "approve")

                # 2. four_eyes_required = true: self-approval (approve) RAISES.
                cr_self = await _create_cr(conn, requester, four_eyes_required=True)
                raised = False
                try:
                    await _insert_approval(conn, cr_self, requester, "approve")
                except DBAPIError:
                    raised = True
                assert raised, "self-approval must be rejected when four_eyes_required is true"

            # A fresh transaction (the previous one is poisoned by the raise).
            async with engine.begin() as conn:
                requester2 = await _seed_user(conn, f"req2-{uuid.uuid4().hex[:8]}")

                # 3. four_eyes_required = false: self-approval is ALLOWED + recorded.
                cr_disabled = await _create_cr(conn, requester2, four_eyes_required=False)
                await _insert_approval(conn, cr_disabled, requester2, "approve")
                count = (
                    await conn.execute(
                        text(
                            "SELECT count(*) FROM approvals WHERE change_request_id = :cr "
                            "AND actor_id = :actor AND decision = 'approve'"
                        ),
                        {"cr": cr_disabled, "actor": requester2},
                    )
                ).scalar_one()
                assert count == 1, "self-approval must be allowed + audited when flag is false"

                # 4. A self-REJECT is always allowed (only approve is constrained).
                cr_reject = await _create_cr(conn, requester2, four_eyes_required=True)
                await _insert_approval(conn, cr_reject, requester2, "reject")
        finally:
            await engine.dispose()

    try:
        asyncio.run(exercise())
    finally:
        command.downgrade(cfg, "0006")
