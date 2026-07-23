"""Postgres-backed test harness (W5-T0) — boots REAL PostgreSQL, runs migrations.

This fixture layer is the answer to the recurring W4 review root cause: the unit
suite runs on in-memory aiosqlite, which silently passes code that is wrong under
**PostgreSQL** (the four documented false-PASSes — ``NULLS FIRST`` ordering, a
unique index on a partitioned table, ``REVOKE ... UPDATE`` append-only, and the
``prev_hash`` chain walk). Every test in :mod:`tests.pg` re-asserts a W4 security
control against a real Postgres, so the W5-T3 phase-exit evidence does not rest on
a backend that hides the bug it claims to gate.

Provisioning (CI-gating-first, W5-T0 spec §Scope):
  * The Postgres URL comes from ``NETOPS_TEST_DATABASE_URL`` (the CI ``services:
    postgres`` job sets it; falls back to the compose default for a local run with
    a reachable Postgres). It is normalised to the ``postgresql+asyncpg://`` async
    driver regardless of how it is supplied.
  * The schema is built by running the REAL ``alembic upgrade head`` against that
    database — the migration path (partitioned ``audit_log``, the ``REVOKE``, the
    per-partition ``seq`` index) is itself part of what SQLite never exercises, so
    we run it rather than ``Base.metadata.create_all``.

Local-skip discipline (L1, W5-T0 spec §Scope / Requirement 2): this layer is a
**separate CI job**, NOT part of the default SQLite smoke. When no Postgres is
reachable (the no-Docker dev host) the whole module **skips with an explicit
reason** at collection time — never a silent green, never a hard failure. The skip
is driven by an actual connection probe (``asyncpg.connect``), so a misconfigured
URL that cannot connect skips with the connection error in the reason rather than
erroring every test.

Determinism (Requirement 6): the schema is migrated ONCE per session, and every
test truncates the tables it touches in its own fixture teardown, so there is no
cross-test ordering dependence on a shared database.
"""

from __future__ import annotations

import asyncio
import os
from collections.abc import AsyncIterator, Iterator
from pathlib import Path

import pytest
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import NullPool

#: The Postgres URL the CI ``services: postgres`` job sets; the compose default is
#: a convenience for a local run with a reachable Postgres. NEVER a real secret —
#: the dev/CI credential is ``netops``/``netops`` on an ephemeral throwaway DB.
_DEFAULT_PG_URL = "postgresql+asyncpg://netops:netops@127.0.0.1:5432/netops_test"

#: Tables the PG tests write to. Truncated per test (CASCADE so the partitioned
#: ``audit_log`` children and FK-referencing rows go too) for a deterministic,
#: order-independent fixture (Requirement 6). Beyond the W4-control tables this
#: adds the W2-T4 worker-idempotency surface: ``config_snapshots`` (config-capture
#: redelivery dedup) and the ChangeRequest spine (``change_requests`` / ``approvals``
#: + the ``users`` the four-eyes guard compares — CASCADE removes the CR/approval/FK
#: rows the throwaway users own; the migration-seeded ``roles`` are intentionally
#: NOT truncated so a freshly-created test user can reference a real role).
_RESET_TABLES = (
    "audit_chain_checkpoint",
    "audit_export_cursor",
    "audit_log",
    "config_archives",
    "config_backup_runs",
    "config_snapshots",
    "approvals",
    "change_requests",
    "devices",
    "device_credentials",
    "users",
    # W2-T1 application-dependency layer (ADR-0052 §1): CASCADE removes the
    # dependency rows with their applications.
    "application_dependencies",
    "applications",
    # P4 W3-T1 report engine + compliance trend history (ADR-0053 §1/§7.2):
    # CASCADE removes artifacts/findings with their runs.
    "report_artifacts",
    "dispatch_outbox",
    "report_runs",
    "compliance_run_findings",
    "compliance_runs",
    # P4 W3-T5 audit chain verification history (ADR-0053 §7.4).
    "audit_chain_verification_runs",
    # M3 trace tables are partitioned; reasoning_trace_steps intentionally has
    # no FK to reasoning_traces, so users ... CASCADE cannot clean orphan steps.
    "reasoning_trace_steps",
    "reasoning_traces",
    "agent_sessions",
)


def _async_url() -> str:
    """Resolve the Postgres URL, normalised to the ``postgresql+asyncpg`` driver."""
    raw = os.environ.get("NETOPS_TEST_DATABASE_URL", _DEFAULT_PG_URL)
    if raw.startswith("postgresql+asyncpg://"):
        return raw
    if raw.startswith("postgresql://"):
        return "postgresql+asyncpg://" + raw[len("postgresql://") :]
    if raw.startswith("postgres://"):
        return "postgresql+asyncpg://" + raw[len("postgres://") :]
    return raw


async def _probe(url: str) -> str | None:
    """Return ``None`` if Postgres is reachable, else a human-readable skip reason."""
    import asyncpg  # local import: asyncpg is a prod dep, but keep collection cheap.

    # asyncpg speaks the bare libpq URL (no SQLAlchemy ``+asyncpg`` suffix).
    libpq = url.replace("postgresql+asyncpg://", "postgresql://")
    try:
        conn = await asyncio.wait_for(asyncpg.connect(libpq), timeout=5)
    except Exception as exc:  # noqa: BLE001 - any connect failure is a clean skip
        return f"{type(exc).__name__}: {exc}"
    await conn.close()
    return None


# Probe ONCE at import time so the whole package skips with a clear reason on a
# host with no Postgres (L1). A reachable-but-broken URL skips with the connection
# error in the reason rather than ERRORING every test in fixture setup.
_SKIP_REASON = asyncio.run(_probe(_async_url()))


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Skip every ``tests/pg/`` item BEFORE fixtures run when no Postgres is reachable.

    A ``pytestmark`` defined in a ``conftest.py`` does NOT propagate to test items,
    and a fixture-level ``pytest.skip`` would still let ``_migrated_pg`` try (and
    ERROR) the connection. Applying the skip here — at collection, keyed off the
    import-time probe — guarantees the whole PG layer SKIPS CLEANLY (exit 0, never a
    fixture error) on the no-Docker dev host (L1), while CI's ``services: postgres``
    job (where the probe succeeds) runs them and bites on a regression.
    """
    if _SKIP_REASON is None:
        return
    skip = pytest.mark.skip(
        reason=(
            "no reachable PostgreSQL for the W5-T0 PG harness "
            f"(NETOPS_TEST_DATABASE_URL / compose default) — {_SKIP_REASON}. "
            "This layer is a separate CI job (services: postgres); it skips cleanly "
            "off-CI (L1)."
        )
    )
    for item in items:
        # Only this package's items (conftest is package-scoped, but be explicit).
        if "tests/pg/" in item.nodeid.replace("\\", "/"):
            item.add_marker(skip)


def _alembic_config() -> object:
    """Build an Alembic ``Config`` pointed at the backend ``alembic/`` tree.

    ``alembic upgrade head`` reads the URL from application settings (``env.py``),
    so the caller sets ``NETOPS_DATABASE_URL`` to the test URL before invoking.
    """
    from alembic.config import Config

    backend_root = Path(__file__).resolve().parents[2]
    config = Config(str(backend_root / "alembic.ini"))
    config.set_main_option("script_location", str(backend_root / "alembic"))
    return config


@pytest.fixture(scope="session")
def _migrated_pg() -> Iterator[str]:
    """Run ``alembic upgrade head`` ONCE against the real Postgres; yield the URL.

    The migration path itself (partitioned ``audit_log`` parent + monthly
    partitions, the per-partition ``seq`` index, the ``REVOKE UPDATE, DELETE``) is
    part of what SQLite never exercises — so the harness runs the real migrations,
    not ``create_all``. ``env.py`` reads the DB URL from ``NETOPS_DATABASE_URL``;
    we set it (and ``NETOPS_ADMIN_PASSWORD`` so migration 0001 does not emit the
    insecure-default warning) for the duration of the upgrade.
    """
    from alembic import command

    from app.core.config import get_settings

    url = _async_url()
    prev_db = os.environ.get("NETOPS_DATABASE_URL")
    prev_admin = os.environ.get("NETOPS_ADMIN_PASSWORD")
    os.environ["NETOPS_DATABASE_URL"] = url
    # A throwaway, non-default bootstrap password so 0001 seeds without the
    # insecure-default warning. NOT a real secret — the DB is ephemeral and
    # destroyed with the CI job; never asserted on, never logged by a test.
    os.environ.setdefault("NETOPS_ADMIN_PASSWORD", "pg-harness-throwaway")
    get_settings.cache_clear()
    try:
        command.upgrade(_alembic_config(), "head")
        yield url
    finally:
        if prev_db is None:
            os.environ.pop("NETOPS_DATABASE_URL", None)
        else:
            os.environ["NETOPS_DATABASE_URL"] = prev_db
        if prev_admin is None:
            os.environ.pop("NETOPS_ADMIN_PASSWORD", None)
        else:
            os.environ["NETOPS_ADMIN_PASSWORD"] = prev_admin
        get_settings.cache_clear()


@pytest.fixture()
async def pg_engine(_migrated_pg: str) -> AsyncIterator[AsyncEngine]:
    """A real-Postgres async engine (``NullPool``) on the migrated schema.

    ``NullPool`` gives each session its own connection so concurrency tests see
    true cross-connection behaviour (the advisory-lock guard), mirroring the W4
    audit-chain concurrency fixture. The W4-control tables are TRUNCATEd before
    and after each test so the suite is order-independent (Requirement 6).
    """
    from sqlalchemy import text

    engine = create_async_engine(_migrated_pg, poolclass=NullPool)

    async def _reset() -> None:
        async with engine.begin() as conn:
            # CASCADE so the partitioned audit_log children + any FK rows go too;
            # RESTART IDENTITY is harmless (no serial here) but keeps it explicit.
            await conn.execute(
                text("TRUNCATE TABLE " + ", ".join(_RESET_TABLES) + " RESTART IDENTITY CASCADE")
            )

    await _reset()
    try:
        yield engine
    finally:
        await _reset()
        await engine.dispose()


@pytest.fixture()
async def pg_session(pg_engine: AsyncEngine) -> AsyncIterator[AsyncSession]:
    """An :class:`AsyncSession` bound to the real-Postgres engine."""
    maker = async_sessionmaker(pg_engine, expire_on_commit=False)
    async with maker() as session:
        yield session
