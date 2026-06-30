"""Worker ``acks_late`` + idempotency hardening (W2-T4) under REAL PostgreSQL.

With ``task_acks_late`` + ``task_reject_on_worker_lost`` (``celery_app.py``,
ADR-0008 §5), a task whose worker is scaled-in / killed mid-run is **redelivered,
not lost** (ADR-0043 §6). That is only safe if the task is idempotent — a re-run
must produce **no duplicate side effect** (the ADR names "a second discovery write,
a duplicate config capture, a double audit row" as the hazards). This module proves
that property on a real Postgres — never SQLite, whose write-locking / isolation
hide the very concurrency this protects (the standing P2 lesson, which is why the
W2-T4 spec mandates ``tests/pg/``):

  * **Config capture** — a ``config.capture_device`` persistence delivered TWICE
    for the same config yields exactly ONE ``config_snapshots`` row AND exactly ONE
    ``config.snapshot_captured`` audit row (the dedup'd re-delivery emits neither a
    second blob nor a second audit row — the "double audit row" hazard).
  * **ChangeRequest execution retry** — a redelivered execution handoff
    (``approved -> executing``) does NOT double-execute: the lifecycle state-machine
    guard makes the second attempt an idempotent ``ConflictError`` no-op (one
    transition, one audit row, the CR stays ``executing``), and the **four-eyes gate
    is not bypassed** (a self-approve is still refused). Idempotency hardens the
    execution handoff without weakening the ADR-0020 two-person control.

No real secret appears here: the only sentinel is an inert fake config string and
throwaway bcrypt-shaped hashes created inside the test, asserted to be absent from
audit detail where relevant.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from app.core.errors import ConflictError, ForbiddenError
from app.core.security import Role as SecurityRole
from app.models import AuditLog, Device, DeviceStatus
from app.models.change_requests import (
    Approval,
    ChangeRequest,
    ChangeRequestKind,
    ChangeRequestState,
)
from app.models.config_mgmt import ConfigSnapshot, ConfigSource
from app.models.identity import Role as DbRole
from app.models.identity import User
from app.services.change_requests.service import AUTOMATION_PRINCIPAL, ChangeRequestService
from app.workers.tasks import config as config_tasks

pytestmark = pytest.mark.integration

#: Inert config text — NOT a real device config, NOT a secret. Captured twice to
#: exercise the content-addressed dedup path under a simulated redelivery.
_RUNNING_CONFIG = "hostname pg-idem-test\n!\ninterface Gi0/0\n no shutdown\n!\nend\n"


async def _seed_device(session: AsyncSession, *, mgmt_ip: str = "10.10.0.1") -> uuid.UUID:
    """Insert one reachable device and return its id (FK target for snapshots)."""
    device = Device(
        mgmt_ip=mgmt_ip,
        hostname="pg-idem-test",
        vendor_id="cisco_ios",
        status=DeviceStatus.REACHABLE,
    )
    session.add(device)
    await session.flush()
    device_id = device.id
    await session.commit()
    return device_id


async def _engineer_role_id(session: AsyncSession) -> uuid.UUID:
    """Resolve the migration-seeded ``engineer`` role id (a real FK target)."""
    role_id = (
        await session.execute(select(DbRole.id).where(DbRole.name == "engineer"))
    ).scalar_one_or_none()
    if role_id is None:  # pragma: no cover - migration always seeds the role set
        raise AssertionError("migration did not seed the 'engineer' role")
    return role_id


async def _seed_user(session: AsyncSession, *, username: str, role_id: uuid.UUID) -> uuid.UUID:
    """Insert one local user with a throwaway (non-secret) password hash."""
    user = User(
        username=username,
        # Inert placeholder hash — never authenticated against, never a real secret.
        password_hash="$2b$12$pg.idem.test.placeholder.hash.value.not.a.secret",
        role_id=role_id,
    )
    session.add(user)
    await session.flush()
    user_id = user.id
    await session.commit()
    return user_id


# ---------------------------------------------------------------------------
# Config capture: double-delivery -> one snapshot row + one audit row
# ---------------------------------------------------------------------------


async def test_config_capture_double_delivery_yields_one_side_effect(
    pg_engine: AsyncEngine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A redelivered ``config.capture_device`` persist is idempotent on real PG.

    The worker's persistence path (``config._persist`` -> ``capture_snapshot``) is
    invoked twice for the SAME config — exactly what ``acks_late`` redelivery does
    after a worker kill mid-run. The content-addressed dedup must collapse it to one
    ``config_snapshots`` row, and the W2-T4 fix must collapse the audit trail to one
    ``config.snapshot_captured`` row (no "double audit row").
    """
    from contextlib import asynccontextmanager

    maker = async_sessionmaker(pg_engine, expire_on_commit=False)
    async with maker() as setup:
        device_id = await _seed_device(setup)

    # Point the worker's per-phase session seam at the REAL-PG engine so the task's
    # own persistence + audit code (``_persist``) runs verbatim against Postgres —
    # the seam ``config._session`` is the documented unit-test boundary, here bound
    # to the migrated PG engine instead of a throwaway one off settings.
    @asynccontextmanager
    async def _pg_session():  # type: ignore[no-untyped-def]
        async with maker() as session:
            yield session

    monkeypatch.setattr(config_tasks, "_session", _pg_session)

    # First delivery: a brand-new blob -> created=True, one snapshot, one audit row.
    hash1, created1 = await config_tasks._persist(
        device_id, _RUNNING_CONFIG, source=ConfigSource.ON_DEMAND, capture_run_id=None
    )
    # Second delivery (the redelivery): identical content -> dedup hit, created=False.
    hash2, created2 = await config_tasks._persist(
        device_id, _RUNNING_CONFIG, source=ConfigSource.ON_DEMAND, capture_run_id=None
    )

    assert created1 is True
    assert created2 is False
    assert hash1 == hash2

    async with maker() as check:
        snapshot_count = (
            await check.execute(
                select(func.count())
                .select_from(ConfigSnapshot)
                .where(ConfigSnapshot.device_id == device_id)
            )
        ).scalar_one()
        captured_audits = (
            await check.execute(
                select(func.count())
                .select_from(AuditLog)
                .where(AuditLog.action == "config.snapshot_captured")
            )
        ).scalar_one()

    # Exactly one side effect each: one stored blob, one audit row for the capture.
    assert snapshot_count == 1, "redelivery must not store a second config blob"
    assert captured_audits == 1, "redelivery must not append a second audit row"


# ---------------------------------------------------------------------------
# ChangeRequest retry: no double-execute, four-eyes gate not bypassed
# ---------------------------------------------------------------------------


async def test_cr_execution_retry_does_not_double_execute(pg_engine: AsyncEngine) -> None:
    """A redelivered CR execution handoff is an idempotent no-op (ADR-0020 gate intact).

    Drives a CR through the real four-eyes-gated lifecycle on Postgres, then claims
    it for execution (``approved -> executing``) TWICE — simulating a redelivered
    execution task. The second claim must be a ``ConflictError`` no-op, not a second
    transition: exactly one ``change_request.approved_to_executing`` audit row, the
    CR stays ``executing``, and the four-eyes approval row count is unchanged.
    """
    maker = async_sessionmaker(pg_engine, expire_on_commit=False)
    async with maker() as setup:
        role_id = await _engineer_role_id(setup)
        requester_id = await _seed_user(setup, username="pg-idem-requester", role_id=role_id)
        approver_id = await _seed_user(setup, username="pg-idem-approver", role_id=role_id)

    service = ChangeRequestService(maker)

    cr = await service.create_draft(
        requester_id=requester_id,
        actor_role=SecurityRole.ENGINEER,
        kind=ChangeRequestKind.CONFIG,
        target_refs={"device_ids": [str(uuid.uuid4())]},
    )
    await service.submit(cr.id, actor_id=requester_id, actor_role=SecurityRole.ENGINEER)

    # Four-eyes gate (ADR-0020 §3): the requester may NOT approve their own CR.
    with pytest.raises(ForbiddenError):
        await service.approve(cr.id, actor_id=requester_id, actor_role=SecurityRole.ENGINEER)

    # A distinct approver clears the gate.
    await service.approve(cr.id, actor_id=approver_id, actor_role=SecurityRole.ENGINEER)

    # First execution claim (the original delivery) transitions approved -> executing.
    executing = await service.mark_executing(cr.id, principal=AUTOMATION_PRINCIPAL)
    assert executing.state is ChangeRequestState.EXECUTING

    # Redelivery: the SAME claim again. The state-machine guard refuses it — the CR
    # is no longer ``approved`` — so it is an idempotent no-op, never a second write.
    with pytest.raises(ConflictError):
        await service.mark_executing(cr.id, principal=AUTOMATION_PRINCIPAL)

    async with maker() as check:
        reloaded = await check.get(ChangeRequest, cr.id)
        assert reloaded is not None
        assert reloaded.state is ChangeRequestState.EXECUTING, "retry must not advance the CR"

        executing_audits = (
            await check.execute(
                select(func.count())
                .select_from(AuditLog)
                .where(AuditLog.action == "change_request.approved_to_executing")
            )
        ).scalar_one()
        assert executing_audits == 1, "a redelivered execution must not double-emit the transition"

        # The four-eyes control produced exactly one approval row (the distinct
        # approver's); the self-approve never reached the database, and the retry
        # added nothing — the gate is not bypassed by idempotency.
        approval_count = (
            await check.execute(
                select(func.count())
                .select_from(Approval)
                .where(Approval.change_request_id == cr.id)
            )
        ).scalar_one()
        assert approval_count == 1
