"""Worker-kill idempotency probe for the W4-T5 drill (G-REL §319/§320).

G-REL §319/§320 (ADR-0008 §5 ``acks_late`` + ``task_reject_on_worker_lost``,
ADR-0043 §6, ADR-0020 four-eyes, ADR-0047 §2/§3/§5): with ``task_acks_late`` +
``task_reject_on_worker_lost`` (``celery_app.py``) a task whose worker node is
killed / scaled-in **mid-run** is **redelivered, not lost** — the message is
re-queued and a surviving worker runs it again. That is safe ONLY if the task is
idempotent: the SECOND run must produce **no duplicate side effect** — no second
DB write, no double ChangeRequest execution, no duplicate audit row — and the
four-eyes gate (ADR-0020) must not be bypassed on the retry. This module gives
the drill (worker-kill-idempotency.sh) three faithful, REAL-store primitives it
drives via ``kubectl exec`` on a backend-image worker pod inside the reduced-scale
HA kind cluster, each exercising the SAME W2-T4 code path the redelivery hits:

  * **config capture** — a ``config.capture_device`` persistence (``_persist`` ->
    ``capture_snapshot``) delivered TWICE for the same config (exactly what
    ``acks_late`` redelivery does after a worker kill mid-run) must collapse to
    exactly ONE ``config_snapshots`` row AND exactly ONE ``config.snapshot_captured``
    audit row (the content-addressed dedup + the W2-T4 audit-once fix).
  * **CR execution retry** — a redelivered execution handoff (``approved ->
    executing``) must NOT double-execute: the lifecycle state-machine guard makes
    the second attempt an idempotent ``ConflictError`` no-op (one transition, one
    audit row, the CR stays ``executing``), and the **four-eyes gate is not
    bypassed** (a self-approve is still refused). Idempotency hardens the handoff
    without weakening the ADR-0020 two-person control.
  * **nightly_backup orchestrator** — a redelivered ``config.nightly_backup`` with
    the SAME ``run_id`` must emit exactly ONE ``config.backup_run_started`` and ONE
    ``config.backup_run_finished`` audit row and dispatch exactly ONE fan-out wave
    — the ``config_backup_runs`` DB-level uniqueness guard (``ON CONFLICT DO
    NOTHING``) is the enforcement.

The drill's exactly-once assertion is that each of these produces exactly the
counts above, and its **Celery success-rate** assertion is that of ``ATTEMPTS``
redelivered task attempts (each = a worker-kill redelivery) at least
``SUCCESS_FLOOR`` percent complete-via-retry with no duplicate side effect
(G-REL §320 ≥ 99%). All are meaningful ONLY against real PostgreSQL (ADR-0047
§5): SQLite's single-writer model hides the write-locking / isolation / unique-
constraint semantics this exact idempotency depends on (the standing P2 lesson,
which is why the W2-T4 property lives in ``backend/tests/pg/`` and this live drill
asserts on the kind CNPG cluster, which IS real Postgres). There is NO SQLite path
— :func:`_sessionmaker` HARD-FAILS on a non-postgresql URL.

NEGATIVE CONTROL (ADR-0047 §2 — the single most important rule): with
``WORKER_IDEM_NEGATIVE_CONTROL=1`` the idempotency guard is DISABLED — the
content-addressed dedup is bypassed so the redelivered capture DOUBLE-WRITES (two
snapshot rows / two audit rows), and the CR execution handoff force-re-executes
(a second transition + a second audit row, and it does NOT re-check four-eyes).
This is exactly the ADR-0047 §2 worker-kill control ("remove ``acks_late`` /
idempotency guard → a re-delivered task double-writes"): the exactly-once
assertion goes RED. The drill ships this so it is a real gate, not green-at-setup.

Each subcommand prints ONE structured line the shell parses:
  ``DRILL worker_idem <sub> snapshots=<n> audits=<n> transitions=<n> approvals=<n>
   attempts=<n> succeeded=<n> success_pct=<n> result=PASS|FAIL``
and exits non-zero on any error (fail closed). No real secret appears: the only
sentinels are an inert fake config string and throwaway bcrypt-shaped hashes
created inside the probe.

Run (inside the worker pod; PYTHONPATH carries the app package):
  python /tmp/worker_idem_probe.py seed
  python /tmp/worker_idem_probe.py capture      # config double-delivery
  python /tmp/worker_idem_probe.py cr-retry     # CR execution retry + four-eyes
  python /tmp/worker_idem_probe.py backup       # nightly_backup double-delivery
  python /tmp/worker_idem_probe.py rate         # ATTEMPTS redeliveries -> success %
  python /tmp/worker_idem_probe.py purge
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
import uuid
from collections.abc import Sequence
from contextlib import asynccontextmanager
from typing import Any

_TAG = "DRILL worker_idem"

# FIXED reduced-scale drill identifiers (ADR-0047 §1 — reduced scale is STATED).
# Fixed UUIDs so seed/purge target exactly these rows and never an operator's real
# inventory in a shared database.
_DRILL_MGMT_IP = "10.79.0.1"
_DRILL_HOSTNAME = "drill-idem-1"
_REQUESTER_USERNAME = "w4t5-idem-requester"
_APPROVER_USERNAME = "w4t5-idem-approver"

#: Inert config text — NOT a real device config, NOT a secret. Captured twice to
#: exercise the content-addressed dedup path under a simulated redelivery.
_RUNNING_CONFIG = "hostname drill-idem-1\n!\ninterface Gi0/0\n no shutdown\n!\nend\n"

#: Redeliveries the success-rate window drives (each = one worker-kill redelivery).
_ATTEMPTS = int(os.environ.get("WORKER_IDEM_ATTEMPTS", "40"))
#: G-REL §320 success floor (percent). 99 by default; overridable for the self-test.
_SUCCESS_FLOOR = int(os.environ.get("WORKER_IDEM_SUCCESS_FLOOR", "99"))

#: NEGATIVE CONTROL (ADR-0047 §2): 1 disables the idempotency guard so a redelivery
#: double-writes → the exactly-once / success-rate assertions go RED.
_NEG_CONTROL = os.environ.get("WORKER_IDEM_NEGATIVE_CONTROL", "0") == "1"


def _emit(
    sub: str,
    *,
    snapshots: int = 0,
    audits: int = 0,
    transitions: int = 0,
    approvals: int = 0,
    attempts: int = 0,
    succeeded: int = 0,
    success_pct: int = 0,
    ok: bool = True,
) -> None:
    """Print the one structured line the shell drill parses (the count contract)."""
    result = "PASS" if ok else "FAIL"
    print(
        f"{_TAG} {sub} snapshots={snapshots} audits={audits} transitions={transitions} "
        f"approvals={approvals} attempts={attempts} succeeded={succeeded} "
        f"success_pct={success_pct} result={result}",
        flush=True,
    )


async def _sessionmaker() -> tuple[Any, Any]:
    """Build a Postgres engine + sessionmaker from the app settings (real PG).

    ADR-0047 §5: there is NO SQLite path — the write-locking / isolation / unique-
    constraint semantics this idempotency depends on do not exist on SQLite.
    """
    from app import db  # noqa: PLC0415
    from app.core.config import get_settings  # noqa: PLC0415

    settings = get_settings()
    url = settings.database_url
    if not url.startswith("postgresql"):
        raise RuntimeError(
            "worker_idem_probe requires real PostgreSQL (ADR-0047 §5) — "
            f"database_url is not a postgresql URL: {url.split('://', 1)[0]}://…"
        )
    engine = db.create_engine(settings)
    return engine, db.create_sessionmaker(engine)


# ---------------------------------------------------------------------------
# Seed / purge — the fixed reduced-scale drill fixtures in Postgres.
# ---------------------------------------------------------------------------


async def _purge(sm: Any) -> None:
    """Remove ONLY the rows this drill owns (keyed by the fixed drill ids)."""
    from sqlalchemy import delete, select  # noqa: PLC0415

    from app.models import AuditLog, Device  # noqa: PLC0415
    from app.models.change_requests import Approval, ChangeRequest  # noqa: PLC0415
    from app.models.config_mgmt import ConfigBackupRun, ConfigSnapshot  # noqa: PLC0415
    from app.models.identity import User  # noqa: PLC0415

    async with sm() as session:
        device_ids = list(
            (
                await session.execute(select(Device.id).where(Device.mgmt_ip == _DRILL_MGMT_IP))
            ).scalars()
        )
        if device_ids:
            await session.execute(
                delete(ConfigSnapshot).where(ConfigSnapshot.device_id.in_(device_ids))
            )
        # Drill-owned CRs: those raised by the drill requester.
        req_ids = list(
            (
                await session.execute(
                    select(User.id).where(
                        User.username.in_([_REQUESTER_USERNAME, _APPROVER_USERNAME])
                    )
                )
            ).scalars()
        )
        if req_ids:
            cr_ids = list(
                (
                    await session.execute(
                        select(ChangeRequest.id).where(ChangeRequest.requester_id.in_(req_ids))
                    )
                ).scalars()
            )
            if cr_ids:
                await session.execute(
                    delete(Approval).where(Approval.change_request_id.in_(cr_ids))
                )
                await session.execute(delete(ChangeRequest).where(ChangeRequest.id.in_(cr_ids)))
        # Drill-owned audit rows (scoped to the drill's snapshot/backup actions with
        # the drill device id in the detail is hard to target generically; instead
        # purge the drill's backup runs + the audit rows whose actor is the config
        # worker actor AND created for a drill device. We keep this conservative:
        # delete only backup runs owned by the drill run-ids we can enumerate — the
        # capture/backup counts below are asserted on a FRESH kind cluster anyway.
        await session.execute(
            delete(ConfigBackupRun).where(ConfigBackupRun.run_uuid.in_(_drill_backup_run_uuids()))
        )
        # Best-effort audit purge for the drill device (config actions carry the
        # device id in target_id for failures; snapshot captures reference the
        # snapshot id). We leave the general audit_log alone (append-only, REVOKEd)
        # and rely on the fresh-cluster assumption for capture/backup audit counts.
        if device_ids:
            await session.execute(
                delete(AuditLog).where(
                    AuditLog.target_id.in_([str(d) for d in device_ids]),
                    AuditLog.action == "config.snapshot_failed",
                )
            )
        # The nightly_backup started/finished audit pair carries target_id = the run
        # uuid; purge the drill's own (fixed) run-ids so a re-run against a persisted
        # DB does not leave a prior run's started/finished rows to inflate the
        # exactly-once count below into a false-RED. Scoped to the drill's run-ids
        # only — the general audit_log stays append-only / REVOKEd and untouched.
        await session.execute(
            delete(AuditLog).where(
                AuditLog.action.in_(
                    ["config.backup_run_started", "config.backup_run_finished"]
                ),
                AuditLog.target_id.in_([str(u) for u in _drill_backup_run_uuids()]),
            )
        )
        await session.execute(delete(Device).where(Device.mgmt_ip == _DRILL_MGMT_IP))
        if req_ids:
            await session.execute(delete(User).where(User.id.in_(req_ids)))
        await session.commit()


def _drill_backup_run_uuids() -> list[uuid.UUID]:
    """The stable nightly_backup run-ids the drill uses (so purge targets them).

    The first is the shared beat-tick id both deliveries carry on the POSITIVE
    path; the second is the DISTINCT id the NEGATIVE CONTROL drives the redelivery
    with to bypass the run-uuid dedup guard (see :func:`_cmd_backup`). Both are
    purged so a re-run — positive or negative — always starts from a clean row set.
    """
    return [
        uuid.UUID("00000000-0000-0000-0000-0000000d4d51"),
        _drill_backup_neg_run_uuid(),
    ]


def _drill_backup_neg_run_uuid() -> uuid.UUID:
    """The DISTINCT run-id the negative control uses to bypass the dedup guard."""
    return uuid.UUID("00000000-0000-0000-0000-0000000d4d52")


async def _seed_device(sm: Any) -> uuid.UUID:
    from app.models import Device, DeviceStatus  # noqa: PLC0415

    async with sm() as session:
        device = Device(
            mgmt_ip=_DRILL_MGMT_IP,
            hostname=_DRILL_HOSTNAME,
            vendor_id="cisco_ios",
            status=DeviceStatus.REACHABLE,
        )
        session.add(device)
        await session.flush()
        device_id = device.id
        await session.commit()
    return device_id


async def _seed_users(sm: Any) -> tuple[uuid.UUID, uuid.UUID]:
    from sqlalchemy import select  # noqa: PLC0415

    from app.models.identity import Role as DbRole  # noqa: PLC0415
    from app.models.identity import User  # noqa: PLC0415

    async with sm() as session:
        role_id = (
            await session.execute(select(DbRole.id).where(DbRole.name == "engineer"))
        ).scalar_one_or_none()
        if role_id is None:
            raise RuntimeError(
                "migration did not seed the 'engineer' role — cannot seed drill users"
            )
        ids: list[uuid.UUID] = []
        for username in (_REQUESTER_USERNAME, _APPROVER_USERNAME):
            user = User(
                username=username,
                # Inert placeholder hash — never authenticated against, never a secret.
                password_hash="$2b$12$w4t5.idem.drill.placeholder.hash.not.a.secret",
                role_id=role_id,
            )
            session.add(user)
            await session.flush()
            ids.append(user.id)
        await session.commit()
    return ids[0], ids[1]


async def _cmd_seed() -> int:
    engine, sm = await _sessionmaker()
    try:
        await _purge(sm)  # idempotent: re-seeding replaces the prior drill rows.
        await _seed_device(sm)
        await _seed_users(sm)
    finally:
        await engine.dispose()
    _emit("seed", ok=True)
    return 0


async def _cmd_purge() -> int:
    engine, sm = await _sessionmaker()
    try:
        await _purge(sm)
    finally:
        await engine.dispose()
    _emit("purge", ok=True)
    return 0


# ---------------------------------------------------------------------------
# capture — config.capture_device double-delivery -> exactly-once side effect.
# ---------------------------------------------------------------------------


async def _device_id(sm: Any) -> uuid.UUID:
    from sqlalchemy import select  # noqa: PLC0415

    from app.models import Device  # noqa: PLC0415

    async with sm() as session:
        did = (
            await session.execute(select(Device.id).where(Device.mgmt_ip == _DRILL_MGMT_IP))
        ).scalar_one_or_none()
    if did is None:
        raise RuntimeError("drill device not seeded — run `seed` before `capture`")
    return did


async def _count_snapshots(sm: Any, device_id: uuid.UUID) -> int:
    from sqlalchemy import func, select  # noqa: PLC0415

    from app.models.config_mgmt import ConfigSnapshot  # noqa: PLC0415

    async with sm() as session:
        return int(
            (
                await session.execute(
                    select(func.count())
                    .select_from(ConfigSnapshot)
                    .where(ConfigSnapshot.device_id == device_id)
                )
            ).scalar_one()
        )


async def _count_capture_audits(sm: Any, device_id: uuid.UUID) -> int:
    from sqlalchemy import func, select  # noqa: PLC0415

    from app.models import AuditLog  # noqa: PLC0415

    async with sm() as session:
        return int(
            (
                await session.execute(
                    select(func.count())
                    .select_from(AuditLog)
                    .where(
                        AuditLog.action == "config.snapshot_captured",
                        # detail->>'device_id' == the drill device (scope to OUR captures).
                        AuditLog.detail["device_id"].astext == str(device_id),
                    )
                )
            ).scalar_one()
        )


async def _deliver_capture(sm: Any, device_id: uuid.UUID) -> None:
    """Run the REAL worker persistence path once (a single ``acks_late`` delivery).

    On the POSITIVE path this is ``config._persist`` verbatim (content-address +
    dedup + audit-once). On the NEGATIVE CONTROL the idempotency guard is bypassed:
    a fresh snapshot row + audit row are written unconditionally, so a redelivery
    double-writes (the ADR-0047 §2 "idempotency guard removed" regression).
    """
    from app.workers.tasks import config as config_tasks  # noqa: PLC0415

    @asynccontextmanager
    async def _pg_session() -> Any:
        async with sm() as session:
            yield session

    # Point the worker's per-phase session seam at the drill sessionmaker so the
    # task's own persistence + audit code runs verbatim against the kind PG (the
    # documented unit-test seam, here bound to the live cluster engine).
    orig_session = config_tasks._session
    config_tasks._session = _pg_session
    try:
        if _NEG_CONTROL:
            await _deliver_capture_no_guard(sm, config_tasks, device_id)
        else:
            await config_tasks._persist(
                device_id,
                _RUNNING_CONFIG,
                source=_on_demand_source(),
                capture_run_id=None,
            )
    finally:
        config_tasks._session = orig_session


def _on_demand_source() -> Any:
    from app.models.config_mgmt import ConfigSource  # noqa: PLC0415

    return ConfigSource.ON_DEMAND


async def _deliver_capture_no_guard(sm: Any, config_tasks: Any, device_id: uuid.UUID) -> None:
    """NEGATIVE CONTROL: write a snapshot + audit row UNCONDITIONALLY (no dedup).

    This models the ADR-0047 §2 regression "remove the idempotency guard": every
    redelivery stores a NEW blob and emits a NEW ``config.snapshot_captured`` audit
    row, so N deliveries produce N side effects — the exactly-once assertion RED.
    """
    import hashlib  # noqa: PLC0415

    from app.models.config_mgmt import ConfigSnapshot  # noqa: PLC0415
    from app.services import audit  # noqa: PLC0415

    # A UNIQUE content hash per delivery defeats the content-address dedup that
    # would otherwise collapse the write — this is precisely the guard being removed.
    salt = uuid.uuid4().hex
    content_hash = hashlib.sha256((_RUNNING_CONFIG + salt).encode()).hexdigest()
    async with sm() as session:
        snap = ConfigSnapshot(
            device_id=device_id,
            content_hash=content_hash,
            content=_RUNNING_CONFIG,
            source=_on_demand_source(),
        )
        session.add(snap)
        await session.flush()
        await audit.record(
            session,
            actor="config-worker",
            action="config.snapshot_captured",
            target_type="config_snapshot",
            target_id=str(snap.id),
            detail={"device_id": str(device_id), "content_hash": content_hash, "created": True},
        )
        await session.commit()


async def _cmd_capture() -> int:
    engine, sm = await _sessionmaker()
    try:
        device_id = await _device_id(sm)
        # Two deliveries for the SAME config — exactly what an acks_late redelivery
        # after a worker kill produces. Positive: dedup → 1 side effect. Negative:
        # guard bypassed → 2 side effects.
        await _deliver_capture(sm, device_id)
        await _deliver_capture(sm, device_id)
        snapshots = await _count_snapshots(sm, device_id)
        audits = await _count_capture_audits(sm, device_id)
    finally:
        await engine.dispose()
    # Exactly-once: one blob, one audit row (the shell asserts ==1 each).
    ok = snapshots == 1 and audits == 1
    _emit("capture", snapshots=snapshots, audits=audits, ok=ok)
    return 0 if ok else 1


# ---------------------------------------------------------------------------
# cr-retry — CR execution handoff retry: no double-execute, four-eyes intact.
# ---------------------------------------------------------------------------


async def _cmd_cr_retry() -> int:
    from app.core.errors import ConflictError, ForbiddenError  # noqa: PLC0415
    from app.core.security import Role as SecurityRole  # noqa: PLC0415
    from app.models.change_requests import (  # noqa: PLC0415
        ChangeRequestKind,
        ChangeRequestState,
    )
    from app.services.change_requests.service import (  # noqa: PLC0415
        AUTOMATION_PRINCIPAL,
        ChangeRequestService,
    )

    engine, sm = await _sessionmaker()
    try:
        from sqlalchemy import func, select  # noqa: PLC0415

        from app.models import AuditLog  # noqa: PLC0415
        from app.models.change_requests import Approval, ChangeRequest  # noqa: PLC0415
        from app.models.identity import User  # noqa: PLC0415

        async with sm() as session:
            requester_id = (
                await session.execute(select(User.id).where(User.username == _REQUESTER_USERNAME))
            ).scalar_one()
            approver_id = (
                await session.execute(select(User.id).where(User.username == _APPROVER_USERNAME))
            ).scalar_one()

        service = ChangeRequestService(sm)
        cr = await service.create_draft(
            requester_id=requester_id,
            actor_role=SecurityRole.ENGINEER,
            kind=ChangeRequestKind.CONFIG,
            target_refs={"device_ids": [str(uuid.uuid4())]},
        )
        await service.submit(cr.id, actor_id=requester_id, actor_role=SecurityRole.ENGINEER)

        # Four-eyes gate (ADR-0020 §3): the requester may NOT approve their own CR.
        four_eyes_held = False
        try:
            await service.approve(cr.id, actor_id=requester_id, actor_role=SecurityRole.ENGINEER)
        except ForbiddenError:
            four_eyes_held = True
        # A distinct approver clears the gate.
        await service.approve(cr.id, actor_id=approver_id, actor_role=SecurityRole.ENGINEER)

        # First execution claim (the original delivery): approved -> executing.
        executing = await service.mark_executing(cr.id, principal=AUTOMATION_PRINCIPAL)
        first_ok = executing.state is ChangeRequestState.EXECUTING

        # Redelivery (the acks_late worker-kill retry): the SAME claim again.
        if _NEG_CONTROL:
            # NEGATIVE CONTROL: force a SECOND execution transition + audit row,
            # bypassing the state-machine guard (the ADR-0047 §2 "double CR
            # execution on retry" regression). We write the transition audit row
            # directly to model a handoff that does not re-check lifecycle state.
            await _force_second_transition(sm, cr.id)
            retry_was_noop = False
        else:
            retry_was_noop = False
            try:
                await service.mark_executing(cr.id, principal=AUTOMATION_PRINCIPAL)
            except ConflictError:
                retry_was_noop = True  # the guard refused the redelivery (idempotent no-op).

        async with sm() as session:
            reloaded = await session.get(ChangeRequest, cr.id)
            stayed_executing = (
                reloaded is not None and reloaded.state is ChangeRequestState.EXECUTING
            )
            transitions = int(
                (
                    await session.execute(
                        select(func.count())
                        .select_from(AuditLog)
                        .where(
                            AuditLog.action == "change_request.approved_to_executing",
                            AuditLog.target_id == str(cr.id),
                        )
                    )
                ).scalar_one()
            )
            approvals = int(
                (
                    await session.execute(
                        select(func.count())
                        .select_from(Approval)
                        .where(Approval.change_request_id == cr.id)
                    )
                ).scalar_one()
            )
    finally:
        await engine.dispose()

    # Exactly-once + gate intact: one transition, one approval, four-eyes held, CR
    # still executing, and (positive path) the retry was an idempotent no-op.
    ok = (
        first_ok
        and four_eyes_held
        and stayed_executing
        and transitions == 1
        and approvals == 1
        and (retry_was_noop or _NEG_CONTROL)
    )
    _emit("cr-retry", transitions=transitions, approvals=approvals, ok=ok)
    return 0 if ok else 1


async def _force_second_transition(sm: Any, cr_id: uuid.UUID) -> None:
    """NEGATIVE CONTROL: emit a SECOND approved_to_executing audit row (double-exec)."""
    from app.services import audit  # noqa: PLC0415

    async with sm() as session:
        await audit.record(
            session,
            actor="automation",
            action="change_request.approved_to_executing",
            target_type="change_request",
            target_id=str(cr_id),
            detail={"redelivery": True, "note": "negative-control forced double execution"},
        )
        await session.commit()


# ---------------------------------------------------------------------------
# backup — config.nightly_backup double-delivery -> one started/finished pair.
# ---------------------------------------------------------------------------


async def _cmd_backup() -> int:
    from app.workers.tasks import config as config_tasks  # noqa: PLC0415

    engine, sm = await _sessionmaker()
    try:
        device_id = await _device_id(sm)

        @asynccontextmanager
        async def _pg_session() -> Any:
            async with sm() as session:
                yield session

        async def _fake_reachable() -> list[uuid.UUID]:
            return [device_id]

        wave_calls: list[int] = []

        def _fake_dispatch(run_id: str, device_ids: list[str]) -> list[dict[str, Any]]:
            wave_calls.append(1)
            return [
                {"ok": True, "device_id": str(d), "content_hash": "drill", "created": True}
                for d in device_ids
            ]

        orig_session = config_tasks._session
        orig_reach = config_tasks._reachable_device_ids
        orig_dispatch = config_tasks._dispatch_captures
        config_tasks._session = _pg_session
        config_tasks._reachable_device_ids = _fake_reachable
        config_tasks._dispatch_captures = _fake_dispatch
        try:
            run_id = str(_drill_backup_run_uuids()[0])
            r1 = await config_tasks._nightly_backup_core(run_id=run_id)
            # Redelivery. POSITIVE: the SAME run_id (the beat-scheduled id both
            # deliveries carry) → the guard classifies it as a terminal duplicate and
            # `skips` it. NEGATIVE CONTROL (ADR-0047 §2): a DISTINCT run_id bypasses the
            # run-uuid ON CONFLICT DO NOTHING guard — modelling "remove the idempotency
            # guard → a re-delivered task double-writes". The second delivery is then
            # `claimed`, emits a SECOND started+finished audit pair, and fires a SECOND
            # fan-out wave, so started/finished read 2 and wave_calls==2 → the
            # exactly-once assertion below goes RED regardless of the guard working.
            redelivery_run_id = str(_drill_backup_neg_run_uuid()) if _NEG_CONTROL else run_id
            r2 = await config_tasks._nightly_backup_core(run_id=redelivery_run_id)
        finally:
            config_tasks._session = orig_session
            config_tasks._reachable_device_ids = orig_reach
            config_tasks._dispatch_captures = orig_dispatch

        from sqlalchemy import func, select  # noqa: PLC0415

        from app.models import AuditLog  # noqa: PLC0415

        async with sm() as session:
            # Scope the exactly-once count to the drill's OWN (fixed) run-ids so a
            # concurrent real beat nightly_backup firing during the drill window (a
            # DIFFERENT run uuid) cannot inflate the count into a false-RED; combined
            # with the _purge above (which clears this run's prior same-uuid rows),
            # the count reflects only this drill's deliveries.
            _drill_run_ids = [str(u) for u in _drill_backup_run_uuids()]
            started = int(
                (
                    await session.execute(
                        select(func.count())
                        .select_from(AuditLog)
                        .where(
                            AuditLog.action == "config.backup_run_started",
                            AuditLog.target_id.in_(_drill_run_ids),
                        )
                    )
                ).scalar_one()
            )
            finished = int(
                (
                    await session.execute(
                        select(func.count())
                        .select_from(AuditLog)
                        .where(
                            AuditLog.action == "config.backup_run_finished",
                            AuditLog.target_id.in_(_drill_run_ids),
                        )
                    )
                ).scalar_one()
            )
    finally:
        await engine.dispose()

    # Exactly-once: one started + one finished audit row, one fan-out wave, and the
    # redelivery returned "skipped" (the ON CONFLICT DO NOTHING guard). On the
    # NEGATIVE CONTROL the redelivery ran under a DISTINCT run_id (guard bypassed):
    # r2 is "succeeded" (not "skipped"), a SECOND started/finished pair landed, and a
    # SECOND fan-out wave fired → started/finished read 2 and len(wave_calls) == 2 →
    # every clause below fails → ok=False → RED (ADR-0047 §2 bite).
    ok = (
        r1["status"] == "succeeded"
        and r2["status"] == "skipped"
        and len(wave_calls) == 1
        and started == 1
        and finished == 1
    )
    _emit("backup", audits=(started + finished), attempts=len(wave_calls), ok=ok)
    return 0 if ok else 1


# ---------------------------------------------------------------------------
# rate — ATTEMPTS redeliveries -> Celery success rate (G-REL §320 >= 99%).
# ---------------------------------------------------------------------------


async def _cmd_rate() -> int:
    """Drive ATTEMPTS worker-kill redeliveries; each must complete exactly-once.

    Each attempt is one ``acks_late`` redelivery of the config-capture side effect
    for the drill device: the capture is delivered twice (the kill + the retry) and
    the attempt SUCCEEDS iff it collapses to exactly one snapshot row for that
    attempt. On the POSITIVE path every attempt dedups → success ~100% (>= 99%).
    On the NEGATIVE CONTROL the guard is off → each redelivery double-writes → the
    exactly-once invariant fails for every attempt → success 0% → RED (G-REL §320).
    """
    engine, sm = await _sessionmaker()
    succeeded = 0
    attempts = _ATTEMPTS
    try:
        device_id = await _device_id(sm)
        for _i in range(attempts):
            before = await _count_snapshots(sm, device_id)
            # Two deliveries of the SAME config for this attempt (kill + retry).
            await _deliver_capture(sm, device_id)
            await _deliver_capture(sm, device_id)
            after = await _count_snapshots(sm, device_id)
            # Exactly-once for THIS attempt: at most one NEW snapshot row (0 if the
            # content already existed from a prior attempt — same config text — which
            # is still exactly-once; the negative control adds 2 unique rows).
            if (after - before) <= 1:
                succeeded += 1
    finally:
        await engine.dispose()
    success_pct = int((succeeded * 100) // attempts) if attempts else 0
    ok = success_pct >= _SUCCESS_FLOOR
    _emit(
        "rate",
        attempts=attempts,
        succeeded=succeeded,
        success_pct=success_pct,
        ok=ok,
    )
    return 0 if ok else 1


_COMMANDS = {
    "seed": _cmd_seed,
    "purge": _cmd_purge,
    "capture": _cmd_capture,
    "cr-retry": _cmd_cr_retry,
    "backup": _cmd_backup,
    "rate": _cmd_rate,
}


def _parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="worker_idem_probe")
    parser.add_argument("command", choices=sorted(_COMMANDS))
    return parser.parse_args(list(argv) if argv is not None else None)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        return asyncio.run(_COMMANDS[args.command]())
    except Exception as exc:  # fail closed — a broken probe is never a pass.
        print(
            f"{_TAG} {args.command} ERROR={type(exc).__name__}: {exc}",
            file=sys.stderr,
            flush=True,
        )
        return 1


if __name__ == "__main__":  # pragma: no cover - module execution shim
    raise SystemExit(main())
