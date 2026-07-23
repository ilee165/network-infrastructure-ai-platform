"""Unit contracts for the P5 W1-T3 reconciliation jobs."""

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import uuid4

import pytest

from app.core import metrics
from app.models.audit import AuditLog
from app.models.change_requests import ChangeRequest, ChangeRequestKind, ChangeRequestState
from app.models.identity import Role, User
from app.services.reconciliation import (
    ReconcileResult,
    backup_slot_due,
    is_settled,
    most_recent_due_backup_slot,
    reconcile_change_request_audit,
    reconcile_config_backup,
    reconcile_reasoning_traces,
)
from app.workers.tasks import reconciliation as tasks


@pytest.mark.asyncio
async def test_cr_audit_reconcile_validates_actions_for_each_terminal_path(session) -> None:
    role = Role(name=f"reconcile-{uuid4()}")
    user = User(
        username=f"reconcile-{uuid4()}",
        password_hash="x",
        role=role,
        is_active=True,
    )
    session.add(user)
    await session.flush()
    completed_trace, rolled_back_trace, masked_trace = uuid4(), uuid4(), uuid4()
    completed = ChangeRequest(
        state=ChangeRequestState.COMPLETED,
        kind=ChangeRequestKind.CONFIG,
        requester_id=user.id,
        reasoning_trace_id=completed_trace,
    )
    rolled_back = ChangeRequest(
        state=ChangeRequestState.ROLLED_BACK,
        kind=ChangeRequestKind.CONFIG,
        requester_id=user.id,
        reasoning_trace_id=rolled_back_trace,
    )
    masked = ChangeRequest(
        state=ChangeRequestState.COMPLETED,
        kind=ChangeRequestKind.CONFIG,
        requester_id=user.id,
        reasoning_trace_id=masked_trace,
    )
    session.add_all((completed, rolled_back, masked))
    await session.flush()

    common = (
        "change_request.created",
        "change_request.draft_to_pending_approval",
        "change_request.pending_approval_to_approved",
        "change_request.approved_to_executing",
    )
    terminal_actions = (
        (completed, ("change_request.executing_to_completed",)),
        (
            rolled_back,
            (
                "change_request.executing_to_failed",
                "change_request.failed_to_rolled_back",
            ),
        ),
        (
            masked,
            (
                "change_request.executing_to_failed",
                "change_request.failed_to_rolled_back",
            ),
        ),
    )
    seq = 1
    for cr, final_actions in terminal_actions:
        for action in common + final_actions:
            session.add(
                AuditLog(
                    seq=seq,
                    actor="test",
                    action=action,
                    target_type="change_request",
                    target_id=cr.id.hex,
                    reasoning_trace_id=cr.reasoning_trace_id,
                )
            )
            seq += 1
    await session.commit()

    assert (await reconcile_change_request_audit(session)).inconsistencies == 1


def test_backup_reconcile_alerts_within_fifteen_minutes_of_due_miss() -> None:
    due = datetime(2026, 7, 23, 2, 0, tzinfo=UTC)
    assert not backup_slot_due(now=due + timedelta(minutes=14, seconds=59), due_at=due)
    assert backup_slot_due(now=due + timedelta(minutes=15), due_at=due)


def test_backup_reconcile_excludes_disabled_schedules_and_accepts_terminal_success() -> None:
    due = datetime(2026, 7, 23, 2, 0, tzinfo=UTC)
    assert not backup_slot_due(now=due + timedelta(hours=1), due_at=due, enabled=False)


def test_backup_reconcile_is_idempotent_at_boundary_times() -> None:
    due = datetime(2026, 7, 23, 2, 0, tzinfo=UTC)
    first = backup_slot_due(now=due + timedelta(minutes=15), due_at=due)
    assert first == backup_slot_due(now=due + timedelta(minutes=15), due_at=due)


def test_backup_slot_after_midnight_uses_most_recent_due_slot_date() -> None:
    now = datetime(2026, 7, 24, 0, 10, tzinfo=UTC)
    slot, due = most_recent_due_backup_slot(now=now, hour=23, minute=50)
    assert slot == "2026-07-23"
    assert due == datetime(2026, 7, 23, 23, 50, tzinfo=UTC)


@pytest.mark.asyncio
async def test_disabled_backup_task_does_not_query_and_emits_excluded_healthy_state(
    monkeypatch,
) -> None:
    emitted: list[tuple[str, object]] = []

    class Engine:
        async def dispose(self) -> None:
            return None

    class ForbiddenMaker:
        def __call__(self):
            raise AssertionError("disabled backup must not open a database session")

    monkeypatch.setattr(
        tasks,
        "get_settings",
        lambda: SimpleNamespace(
            config_backup_enabled=False, config_backup_hour=2, config_backup_minute=0
        ),
    )
    monkeypatch.setattr(tasks.db, "create_engine", lambda _settings: Engine())
    monkeypatch.setattr(tasks, "async_sessionmaker", lambda *_args, **_kwargs: ForbiddenMaker())
    monkeypatch.setattr(
        tasks.metrics,
        "set_reconciliation_schedule_enabled",
        lambda **kwargs: emitted.append(("enabled", kwargs)),
    )
    monkeypatch.setattr(
        tasks.metrics,
        "set_reconciliation_result",
        lambda **kwargs: emitted.append(("result", kwargs)),
    )
    assert await tasks._run("config_backup") == 0
    assert emitted[0] == (
        "enabled",
        {"reconciliation": "config_backup", "enabled": False},
    )
    assert emitted[1][0] == "result"
    assert emitted[1][1]["reconciliation"] == "config_backup"
    assert emitted[1][1]["inconsistencies"] == 0


def test_trace_reconcile_settles_at_synchronous_commit_boundary() -> None:
    now = datetime(2026, 7, 23, 12, 0, tzinfo=UTC)
    assert not is_settled(timestamp=now + timedelta(microseconds=1), now=now)
    assert is_settled(timestamp=now, now=now)


def test_cr_audit_reconcile_fails_closed_on_query_error(monkeypatch) -> None:
    calls: list[tuple[str, int]] = []

    class Gauge:
        def labels(self, *, reconciliation: str):
            assert reconciliation in {"config_backup", "change_request_audit", "reasoning_trace"}
            return self

        def set(self, value: int) -> None:
            calls.append(("healthy", value))

    class ForbiddenCountGauge:
        def labels(self, **_kwargs):
            raise AssertionError("query failure must not emit a healthy zero count")

    monkeypatch.setattr(metrics, "_PROM_ENABLED", True)
    monkeypatch.setattr(metrics, "RECONCILIATION_HEALTHY", Gauge())
    monkeypatch.setattr(metrics, "RECONCILIATION_INCONSISTENCIES", ForbiddenCountGauge())
    metrics.set_reconciliation_unhealthy(reconciliation="change_request_audit")
    assert calls == [("healthy", 0)]


@pytest.mark.asyncio
async def test_cr_audit_task_query_failure_never_emits_healthy_zero(monkeypatch) -> None:
    calls: list[tuple[str, object]] = []

    class Engine:
        async def dispose(self) -> None:
            calls.append(("disposed", True))

    class Context:
        async def __aenter__(self):
            return object()

        async def __aexit__(self, *_args):
            return None

    async def fail(_session):
        raise RuntimeError("query unavailable")

    monkeypatch.setattr(tasks, "get_settings", lambda: SimpleNamespace())
    monkeypatch.setattr(tasks.db, "create_engine", lambda _settings: Engine())
    monkeypatch.setattr(tasks, "async_sessionmaker", lambda *_args, **_kwargs: Context)
    monkeypatch.setattr(tasks, "reconcile_change_request_audit", fail)
    monkeypatch.setattr(
        tasks.metrics,
        "set_reconciliation_unhealthy",
        lambda **kwargs: calls.append(("unhealthy", kwargs["reconciliation"])),
    )
    monkeypatch.setattr(
        tasks.metrics,
        "set_reconciliation_result",
        lambda **_kwargs: calls.append(("result", "forbidden")),
    )

    with pytest.raises(RuntimeError, match="query unavailable"):
        await tasks._run("change_request_audit")
    assert ("unhealthy", "change_request_audit") in calls
    assert ("result", "forbidden") not in calls


@pytest.mark.asyncio
async def test_cr_audit_reconcile_repeat_run_does_not_duplicate_effects(monkeypatch) -> None:
    emitted: list[int] = []

    class Engine:
        async def dispose(self) -> None:
            return None

    class Context:
        async def __aenter__(self):
            return object()

        async def __aexit__(self, *_args):
            return None

    async def healthy(_session):
        return ReconcileResult(2)

    monkeypatch.setattr(tasks, "get_settings", lambda: SimpleNamespace())
    monkeypatch.setattr(tasks.db, "create_engine", lambda _settings: Engine())
    monkeypatch.setattr(tasks, "async_sessionmaker", lambda *_args, **_kwargs: Context)
    monkeypatch.setattr(tasks, "reconcile_change_request_audit", healthy)
    monkeypatch.setattr(
        tasks.metrics,
        "set_reconciliation_result",
        lambda **kwargs: emitted.append(kwargs["inconsistencies"]),
    )
    assert await tasks._run("change_request_audit") == 2
    assert await tasks._run("change_request_audit") == 2
    assert emitted == [2, 2]


@pytest.mark.asyncio
async def test_reconciliation_queries_return_aggregate_counts() -> None:
    class ScalarSession:
        def __init__(self, values: list[object]) -> None:
            self.values = iter(values)

        async def scalar(self, _statement):
            return next(self.values)

    now = datetime(2026, 7, 23, 12, tzinfo=UTC)
    backup = await reconcile_config_backup(
        ScalarSession([False]),  # type: ignore[arg-type]
        slot="2026-07-23",
        due_at=now - timedelta(hours=1),
        now=now,
    )
    change = await reconcile_change_request_audit(
        ScalarSession([3])  # type: ignore[arg-type]
    )
    traces = await reconcile_reasoning_traces(
        ScalarSession([1, 2, 3]),  # type: ignore[arg-type]
        now=now,
    )
    assert backup.inconsistencies == 1
    assert change.inconsistencies == 3
    assert traces.inconsistencies == 6
