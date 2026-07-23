"""Real-PostgreSQL crash-window and locking tests for ADR-0059."""

from __future__ import annotations

import asyncio
import hashlib
import uuid
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.engines.reports import RenderedArtifact, deterministic_run_id
from app.engines.reports.payloads import ReportPayload
from app.models import AuditLog
from app.models.dispatch_outbox import (
    DispatchConsumerState,
    DispatchOutbox,
    DispatchOutboxState,
)
from app.models.reports import ReportArtifact, ReportFormat, ReportKind, ReportRun, ReportRunStatus
from app.services.report_outbox import (
    ConsumerClaimStatus,
    claim_consumer,
    claim_pending,
    enqueue_report,
    mark_claim_dispatched,
    reap_stale_claims,
    requeue_dead,
)

pytestmark = pytest.mark.integration


@pytest.mark.asyncio
async def test_report_outbox_rollback_persists_neither_transition_nor_envelope(
    pg_session: AsyncSession,
) -> None:
    await enqueue_report(
        pg_session,
        run_id=deterministic_run_id(
            ReportKind.CHANGE,
            datetime(2026, 7, 1, tzinfo=UTC),
            datetime(2026, 7, 8, tzinfo=UTC),
        ),
        kind=ReportKind.CHANGE,
        period_start=datetime(2026, 7, 1, tzinfo=UTC),
        period_end=datetime(2026, 7, 8, tzinfo=UTC),
        trigger="on_demand",
        requested_by=uuid.uuid4(),
    )
    await pg_session.rollback()
    assert await pg_session.scalar(select(func.count()).select_from(ReportRun)) == 0
    assert await pg_session.scalar(select(func.count()).select_from(DispatchOutbox)) == 0


@pytest.mark.asyncio
async def test_report_outbox_committed_row_survives_crash_before_relay(
    pg_session: AsyncSession,
) -> None:
    run = await enqueue_report(
        pg_session,
        run_id=deterministic_run_id(
            ReportKind.CHANGE,
            datetime(2026, 7, 1, tzinfo=UTC),
            datetime(2026, 7, 8, tzinfo=UTC),
        ),
        kind=ReportKind.CHANGE,
        period_start=datetime(2026, 7, 1, tzinfo=UTC),
        period_end=datetime(2026, 7, 8, tzinfo=UTC),
        trigger="scheduled",
        requested_by=None,
    )
    await pg_session.commit()
    row = await pg_session.scalar(
        select(DispatchOutbox).where(DispatchOutbox.aggregate_id == run.id)
    )
    assert row is not None
    assert row.state == DispatchOutboxState.PENDING.value


@pytest.mark.asyncio
async def test_report_outbox_stale_claim_returns_to_pending_after_lease(
    pg_session: AsyncSession,
) -> None:
    await enqueue_report(
        pg_session,
        run_id=deterministic_run_id(
            ReportKind.CHANGE,
            datetime(2026, 7, 1, tzinfo=UTC),
            datetime(2026, 7, 8, tzinfo=UTC),
        ),
        kind=ReportKind.CHANGE,
        period_start=datetime(2026, 7, 1, tzinfo=UTC),
        period_end=datetime(2026, 7, 8, tzinfo=UTC),
        trigger="scheduled",
        requested_by=None,
    )
    await pg_session.commit()
    claimed = await claim_pending(pg_session, owner="relay-a", batch_size=1)
    await pg_session.commit()
    assert len(claimed) == 1
    claimed[0].claimed_at = datetime.now(UTC) - timedelta(hours=1)
    await pg_session.commit()
    assert await reap_stale_claims(pg_session, lease_seconds=60) == 1
    await pg_session.commit()
    await pg_session.refresh(claimed[0])
    assert claimed[0].state == DispatchOutboxState.PENDING.value


@pytest.mark.asyncio
async def test_report_outbox_concurrent_relays_claim_each_row_once(
    pg_session: AsyncSession,
) -> None:
    start = datetime(2026, 7, 1, tzinfo=UTC)
    end = datetime(2026, 7, 8, tzinfo=UTC)
    await enqueue_report(
        pg_session,
        run_id=deterministic_run_id(ReportKind.CHANGE, start, end),
        kind=ReportKind.CHANGE,
        period_start=start,
        period_end=end,
        trigger="scheduled",
        requested_by=None,
    )
    await pg_session.commit()
    assert pg_session.bind is not None
    maker = async_sessionmaker(pg_session.bind, expire_on_commit=False)
    async with maker() as relay_a, maker() as relay_b:
        first = await claim_pending(relay_a, owner="relay-a", batch_size=1)
        assert len(first) == 1
        second = await claim_pending(relay_b, owner="relay-b", batch_size=1)
        await relay_b.commit()
        await relay_a.commit()
    assert second == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("first_trigger", "second_trigger"),
    [("on_demand", "on_demand"), ("scheduled", "on_demand")],
)
async def test_report_outbox_concurrent_cross_path_enqueue_has_one_run_and_envelope(
    pg_session: AsyncSession,
    first_trigger: str,
    second_trigger: str,
) -> None:
    start = datetime(2026, 7, 1, tzinfo=UTC)
    end = datetime(2026, 7, 8, tzinfo=UTC)
    run_id = deterministic_run_id(ReportKind.CHANGE, start, end)
    assert pg_session.bind is not None
    maker = async_sessionmaker(pg_session.bind, expire_on_commit=False)

    async def _request(trigger: str) -> None:
        async with maker() as session:
            await enqueue_report(
                session,
                run_id=run_id,
                kind=ReportKind.CHANGE,
                period_start=start,
                period_end=end,
                trigger=trigger,
                requested_by=uuid.uuid4() if trigger == "on_demand" else None,
            )
            await session.commit()

    await asyncio.wait_for(
        asyncio.gather(_request(first_trigger), _request(second_trigger)),
        timeout=10,
    )
    assert await pg_session.scalar(select(func.count()).select_from(ReportRun)) == 1
    assert await pg_session.scalar(select(func.count()).select_from(DispatchOutbox)) == 1


@pytest.mark.asyncio
async def test_report_outbox_stale_relay_owner_is_fenced_after_reclaim(
    pg_session: AsyncSession,
) -> None:
    start = datetime(2026, 7, 1, tzinfo=UTC)
    end = datetime(2026, 7, 8, tzinfo=UTC)
    await enqueue_report(
        pg_session,
        run_id=deterministic_run_id(ReportKind.CHANGE, start, end),
        kind=ReportKind.CHANGE,
        period_start=start,
        period_end=end,
        trigger="scheduled",
        requested_by=None,
    )
    await pg_session.commit()
    row = (await claim_pending(pg_session, owner="relay-a", batch_size=1))[0]
    await pg_session.commit()
    row.claimed_at = datetime.now(UTC) - timedelta(minutes=10)
    await pg_session.commit()
    assert await reap_stale_claims(pg_session, lease_seconds=60) == 1
    await pg_session.commit()
    reclaimed = (await claim_pending(pg_session, owner="relay-b", batch_size=1))[0]
    await pg_session.commit()
    assert reclaimed.id == row.id
    assert not await mark_claim_dispatched(
        pg_session,
        dispatch_id=row.id,
        owner="relay-a",
        now=datetime.now(UTC),
    )
    await pg_session.commit()
    await pg_session.refresh(row)
    assert row.state == DispatchOutboxState.CLAIMED.value
    assert row.claim_owner == "relay-b"


@pytest.mark.asyncio
async def test_report_outbox_duplicate_consumer_recovers_worker_death(
    pg_session: AsyncSession,
) -> None:
    start = datetime(2026, 7, 1, tzinfo=UTC)
    end = datetime(2026, 7, 8, tzinfo=UTC)
    run_id = deterministic_run_id(ReportKind.CHANGE, start, end)
    await enqueue_report(
        pg_session,
        run_id=run_id,
        kind=ReportKind.CHANGE,
        period_start=start,
        period_end=end,
        trigger="scheduled",
        requested_by=None,
    )
    row = (await pg_session.execute(select(DispatchOutbox))).scalar_one()
    await pg_session.commit()
    first = await claim_consumer(
        pg_session,
        dispatch_id=row.id,
        run_id=run_id,
        owner="worker-a",
        lease_seconds=60,
        now=datetime.now(UTC),
    )
    assert first.status is ConsumerClaimStatus.CLAIMED
    await pg_session.commit()
    active = await claim_consumer(
        pg_session,
        dispatch_id=row.id,
        run_id=run_id,
        owner="worker-b",
        lease_seconds=60,
        now=datetime.now(UTC),
    )
    assert active.status is ConsumerClaimStatus.ACTIVE
    await pg_session.rollback()
    row.consumer_claimed_at = datetime.now(UTC) - timedelta(minutes=2)
    await pg_session.commit()
    recovered = await claim_consumer(
        pg_session,
        dispatch_id=row.id,
        run_id=run_id,
        owner="worker-b",
        lease_seconds=60,
        now=datetime.now(UTC),
    )
    assert recovered.status is ConsumerClaimStatus.RECOVERED


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", [False, True])
async def test_report_outbox_post_send_pre_mark_redelivery_has_one_terminal_effect(
    pg_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
    failure: bool,
) -> None:
    from app.workers.tasks import reports as report_tasks

    start = datetime(2026, 7, 1, tzinfo=UTC)
    end = datetime(2026, 7, 8, tzinfo=UTC)
    run_id = deterministic_run_id(ReportKind.CHANGE, start, end)
    await enqueue_report(
        pg_session,
        run_id=run_id,
        kind=ReportKind.CHANGE,
        period_start=start,
        period_end=end,
        trigger="on_demand",
        requested_by=uuid.uuid4(),
    )
    row = (await pg_session.execute(select(DispatchOutbox))).scalar_one()
    row.state = DispatchOutboxState.CLAIMED.value  # broker send happened; relay mark crashed
    await pg_session.commit()
    assert pg_session.bind is not None
    maker = async_sessionmaker(pg_session.bind, expire_on_commit=False)

    @asynccontextmanager
    async def _pg_task_session() -> Any:
        async with maker() as session:
            yield session

    builds = 0

    async def _build(*_args: Any, **_kwargs: Any) -> ReportPayload:
        nonlocal builds
        builds += 1
        if failure:
            raise RuntimeError("raw-secret-hunter2")
        return ReportPayload(
            kind="change",
            title="Change report",
            period_start=start,
            period_end=end,
            generated_at=datetime.now(UTC),
            sections=(),
        )

    content = b"one-render"
    rendered = RenderedArtifact(
        format=ReportFormat.CSV,
        content=content,
        sha256=hashlib.sha256(content).hexdigest(),
        size_bytes=len(content),
    )
    monkeypatch.setattr(report_tasks, "_session", _pg_task_session)
    monkeypatch.setattr(report_tasks, "build_payload", _build)
    monkeypatch.setattr(report_tasks, "render_artifacts", lambda _payload: [rendered])

    first = await report_tasks._generate_report_core(str(row.id), str(run_id))
    second = await report_tasks._generate_report_core(str(row.id), str(run_id))
    assert builds == 1
    assert second["status"] == ("failed" if failure else "succeeded")
    await pg_session.refresh(row)
    run = await pg_session.get(ReportRun, run_id)
    assert run is not None
    if failure:
        assert first["error_class"] == "builder_error"
        assert row.consumer_state == DispatchConsumerState.FAILED.value
        assert row.consumer_error_code == "builder_error"
        assert run.status == ReportRunStatus.FAILED.value
        assert await pg_session.scalar(select(func.count()).select_from(ReportArtifact)) == 0
        audit_text = str(
            list(
                (
                    await pg_session.scalars(
                        select(AuditLog).where(AuditLog.target_id == str(run_id))
                    )
                ).all()
            )
        )
        assert "raw-secret-hunter2" not in audit_text
    else:
        assert first["status"] == "succeeded"
        assert row.consumer_state == DispatchConsumerState.SUCCEEDED.value
        assert run.status == ReportRunStatus.SUCCEEDED.value
        assert await pg_session.scalar(select(func.count()).select_from(ReportArtifact)) == 1


@pytest.mark.asyncio
async def test_report_outbox_poison_becomes_dead_and_safe_replay_is_auditable(
    pg_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app import db
    from app.services import audit
    from app.workers.tasks import report_outbox as relay_tasks

    start = datetime(2026, 7, 1, tzinfo=UTC)
    end = datetime(2026, 7, 8, tzinfo=UTC)
    run_id = deterministic_run_id(ReportKind.CHANGE, start, end)
    await enqueue_report(
        pg_session,
        run_id=run_id,
        kind=ReportKind.CHANGE,
        period_start=start,
        period_end=end,
        trigger="scheduled",
        requested_by=None,
    )
    row = (await pg_session.execute(select(DispatchOutbox))).scalar_one()
    row.payload_json = {
        "dispatch_id": str(row.id),
        "run_id": str(run_id),
        "secret": "raw-secret-hunter2",
    }
    await pg_session.commit()
    assert pg_session.bind is not None
    maker = async_sessionmaker(pg_session.bind, expire_on_commit=False)
    monkeypatch.setattr(db, "get_sessionmaker", lambda: maker)
    monkeypatch.setattr(
        relay_tasks,
        "durable_dispatch",
        lambda **_kwargs: pytest.fail("poison envelope reached broker"),
    )
    result = await relay_tasks._relay_core(1)
    assert result["dead"] == 1
    await pg_session.refresh(row)
    assert row.state == DispatchOutboxState.DEAD.value
    assert row.last_error_code == "invalid_envelope"
    assert "raw-secret-hunter2" not in str(row.last_error_code)

    row.payload_json = {"dispatch_id": str(row.id), "run_id": str(run_id)}
    await pg_session.commit()
    replayed = await requeue_dead(pg_session, row.id)
    assert replayed is not None
    await audit.record(
        pg_session,
        actor="user:admin",
        action="report.outbox_requeued",
        target_type="dispatch_outbox",
        target_id=str(row.id),
        detail={"aggregate_type": row.aggregate_type, "aggregate_id": str(row.aggregate_id)},
    )
    await pg_session.commit()
    assert (
        await pg_session.scalar(
            select(func.count())
            .select_from(AuditLog)
            .where(
                AuditLog.action == "report.outbox_requeued",
                AuditLog.target_id == str(row.id),
            )
        )
        == 1
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "poison_shape",
    ["array-of-pairs", "list", "scalar", "null"],
)
async def test_report_outbox_non_object_json_poison_is_dead_without_publication(
    pg_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
    poison_shape: str,
) -> None:
    from app import db
    from app.workers.tasks import report_outbox as relay_tasks

    start = datetime(2026, 7, 1, tzinfo=UTC)
    end = datetime(2026, 7, 8, tzinfo=UTC)
    run_id = deterministic_run_id(ReportKind.CHANGE, start, end)
    await enqueue_report(
        pg_session,
        run_id=run_id,
        kind=ReportKind.CHANGE,
        period_start=start,
        period_end=end,
        trigger="scheduled",
        requested_by=None,
    )
    row = (await pg_session.execute(select(DispatchOutbox))).scalar_one()
    poison: object
    if poison_shape == "array-of-pairs":
        poison = [
            ["dispatch_id", str(row.id)],
            ["run_id", str(run_id)],
        ]
    elif poison_shape == "list":
        poison = ["raw-secret-hunter2"]
    elif poison_shape == "scalar":
        poison = "raw-secret-hunter2"
    else:
        poison = None
    row.payload_json = poison  # type: ignore[assignment]
    await pg_session.commit()

    assert pg_session.bind is not None
    maker = async_sessionmaker(pg_session.bind, expire_on_commit=False)
    monkeypatch.setattr(db, "get_sessionmaker", lambda: maker)
    monkeypatch.setattr(
        relay_tasks,
        "durable_dispatch",
        lambda **_kwargs: pytest.fail("poison envelope reached broker"),
    )

    result = await relay_tasks._relay_core(1)

    assert result == {"claimed": 1, "dispatched": 0, "retried": 0, "dead": 1}
    await pg_session.refresh(row)
    assert row.state == DispatchOutboxState.DEAD.value
    assert row.last_error_code == "invalid_envelope"
    assert "raw-secret-hunter2" not in str(result)
    assert "raw-secret-hunter2" not in str(row.last_error_code)
