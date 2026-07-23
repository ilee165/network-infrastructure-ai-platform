"""Unit contracts for ADR-0059 report dispatch outbox."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import metrics
from app.engines.reports import deterministic_run_id
from app.models.dispatch_outbox import DispatchOutbox, DispatchOutboxState
from app.models.reports import ReportKind
from app.services.report_outbox import (
    ConsumerClaimStatus,
    InvalidDispatchEnvelope,
    bounded_relay_batch_size,
    claim_consumer,
    enqueue_report,
    mark_claim_dispatched,
    report_envelope,
    validate_dispatch_row,
)
from app.workers.dispatch import durable_dispatch


def test_report_outbox_payload_and_metrics_never_contain_secret_or_raw_error() -> None:
    envelope = report_envelope(
        run_id=uuid.uuid4(),
        kind="change",
        period_start=datetime(2026, 7, 1, tzinfo=UTC),
        period_end=datetime(2026, 7, 8, tzinfo=UTC),
        trigger="on_demand",
        requested_by=uuid.uuid4(),
    )
    assert envelope.payload == {
        "dispatch_id": str(envelope.id),
        "run_id": str(envelope.run_id),
    }
    assert envelope.state is DispatchOutboxState.PENDING


def test_poison_envelope_is_rejected_before_publication_without_echo() -> None:
    secret = "do-not-publish-hunter2"
    with pytest.raises(InvalidDispatchEnvelope) as raised:
        durable_dispatch(
            task_name="reports.generate",
            payload={
                "dispatch_id": str(uuid.uuid4()),
                "run_id": str(uuid.uuid4()),
                "secret": secret,
            },
            queue="docs",
            dispatch_id=uuid.uuid4(),
        )
    assert secret not in str(raised.value)


def test_durable_dispatch_uses_payload_dispatch_id_as_celery_task_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.workers import dispatch as dispatch_module

    dispatch_id = uuid.uuid4()
    run_id = uuid.uuid4()
    calls: list[tuple[str, dict[str, object]]] = []
    monkeypatch.setattr(
        dispatch_module.celery_app,
        "send_task",
        lambda name, **kwargs: calls.append((name, kwargs)),
    )
    durable_dispatch(
        task_name="reports.generate",
        payload={"dispatch_id": str(dispatch_id), "run_id": str(run_id)},
        queue="docs",
        dispatch_id=dispatch_id,
    )
    assert calls[0][0] == "reports.generate"
    assert calls[0][1]["task_id"] == str(dispatch_id)
    assert calls[0][1]["kwargs"] == {
        "dispatch_id": str(dispatch_id),
        "run_id": str(run_id),
    }


def test_dispatch_wrapper_preserves_queue_countdown_eta_and_task_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.workers import dispatch as dispatch_module

    eta = datetime(2026, 7, 23, 12, tzinfo=UTC)
    calls: list[tuple[str, dict[str, object]]] = []
    monkeypatch.setattr(
        dispatch_module.celery_app,
        "send_task",
        lambda name, **options: calls.append((name, options)),
    )

    durable_dispatch(
        task_name="discovery.run",
        args=["run-id"],
        queue="discovery",
        countdown=30,
        eta=eta,
        task_id="caller-idempotency-key",
    )

    assert calls == [
        (
            "discovery.run",
            {
                "args": ["run-id"],
                "queue": "discovery",
                "countdown": 30,
                "eta": eta,
                "task_id": "caller-idempotency-key",
                "retry": True,
                "retry_policy": {
                    "max_retries": 3,
                    "interval_start": 0,
                    "interval_step": 1,
                },
            },
        )
    ]


def test_dispatch_wrapper_redacts_publication_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.workers import dispatch as dispatch_module
    from app.workers.dispatch import DispatchPublicationError

    secret = "redis://user:hunter2@broker.internal/0"

    def _fail(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError(secret)

    monkeypatch.setattr(dispatch_module.celery_app, "send_task", _fail)
    with pytest.raises(DispatchPublicationError, match="publication_failed") as raised:
        durable_dispatch(
            task_name="discovery.run",
            args=["run-id"],
            queue="discovery",
        )
    pending: list[BaseException] = [raised.value]
    seen: set[int] = set()
    while pending:
        error = pending.pop()
        if id(error) in seen:
            continue
        seen.add(id(error))
        assert secret not in str(error)
        assert error.__cause__ is None
        assert error.__context__ is None
        pending.extend(
            linked for linked in (error.__cause__, error.__context__) if linked is not None
        )


def test_row_validation_fences_dispatch_and_aggregate_identity() -> None:
    dispatch_id = uuid.uuid4()
    run_id = uuid.uuid4()
    row = DispatchOutbox(
        id=dispatch_id,
        aggregate_type="report_run",
        aggregate_id=run_id,
        task_name="reports.generate",
        queue="docs",
        payload_json={"dispatch_id": str(dispatch_id), "run_id": str(run_id)},
        state=DispatchOutboxState.CLAIMED.value,
        claim_owner="relay-a",
    )
    payload = validate_dispatch_row(row)
    assert payload.dispatch_id == dispatch_id
    assert payload.run_id == run_id

    row.payload_json = {"dispatch_id": str(uuid.uuid4()), "run_id": str(run_id)}
    with pytest.raises(InvalidDispatchEnvelope, match="invalid_dispatch_identity"):
        validate_dispatch_row(row)

    row.payload_json = {"dispatch_id": str(dispatch_id), "run_id": str(uuid.uuid4())}
    with pytest.raises(InvalidDispatchEnvelope, match="invalid_aggregate_identity"):
        validate_dispatch_row(row)


@pytest.mark.parametrize(("requested", "configured_max", "expected"), [(1, 50, 1), (51, 50, 50)])
def test_relay_batch_is_positive_and_clamped_to_configured_max(
    requested: int, configured_max: int, expected: int
) -> None:
    assert bounded_relay_batch_size(requested, configured_max=configured_max) == expected


@pytest.mark.parametrize(("requested", "configured_max"), [(0, 50), (-1, 50), (1, 0)])
def test_relay_batch_rejects_non_positive_values(requested: int, configured_max: int) -> None:
    with pytest.raises(ValueError, match="relay_batch_invalid"):
        bounded_relay_batch_size(requested, configured_max=configured_max)


def test_outbox_gauges_use_mostrecent_and_duplicate_event_is_bounded() -> None:
    if metrics.REPORT_OUTBOX_PENDING is None:
        pytest.skip("prometheus_client is not installed")
    assert metrics.REPORT_OUTBOX_PENDING._multiprocess_mode == "mostrecent"
    assert metrics.REPORT_OUTBOX_OLDEST_SECONDS._multiprocess_mode == "mostrecent"
    assert metrics.REPORT_OUTBOX_RELAY_LAST_SUCCESS_TIMESTAMP._multiprocess_mode == "mostrecent"
    metrics.record_report_outbox_event(event="duplicate_consumer")
    with pytest.raises(ValueError, match="report_outbox_event_invalid"):
        metrics.record_report_outbox_event(event="secret-hunter2")


@pytest.mark.asyncio
async def test_stale_relay_owner_cannot_mark_reclaimed_row_dispatched(
    session: AsyncSession,
) -> None:
    start = datetime(2026, 7, 1, tzinfo=UTC)
    end = datetime(2026, 7, 8, tzinfo=UTC)
    run_id = deterministic_run_id(ReportKind.CHANGE, start, end)
    await enqueue_report(
        session,
        run_id=run_id,
        kind=ReportKind.CHANGE,
        period_start=start,
        period_end=end,
        trigger="scheduled",
        requested_by=None,
    )
    row = (await session.execute(select(DispatchOutbox))).scalar_one()
    row.state = DispatchOutboxState.CLAIMED.value
    row.claim_owner = "relay-b"
    await session.flush()

    assert not await mark_claim_dispatched(
        session,
        dispatch_id=row.id,
        owner="relay-a",
        now=datetime.now(UTC),
    )
    await session.refresh(row)
    assert row.state == DispatchOutboxState.CLAIMED.value
    assert row.claim_owner == "relay-b"


@pytest.mark.asyncio
async def test_consumer_active_duplicate_waits_and_stale_owner_recovers(
    session: AsyncSession,
) -> None:
    start = datetime(2026, 7, 1, tzinfo=UTC)
    end = datetime(2026, 7, 8, tzinfo=UTC)
    run_id = deterministic_run_id(ReportKind.CHANGE, start, end)
    await enqueue_report(
        session,
        run_id=run_id,
        kind=ReportKind.CHANGE,
        period_start=start,
        period_end=end,
        trigger="scheduled",
        requested_by=None,
    )
    row = (await session.execute(select(DispatchOutbox))).scalar_one()
    await session.commit()

    first = await claim_consumer(
        session,
        dispatch_id=row.id,
        run_id=run_id,
        owner="consumer-a",
        lease_seconds=60,
        now=datetime.now(UTC),
    )
    assert first.status is ConsumerClaimStatus.CLAIMED
    await session.commit()

    duplicate = await claim_consumer(
        session,
        dispatch_id=row.id,
        run_id=run_id,
        owner="consumer-b",
        lease_seconds=60,
        now=datetime.now(UTC),
    )
    assert duplicate.status is ConsumerClaimStatus.ACTIVE
    await session.rollback()

    row.consumer_claimed_at = datetime.now(UTC) - timedelta(minutes=2)
    await session.commit()
    recovered = await claim_consumer(
        session,
        dispatch_id=row.id,
        run_id=run_id,
        owner="consumer-b",
        lease_seconds=60,
        now=datetime.now(UTC),
    )
    assert recovered.status is ConsumerClaimStatus.RECOVERED
    assert recovered.owner == "consumer-b"
    assert recovered.kind is ReportKind.CHANGE
