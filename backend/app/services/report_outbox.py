"""Transactional report enqueue, relay leasing, and safe publication (ADR-0059)."""

from __future__ import annotations

import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any

from sqlalchemy import func, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dispatch_outbox import (
    DispatchConsumerState,
    DispatchOutbox,
    DispatchOutboxState,
)
from app.models.reports import ReportKind, ReportRun, ReportRunStatus

REPORT_TASK = "reports.generate"
QUEUE_DOCS = "docs"
_ALLOWED = {(REPORT_TASK, QUEUE_DOCS)}
_PAYLOAD_KEYS = {"dispatch_id", "run_id"}


class InvalidDispatchEnvelope(ValueError):
    """Envelope is not an allowlisted, identifier-only report publication."""


@dataclass(frozen=True)
class ReportDispatchPayload:
    dispatch_id: uuid.UUID
    run_id: uuid.UUID


class ConsumerClaimStatus(StrEnum):
    CLAIMED = "claimed"
    ACTIVE = "active"
    RECOVERED = "recovered"
    SUCCEEDED = "succeeded"
    FAILED = "failed"


@dataclass(frozen=True)
class ConsumerClaim:
    status: ConsumerClaimStatus
    dispatch_id: uuid.UUID
    run_id: uuid.UUID
    owner: str | None
    kind: ReportKind
    trigger: str
    requested_by: uuid.UUID | None
    period_start: datetime
    period_end: datetime


def _parse_payload(payload: Mapping[str, Any]) -> ReportDispatchPayload:
    identifiers_are_strings = all(
        isinstance(payload[key], str) for key in _PAYLOAD_KEYS if key in payload
    )
    if set(payload) != _PAYLOAD_KEYS or not identifiers_are_strings:
        raise InvalidDispatchEnvelope("invalid_payload_shape")
    try:
        dispatch_id = uuid.UUID(payload["dispatch_id"])
        run_id = uuid.UUID(payload["run_id"])
    except (ValueError, TypeError, AttributeError) as exc:
        raise InvalidDispatchEnvelope("invalid_payload_identifier") from exc
    if str(dispatch_id) != payload["dispatch_id"] or str(run_id) != payload["run_id"]:
        raise InvalidDispatchEnvelope("invalid_payload_identifier")
    return ReportDispatchPayload(dispatch_id=dispatch_id, run_id=run_id)


def validate_dispatch(
    task_name: str,
    payload: Mapping[str, Any],
    queue: str,
    *,
    dispatch_id: uuid.UUID,
) -> ReportDispatchPayload:
    if (task_name, queue) not in _ALLOWED:
        raise InvalidDispatchEnvelope("dispatch_not_allowlisted")
    parsed = _parse_payload(payload)
    if parsed.dispatch_id != dispatch_id:
        raise InvalidDispatchEnvelope("invalid_dispatch_identity")
    return parsed


def validate_dispatch_row(row: DispatchOutbox) -> ReportDispatchPayload:
    if row.aggregate_type != "report_run":
        raise InvalidDispatchEnvelope("invalid_aggregate_type")
    payload: object = row.payload_json
    if not isinstance(payload, Mapping):
        raise InvalidDispatchEnvelope("invalid_payload_shape")
    parsed = validate_dispatch(
        row.task_name,
        payload,
        row.queue,
        dispatch_id=row.id,
    )
    if parsed.run_id != row.aggregate_id:
        raise InvalidDispatchEnvelope("invalid_aggregate_identity")
    return parsed


def bounded_relay_batch_size(requested: int, *, configured_max: int) -> int:
    if requested <= 0 or configured_max <= 0:
        raise ValueError("relay_batch_invalid")
    return min(requested, configured_max)


@dataclass(frozen=True)
class ReportEnvelope:
    id: uuid.UUID
    run_id: uuid.UUID
    payload: dict[str, str | None]
    state: DispatchOutboxState = DispatchOutboxState.PENDING


def report_envelope(
    *,
    run_id: uuid.UUID,
    kind: str,
    period_start: datetime,
    period_end: datetime,
    trigger: str,
    requested_by: uuid.UUID | None,
) -> ReportEnvelope:
    dispatch_id = uuid.uuid4()
    return ReportEnvelope(
        id=dispatch_id,
        run_id=run_id,
        payload={
            "dispatch_id": str(dispatch_id),
            "run_id": str(run_id),
        },
    )


async def enqueue_report(
    session: AsyncSession,
    *,
    run_id: uuid.UUID,
    kind: ReportKind,
    period_start: datetime,
    period_end: datetime,
    trigger: str,
    requested_by: uuid.UUID | None,
) -> ReportRun:
    """Atomically and conflict-safely persist one queued run and envelope."""
    now = datetime.now(UTC)
    run_values: dict[str, Any] = {
        "id": run_id,
        "kind": kind.value,
        "trigger": trigger,
        "requested_by": requested_by,
        "period_start": period_start,
        "period_end": period_end,
        "status": ReportRunStatus.QUEUED.value,
        "regime_tags": [],
        "created_at": now,
        "updated_at": now,
    }
    dialect = session.bind.dialect.name if session.bind is not None else "sqlite"
    run_insert: Any
    if dialect == "postgresql":
        run_insert = pg_insert(ReportRun).values(**run_values).on_conflict_do_nothing()
    else:
        run_insert = sqlite_insert(ReportRun).values(**run_values).on_conflict_do_nothing()
    await session.execute(run_insert)
    run = (
        await session.execute(select(ReportRun).where(ReportRun.id == run_id).with_for_update())
    ).scalar_one()
    fresh_failed_retry = run.status == ReportRunStatus.FAILED.value
    if fresh_failed_retry:
        run.status = ReportRunStatus.QUEUED.value
        run.error_class = None
        run.finished_at = None
        run.trigger = trigger
        run.requested_by = requested_by
        run.updated_at = now

    envelope = report_envelope(
        run_id=run_id,
        kind=kind.value,
        period_start=period_start,
        period_end=period_end,
        trigger=trigger,
        requested_by=requested_by,
    )
    outbox_values = {
        "id": envelope.id,
        "aggregate_type": "report_run",
        "aggregate_id": run_id,
        "task_name": REPORT_TASK,
        "queue": QUEUE_DOCS,
        "payload_json": envelope.payload,
        "state": envelope.state.value,
        "attempts": 0,
        "available_at": now,
        "created_at": now,
        "consumer_state": DispatchConsumerState.PENDING.value,
    }
    outbox_insert: Any
    if dialect == "postgresql":
        outbox_insert = pg_insert(DispatchOutbox).values(**outbox_values).on_conflict_do_nothing()
    else:
        outbox_insert = (
            sqlite_insert(DispatchOutbox).values(**outbox_values).on_conflict_do_nothing()
        )
    await session.execute(outbox_insert)
    existing = (
        await session.execute(
            select(DispatchOutbox)
            .where(
                DispatchOutbox.aggregate_type == "report_run",
                DispatchOutbox.aggregate_id == run_id,
                DispatchOutbox.task_name == REPORT_TASK,
            )
            .with_for_update()
        )
    ).scalar_one()
    validate_dispatch_row(existing)
    if fresh_failed_retry:
        existing.state = DispatchOutboxState.PENDING.value
        existing.attempts = 0
        existing.available_at = now
        existing.claimed_at = None
        existing.claim_owner = None
        existing.dispatched_at = None
        existing.last_error_code = None
        existing.consumer_state = DispatchConsumerState.PENDING.value
        existing.consumer_owner = None
        existing.consumer_claimed_at = None
        existing.consumer_finished_at = None
        existing.consumer_error_code = None
    await session.flush()
    return run


async def mark_claim_dispatched(
    session: AsyncSession,
    *,
    dispatch_id: uuid.UUID,
    owner: str,
    now: datetime,
) -> bool:
    result = await session.execute(
        update(DispatchOutbox)
        .where(
            DispatchOutbox.id == dispatch_id,
            DispatchOutbox.state == DispatchOutboxState.CLAIMED.value,
            DispatchOutbox.claim_owner == owner,
        )
        .values(
            state=DispatchOutboxState.DISPATCHED.value,
            dispatched_at=now,
            claimed_at=None,
            claim_owner=None,
            last_error_code=None,
        )
    )
    return result.rowcount == 1  # type: ignore[attr-defined]


async def mark_claim_failed(
    session: AsyncSession,
    *,
    dispatch_id: uuid.UUID,
    owner: str,
    attempts: int,
    error_code: str,
    retryable: bool,
    max_attempts: int,
    now: datetime,
) -> DispatchOutboxState | None:
    state = (
        DispatchOutboxState.PENDING
        if retryable and attempts < max_attempts
        else DispatchOutboxState.DEAD
    )
    values: dict[str, Any] = {
        "state": state.value,
        "attempts": attempts,
        "last_error_code": error_code,
        "claim_owner": None,
        "claimed_at": None,
    }
    if state is DispatchOutboxState.PENDING:
        values["available_at"] = now + timedelta(seconds=min(300, 2**attempts))
    result = await session.execute(
        update(DispatchOutbox)
        .where(
            DispatchOutbox.id == dispatch_id,
            DispatchOutbox.state == DispatchOutboxState.CLAIMED.value,
            DispatchOutbox.claim_owner == owner,
        )
        .values(**values)
    )
    return state if result.rowcount == 1 else None  # type: ignore[attr-defined]


async def claim_consumer(
    session: AsyncSession,
    *,
    dispatch_id: uuid.UUID,
    run_id: uuid.UUID,
    owner: str,
    lease_seconds: int,
    now: datetime,
) -> ConsumerClaim:
    """Atomically claim one dispatched report by stable dispatch identity."""
    if not owner or lease_seconds <= 0:
        raise ValueError("consumer_claim_invalid")
    row = (
        await session.execute(
            select(DispatchOutbox).where(DispatchOutbox.id == dispatch_id).with_for_update()
        )
    ).scalar_one_or_none()
    if row is None:
        raise InvalidDispatchEnvelope("dispatch_not_found")
    payload = validate_dispatch_row(row)
    if payload.run_id != run_id:
        raise InvalidDispatchEnvelope("invalid_aggregate_identity")
    run = (
        await session.execute(select(ReportRun).where(ReportRun.id == run_id).with_for_update())
    ).scalar_one_or_none()
    if run is None:
        raise InvalidDispatchEnvelope("report_run_not_found")

    status: ConsumerClaimStatus
    if (
        row.consumer_state == DispatchConsumerState.SUCCEEDED.value
        or run.status == ReportRunStatus.SUCCEEDED.value
    ):
        row.consumer_state = DispatchConsumerState.SUCCEEDED.value
        row.consumer_owner = None
        row.consumer_claimed_at = None
        row.consumer_finished_at = row.consumer_finished_at or now
        status = ConsumerClaimStatus.SUCCEEDED
    elif row.consumer_state == DispatchConsumerState.FAILED.value:
        status = ConsumerClaimStatus.FAILED
    elif (
        row.consumer_state == DispatchConsumerState.RUNNING.value
        and row.consumer_claimed_at is not None
        and row.consumer_claimed_at >= now - timedelta(seconds=lease_seconds)
    ):
        status = ConsumerClaimStatus.ACTIVE
    else:
        recovered = row.consumer_state == DispatchConsumerState.RUNNING.value
        row.consumer_state = DispatchConsumerState.RUNNING.value
        row.consumer_owner = owner
        row.consumer_claimed_at = now
        row.consumer_finished_at = None
        row.consumer_error_code = None
        run.status = ReportRunStatus.RUNNING.value
        run.error_class = None
        run.finished_at = None
        run.updated_at = now
        status = ConsumerClaimStatus.RECOVERED if recovered else ConsumerClaimStatus.CLAIMED
    await session.flush()
    return ConsumerClaim(
        status=status,
        dispatch_id=dispatch_id,
        run_id=run.id,
        owner=row.consumer_owner,
        kind=ReportKind(run.kind),
        trigger=run.trigger,
        requested_by=run.requested_by,
        period_start=run.period_start,
        period_end=run.period_end,
    )


async def lock_owned_consumer(
    session: AsyncSession, *, dispatch_id: uuid.UUID, owner: str
) -> DispatchOutbox | None:
    """Fence terminal effects to the current durable consumer lease owner."""
    return (
        await session.execute(
            select(DispatchOutbox)
            .where(
                DispatchOutbox.id == dispatch_id,
                DispatchOutbox.consumer_state == DispatchConsumerState.RUNNING.value,
                DispatchOutbox.consumer_owner == owner,
            )
            .with_for_update()
        )
    ).scalar_one_or_none()


async def claim_pending(
    session: AsyncSession, *, owner: str, batch_size: int, now: datetime | None = None
) -> list[DispatchOutbox]:
    if not owner or batch_size <= 0:
        raise ValueError("relay_claim_invalid")
    now = now or datetime.now(UTC)
    rows = list(
        (
            await session.scalars(
                select(DispatchOutbox)
                .where(
                    DispatchOutbox.state == DispatchOutboxState.PENDING.value,
                    DispatchOutbox.available_at <= now,
                )
                .order_by(DispatchOutbox.created_at)
                .limit(batch_size)
                .with_for_update(skip_locked=True)
            )
        ).all()
    )
    for row in rows:
        row.state = DispatchOutboxState.CLAIMED.value
        row.claimed_at = now
        row.claim_owner = owner
    await session.flush()
    return rows


async def reap_stale_claims(
    session: AsyncSession, *, lease_seconds: int, now: datetime | None = None
) -> int:
    now = now or datetime.now(UTC)
    result = await session.execute(
        update(DispatchOutbox)
        .where(
            DispatchOutbox.state == DispatchOutboxState.CLAIMED.value,
            DispatchOutbox.claimed_at < now - timedelta(seconds=lease_seconds),
        )
        .values(
            state=DispatchOutboxState.PENDING.value,
            claimed_at=None,
            claim_owner=None,
            available_at=now,
        )
    )
    return int(result.rowcount or 0)  # type: ignore[attr-defined]


async def requeue_dead(session: AsyncSession, dispatch_id: uuid.UUID) -> DispatchOutbox | None:
    """Revalidate and return one replay-safe dead report envelope to pending."""
    row = await session.scalar(
        select(DispatchOutbox).where(DispatchOutbox.id == dispatch_id).with_for_update()
    )
    if row is None or row.state != DispatchOutboxState.DEAD.value:
        return None
    validate_dispatch_row(row)
    row.state = DispatchOutboxState.PENDING.value
    row.available_at = datetime.now(UTC)
    row.claimed_at = None
    row.claim_owner = None
    row.last_error_code = None
    await session.flush()
    return row


async def outbox_status(session: AsyncSession, now: datetime) -> tuple[int, float]:
    count, oldest = (
        await session.execute(
            select(func.count(), func.min(DispatchOutbox.created_at)).where(
                DispatchOutbox.state == DispatchOutboxState.PENDING.value
            )
        )
    ).one()
    return int(count), max(0.0, (now - oldest).total_seconds()) if oldest else 0.0
