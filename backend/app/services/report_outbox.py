"""Transactional report enqueue, relay leasing, and safe publication (ADR-0059)."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dispatch_outbox import DispatchOutbox, DispatchOutboxState
from app.models.reports import ReportKind, ReportRun, ReportRunStatus

REPORT_TASK = "reports.generate"
QUEUE_DOCS = "docs"
_ALLOWED = {(REPORT_TASK, QUEUE_DOCS)}
_PAYLOAD_KEYS = {
    "dispatch_id",
    "kind",
    "period_start",
    "period_end",
    "trigger",
    "requested_by",
}


class InvalidDispatchEnvelope(ValueError):
    """Envelope is not an allowlisted, identifier-only report publication."""


def validate_dispatch(task_name: str, payload: dict[str, Any], queue: str) -> None:
    if (task_name, queue) not in _ALLOWED or set(payload) != _PAYLOAD_KEYS:
        raise InvalidDispatchEnvelope("dispatch envelope is not allowlisted")
    if payload.get("dispatch_id") is None:
        raise InvalidDispatchEnvelope("dispatch envelope lacks idempotency key")


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
            "kind": kind,
            "period_start": period_start.isoformat(),
            "period_end": period_end.isoformat(),
            "trigger": trigger,
            "requested_by": str(requested_by) if requested_by else None,
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
    """Insert the queued run and envelope on the caller's transaction."""
    run = await session.get(ReportRun, run_id)
    if run is None:
        run = ReportRun(
            id=run_id,
            kind=kind.value,
            trigger=trigger,
            requested_by=requested_by,
            period_start=period_start,
            period_end=period_end,
            status=ReportRunStatus.QUEUED.value,
            regime_tags=[],
        )
        session.add(run)
        await session.flush()
    existing = await session.scalar(
        select(DispatchOutbox).where(
            DispatchOutbox.aggregate_type == "report_run",
            DispatchOutbox.aggregate_id == run_id,
            DispatchOutbox.task_name == REPORT_TASK,
        )
    )
    if existing is None:
        envelope = report_envelope(
            run_id=run_id,
            kind=kind.value,
            period_start=period_start,
            period_end=period_end,
            trigger=trigger,
            requested_by=requested_by,
        )
        session.add(
            DispatchOutbox(
                id=envelope.id,
                aggregate_type="report_run",
                aggregate_id=run_id,
                task_name=REPORT_TASK,
                queue=QUEUE_DOCS,
                payload_json=envelope.payload,
                state=envelope.state.value,
            )
        )
        await session.flush()
    return run


async def claim_pending(
    session: AsyncSession, *, owner: str, batch_size: int, now: datetime | None = None
) -> list[DispatchOutbox]:
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
    validate_dispatch(row.task_name, dict(row.payload_json), row.queue)
    if row.aggregate_type != "report_run" or row.payload_json["dispatch_id"] != str(row.id):
        raise InvalidDispatchEnvelope("dispatch aggregate is not replay-safe")
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
