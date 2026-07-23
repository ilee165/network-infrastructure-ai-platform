"""Celery relay and lease reaper for durable report publications."""

from __future__ import annotations

import asyncio
import socket
from datetime import UTC, datetime

from app import db
from app.core.config import get_settings
from app.core.metrics import (
    record_report_outbox_event,
    set_report_outbox_backlog,
    set_report_outbox_relay_last_success,
)
from app.services.report_outbox import (
    InvalidDispatchEnvelope,
    bounded_relay_batch_size,
    claim_pending,
    mark_claim_dispatched,
    mark_claim_failed,
    outbox_status,
    reap_stale_claims,
    validate_dispatch_row,
)
from app.workers.celery_app import celery_app
from app.workers.dispatch import durable_dispatch

_MAX_ATTEMPTS = 5


async def _relay_core(batch_size: int | None = None) -> dict[str, int]:
    configured_max = get_settings().report_outbox_max_batch_size
    effective_batch = bounded_relay_batch_size(
        batch_size if batch_size is not None else configured_max,
        configured_max=configured_max,
    )
    maker = db.get_sessionmaker()
    owner = f"{socket.gethostname()}:{id(asyncio.current_task())}"
    async with maker() as session:
        rows = await claim_pending(session, owner=owner, batch_size=effective_batch)
        pending, oldest = await outbox_status(session, datetime.now(UTC))
        set_report_outbox_backlog(pending=pending, oldest_seconds=oldest)
        await session.commit()
    for _ in rows:
        record_report_outbox_event(event="claimed")
    dispatched = retried = dead = 0
    for claimed in rows:
        try:
            validate_dispatch_row(claimed)
            durable_dispatch(
                task_name=claimed.task_name,
                payload=dict(claimed.payload_json),
                queue=claimed.queue,
                dispatch_id=claimed.id,
            )
        except InvalidDispatchEnvelope:
            error_code = "invalid_envelope"
            retryable = False
        except Exception:  # broker/transport details are deliberately discarded
            error_code = "broker_unavailable"
            retryable = True
        else:
            error_code = ""
            retryable = False
        async with maker() as session:
            if not error_code:
                transitioned = await mark_claim_dispatched(
                    session,
                    dispatch_id=claimed.id,
                    owner=owner,
                    now=datetime.now(UTC),
                )
                if transitioned:
                    dispatched += 1
                    record_report_outbox_event(event="dispatched")
            else:
                transition = await mark_claim_failed(
                    session,
                    dispatch_id=claimed.id,
                    owner=owner,
                    attempts=claimed.attempts + 1,
                    error_code=error_code,
                    retryable=retryable,
                    max_attempts=_MAX_ATTEMPTS,
                    now=datetime.now(UTC),
                )
                if transition is None:
                    await session.rollback()
                    continue
                if transition.value == "pending":
                    retried += 1
                    record_report_outbox_event(event="retry")
                else:
                    dead += 1
                    record_report_outbox_event(event="dead")
            await session.commit()
    set_report_outbox_relay_last_success(timestamp=datetime.now(UTC).timestamp())
    return {"claimed": len(rows), "dispatched": dispatched, "retried": retried, "dead": dead}


@celery_app.task(name="reports.outbox_relay")
def relay(batch_size: int | None = None) -> dict[str, int]:
    return asyncio.run(_relay_core(batch_size))


@celery_app.task(name="reports.outbox_reaper")
def reaper(lease_seconds: int = 300) -> dict[str, int]:
    async def _run() -> dict[str, int]:
        async with db.get_sessionmaker()() as session:
            recovered = await reap_stale_claims(session, lease_seconds=lease_seconds)
            await session.commit()
            for _ in range(recovered):
                record_report_outbox_event(event="recovered")
            return {"recovered": recovered}

    return asyncio.run(_run())
