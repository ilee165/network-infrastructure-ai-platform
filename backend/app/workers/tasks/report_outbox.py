"""Celery relay and lease reaper for durable report publications."""

from __future__ import annotations

import asyncio
import socket
from datetime import UTC, datetime, timedelta

from app import db
from app.core.metrics import (
    record_report_outbox_event,
    set_report_outbox_backlog,
)
from app.models.dispatch_outbox import DispatchOutboxState
from app.services.report_outbox import (
    InvalidDispatchEnvelope,
    claim_pending,
    outbox_status,
    reap_stale_claims,
)
from app.workers.celery_app import celery_app
from app.workers.dispatch import durable_dispatch

_MAX_ATTEMPTS = 5


async def _relay_core(batch_size: int = 50) -> dict[str, int]:
    maker = db.get_sessionmaker()
    async with maker() as session:
        rows = await claim_pending(
            session, owner=f"{socket.gethostname()}:{id(session)}", batch_size=batch_size
        )
        pending, oldest = await outbox_status(session, datetime.now(UTC))
        set_report_outbox_backlog(pending=pending, oldest_seconds=oldest)
        await session.commit()
    for _ in rows:
        record_report_outbox_event(event="claimed")
    dispatched = retried = dead = 0
    for claimed in rows:
        try:
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
            row = await session.get(type(claimed), claimed.id, with_for_update=True)
            if row is None or row.state != DispatchOutboxState.CLAIMED.value:
                continue
            if not error_code:
                row.state = DispatchOutboxState.DISPATCHED.value
                row.dispatched_at = datetime.now(UTC)
                row.claim_owner = None
                row.claimed_at = None
                dispatched += 1
                record_report_outbox_event(event="dispatched")
            else:
                row.attempts += 1
                row.last_error_code = error_code
                row.claim_owner = None
                row.claimed_at = None
                if retryable and row.attempts < _MAX_ATTEMPTS:
                    row.state = DispatchOutboxState.PENDING.value
                    row.available_at = datetime.now(UTC) + timedelta(
                        seconds=min(300, 2**row.attempts)
                    )
                    retried += 1
                    record_report_outbox_event(event="retry")
                else:
                    row.state = DispatchOutboxState.DEAD.value
                    dead += 1
                    record_report_outbox_event(event="dead")
            await session.commit()
    return {"claimed": len(rows), "dispatched": dispatched, "retried": retried, "dead": dead}


@celery_app.task(name="reports.outbox_relay")
def relay(batch_size: int = 50) -> dict[str, int]:
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
