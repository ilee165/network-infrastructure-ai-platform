"""Celery relay and lease reaper for durable report publications."""

from __future__ import annotations

import asyncio
import socket
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app import db
from app.core.config import get_settings
from app.core.metrics import (
    record_report_outbox_event,
    set_report_outbox_backlog,
    set_report_outbox_relay_last_success,
)
from app.engines.reports.idempotency import coerce_utc, deterministic_run_id, scheduled_period
from app.models.dispatch_outbox import DispatchOutbox
from app.models.reports import ReportKind, ReportRun, ReportTrigger
from app.services.report_outbox import (
    REPORT_TASK,
    InvalidDispatchEnvelope,
    bounded_relay_batch_size,
    claim_pending,
    enqueue_report,
    mark_claim_dispatched,
    mark_claim_failed,
    outbox_status,
    reap_stale_claims,
    validate_dispatch_row,
)
from app.workers.celery_app import celery_app
from app.workers.dispatch import durable_dispatch

_MAX_ATTEMPTS = 5
# Fixed startup/recovery work bound: covers at least one monthly slot and five
# weekly slots while keeping each five-second relay sweep finite.
SCHEDULE_RECOVERY_LOOKBACK = timedelta(days=35)


@dataclass(frozen=True)
class ScheduledReportSpec:
    """One configured Celery Beat report schedule."""

    kind: ReportKind
    cadence: str
    hour: int
    minute: int


def _due_schedule_fires(
    *,
    now: datetime,
    schedule: ScheduledReportSpec,
    lookback: timedelta,
) -> tuple[datetime, ...]:
    """Return bounded UTC Beat slots that should already have fired."""
    if lookback <= timedelta(0) or lookback > SCHEDULE_RECOVERY_LOOKBACK:
        raise ValueError("schedule_recovery_lookback_invalid")
    at = coerce_utc(now)
    cutoff = at - lookback
    day = cutoff.replace(hour=0, minute=0, second=0, microsecond=0)
    last_day = at.replace(hour=0, minute=0, second=0, microsecond=0)
    fires: list[datetime] = []
    while day <= last_day:
        fire = day.replace(hour=schedule.hour, minute=schedule.minute)
        cadence_matches = (
            schedule.cadence == "daily"
            or (schedule.cadence == "weekly" and fire.weekday() == 6)
            or (schedule.cadence == "monthly" and fire.day == 1)
        )
        if cadence_matches and cutoff <= fire <= at:
            fires.append(fire)
        day += timedelta(days=1)
    return tuple(fires)


async def materialize_due_scheduled_reports(
    session: AsyncSession,
    *,
    now: datetime,
    schedules: tuple[ScheduledReportSpec, ...],
    lookback: timedelta = SCHEDULE_RECOVERY_LOOKBACK,
) -> int:
    """Create missing scheduled run/outbox pairs for bounded due Beat slots.

    This transaction only spans PostgreSQL writes. Broker publication happens
    after commit through the normal leased outbox relay.
    """
    materialized = 0
    for schedule in schedules:
        for fire in _due_schedule_fires(now=now, schedule=schedule, lookback=lookback):
            period_start, period_end = scheduled_period(schedule.cadence, fire)
            run_id = deterministic_run_id(schedule.kind, period_start, period_end)
            existing_run = await session.get(ReportRun, run_id)
            existing_outbox = await session.scalar(
                select(DispatchOutbox.id).where(
                    DispatchOutbox.aggregate_type == "report_run",
                    DispatchOutbox.aggregate_id == run_id,
                    DispatchOutbox.task_name == REPORT_TASK,
                )
            )
            if existing_run is not None and existing_outbox is not None:
                continue
            await enqueue_report(
                session,
                run_id=run_id,
                kind=schedule.kind,
                period_start=period_start,
                period_end=period_end,
                trigger=ReportTrigger.SCHEDULED.value,
                requested_by=None,
            )
            materialized += 1
    return materialized


def _configured_schedules() -> tuple[ScheduledReportSpec, ...]:
    settings = get_settings()
    return (
        ScheduledReportSpec(
            ReportKind.CHANGE,
            settings.report_change_cadence,
            settings.report_generation_hour,
            settings.report_generation_minute,
        ),
        ScheduledReportSpec(
            ReportKind.COMPLIANCE_POSTURE,
            settings.report_compliance_posture_cadence,
            settings.report_generation_hour,
            settings.report_generation_minute,
        ),
        ScheduledReportSpec(
            ReportKind.ACCESS_REVIEW,
            settings.report_access_review_cadence,
            settings.report_generation_hour,
            settings.report_generation_minute,
        ),
        ScheduledReportSpec(
            ReportKind.AUDIT_INTEGRITY,
            settings.report_audit_integrity_cadence,
            settings.report_generation_hour,
            settings.report_generation_minute,
        ),
    )


async def _relay_core(
    batch_size: int | None = None,
    *,
    now: datetime | None = None,
    schedules: tuple[ScheduledReportSpec, ...] = (),
    recovery_lookback: timedelta = SCHEDULE_RECOVERY_LOOKBACK,
) -> dict[str, int]:
    configured_max = get_settings().report_outbox_max_batch_size
    effective_batch = bounded_relay_batch_size(
        batch_size if batch_size is not None else configured_max,
        configured_max=configured_max,
    )
    maker = db.get_sessionmaker()
    owner = f"{socket.gethostname()}:{id(asyncio.current_task())}"
    relay_now = now if now is not None else datetime.now(UTC)
    async with maker() as session:
        if schedules:
            await materialize_due_scheduled_reports(
                session,
                now=relay_now,
                schedules=schedules,
                lookback=recovery_lookback,
            )
        rows = await claim_pending(session, owner=owner, batch_size=effective_batch)
        pending, oldest = await outbox_status(session, relay_now)
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
    return asyncio.run(_relay_core(batch_size, schedules=_configured_schedules()))


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
