"""Idempotent read-only reconciliation jobs for PRODUCTION.md §6 rows 5/6/9."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

from sqlalchemy.ext.asyncio import async_sessionmaker

from app import db
from app.core import metrics
from app.core.config import get_settings
from app.services.reconciliation import (
    reconcile_change_request_audit,
    reconcile_config_backup,
    reconcile_reasoning_traces,
)
from app.workers.celery_app import celery_app


async def _run(kind: str) -> int:
    settings = get_settings()
    engine = db.create_engine(settings)
    maker = async_sessionmaker(engine, expire_on_commit=False)
    now = datetime.now(UTC)
    try:
        async with maker() as session:
            if kind == "config_backup":
                due_at = now.replace(
                    hour=settings.config_backup_hour,
                    minute=settings.config_backup_minute,
                    second=0,
                    microsecond=0,
                )
                inconsistencies = (
                    await reconcile_config_backup(
                        session, slot=now.date().isoformat(), due_at=due_at, now=now
                    )
                ).inconsistencies
            elif kind == "change_request_audit":
                inconsistencies = (await reconcile_change_request_audit(session)).inconsistencies
            else:
                inconsistencies = (
                    await reconcile_reasoning_traces(session, now=now)
                ).inconsistencies
        metrics.set_reconciliation_result(
            reconciliation=kind,
            inconsistencies=inconsistencies,
            timestamp=now.timestamp(),
        )
        return inconsistencies
    except Exception:
        metrics.set_reconciliation_unhealthy(reconciliation=kind)
        raise
    finally:
        await engine.dispose()


@celery_app.task(name="system.reconcile_config_backup")
def reconcile_config_backup_task() -> int:
    return asyncio.run(_run("config_backup"))


@celery_app.task(name="system.reconcile_change_request_audit")
def reconcile_change_request_audit_task() -> int:
    return asyncio.run(_run("change_request_audit"))


@celery_app.task(name="system.reconcile_reasoning_traces")
def reconcile_reasoning_traces_task() -> int:
    return asyncio.run(_run("reasoning_trace"))
