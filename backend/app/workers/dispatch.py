"""Hardened, allowlisted Celery publication boundary (ADR-0059)."""

from __future__ import annotations

import uuid
from typing import Any

from app.services.report_outbox import validate_dispatch
from app.workers.celery_app import celery_app


def durable_dispatch(
    *,
    task_name: str,
    payload: dict[str, Any],
    queue: str,
    dispatch_id: uuid.UUID,
) -> Any:
    validate_dispatch(task_name, payload, queue)
    return celery_app.send_task(
        task_name,
        kwargs=payload,
        queue=queue,
        task_id=str(dispatch_id),
        retry=True,
        retry_policy={"max_retries": 3, "interval_start": 0, "interval_step": 1},
    )
