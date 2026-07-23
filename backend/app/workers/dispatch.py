"""Hardened, allowlisted Celery publication boundary (ADR-0059)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from app.services.report_outbox import REPORT_TASK, validate_dispatch
from app.workers.celery_app import (
    QUEUE_DISCOVERY,
    QUEUE_DOCS,
    QUEUE_PACKET_CAPTURE,
    QUEUE_TOPOLOGY,
    celery_app,
)

_ALLOWED_TASK_QUEUES = {
    (REPORT_TASK, QUEUE_DOCS),
    ("discovery.run", QUEUE_DISCOVERY),
    ("packet.capture_device", QUEUE_PACKET_CAPTURE),
    ("packet.capture_segment", QUEUE_PACKET_CAPTURE),
    ("topology.sync_after_run", QUEUE_TOPOLOGY),
}


class DispatchPublicationError(RuntimeError):
    """Redacted broker publication failure."""


def durable_dispatch(
    *,
    task_name: str,
    queue: str,
    payload: dict[str, Any] | None = None,
    args: list[Any] | None = None,
    countdown: float | None = None,
    eta: datetime | None = None,
    task_id: str | None = None,
    dispatch_id: uuid.UUID | None = None,
) -> Any:
    if (task_name, queue) not in _ALLOWED_TASK_QUEUES:
        raise ValueError("dispatch_not_allowlisted")
    if payload is not None and args is not None:
        raise ValueError("dispatch_arguments_ambiguous")
    if dispatch_id is not None:
        if payload is None:
            raise ValueError("dispatch_payload_required")
        validate_dispatch(task_name, payload, queue, dispatch_id=dispatch_id)
        stable_task_id = str(dispatch_id)
        if task_id is not None and task_id != stable_task_id:
            raise ValueError("dispatch_identity_conflict")
        task_id = stable_task_id
    options: dict[str, Any] = {
        "queue": queue,
        "retry": True,
        "retry_policy": {"max_retries": 3, "interval_start": 0, "interval_step": 1},
    }
    if payload is not None:
        options["kwargs"] = payload
    if args is not None:
        options["args"] = args
    if countdown is not None:
        options["countdown"] = countdown
    if eta is not None:
        options["eta"] = eta
    if task_id is not None:
        options["task_id"] = task_id
    try:
        return celery_app.send_task(task_name, **options)
    except Exception:
        raise DispatchPublicationError("publication_failed") from None
