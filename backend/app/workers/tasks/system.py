"""Operational tasks on the ``system`` queue."""

from __future__ import annotations

from datetime import UTC, datetime

from app.workers.celery_app import celery_app


@celery_app.task(name="system.healthcheck")
def healthcheck() -> dict[str, str]:
    """Trivial broker round-trip proof.

    Used by the worker container healthcheck (alongside ``celery inspect
    ping``, ADR-0015 §4) and by smoke tests to verify queue wiring.
    """
    return {"status": "ok", "timestamp": datetime.now(UTC).isoformat()}
