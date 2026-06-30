"""Operational tasks on the ``system`` queue."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Protocol, cast

from app.core import metrics
from app.core.config import get_settings
from app.workers.celery_app import WORK_QUEUES, celery_app


@celery_app.task(name="system.healthcheck")
def healthcheck() -> dict[str, str]:
    """Trivial broker round-trip proof.

    Used by the worker container healthcheck (alongside ``celery inspect
    ping``, ADR-0015 §4) and by smoke tests to verify queue wiring.
    """
    return {"status": "ok", "timestamp": datetime.now(UTC).isoformat()}


class _QueueLengthClient(Protocol):
    """Minimal Redis surface used to read a queue's backlog (the ``LLEN`` op)."""

    def llen(self, name: str) -> int:  # pragma: no cover - structural typing only
        ...


def sample_queue_depths(
    client: _QueueLengthClient, queues: tuple[str, ...] = WORK_QUEUES
) -> dict[str, int]:
    """Read each work queue's Redis backlog and set ``netops_celery_queue_depth``.

    A Celery/Redis queue is a Redis LIST keyed by the queue name; its ``LLEN`` is
    the pending-task backlog (ADR-0015 §2 — the queue-stall saturation signal that
    the W3-T5 fault-injection perturbs, ADR-0046 §1/§5). The *client* is injected so
    the sampler is unit-testable against a fake; production passes a real Redis
    client. Returns the per-queue depths it observed (also useful for logging/tests).
    """
    depths: dict[str, int] = {}
    for queue in queues:
        depth = int(client.llen(queue))
        depths[queue] = depth
        metrics.set_celery_queue_depth(queue=queue, depth=depth)
    return depths


@celery_app.task(name="system.sample_queue_depths")
def sample_queue_depths_task() -> dict[str, int]:
    """Beat task: sample every work queue's depth into the Prometheus gauge.

    Builds a Redis client from settings (the same broker URL Celery uses) and
    delegates to :func:`sample_queue_depths`. Scheduled in
    :func:`app.workers.celery_app.create_celery_app` so the saturation series stays
    fresh between scrapes without a separate celery-exporter sidecar (ADR-0015 §2
    leaves the exporter PROPOSED; this is the hand-rolled, no-sidecar path).
    """
    import redis

    client = redis.Redis.from_url(get_settings().redis_url)
    try:
        # redis-py types the SYNC client's llen as ``Awaitable[int] | int`` (the
        # async/sync overload share one stub); at runtime the sync client returns
        # a plain int, which ``sample_queue_depths`` coerces via ``int(...)``.
        return sample_queue_depths(cast("_QueueLengthClient", client))
    finally:
        client.close()
