"""Celery application (ADR-0008): Redis broker/result backend, four work queues.

Canonical queues (D8): ``discovery``, ``config``, ``packet``, ``docs`` — plus a
``system`` default queue for operational tasks (healthcheck). Task names follow
``"<queue>.<verb>_<noun>"`` and are routed to their queue by prefix, so adding a
task never requires editing routes.

Execution semantics per ADR-0008 §5: acks-late + reject-on-worker-lost (tasks
must be idempotent), prefetch 1 for fair fan-out, JSON-only serialization.
"""

from __future__ import annotations

from celery import Celery
from kombu import Queue

from app.core.config import get_settings

#: Canonical D8 queue names — referenced by compose/K8s worker commands.
QUEUE_DISCOVERY = "discovery"
QUEUE_CONFIG = "config"
QUEUE_PACKET = "packet"
QUEUE_DOCS = "docs"
#: Default queue for operational tasks (not a D8 work queue).
QUEUE_SYSTEM = "system"

WORK_QUEUES: tuple[str, ...] = (QUEUE_DISCOVERY, QUEUE_CONFIG, QUEUE_PACKET, QUEUE_DOCS)


def create_celery_app() -> Celery:
    """Build the Celery app from settings (broker and backend are Redis)."""
    settings = get_settings()
    celery = Celery(
        "netops",
        broker=settings.redis_url,
        backend=settings.redis_url,
        include=["app.workers.tasks.system", "app.workers.tasks.discovery"],
        # M2+: "app.workers.tasks.config", ".packet", ".docs"
    )
    celery.conf.update(
        # JSON-only serialization (no pickle — secure by default).
        task_serializer="json",
        result_serializer="json",
        accept_content=["json"],
        timezone="UTC",
        enable_utc=True,
        # Reliability semantics (ADR-0008 §5): redeliver on worker loss; tasks idempotent.
        task_acks_late=True,
        task_reject_on_worker_lost=True,
        worker_prefetch_multiplier=1,
        # Queues + prefix routing (D8).
        task_default_queue=QUEUE_SYSTEM,
        task_queues=(
            Queue(QUEUE_SYSTEM),
            Queue(QUEUE_DISCOVERY),
            Queue(QUEUE_CONFIG),
            Queue(QUEUE_PACKET),
            Queue(QUEUE_DOCS),
        ),
        task_routes={
            "discovery.*": {"queue": QUEUE_DISCOVERY},
            "config.*": {"queue": QUEUE_CONFIG},
            "packet.*": {"queue": QUEUE_PACKET},
            "docs.*": {"queue": QUEUE_DOCS},
            "system.*": {"queue": QUEUE_SYSTEM},
        },
    )
    return celery


#: Worker entrypoint: ``celery -A app.workers.celery_app worker -Q <queue>``.
celery_app = create_celery_app()
