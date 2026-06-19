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
from celery.schedules import crontab
from kombu import Queue

from app.core.config import get_settings

#: Canonical D8 queue names — referenced by compose/K8s worker commands.
QUEUE_DISCOVERY = "discovery"
QUEUE_CONFIG = "config"
QUEUE_PACKET = "packet"
QUEUE_DOCS = "docs"
#: Topology projection queue (M2): Postgres -> Neo4j sync after discovery.
QUEUE_TOPOLOGY = "topology"
#: Default queue for operational tasks (not a D8 work queue).
QUEUE_SYSTEM = "system"

WORK_QUEUES: tuple[str, ...] = (
    QUEUE_DISCOVERY,
    QUEUE_CONFIG,
    QUEUE_PACKET,
    QUEUE_DOCS,
    QUEUE_TOPOLOGY,
)


def create_celery_app() -> Celery:
    """Build the Celery app from settings (broker and backend are Redis)."""
    settings = get_settings()
    celery = Celery(
        "netops",
        broker=settings.redis_url,
        backend=settings.redis_url,
        include=[
            "app.workers.tasks.system",
            "app.workers.tasks.discovery",
            "app.workers.tasks.topology",
            "app.workers.tasks.config",
            "app.workers.tasks.packet",
        ],
        # M5+: ".docs"
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
            Queue(QUEUE_TOPOLOGY),
        ),
        task_routes={
            "discovery.*": {"queue": QUEUE_DISCOVERY},
            "config.*": {"queue": QUEUE_CONFIG},
            "packet.*": {"queue": QUEUE_PACKET},
            "docs.*": {"queue": QUEUE_DOCS},
            "topology.*": {"queue": QUEUE_TOPOLOGY},
            "system.*": {"queue": QUEUE_SYSTEM},
        },
        # Celery-beat schedules (ADR-0017 §1): the nightly config backup fans out
        # one capture per reachable device at a configurable UTC time. Beat is run
        # as a dedicated process: ``celery -A app.workers.celery_app beat``.
        beat_schedule={
            "config-nightly-backup": {
                "task": "config.nightly_backup",
                "schedule": crontab(
                    hour=str(settings.config_backup_hour),
                    minute=str(settings.config_backup_minute),
                ),
            },
            # pcap retention purge (ADR-0023 §4): delete expired pcap files and
            # tombstone their metadata rows on a daily UTC schedule.
            "pcap-retention-purge": {
                "task": "packet.purge_expired",
                "schedule": crontab(
                    hour=str(settings.pcap_retention_hour),
                    minute=str(settings.pcap_retention_minute),
                ),
            },
            # raw-artifact retention purge (M5 hardening, ADR-0023 §4 parity):
            # hard-delete verbatim device CLI output past the retention window on
            # a daily UTC schedule (auditing each sweep).
            "raw-artifact-retention-purge": {
                "task": "discovery.purge_expired_artifacts",
                "schedule": crontab(
                    hour=str(settings.raw_artifact_retention_hour),
                    minute=str(settings.raw_artifact_retention_minute),
                ),
            },
        },
    )
    return celery


#: Worker entrypoint: ``celery -A app.workers.celery_app worker -Q <queue>``.
celery_app = create_celery_app()
