"""Celery application (ADR-0008): Redis broker/result backend, four work queues.

Canonical queues (D8): ``discovery``, ``config``, ``docs`` — plus a ``system``
default queue for operational tasks (healthcheck). Most task names follow
``"<queue>.<verb>_<noun>"`` and are routed to their queue by prefix, so adding a
task never requires editing routes.

The ``packet`` queue is the sole exception (ADR-0031 §1): it is split into two
separately-hardened workloads, so ``packet.*`` tasks route by verb rather than by
the shared ``packet`` prefix — ``packet.capture_*`` and ``packet.purge_*`` to
``packet_capture`` (writes/deletes the read-write pcap volume), ``packet.analyze_*``
to the zero-capability, no-egress ``packet_analysis`` sandbox.

Execution semantics per ADR-0008 §5: acks-late + reject-on-worker-lost (tasks
must be idempotent), prefetch 1 for fair fan-out, JSON-only serialization.

Redelivery safety per queue (W2-T4, ADR-0043 §6 — the code half of "scale-in /
node loss only re-runs work"): ``task_acks_late`` + ``task_reject_on_worker_lost``
are enabled GLOBALLY, so a task interrupted by a scaled-in / lost worker is
**redelivered, not lost** — but that is only safe if every side-effecting task on
the queue is idempotent under re-run. The per-queue rationale is documented in
:data:`QUEUE_REDELIVERY_RATIONALE` (and re-asserted on real PG in
``tests/pg/test_worker_idempotency_pg.py``); the live worker-kill proof is W4-T5.
The CR four-eyes gate (ADR-0020) is **not** weakened by any of this: a redelivered
CR execution is an idempotent no-op via the lifecycle state-machine guard, never a
second write that bypasses approval.
"""

from __future__ import annotations

from celery import Celery
from celery.schedules import crontab
from celery.signals import worker_init
from kombu import Queue

from app.core.config import get_settings
from app.core.logging import get_logger

_logger = get_logger(__name__)

#: Canonical D8 queue names — referenced by compose/K8s worker commands.
QUEUE_DISCOVERY = "discovery"
QUEUE_CONFIG = "config"
#: Packet pipeline split (ADR-0031 §1): the credential-bearing capture/retention
#: half (read-write pcap volume) and the untrusted-pcap parser half run as two
#: separately-hardened workloads on distinct queues. ``packet.capture_*`` and the
#: ``packet.purge_*`` retention sweep route to ``packet_capture`` (the workload
#: that writes/deletes the volume); ``packet.analyze_*`` routes to the zero-cap,
#: no-egress ``packet_analysis`` sandbox. They never share a process.
QUEUE_PACKET_CAPTURE = "packet_capture"
QUEUE_PACKET_ANALYSIS = "packet_analysis"
QUEUE_DOCS = "docs"
#: Topology projection queue (M2): Postgres -> Neo4j sync after discovery.
QUEUE_TOPOLOGY = "topology"
#: Default queue for operational tasks (not a D8 work queue).
QUEUE_SYSTEM = "system"

WORK_QUEUES: tuple[str, ...] = (
    QUEUE_DISCOVERY,
    QUEUE_CONFIG,
    QUEUE_PACKET_CAPTURE,
    QUEUE_PACKET_ANALYSIS,
    QUEUE_DOCS,
    QUEUE_TOPOLOGY,
)

#: Per-queue redelivery-safety rationale (W2-T4, ADR-0043 §6 / ADR-0008 §5).
#:
#: ``task_acks_late`` + ``task_reject_on_worker_lost`` are GLOBAL (see
#: :func:`create_celery_app`), so a task on ANY queue is redelivered — not lost —
#: when its worker is scaled-in / killed mid-run. That is only correct because
#: every side-effecting task is idempotent under re-run; this mapping records WHY
#: a redelivery on each queue produces no duplicate side effect. It is documentation
#: (asserted by ``tests/pg/test_worker_idempotency_pg.py`` + the per-task unit
#: suites; the live worker-kill proof is W4-T5), not a runtime config input.
QUEUE_REDELIVERY_RATIONALE: dict[str, str] = {
    QUEUE_DISCOVERY: (
        "Idempotent by natural-key upsert. ``discovery.collect_device`` persists "
        "via select-by-(mgmt_ip / device_id, name) upsert (engines.discovery."
        "persistence) — a re-run overwrites the same device/interface/route/neighbor "
        "rows, never inserting duplicates. Credential-decrypt audit rows are an "
        "append-only evidence trail (a re-run records a genuine second decrypt "
        "event), and raw_artifacts are retention-purged append-only evidence; "
        "neither is a duplicated business side effect. ``discovery.run`` re-drives "
        "the run lifecycle deterministically from stored run params."
    ),
    QUEUE_CONFIG: (
        "Idempotent by content-addressing + DB-level run guard. "
        "``config.capture_device`` -> engines.config_mgmt.capture_snapshot dedups "
        "on (device_id, content_hash): a redelivery of an unchanged config stores NO "
        "new blob and (W2-T4 fix) emits NO second ``config.snapshot_captured`` audit "
        "row — it only advances ``captured_at`` to mark the fresh observation. "
        "``config.nightly_backup`` (the beat orchestrator) accepts an optional "
        "``run_id`` and derives a deterministic slot UUID when absent; it INSERTs a "
        "``config_backup_runs`` row ON CONFLICT DO NOTHING before any audit emit or "
        "fan-out — a redelivered task finds the row already present, returns "
        "``status='skipped'``, and emits no second ``config.backup_run_started`` / "
        "``config.backup_run_finished`` audit pair and dispatches no second capture "
        "wave (W2-T4 finding, ADR-0043 §6, proven on real PG in "
        "tests/pg/test_worker_idempotency_pg.py)."
    ),
    QUEUE_PACKET_CAPTURE: (
        "``packet.capture_*`` writes are keyed to a pre-created capture row whose "
        "state machine (engines.packet.capture) guards re-entry, and "
        "``packet.purge_expired`` is a cutoff-driven retention sweep that tombstones "
        "by id — a re-run deletes/tombstones nothing already tombstoned (a no-op)."
    ),
    QUEUE_PACKET_ANALYSIS: (
        "``packet.analyze_*`` reads the pcap READ-ONLY in the zero-egress sandbox and "
        "writes findings keyed to the capture id; a re-run recomputes the same "
        "deterministic findings for the same immutable pcap (safe overwrite)."
    ),
    QUEUE_DOCS: (
        "Generated documents are content-addressed / keyed to their source "
        "(config snapshot, run) the same way as config snapshots; a re-run "
        "regenerates the same artifact rather than appending a duplicate. (No "
        "docs Celery task is wired yet — the include list reserves ``.docs``.)"
    ),
    QUEUE_TOPOLOGY: (
        "``topology.sync_after_run`` is a full projection of current inventory into "
        "Neo4j + a snapshot; it is an overwrite/rebuild, so a redelivery re-projects "
        "the same state (idempotent) and never re-raises."
    ),
    QUEUE_SYSTEM: (
        "Operational tasks only. ``system.healthcheck`` is read-only; "
        "``credentials.re_wrap_keys`` is a confirm-then-swap KEK re-wrap that is "
        "idempotent by construction (already-active-version rows are skipped, the "
        "decrypted payload is byte-identical), so a redelivery re-wraps nothing new."
    ),
}


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
            "app.workers.tasks.credentials",
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
            Queue(QUEUE_PACKET_CAPTURE),
            Queue(QUEUE_PACKET_ANALYSIS),
            Queue(QUEUE_DOCS),
            Queue(QUEUE_TOPOLOGY),
        ),
        task_routes={
            "discovery.*": {"queue": QUEUE_DISCOVERY},
            "config.*": {"queue": QUEUE_CONFIG},
            # Packet split (ADR-0031 §1): route by verb, not the shared prefix.
            # The credential-bearing capture path and the volume-deleting
            # retention sweep go to the read-write capture workload; the
            # untrusted-pcap parser goes to the zero-egress analysis sandbox.
            "packet.capture_*": {"queue": QUEUE_PACKET_CAPTURE},
            "packet.purge_*": {"queue": QUEUE_PACKET_CAPTURE},
            "packet.analyze_*": {"queue": QUEUE_PACKET_ANALYSIS},
            "docs.*": {"queue": QUEUE_DOCS},
            "topology.*": {"queue": QUEUE_TOPOLOGY},
            "system.*": {"queue": QUEUE_SYSTEM},
            # KEK rotation re-wrap (W6-T3): an operator/KMS-triggered operational
            # task (not a D8 work queue, not beat-coupled to DR) — runs on the
            # default system queue.
            "credentials.*": {"queue": QUEUE_SYSTEM},
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
            # queue-depth sampling (W3-T0, ADR-0015 §2 / ADR-0046 §1/§5): refresh the
            # ``netops_celery_queue_depth`` saturation gauge from each work queue's
            # Redis backlog every 15 s so the queue-stall SLI stays fresh between
            # scrapes (the hand-rolled, no-celery-exporter-sidecar path).
            "queue-depth-sample": {
                "task": "system.sample_queue_depths",
                "schedule": settings.queue_depth_sample_seconds,
            },
        },
    )
    return celery


def start_worker_metrics_server(port: int) -> bool:
    """Start the worker's Prometheus ``/metrics`` HTTP server on *port* (W3-T0).

    The Celery worker has no HTTP server of its own, so the default-REGISTRY
    series — the KEK posture gauges, the topology-RTO histogram, and the
    ``netops_*`` discovery/LLM/CR/queue series this worker emits (ADR-0015 §2) —
    are exposed by a tiny ``prometheus_client`` HTTP server started once in the
    worker main process. The K8s worker Deployments scrape this port.

    Graceful by design (mirrors :mod:`app.core.metrics`): returns ``False`` (and
    logs, never raises) when ``prometheus_client`` is absent or the port is
    already bound — a metrics-server failure must never take a worker down or
    stop it draining its queue.
    """
    try:
        from prometheus_client import start_http_server
    except ImportError:
        _logger.info("worker.metrics_server_skipped", reason="prometheus_client_absent")
        return False
    try:
        start_http_server(port)
    except OSError as exc:
        # Port already bound (e.g. a co-located second worker, or a re-init) must
        # not crash the worker; the first server keeps serving the shared REGISTRY.
        _logger.warning(
            "worker.metrics_server_unavailable", port=port, reason_class=type(exc).__name__
        )
        return False
    _logger.info("worker.metrics_server_started", port=port)
    return True


@worker_init.connect
def _start_metrics_on_worker_init(**_kwargs: object) -> None:
    """Expose ``/metrics`` once when a Celery worker boots (W3-T0, ADR-0015 §2).

    ``worker_init`` fires once in the worker MAIN process (before prefork children),
    so the HTTP server binds the configured port exactly once per worker.
    """
    start_worker_metrics_server(get_settings().worker_metrics_port)


#: Worker entrypoint: ``celery -A app.workers.celery_app worker -Q <queue>``.
celery_app = create_celery_app()
