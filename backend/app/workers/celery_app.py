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

import os
from datetime import UTC, datetime
from typing import Any

from celery import Celery
from celery.beat import BeatLazyFunc
from celery.schedules import crontab
from celery.signals import worker_init, worker_process_shutdown
from kombu import Queue

from app.core.config import Settings, get_settings
from app.core.logging import get_logger
from app.engines.reports.idempotency import scheduled_period

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
        "``packet.capture_*`` is idempotent under redelivery (task_acks_late): "
        "before any physical capture the worker claims by unique ``capture_id`` "
        "(``claim_or_get_capture`` / ``ingest_capture`` ON CONFLICT DO NOTHING) so "
        "a redelivered task is a no-op success; "
        "``packet.purge_expired`` is a cutoff-driven retention sweep that tombstones "
        "by id — a re-run deletes/tombstones nothing already tombstoned (a no-op)."
    ),
    QUEUE_PACKET_ANALYSIS: (
        "``packet.analyze_*`` reads the pcap READ-ONLY in the zero-egress sandbox and "
        "writes findings keyed to the capture id; a re-run recomputes the same "
        "deterministic findings for the same immutable pcap (safe overwrite)."
    ),
    QUEUE_DOCS: (
        "Idempotent by deterministic claim row (P4 W3-T1, ADR-0053 §2). "
        "``reports.generate`` / ``reports.generate_scheduled`` derive the run PK "
        "from ``(kind, period)`` and INSERT it ON CONFLICT DO NOTHING before any "
        "render or audit emit — a redelivered (or beat+on-demand colliding) task "
        "finds the row and skips/resumes instead of double-generating. "
        "``reports.purge_expired`` is a cutoff-driven retention sweep (re-run "
        "deletes nothing already deleted); ``reports.compliance_sweep`` claims a "
        "deterministic per-UTC-date run row the same way, so a redelivery "
        "persists no duplicate trend history."
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
        "decrypted payload is byte-identical), so a redelivery re-wraps nothing new. "
        "``system.ensure_partitions`` is idempotent DDL (CREATE TABLE IF NOT EXISTS)."
    ),
}


def _report_crontab(settings: Settings, cadence: str) -> crontab:
    """Map a per-kind report cadence to its beat crontab (ADR-0053 §2).

    ``daily`` fires every day, ``weekly`` on Sunday, ``monthly`` on the 1st —
    always at the shared ``report_generation_hour``/``minute`` UTC time. The
    cadence values are ``Literal``-typed in :class:`~app.core.config.Settings`,
    so an unknown token can only be a programming error.
    """
    hour = str(settings.report_generation_hour)
    minute = str(settings.report_generation_minute)
    if cadence == "daily":
        return crontab(hour=hour, minute=minute)
    if cadence == "weekly":
        return crontab(hour=hour, minute=minute, day_of_week="0")
    if cadence == "monthly":
        return crontab(hour=hour, minute=minute, day_of_month="1")
    raise ValueError(f"unknown report cadence {cadence!r}; expected daily|weekly|monthly")


def _scheduled_period_bound(cadence: str, index: int) -> str:
    """``BeatLazyFunc`` target: one bound of the CURRENT cadence period.

    PR #166 F2 (beat-slot identity): Celery beat evaluates ``BeatLazyFunc``
    entries in ``Scheduler.apply_async`` — i.e. AT DISPATCH TIME, right when
    beat decides to fire the task — not when the worker later executes it.
    Embedding the computed bound in the outgoing message means a redelivered
    or delayed-past-midnight tick still carries the period beat actually
    meant; the worker (:func:`app.workers.tasks.reports.generate_scheduled`)
    never re-derives it from its own execution-time clock. Returns an ISO
    string (JSON-serializable task arg), *index* selects start (``0``) or
    end (``1``) of the ``(start, end)`` pair :func:`scheduled_period` returns.
    """
    return scheduled_period(cadence, datetime.now(UTC))[index].isoformat()


def _report_schedule_kwargs(cadence: str) -> dict[str, BeatLazyFunc]:
    """The lazy ``period_start``/``period_end`` kwargs for one report beat entry."""
    return {
        "period_start": BeatLazyFunc(_scheduled_period_bound, cadence, 0),
        "period_end": BeatLazyFunc(_scheduled_period_bound, cadence, 1),
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
            "app.workers.tasks.maintenance",
            "app.workers.tasks.reports",
            "app.workers.tasks.report_outbox",
            "app.workers.tasks.reconciliation",
        ],
    )
    if settings.redis_url.startswith("sentinel://"):
        # Kombu's Sentinel transport requires the master name (and the Sentinel
        # AUTH password when set) via transport options — the sentinel:// URL
        # alone carries only non-secret host coordinates (ADR-0044 §1).
        sentinel_options: dict[str, object] = {"master_name": settings.redis_sentinel_master}
        if settings.redis_password:
            sentinel_options["sentinel_kwargs"] = {"password": settings.redis_password}
        celery.conf.broker_transport_options = dict(sentinel_options)
        celery.conf.result_backend_transport_options = dict(sentinel_options)
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
            # Report generation is the document-generation workload class
            # (ADR-0053 §2, D8): no new queue, no new worker Deployment.
            "reports.*": {"queue": QUEUE_DOCS},
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
            "config-backup-reconcile": {
                "task": "system.reconcile_config_backup",
                "schedule": crontab(
                    hour=str(
                        (settings.config_backup_hour + (settings.config_backup_minute + 15) // 60)
                        % 24
                    ),
                    minute=str((settings.config_backup_minute + 15) % 60),
                ),
            },
            "change-request-audit-reconcile": {
                "task": "system.reconcile_change_request_audit",
                "schedule": crontab(hour="0", minute="35"),
            },
            "reasoning-trace-reconcile": {
                "task": "system.reconcile_reasoning_traces",
                "schedule": crontab(hour="0", minute="40"),
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
            # monthly-partition pre-creation (H4, 2026-07-10 review): guarantee the
            # current+next monthly partitions exist for the four range-partitioned
            # tables (ADR-0011) so rows never leak into the DEFAULT partition.
            # Daily + idempotent (CREATE TABLE IF NOT EXISTS); PG-only, no-op
            # elsewhere. Fixed 00:20 UTC — before the retention sweeps.
            "partition-precreate": {
                "task": "system.ensure_partitions",
                "schedule": crontab(hour="0", minute="20"),
            },
            # queue-depth sampling (W3-T0, ADR-0015 §2 / ADR-0046 §1/§5): refresh the
            # ``netops_celery_queue_depth`` saturation gauge from each work queue's
            # Redis backlog every 15 s so the queue-stall SLI stays fresh between
            # scrapes (the hand-rolled, no-celery-exporter-sidecar path).
            "queue-depth-sample": {
                "task": "system.sample_queue_depths",
                "schedule": settings.queue_depth_sample_seconds,
            },
            # Compliance/audit report generation (P4 W3-T1, ADR-0053 §2): one
            # beat entry per kind at the operator-configurable cadence (weekly
            # fires Sunday, monthly fires the 1st, at the shared UTC time).
            # Generation is idempotent per (kind, period) via the claim row, so
            # beat loss / redelivery re-fires safely (PRODUCTION.md §3.2).
            "report-generate-change": {
                "task": "reports.generate_scheduled",
                "args": ("change",),
                "kwargs": _report_schedule_kwargs(settings.report_change_cadence),
                "schedule": _report_crontab(settings, settings.report_change_cadence),
            },
            "report-generate-compliance-posture": {
                "task": "reports.generate_scheduled",
                "args": ("compliance_posture",),
                "kwargs": _report_schedule_kwargs(settings.report_compliance_posture_cadence),
                "schedule": _report_crontab(settings, settings.report_compliance_posture_cadence),
            },
            "report-generate-access-review": {
                "task": "reports.generate_scheduled",
                "args": ("access_review",),
                "kwargs": _report_schedule_kwargs(settings.report_access_review_cadence),
                "schedule": _report_crontab(settings, settings.report_access_review_cadence),
            },
            "report-generate-audit-integrity": {
                "task": "reports.generate_scheduled",
                "args": ("audit_integrity",),
                "kwargs": _report_schedule_kwargs(settings.report_audit_integrity_cadence),
                "schedule": _report_crontab(settings, settings.report_audit_integrity_cadence),
            },
            # Report-artifact retention purge (ADR-0053 §4): daily hard-delete
            # of artifacts past their expiry (7-year PROPOSED default).
            "report-retention-purge": {
                "task": "reports.purge_expired",
                "schedule": crontab(
                    hour=str(settings.report_purge_hour),
                    minute=str(settings.report_purge_minute),
                ),
            },
            "report-outbox-relay": {
                "task": "reports.outbox_relay",
                "schedule": 5.0,
            },
            "report-outbox-reaper": {
                "task": "reports.outbox_reaper",
                "schedule": 60.0,
            },
            # Daily compliance evaluation sweep (ADR-0053 §2) feeding the §7.2
            # trend history — without it the posture report has no time series.
            "compliance-daily-sweep": {
                "task": "reports.compliance_sweep",
                "schedule": crontab(
                    hour=str(settings.compliance_sweep_hour),
                    minute=str(settings.compliance_sweep_minute),
                ),
            },
        },
    )
    if not settings.config_backup_enabled:
        celery.conf.beat_schedule.pop("config-nightly-backup", None)
    return celery


def _multiprocess_registry() -> Any | None:
    """Build a ``MultiProcessCollector``-backed registry, or ``None`` (PR #166 F4).

    Celery's prefork pool runs task BODIES in CHILD processes; every metric
    setter a task calls (``observe_report_generation``, ``set_report_last_
    success``, ...) therefore mutates that CHILD's own per-process
    ``prometheus_client`` value — never the parent's in-memory default
    ``REGISTRY`` the ``/metrics`` HTTP server (started once in the PARENT at
    ``worker_init``, before any child forks) was serving. Scraping the default
    ``REGISTRY`` in that parent forever reads the metrics' zero/unset initial
    state, no matter how many tasks the children complete (compose ``-c 2``+).

    When ``PROMETHEUS_MULTIPROC_DIR`` is set (the standard ``prometheus_client``
    multiprocess-mode contract — every ``Counter``/``Gauge``/``Histogram``
    created anywhere in the process already writes to that directory's mmap
    files once the env var is present at import time), this returns a fresh
    ``CollectorRegistry`` wired to a ``MultiProcessCollector`` over that
    directory, which aggregates every process's file into one scrape. Returns
    ``None`` (caller falls back to the default ``REGISTRY``) when the dir is
    unset — the existing single-process dev/test behavior is unchanged.
    """
    directory = os.environ.get("PROMETHEUS_MULTIPROC_DIR")
    if not directory:
        return None
    from prometheus_client import CollectorRegistry, multiprocess

    os.makedirs(directory, exist_ok=True)
    registry = CollectorRegistry()
    multiprocess.MultiProcessCollector(registry, path=directory)
    return registry


def start_worker_metrics_server(port: int) -> bool:
    """Start the worker's Prometheus ``/metrics`` HTTP server on *port* (W3-T0).

    The Celery worker has no HTTP server of its own, so the default-REGISTRY
    series — the KEK posture gauges, the topology-RTO histogram, and the
    ``netops_*`` discovery/LLM/CR/queue series this worker emits (ADR-0015 §2) —
    are exposed by a tiny ``prometheus_client`` HTTP server started once in the
    worker main process. The K8s worker Deployments scrape this port.

    PR #166 F4: when ``PROMETHEUS_MULTIPROC_DIR`` is set, the server instead
    serves a :func:`_multiprocess_registry` — a ``MultiProcessCollector`` over
    every prefork child's own mmap files — so task-body metric mutations
    (which happen in the children, never the parent) are actually visible here.

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
    registry = _multiprocess_registry()
    try:
        if registry is not None:
            start_http_server(port, registry=registry)
        else:
            start_http_server(port)
    except OSError as exc:
        # Port already bound (e.g. a co-located second worker, or a re-init) must
        # not crash the worker; the first server keeps serving the shared REGISTRY.
        _logger.warning(
            "worker.metrics_server_unavailable", port=port, reason_class=type(exc).__name__
        )
        return False
    _logger.info("worker.metrics_server_started", port=port, multiprocess=registry is not None)
    return True


@worker_init.connect
def _start_metrics_on_worker_init(**_kwargs: object) -> None:
    """Expose ``/metrics`` once when a Celery worker boots (W3-T0, ADR-0015 §2).

    ``worker_init`` fires once in the worker MAIN process (before prefork children),
    so the HTTP server binds the configured port exactly once per worker.

    PR #166 F6: also re-hydrates the report-engine staleness gauge for all
    four kinds from durable history (or the worker's boot timestamp, for a
    kind that has never once succeeded) — see
    :func:`app.workers.tasks.reports.seed_last_success_gauges`. Imported here
    (not at module level) to avoid a celery_app <-> tasks.reports import cycle;
    by the time this signal fires the task modules are already imported.
    """
    start_worker_metrics_server(get_settings().worker_metrics_port)
    from app.workers.tasks.reports import seed_last_success_gauges

    seed_last_success_gauges()


@worker_process_shutdown.connect
def _mark_prefork_child_dead(pid: int | None = None, **_kwargs: object) -> None:
    """Retire a prefork child's multiprocess-mode mmap files on exit (PR #166 F4).

    Without this, a child that exits (worker restart, ``--max-tasks-per-child``
    churn) leaves its per-process gauge/counter/histogram files in
    ``PROMETHEUS_MULTIPROC_DIR`` forever — unbounded directory growth, and a
    dead child's stale last-write competing in the ``mostrecent`` gauge
    aggregation. ``multiprocess.mark_process_dead`` (the documented
    ``prometheus_client`` cleanup hook, mirroring the gunicorn ``child_exit``
    pattern) deletes that pid's files. No-op when this worker is not running
    in multiprocess mode, or ``prometheus_client`` is absent.
    """
    directory = os.environ.get("PROMETHEUS_MULTIPROC_DIR")
    if not directory or pid is None:
        return
    try:
        from prometheus_client import multiprocess
    except ImportError:
        return
    multiprocess.mark_process_dead(pid)


#: Worker entrypoint: ``celery -A app.workers.celery_app worker -Q <queue>``.
celery_app = create_celery_app()
