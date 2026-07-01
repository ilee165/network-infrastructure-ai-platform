"""Prometheus metric set + setters for the platform (ADR-0015 §2, ADR-0046 §1).

This module owns the application's domain Prometheus series — the KEK-provider
posture gauges (P1 W6-T2) plus the ``netops_*`` HTTP / discovery / LLM / agent /
ChangeRequest / queue series (P3 W3-T0) that the §6 SLIs and the ADR-0046 §1
recording rules are defined over. Everything registers on the default
``prometheus_client`` ``REGISTRY`` so the api + worker ``/metrics`` endpoints
expose one consistent set, and W3-T2 derives every SLI recording rule from these
exact names (a renamed base metric breaks the rule lint, by design).

KEK posture gauges (ADR-0032 §2/§4 — gate-checkable, not just a log line):

  * ``vault_key_provider_production_grade`` — Gauge ``1`` when the active provider
    self-reports :attr:`~app.core.crypto.KeyProvider.is_production_grade`, else
    ``0`` (a local Env/File fallback). Set once at startup (ADR-0032 §2/§5).
  * ``vault_key_provider_healthy`` — Gauge ``1`` when ``provider.health()`` last
    reported reachable, else ``0``. Refreshed by the readiness probe so an
    unreachable KMS pulls the replica from rotation while it stays *live*
    (ADR-0032 §4).

``netops_*`` SLI base series (ADR-0015 §2 / ADR-0046 §1):

  * ``netops_http_requests_total{method, route, status_class}`` +
    ``netops_http_request_duration_seconds{method, route}`` — API availability
    (non-5xx ratio) and read latency; also the base for the W2 api-HPA
    ``http_requests_per_second`` request-rate signal (ADR-0043 §1). The ``route``
    label is the **templated** FastAPI route pattern (``/api/v1/devices/{id}``),
    never the raw path or an id — cardinality discipline (ADR-0015 §2,
    ADR-0046 §1 §90).
  * ``netops_discovery_runs_total{status}`` + ``netops_discovery_duration_seconds``
    — discovery job success rate.
  * ``netops_llm_requests_total{profile, model}`` /
    ``netops_llm_tokens_total{profile, direction}`` /
    ``netops_llm_latency_seconds{profile}`` — LLM cost + latency per profile.
  * ``netops_agent_first_token_seconds{profile}`` — agent-chat first-token latency
    (the §6 first-token SLI), observed as time-to-first-persisted-reasoning-step.
  * ``netops_change_requests_total{state}`` +
    ``netops_change_request_approval_latency_seconds`` — ChangeRequest workflow.
  * ``netops_celery_queue_depth{queue}`` — per-queue backlog gauge (the series the
    W3-T5 queue-stall fault-injection perturbs).
  * ``audit_export_lag_seconds`` — audit→SIEM export lag (``now − commit_ts of the
    last exported audit row``), the §6 ``p95 < 60 s`` SLI W3-T3 alerts on
    (ADR-0045 §3). A held-down SIEM grows the backlog in the durable ``audit_log``
    table (NOT in lost rows) and drives this gauge up; a recovered sink drains it.

Registration is **graceful**, mirroring :mod:`app.engines.topology.metrics`:
``prometheus_client`` is an optional observability dependency (D15). When it is
importable the metrics register on the default ``REGISTRY``; when it is not, the
setters become safe no-ops so importing this module — and the request / worker /
agent hot paths that call it — never hard-fails on a slim install. Only a missing
dependency degrades to no-ops; a real registration/runtime error (e.g. a
duplicate-series collision on the default ``REGISTRY``) still surfaces (CR5).

Secure by default (ADR-0032 §6 / ADR-0046 §1): every series carries counts,
durations, and bounded enum labels only — never a key handle, ARN, vault URI,
``credential_ref``, device id, raw path, user id, prompt body, or any payload.
"""

from __future__ import annotations

from typing import Any

__all__ = [
    "AGENT_FIRST_TOKEN_SECONDS",
    "AUDIT_EXPORT_LAG_SECONDS",
    "CHANGE_REQUESTS_TOTAL",
    "CHANGE_REQUEST_APPROVAL_LATENCY_SECONDS",
    "CELERY_QUEUE_DEPTH",
    "DISCOVERY_DURATION_SECONDS",
    "DISCOVERY_RUNS_TOTAL",
    "HTTP_REQUESTS_TOTAL",
    "HTTP_REQUEST_DURATION_SECONDS",
    "LLM_LATENCY_SECONDS",
    "LLM_REQUESTS_TOTAL",
    "LLM_TOKENS_TOTAL",
    "PROVIDER_HEALTHY",
    "PROVIDER_PRODUCTION_GRADE",
    "observe_agent_first_token",
    "observe_discovery_run",
    "observe_http_request",
    "observe_llm_request",
    "record_change_request_transition",
    "set_audit_export_lag",
    "set_celery_queue_depth",
    "set_provider_healthy",
    "set_provider_production_grade",
    "status_class_for",
]

# Latency-histogram buckets in SECONDS, straddling the §6 API/agent SLO targets
# (API read p95 < 300 ms / p99 < 1 s, first-token p95): fine resolution below 1 s,
# coarser tail for slow LLM/agent turns so the histogram resolves both objectives. The
# 0.3 boundary is REQUIRED for the API read-latency SLO (p95 < 300 ms): a burn-rate
# over le=0.25 would measure the wrong threshold. Keep the tuple sorted ascending.
_LATENCY_BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.3, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0)
# Wider buckets (seconds) for discovery-run wall clock and approval latency.
_RUN_BUCKETS = (1.0, 5.0, 15.0, 30.0, 60.0, 300.0, 900.0, 1800.0, 3600.0)


try:  # Optional observability dependency (D15) — degrade to no-ops if absent.
    from prometheus_client import Counter, Gauge, Histogram

    PROVIDER_PRODUCTION_GRADE: Any = Gauge(
        "vault_key_provider_production_grade",
        "1 when the active credential-vault KEK provider self-reports "
        "production-grade (a real KMS backend), 0 for a local Env/File fallback "
        "(ADR-0032 §2).",
    )
    PROVIDER_HEALTHY: Any = Gauge(
        "vault_key_provider_healthy",
        "1 when the active KEK provider was last reachable, 0 when its health() "
        "reported unavailable (drives the fail-closed readiness gate, ADR-0032 §4).",
    )

    # --- HTTP (api) — availability + read latency + the HPA request-rate base ---
    HTTP_REQUESTS_TOTAL: Any = Counter(
        "netops_http_requests_total",
        "Total HTTP requests served, labelled by method, the TEMPLATED route "
        "pattern (never the raw path / id), and 2xx/3xx/4xx/5xx status class. "
        "Availability = non-5xx ratio; rate() backs the api-HPA request-rate "
        "(ADR-0046 §1, ADR-0043 §1).",
        ["method", "route", "status_class"],
    )
    HTTP_REQUEST_DURATION_SECONDS: Any = Histogram(
        "netops_http_request_duration_seconds",
        "HTTP request handler duration in seconds, labelled by method + templated "
        "route — the API read-latency p95/p99 SLI (ADR-0046 §1).",
        ["method", "route"],
        buckets=_LATENCY_BUCKETS,
    )

    # --- Discovery (worker) — job success rate ---
    DISCOVERY_RUNS_TOTAL: Any = Counter(
        "netops_discovery_runs_total",
        "Discovery runs that reached a terminal state, by status "
        "(succeeded|partial|failed) — the discovery success-rate SLI (ADR-0046 §1).",
        ["status"],
    )
    DISCOVERY_DURATION_SECONDS: Any = Histogram(
        "netops_discovery_duration_seconds",
        "Wall-clock seconds for one discovery run (seed wave -> terminal state).",
        buckets=_RUN_BUCKETS,
    )

    # --- LLM (api + worker) — cost + latency per ADR-0009 profile ---
    LLM_REQUESTS_TOTAL: Any = Counter(
        "netops_llm_requests_total",
        "LLM model selections/requests, by ADR-0009 profile and resolved model.",
        ["profile", "model"],
    )
    LLM_TOKENS_TOTAL: Any = Counter(
        "netops_llm_tokens_total",
        "LLM tokens consumed, by profile and direction (input|output).",
        ["profile", "direction"],
    )
    LLM_LATENCY_SECONDS: Any = Histogram(
        "netops_llm_latency_seconds",
        "LLM request latency in seconds, by profile.",
        ["profile"],
        buckets=_LATENCY_BUCKETS,
    )

    # --- Agent — chat first-token latency (§6 first-token SLI) ---
    AGENT_FIRST_TOKEN_SECONDS: Any = Histogram(
        "netops_agent_first_token_seconds",
        "Seconds from agent-run start to the first persisted reasoning step (the "
        "operational first-token signal), by reasoning profile (ADR-0046 §1).",
        ["profile"],
        buckets=_LATENCY_BUCKETS,
    )

    # --- ChangeRequest — workflow health ---
    CHANGE_REQUESTS_TOTAL: Any = Counter(
        "netops_change_requests_total",
        "ChangeRequest lifecycle transitions, by the state entered "
        "(draft|pending_approval|approved|rejected|executing|executed|failed|...).",
        ["state"],
    )
    CHANGE_REQUEST_APPROVAL_LATENCY_SECONDS: Any = Histogram(
        "netops_change_request_approval_latency_seconds",
        "Seconds a ChangeRequest spent awaiting approval before an approve/reject decision.",
        buckets=_RUN_BUCKETS,
    )

    # --- Celery — per-queue backlog (W3-T5 queue-stall fault-injection target) ---
    CELERY_QUEUE_DEPTH: Any = Gauge(
        "netops_celery_queue_depth",
        "Pending task backlog per Celery queue (discovery|config|packet*|docs|...) "
        "— the queue-stall saturation signal (ADR-0015 §2, ADR-0046 §1/§5).",
        ["queue"],
    )

    # --- Audit → SIEM export — the export-lag SLI (ADR-0045 §3) ---
    AUDIT_EXPORT_LAG_SECONDS: Any = Gauge(
        "audit_export_lag_seconds",
        "Audit->SIEM export lag in seconds: now - the commit timestamp of the last "
        "audit_log row confirmed delivered to the SIEM (ADR-0045 §3). The p95 < 60 s "
        "SLI W3-T3 alerts on; a held-down SIEM grows the durable backlog and drives "
        "this up (no audit row is lost), a recovered sink drains it.",
    )

    _PROM_ENABLED = True
except ImportError:  # pragma: no cover - exercised only on a slim install
    # No prometheus_client: keep the symbols present (callers reference them) but
    # inert. The startup banner + readiness body + structured logs remain the
    # source of truth. Only a missing dependency degrades to no-ops — a real
    # registration/runtime error (e.g. a duplicate-series collision on the default
    # REGISTRY) must surface, not silently disable observability (CR5).
    PROVIDER_PRODUCTION_GRADE = None
    PROVIDER_HEALTHY = None
    HTTP_REQUESTS_TOTAL = None
    HTTP_REQUEST_DURATION_SECONDS = None
    DISCOVERY_RUNS_TOTAL = None
    DISCOVERY_DURATION_SECONDS = None
    LLM_REQUESTS_TOTAL = None
    LLM_TOKENS_TOTAL = None
    LLM_LATENCY_SECONDS = None
    AGENT_FIRST_TOKEN_SECONDS = None
    CHANGE_REQUESTS_TOTAL = None
    CHANGE_REQUEST_APPROVAL_LATENCY_SECONDS = None
    CELERY_QUEUE_DEPTH = None
    AUDIT_EXPORT_LAG_SECONDS = None
    _PROM_ENABLED = False


def set_provider_production_grade(*, production_grade: bool) -> None:
    """Record the active KEK provider's production-grade posture (0/1 gauge).

    No-op when ``prometheus_client`` is unavailable; the startup banner still
    carries the posture either way.
    """
    if not _PROM_ENABLED:
        return
    PROVIDER_PRODUCTION_GRADE.set(1 if production_grade else 0)


def set_provider_healthy(*, healthy: bool) -> None:
    """Record the active KEK provider's last-observed liveness (0/1 gauge).

    No-op when ``prometheus_client`` is unavailable; the readiness body still
    reports per-dependency up/down either way.
    """
    if not _PROM_ENABLED:
        return
    PROVIDER_HEALTHY.set(1 if healthy else 0)


def status_class_for(status_code: int) -> str:
    """Map an HTTP status code to its bounded ``2xx``/``3xx``/``4xx``/``5xx`` class.

    Bucketing to the status *class* (not the raw code) keeps the
    ``netops_http_requests_total`` label set small and lets the availability SLI
    read ``status_class != "5xx"`` directly (ADR-0046 §1).
    """
    return f"{status_code // 100}xx"


def observe_http_request(
    *, method: str, route: str, status_code: int, duration_seconds: float
) -> None:
    """Record one served HTTP request: count (by status class) + handler duration.

    ``route`` MUST be the templated FastAPI route pattern (``/api/v1/devices/{id}``),
    never the raw path or an id — the caller (the metrics middleware) is
    responsible for that bounded value. No-op when ``prometheus_client`` is absent.
    """
    if not _PROM_ENABLED:
        return
    HTTP_REQUESTS_TOTAL.labels(
        method=method, route=route, status_class=status_class_for(status_code)
    ).inc()
    HTTP_REQUEST_DURATION_SECONDS.labels(method=method, route=route).observe(duration_seconds)


def observe_discovery_run(*, status: str, duration_seconds: float | None = None) -> None:
    """Record one terminal discovery run (``succeeded``/``partial``/``failed``).

    No-op when ``prometheus_client`` is absent; the run's structured log line and
    persisted ``DiscoveryRun`` row remain the source of truth either way.
    """
    if not _PROM_ENABLED:
        return
    DISCOVERY_RUNS_TOTAL.labels(status=status).inc()
    if duration_seconds is not None:
        DISCOVERY_DURATION_SECONDS.observe(duration_seconds)


def observe_llm_request(
    *,
    profile: str,
    model: str,
    latency_seconds: float | None = None,
    input_tokens: int | None = None,
    output_tokens: int | None = None,
) -> None:
    """Record one LLM request: a request count + optional latency / token totals.

    Carries only the profile, the resolved model name, and counts — never a prompt
    or response body (ADR-0009 D3 / ADR-0046 §1). No-op without ``prometheus_client``.
    """
    if not _PROM_ENABLED:
        return
    LLM_REQUESTS_TOTAL.labels(profile=profile, model=model).inc()
    if latency_seconds is not None:
        LLM_LATENCY_SECONDS.labels(profile=profile).observe(latency_seconds)
    if input_tokens is not None:
        LLM_TOKENS_TOTAL.labels(profile=profile, direction="input").inc(input_tokens)
    if output_tokens is not None:
        LLM_TOKENS_TOTAL.labels(profile=profile, direction="output").inc(output_tokens)


def observe_agent_first_token(*, profile: str, seconds: float) -> None:
    """Record an agent run's time-to-first-persisted-reasoning-step, by profile.

    This is the operational first-token signal for the §6 first-token-latency SLI
    (ADR-0046 §1): the agent run is step-granular, so the first persisted reasoning
    step is the earliest user-visible output. No-op without ``prometheus_client``.
    """
    if not _PROM_ENABLED:
        return
    AGENT_FIRST_TOKEN_SECONDS.labels(profile=profile).observe(seconds)


def record_change_request_transition(
    *, state: str, approval_latency_seconds: float | None = None
) -> None:
    """Record one ChangeRequest entering *state*; optionally the approval wait.

    ``state`` is the bounded lifecycle enum value (the CR state machine); no CR
    payload or target detail is recorded (ADR-0020 §4). No-op without
    ``prometheus_client``.
    """
    if not _PROM_ENABLED:
        return
    CHANGE_REQUESTS_TOTAL.labels(state=state).inc()
    if approval_latency_seconds is not None:
        CHANGE_REQUEST_APPROVAL_LATENCY_SECONDS.observe(approval_latency_seconds)


def set_celery_queue_depth(*, queue: str, depth: int) -> None:
    """Set the pending-task backlog gauge for *queue* (the queue-stall SLI base).

    No-op without ``prometheus_client``. The depth is read from Redis by the
    sampler that calls this; this module owns only the series, not the poll.
    """
    if not _PROM_ENABLED:
        return
    CELERY_QUEUE_DEPTH.labels(queue=queue).set(depth)


def set_audit_export_lag(*, lag_seconds: float) -> None:
    """Set the audit->SIEM export-lag gauge (ADR-0045 §3 — the §6 p95 < 60 s SLI).

    *lag_seconds* is ``now − commit_ts of the last audit row confirmed delivered``,
    computed by the export pipeline after each cycle (caught-up ⇒ ~0). The value
    carries no row content, only the age of the cursor — never secret material. The
    export pipeline owns the poll; this module owns only the series. No-op without
    ``prometheus_client`` (the structured ``audit.export`` log line still records it).
    """
    if not _PROM_ENABLED:
        return
    AUDIT_EXPORT_LAG_SECONDS.set(lag_seconds)
