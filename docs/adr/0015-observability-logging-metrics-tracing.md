# ADR-0015: Observability — Structured Logging, Metrics, Tracing, Health Endpoints

**Status:** Accepted | **Date:** 2026-06-09 | **Decision:** D15

## Context

CLAUDE.md's production-readiness section requires every iteration to improve **observability** (alongside reliability and maintainability), under **"Local first"** and **"Self hosted"** — so the platform must be observable without phoning home or mandating an external SaaS. The brief (D15) fixes: **structlog JSON logging**, **Prometheus `/metrics`**, **OpenTelemetry tracing with an optional collector**, and **health/readiness endpoints on every container**. These endpoints are load-bearing elsewhere: Compose healthchecks and K8s probes (ADR-0013) depend on them from milestone M0. Observability is distinct from the **audit log** (ADR-0011): logs and traces are operational and lossy; audit is a legal record and append-only — neither substitutes for the other.

## Decision

### 1. Logging — structlog, JSON, correlated

- All backend logging goes through **structlog** with a JSON renderer to stdout (container-native; the operator's log shipper — Loki, ELK, CloudWatch — is their choice, not ours). Console-pretty renderer in dev.
- Stdlib `logging` (uvicorn, SQLAlchemy, Celery, netmiko) is routed through structlog's `ProcessorFormatter` so *every* line in the stream is one JSON object.
- **Correlation via `contextvars`:** an ASGI middleware binds `request_id` (and accepts an inbound `X-Request-ID`); the agent framework binds `agent_session_id`, `user_id`, and `reasoning_trace_id`; Celery task signatures carry these bindings into workers so a discovery run is traceable from HTTP request to task to device session in one grep.
- **Redaction processor:** a structlog processor strips known secret fields (credentials, tokens, KEK material) before rendering — defense-in-depth for ADR-0011's "secrets never in logs".

### 2. Metrics — Prometheus

- `api` exposes `/metrics` via `prometheus-client`; **PROPOSED:** FastAPI HTTP metrics via `prometheus-fastapi-instrumentator` (latency/requests/in-flight per route) — the brief mandates Prometheus metrics but not the instrumentation library.
- Domain metrics (counters/histograms, labeled conservatively to bound cardinality):
  - `netops_plugin_command_duration_seconds{vendor, capability}` and `netops_plugin_errors_total{vendor, capability}` — multi-vendor health at a glance (D6/D7).
  - `netops_discovery_runs_total{status}` / `netops_discovery_duration_seconds`.
  - `netops_llm_requests_total{profile, model}`, `netops_llm_tokens_total{profile, direction}`, `netops_llm_latency_seconds{profile}` — cost and latency per ADR-0009 profile.
  - `netops_change_requests_total{state}` and approval-latency histogram (D11 workflow health).
  - `netops_celery_queue_depth{queue}` for `discovery|config|packet|docs` (D8). **PROPOSED:** worker/task metrics scraped via a `celery-exporter` sidecar service in Compose/Helm rather than hand-rolled task instrumentation.
- Grafana dashboards are shipped as JSON in `deploy/` (**PROPOSED**) but running Prometheus/Grafana is the operator's choice — the platform only *exposes*; it does not bundle a monitoring stack by default.

### 3. Tracing — OpenTelemetry, off by default

- `opentelemetry-sdk` with auto-instrumentation for FastAPI, SQLAlchemy, Celery, httpx, and redis. Spans activate and export via OTLP **only when `OTEL_EXPORTER_OTLP_ENDPOINT` is set** — no egress, no overhead by default (local-first, secure by default). The optional collector is the operator's (in-cluster otel-collector, Jaeger, Tempo…).
- Agent runs add custom spans per LangGraph node and tool call, attributed with `agent_session_id` — giving a flame-graph view of "why did this troubleshooting run take 90 seconds", complementary to (not replacing) the persisted reasoning trace.

### 4. Health and readiness — every container

| Container | Liveness | Readiness |
|---|---|---|
| `api` | `GET /healthz` (process up, event loop responsive) | `GET /readyz` — checks Postgres, Redis, Neo4j connectivity; degrades with per-dependency detail |
| `worker` | **PROPOSED:** `celery inspect ping` wrapped in a container healthcheck script | same script + broker connectivity |
| `frontend` | nginx `GET /healthz` static 200 | same |
| `postgres` / `redis` / `neo4j` | native (`pg_isready`, `redis-cli ping`, Neo4j HTTP `/`) | native |

- `/readyz` failing on a dependency outage takes `api` out of rotation without killing it (probes per ADR-0013). Health endpoints are unauthenticated but expose **no** version/config detail beyond per-dependency up/down (**PROPOSED** hardening choice).

## Consequences

**Positive**
- One JSON log stream with request/agent-session correlation makes multi-container debugging tractable from day one, and slots into whatever aggregation the enterprise already runs.
- Expose-don't-bundle keeps the self-hosted footprint lean while remaining fully compatible with standard Prometheus/Grafana/OTel stacks enterprises already operate.
- LLM token/latency metrics per profile give operators the data to choose between `local` and commercial providers (ADR-0009) on evidence.
- Tracing-off-by-default means zero telemetry leaves the deployment unless the operator wires it — consistent with secure-by-default and air-gapped operation.

**Negative**
- No bundled dashboarding means a bare MVP install has metrics nobody is looking at until the operator connects Prometheus; "works but unobserved" is a real early-adopter pitfall (mitigated by shipping dashboard JSON and compose snippets as opt-in).
- Label discipline on metrics is a permanent review burden — one careless `device_id` label and Prometheus cardinality explodes at enterprise device counts.
- Three pillars (structlog, Prometheus, OTel) instrumented across api *and* workers is genuine ongoing maintenance, and Celery's OTel context propagation has rough edges that need explicit tests.
- The worker healthcheck via `celery inspect ping` is heavier than an HTTP probe and can false-negative under broker load.

## Alternatives considered

1. **Bundle a full monitoring stack (Prometheus + Grafana + Loki) in the default Compose/Helm install.** Rejected: triples the default footprint, duplicates infrastructure every target enterprise already has, and turns the platform team into operators of a monitoring distribution. Shipped instead as optional snippets/dashboards.
2. **Sentry (or another APM SaaS) as the primary error/trace destination.** Rejected as a default: external egress violates local-first/secure-by-default and fails air-gapped deployments outright (an explicit Consultant open item, brief section 9). Operators can point the OTLP exporter at self-hosted Sentry or any APM if they choose.
3. **Plain stdlib logging with formatted strings, no structlog.** Rejected: unparseable in aggregators, no processor pipeline for redaction, and contextvar correlation would be reimplemented by hand — structlog provides exactly this and is fixed by D15 anyway.
4. **StatsD/Telegraf push metrics instead of Prometheus pull.** Rejected: pull + `/metrics` is the K8s-native convention (ADR-0013's probes and ServiceMonitors compose with it), avoids running an aggregation daemon as a hard dependency, and is what D15 mandates.
