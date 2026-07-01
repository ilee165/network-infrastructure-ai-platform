# W3-T0 — Metrics instrumentation: back the §6 SLIs (HTTP middleware + `netops_*` domain series + `/metrics`)

| | |
|---|---|
| **Wave** | P3 W3 — SIEM export + SLO enforcement |
| **Owner** | `wf-implementer` |
| **Review tier** | combined sonnet (not secret-surface; emits 0/1 + counts, never payload) |
| **Depends on** | W0-T5 (ADR-0046), W2 (HPA `http_requests_per_second` consumer, merged) |
| **ADRs** | ADR-0015 (the `netops_*` metric set + `/metrics`), ADR-0046 §1 (the SLI→metric mapping the recording rules derive from), ADR-0043 (HPA request-rate metric) |
| **PRODUCTION.md** | §6 (SLI "Measured by" column), §11 G-OBS |
| **Status** | Proposed (added 2026-06-30 — user-approved gap closure; see plan §3 W3 row) |

## Why this task exists (the gap)

ADR-0046 §1 states the recording rules (W3-T2) derive every §6 SLI from "the
existing ADR-0015 `netops_*` series." **Those series do not exist in code** — a
2026-06-30 audit found only the P1-W6 Vault KEK gauges (`vault_key_provider_*`)
and the P1-W5 topology-rebuild metrics; no HTTP request/latency instrumentation,
no `netops_discovery_*`/`netops_llm_*`/`netops_change_requests_*` emitters, and no
served `/metrics` route (only referenced in docstrings). Building T2–T5 on absent
series would flag ~7/9 SLIs as un-backed and leave G-OBS hollow. ADR-0015 named
the metrics; this task **wires them**. No new architecture — it implements the
already-ratified ADR-0015 metric set + the §6 "Measured by" column.

## Objective

Emit the `netops_*` Prometheus series the §6 SLIs and ADR-0046 §1 recording rules
are defined over, expose them on a served `/metrics` endpoint (api + worker), and
align the API request-rate series with the W2 HPA's `http_requests_per_second`
consumer so that autoscaling metric goes live. Reuse the existing graceful-degrade
pattern in `app/core/metrics.py` (no-op when `prometheus_client` is absent).

## Scope

**In** — instrument at the event sites that already fire:

1. **HTTP middleware** (FastAPI) → `netops_http_requests_total{method, route, status_class}`
   (availability = non-5xx ratio on `/api/v1/*`; also the base for the HPA
   request-rate) and `netops_http_request_duration_seconds{method, route}` histogram
   (read-latency p95/p99). **Route label = the templated route pattern**
   (`/api/v1/devices/{id}`), never the raw path — cardinality discipline (ADR-0046 §1,
   ADR-0015 §2).
2. **Domain counters** (ADR-0015 §1) at their existing emit sites:
   `netops_discovery_runs_total{status}` + `netops_discovery_duration_seconds`;
   `netops_llm_requests_total{profile, model}`, `netops_llm_tokens_total{profile, direction}`,
   `netops_llm_latency_seconds{profile}` and an agent **first-token** histogram
   `netops_agent_first_token_seconds{profile}`; `netops_change_requests_total{state}`
   + approval-latency histogram; `netops_celery_queue_depth{queue}` (the queue-stall
   series W3-T5 perturbs).
3. **Served `/metrics`** on api and worker (ASGI mount / `generate_latest` over the
   default `REGISTRY`) if not already wired; the existing KEK/topology gauges become
   scrapeable through it.
4. **HPA alignment** — publish the request-rate so the W2 `http_requests_per_second`
   Pods metric resolves (recording rule `rate(netops_http_requests_total[…])` and/or
   the Prometheus-adapter mapping). If the custom-metrics adapter cannot be wired on
   this host, **say so** and ship the underlying counter + the rate recording rule
   the adapter would consume (L1 — flag, don't fake).

**Out** — the recording rules themselves (W3-T2 consumes these series); alerts (T3);
dashboards (T4); reconciliation-job SLIs that are *not* event-counter-shaped
(CR→audit completeness, reasoning-trace persistence, config-backup completeness,
topology-projection freshness) — emit what has an event site, and **flag** any §6
SLI whose backing is a reconciliation job to its owner rather than fabricating a
counter (ADR-0046 §1 "a missing series is a flagged gap, not a fabricated rule").

## Requirements

1. **`netops_*` namespace + ADR-0046 §1 names** — series named so the §1 recording
   rules (`slo:netops_api_availability:ratio_rate5m`, `slo:netops_api_read_latency:p95_5m`,
   `slo:netops_discovery_success:…`, etc.) derive cleanly. Confirm names against ADR-0046 §1.
2. **Cardinality bounded** — templated route only; no `device_id`, raw path, user id,
   or unbounded label. ADR-0015 §2 / ADR-0046 §1 §90.
3. **No payload / secret in any label or value** — counts and durations only.
4. **Graceful-degrade preserved** — importing the metrics module and the hot paths
   never hard-fail when `prometheus_client` is absent (mirror `core/metrics.py`); a
   real duplicate-series/registration error still surfaces (CR5), not silently disabled.
5. **Never block the request path** — middleware observation is O(1), no I/O.
6. **`/metrics` served** and returns the registered series; api + worker.
7. **HPA metric live or honestly flagged** — `http_requests_per_second` resolves, or
   the adapter gap is named with the counter + rate rule shipped.

## Contracts / artifacts

- Extended/`new app/core/metrics.py` (or a sibling) with the metric objects + helper
  setters; FastAPI metrics middleware; `/metrics` route wiring (api + worker); emit
  calls at the discovery/llm/agent/CR/queue event sites; a `/metrics`-served test.

## Test & gate plan

- Unit/integration: middleware records a request (status_class + duration observed);
  templated-route label asserted (raw path/id NOT present — cardinality test bites);
  each domain counter increments at its event site; `/metrics` endpoint returns the
  series; graceful no-op asserted when `prometheus_client` mocked absent.
- Backend D16 gates green; `include_router` introspection green; mypy/ruff clean.
- `promtool`/rule validation is W3-T2's; this task delivers the series they read.

## Exit criteria

- [ ] `netops_http_requests_total` + `netops_http_request_duration_seconds` emitted via middleware with **templated-route, bounded labels** (cardinality test bites on a raw-path/id leak).
- [ ] ADR-0015 domain series (`netops_discovery_*`, `netops_llm_*`, `netops_agent_first_token_seconds`, `netops_change_requests_*`, `netops_celery_queue_depth`) emitted at existing event sites; reconciliation-only SLIs flagged, not fabricated.
- [ ] `/metrics` served on api + worker; graceful no-op without `prometheus_client` preserved; no payload/secret in any series.
- [ ] HPA `http_requests_per_second` resolves (adapter/rate rule) **or** the adapter gap is named with counter + rate rule shipped.
- [ ] `pg-integration` (where touched) + backend D16 + `include_router` green; one atomic commit.

## Workflow

`wf-implementer` → `wf-spec-reviewer` (sonnet) + `wf-quality-reviewer` (sonnet) → `wf-fixer` (sonnet) if findings → `wf-verifier` → one atomic commit.

## Risks

- **High-cardinality route label** → Prometheus blow-up. Templated route only; the
  cardinality test must bite.
- **Over-scoping into reconciliation SLIs** → fabricated counters that lie. Flag, don't fake.
- **Middleware adds latency / blocks** → observation must be O(1), no I/O on the request path.
- **Metric-name drift from ADR-0046 §1** → T2 recording rules can't reference them. Confirm names against the ADR.
