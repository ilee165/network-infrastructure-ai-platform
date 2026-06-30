# Runbook — SLO: API read latency burn-rate alerts

> **STUB — runbook contract, not yet narrated.** Satisfies the ADR-0046 §3
> mandatory-`runbook_url` contract (G-OBS §385, freshness <= 90 days). Operator
> prose is the **Documentation Agent**'s output (ADR-0019 §4), named-deferred until
> a reachable LLM provider exists; this stub carries the deterministic facts + the
> on-call checklist only.

last-reviewed: 2026-06-30

## SLO

| Field | Value |
|---|---|
| §6 SLI | API read latency |
| §6 SLO | p95 < 300 ms **AND** p99 < 1 s |
| Latency budget | <= 5% of requests may exceed 300 ms (p95); <= 1% may exceed 1 s (p99) |
| Recording rules (W3-T2) | `slo:netops_api_read_latency:p95_5m`, `slo:netops_api_read_latency:p99_5m` |
| Alerts (W3-T3) | `NetopsApiReadLatencyP95FastBurn` (page, 14.4x over 5m & 1h), `NetopsApiReadLatencyP95SlowBurn` (ticket, 6x over 30m & 6h), `NetopsApiReadLatencyP99FastBurn` (page) |
| ADRs | ADR-0046 §2 §118 (latency = burn on fraction exceeding objective, NOT quantile-over-threshold), ADR-0015 |

## What firing means

The **fraction of read requests exceeding the objective threshold** (300 ms for
p95, 1 s for p99) is burning the latency budget. Per ADR-0046 §2 §118 the SLO alert
burns on the too-slow request *fraction* (computed from the duration histogram's
`le` buckets), NOT a quantile breaching a static threshold — the latter is the
disallowed single-threshold form. Fast tier = confirmed over 5m & 1h; slow tier =
sustained over 30m & 6h.

## On-call checklist (deterministic)

1. Which routes are slow? Inspect the `netops_http_request_duration_seconds_bucket`
   distribution by route/method (high-cardinality labels are kept on the raw
   histogram, aggregated away only in the SLI).
2. Saturation: api CPU/memory, worker queue backpressure, DB connection-pool
   exhaustion (PgBouncer, ADR-0042), Neo4j projection query latency.
3. Recent deploy or migration (an N+1 query / missing index is the classic cause).
4. Scale: is the api HPA (W2-T1) at max replicas? Is `http_requests_per_second`
   (ADR-0043 adapter) elevated?
5. After mitigation, confirm the too-slow fraction drops below the budget and the
   alert clears.

## Related

- `deploy/observability/slo-burn-rate.alerts.yaml`, `slo-recording.rules.yaml`
- Fault-injection MTTD harness (W3-T5).
