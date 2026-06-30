# Runbook — SLO: Topology projection freshness burn-rate alerts

> **STUB — runbook contract, not yet narrated.** Satisfies the ADR-0046 §3
> mandatory-`runbook_url` contract (G-OBS §385, freshness <= 90 days). Operator
> prose is the **Documentation Agent**'s output (ADR-0019 §4), named-deferred until
> a reachable LLM provider exists; deterministic facts + checklist only.

last-reviewed: 2026-06-30

## SLO

| Field | Value |
|---|---|
| §6 SLI | Topology projection freshness |
| §6 SLO | Projection lag after a discovery run < 5 min (300 s) |
| Recording rule (W3-T2) | `slo:netops_topology_projection_lag:seconds` (base gauge `topology_graph_age_seconds`, ADR-0030) |
| Alerts (W3-T3) | `NetopsTopologyProjectionLagFastBreach` (page, > 300 s over 5m), `NetopsTopologyProjectionLagSlowBreach` (ticket, > 300 s sustained over 30m) |
| ADRs | ADR-0046 §2 §119 (gauge SLO = breach over fast+slow window pair), ADR-0030 (auto-rebuild + freshness gauge), ADR-0015 |

## What firing means

The Neo4j topology projection is stale relative to the latest discovery run. The
gauge SLO is alerted as a multi-window breach (ADR-0046 §2 §119): **fast** pages
when the freshness gauge exceeds 300 s across a 5m window; **slow** tickets when it
stays above 300 s for an entire 30m window (a sustained staleness, not a single
rebuild spike).

## On-call checklist (deterministic)

1. Is the auto-rebuild reconcile running? (ADR-0030 — the freshness gauge is emitted
   by the reconcile). Check the rebuild job/CronJob status and last-success time.
2. Neo4j health: is the projection target up? A liveness failure triggers automatic
   recreate + rebuild (PRODUCTION.md §5) — confirm it completed.
3. Is a large discovery run in flight (legitimately growing the projection backlog)?
   A transient spike clears; a sustained breach (the slow alert) is the real signal.
4. If the rebuild is stuck: see `dr-neo4j-rebuild.md` (Neo4j is rebuilt from
   Postgres, D5).
5. After rebuild, confirm the freshness gauge drops below 300 s and the alert clears.

## Related

- `deploy/observability/slo-burn-rate.alerts.yaml`, `slo-recording.rules.yaml`
- `dr-neo4j-rebuild.md`; Fault-injection MTTD harness (W3-T5).
