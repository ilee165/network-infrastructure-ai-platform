# Runbook — SLO: Audit -> SIEM export lag burn-rate alerts

> **STUB — runbook contract, not yet narrated.** Satisfies the ADR-0046 §3
> mandatory-`runbook_url` contract (G-OBS §385, freshness <= 90 days). Operator
> prose is the **Documentation Agent**'s output (ADR-0019 §4), named-deferred until
> a reachable LLM provider exists; deterministic facts + checklist only.

last-reviewed: 2026-06-30

## SLO

| Field | Value |
|---|---|
| §6 SLI | Audit -> SIEM export lag |
| §6 SLO | p95 < 60 s |
| Recording rule (W3-T2) | `slo:netops_audit_siem_export_lag:seconds` (base gauge `audit_export_lag_seconds`, W3-T1) |
| Alerts (W3-T3) | `NetopsAuditSiemExportLagFastBreach` (page, > 60 s over 5m), `NetopsAuditSiemExportLagSlowBreach` (ticket, > 60 s sustained over 30m) |
| ADRs | ADR-0045 §3 (export-lag SLI), ADR-0046 §2 §119 (gauge SLO = breach over fast+slow window pair), ADR-0015 |

## What firing means

Audit events are not reaching the customer SIEM within the 60 s lag SLO
(G-OBS §388: "Audit -> SIEM export operating within the lag SLO"). The durable
export cursor (ADR-0045) is falling behind. **Fast** pages on a > 60 s lag over 5m;
**slow** tickets when the lag stays above 60 s for an entire 30m window (a sustained
backlog, not a single export-cycle spike).

## On-call checklist (deterministic)

1. Is the export pipeline running? Check the `audit-siem-export` Deployment
   (`deploy/kubernetes/netops/templates/audit-siem-export-deployment.yaml`) and its
   logs for sink errors.
2. Sink reachability: the configured transport (syslog/CEF over TLS, or HTTPS/JSON,
   ADR-0045 §1) — is the SIEM collector up and accepting? Check the egress
   NetworkPolicy (W3-T1) is not blocking the collector endpoint.
3. Backpressure: is the durable `seq` cursor advancing? At-least-once delivery means
   a wedged sink grows the backlog until the sink recovers.
4. TLS / cert issues on the syslog (RFC5425) sink are a common cause — check cert
   validity and the CA trust chain.
5. After the sink recovers, confirm the lag gauge drops below 60 s and the alert
   clears (the backlog drains in `seq` order).

## Related

- `deploy/observability/slo-burn-rate.alerts.yaml`, `slo-recording.rules.yaml`
- Audit hash-chain runbook: `audit-chain-verify-and-reseal.md`
- Fault-injection MTTD harness (W3-T5).
