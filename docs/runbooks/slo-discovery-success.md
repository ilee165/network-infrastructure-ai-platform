# Runbook — SLO: Discovery job success-rate burn-rate alerts

> **STUB — runbook contract, not yet narrated.** Satisfies the ADR-0046 §3
> mandatory-`runbook_url` contract (G-OBS §385, freshness <= 90 days). Operator
> prose is the **Documentation Agent**'s output (ADR-0019 §4), named-deferred until
> a reachable LLM provider exists; deterministic facts + checklist only.

last-reviewed: 2026-06-30

## SLO

| Field | Value |
|---|---|
| §6 SLI | Discovery job success rate |
| §6 SLO | >= 99% of device tasks succeed (after retries) per run |
| Error budget | 1 - 0.99 = **1%** |
| Recording rule (W3-T2) | `slo:netops_discovery_success:ratio_rate_run` |
| Alerts (W3-T3) | `NetopsDiscoverySuccessFastBurn` (page, 14.4x over 5m & 1h), `NetopsDiscoverySuccessSlowBurn` (ticket, 6x over 30m & 6h) |
| ADRs | ADR-0046 §2/§5 (queue-stall is a §337 MTTD scenario), ADR-0043 (KEDA per-queue scaling), ADR-0015 |

## What firing means

The discovery failed/partial run ratio is consuming the 1% per-run error budget.
A sustained drop is also the **§337 queue-stall** signal (ADR-0046 §5): if the
`discovery` worker queue stops draining, the success ratio falls. Fast tier pages
on a confirmed 5m & 1h burn; slow tier tickets on a 30m & 6h burn.

## On-call checklist (deterministic)

1. Distinguish *failures* from *stall*: check `netops_celery_queue_depth{queue="discovery"}`
   — climbing depth + falling success = a stall; flat depth + failures = device/credential
   issues.
2. Stall: KEDA ScaledObject for the `discovery` queue (W2-T3) — is it scaling? Are
   workers healthy? Redis broker (Sentinel, ADR-0044) reachable?
3. Failures: are they concentrated on one vendor/site/credential? Check device
   reachability and credential validity (rotation, ADR-0040).
4. Retries: confirm the after-retries terminal status — transient SSH/SNMP timeouts
   should self-heal; persistent failures need device-side investigation.
5. After mitigation, confirm the per-run success ratio recovers above 99%.

## Related

- `deploy/observability/slo-burn-rate.alerts.yaml`, `slo-recording.rules.yaml`
- Fault-injection MTTD harness (W3-T5): queue-stall scenario.
