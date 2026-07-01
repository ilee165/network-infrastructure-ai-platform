# Runbook — SLO: Agent chat first-token latency burn-rate alerts

> **STUB — runbook contract, not yet narrated.** Satisfies the ADR-0046 §3
> mandatory-`runbook_url` contract (G-OBS §385, freshness <= 90 days). Operator
> prose is the **Documentation Agent**'s output (ADR-0019 §4), named-deferred until
> a reachable LLM provider exists; deterministic facts + checklist only.

last-reviewed: 2026-06-30

## SLO

| Field | Value |
|---|---|
| §6 SLI | Agent chat first-token latency |
| §6 SLO | p95 < 5 s (`local` profile, reference GPU); p95 < 3 s (`external` providers) |
| Latency budget | <= 5% of first-token events may exceed the per-profile objective |
| Recording rule (W3-T2) | `slo:netops_agent_first_token_latency:p95_5m` (kept per `profile`) |
| Alerts (W3-T3) | `NetopsAgentFirstTokenLocalFastBurn` (page, local, 14.4x over 5m & 1h), `NetopsAgentFirstTokenExternalFastBurn` (page, external) |
| ADRs | ADR-0046 §2 (per-profile objective split), ADR-0009 (profile enum), ADR-0015 |

## What firing means

First-token latency is breaching the **per-profile** objective (5 s local / 3 s
external) for too large a fraction of agent chats. The alert is kept split by
`profile` so the local-vs-external objective distinction (§6) is preserved — a
single global quantile would erase it.

## On-call checklist (deterministic)

1. Which profile fired? `local` -> the on-prem Ollama/GPU pool (ADR-0009);
   `external` -> the configured external provider.
2. `local`: GPU pool saturation / model cold-start / Ollama queue depth. Check the
   reference-GPU availability (PRODUCTION.md §12 GPU open item).
3. `external`: provider-side latency or rate-limiting; check `netops_llm_*` error /
   latency series and the provider-healthy gauge.
4. Confirm the agent OTel spans (session -> LLM call) to localize the delay
   (queueing vs first-token generation).
5. After mitigation, confirm the per-profile too-slow fraction drops below budget.

## Related

- `deploy/observability/slo-burn-rate.alerts.yaml`, `slo-recording.rules.yaml`
- Fault-injection MTTD harness (W3-T5): LLM-provider-failure scenario (ADR-0046 §5).
