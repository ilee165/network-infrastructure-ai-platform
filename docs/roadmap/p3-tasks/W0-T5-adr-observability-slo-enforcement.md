# W0-T5 — ADR-0046 Observability-SLO enforcement (recording rules, burn-rate alerts, dashboards, fault-injection MTTD)

| | |
|---|---|
| **Wave** | P3 W0 — ADRs / design gate |
| **Owner** | `wf-implementer` |
| **Review tier** | sonnet |
| **Depends on** | — |
| **Builds on** | ADR-0015 (observability: structlog/Prometheus/OTel/health) |
| **PRODUCTION.md** | §6 (SLO table), §11 G-OBS |
| **Status** | Proposed |

## Objective

Ratify how the §6 SLOs become **enforced**: a Prometheus **recording rule** per
SLI, **multi-window multi-burn-rate alerts** per SLO with mandatory runbook links,
**golden-signal Grafana dashboards-as-code**, and a **fault-injection MTTD harness**
(< 5 min). Fix the error-budget + burn-rate/window pairs and the "alert-as-test"
gate (`promtool` firing proof) that W3-T2..T5 implement.

## Scope

**In** — the recording-rule naming convention (one per §6 SLI); the burn-rate
methodology (fast + slow window pair per SLO budget, à la the Google SRE
multi-window approach); the runbook-link requirement (every alert → a runbook
path, freshness ≤ 90 days); the dashboard-as-code format (jsonnet/JSON in-repo,
linted); the fault-injection scenarios (DB down, queue stall, LLM-provider failure)
and the MTTD budget; the **alert-as-test gate** (`promtool test rules` with a
firing negative control — the anti-false-green rule).

**Out** — implementation (W3-T2..T5); the SIEM-export lag SLO mechanism (ADR-0045,
its alert lives here); certified-scale SLO numbers (rebased on Consultant answer).

## Requirements (grounded in PRODUCTION.md §6, §11 G-OBS)

1. **One recording rule per §6 SLI** (all 9 rows), naming the SLI.
2. **Multi-window burn-rate alert per SLO** with the error budget + window pair
   stated in the rule comment; single-threshold trips disallowed.
3. **Runbook link mandatory** — an alert with no runbook is incomplete (G-OBS §336).
4. **Dashboards-as-code** — golden signals (latency/traffic/errors/saturation) for
   api, each queue, PG, Neo4j, Redis, LLM (G-OBS §335); in-repo, linted.
5. **Fault-injection MTTD < 5 min** (G-OBS §337) proven by `promtool`-firing over
   synthetic series; the live-cluster MTTD run is named-deferred only if §0 says so.
6. **Alert-as-test gate:** every alert ships a *should-fire* `promtool` case — the
   anti-false-green discipline (P1-W4 lesson).

## Contracts / artifacts

- `docs/adr/0046-observability-slo-enforcement.md` (Proposed), ADR index updated.

## Test & gate plan

- D16 docs gates only. The ADR names the W3-T2..T5 assertions and the `promtool`
  gate that must bite.

## Exit criteria

- [ ] ADR-0046 written: recording-rule convention; burn-rate methodology + budgets; runbook-link rule; dashboard-as-code format; fault-injection scenarios + MTTD; alert-as-test gate.
- [ ] ADR index updated; one atomic commit.

## Workflow

`wf-implementer` drafts → combined sonnet review → fixer if findings → verifier → one atomic commit.

## Risks

- **Single-threshold alerts** (no burn-rate) → noisy + slow. The ADR fixes
  multi-window burn-rate up front.
- **Green-at-setup alerts that never fire** — the alert-as-test gate is the guard;
  it must be in the ADR, not improvised in W3.
