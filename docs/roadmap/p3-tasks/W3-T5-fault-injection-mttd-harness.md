# W3-T5 — Fault-injection MTTD harness (DB down / queue stall / LLM-provider failure → alert fires < 5 min)

| | |
|---|---|
| **Wave** | P3 W3 — SIEM export + SLO enforcement |
| **Owner** | `wf-observability` |
| **Review tier** | sonnet |
| **Depends on** | **W3-T3** (burn-rate alerts) |
| **ADRs** | ADR-0046 (the contract), ADR-0015 (alerting) |
| **PRODUCTION.md** | §11 G-OBS §337 |
| **Status** | Proposed |

## Objective

Implement the MTTD-proof layer of ADR-0046 (G-OBS §337): a **fault-injection
harness** that drives the three synthetic failure scenarios — **DB down, queue
stall, LLM-provider failure** — and asserts the corresponding W3-T3 alert **fires
within the MTTD budget (< 5 min)**. The mechanism bites in CI over synthetic
series; the live-cluster MTTD run is named-deferred per §0.

## Scope

**In** — a harness that synthesizes the metric series each failure produces (DB
scrape gap / 5xx spike, queue depth stall, LLM error-rate spike), feeds them to
`promtool test rules` (or a Prometheus test instance), and asserts the alert fires
within the 5-min window; a negative control (healthy series → no alert).

**Out** — the alerts themselves (W3-T3); the live-cluster chaos run (W4 reliability
drills exercise real failures; the MTTD-on-real-cluster is named-deferred);
dashboards (W3-T4).

## Requirements (grounded in ADR-0046, PRODUCTION.md §11 G-OBS §337)

1. **Three scenarios** — DB down, queue stall, LLM-provider failure each modelled as
   a synthetic series.
2. **MTTD < 5 min asserted** — the alert fires within the window over the synthetic
   series; the assertion is the gate.
3. **Negative control** — a healthy series does **not** fire (no false positive);
   both directions tested (the alert-as-test discipline).
4. **CI-runnable** — runs deterministically in CI via `promtool`/test Prometheus;
   live-cluster MTTD named-deferred (no real cluster on host — say so, L1).

## Contracts / artifacts

- Fault-injection harness + synthetic series per scenario; MTTD assertions; CI wiring.

## Test & gate plan

- Harness runs in CI: each scenario fires its alert within 5 min; healthy series
  does not fire.
- `promtool`/test-Prometheus locally first where available (L1).

## Exit criteria

- [x] Harness drives DB-down / queue-stall / LLM-failure synthetic series.
      (`deploy/observability/slo-mttd.faultinjection.test.yaml`: DB down →
      `NetopsApiAvailabilityFastBurn` (5xx spike); queue stall →
      `NetopsDiscoverySuccessFastBurn` (success-ratio drop, ADR-0046 §5); LLM-
      provider failure → `NetopsAgentFirstTokenExternalFastBurn` (first-token
      spill past the 3 s objective — the operator-visible symptom; see flag).)
- [x] Each fires its alert within **MTTD < 5 min** (DB ≤ 4 m, queue ≤ 4 m, LLM
      3 m — the firing eval_time is the simulated MTTD, asserted strictly < 5 m,
      the window IS the assertion); healthy series does not fire (a negative
      control per scenario, silent at 5 m).
- [x] Runs deterministically in CI (wired into the `observability` job as
      `promtool test rules` + a `run-mttd-bite.sh` BITE proof — a fast alert
      slowed past the budget fails the MTTD assertions); live-cluster MTTD
      **named-deferred** to W4/W5 (no real cluster on host, ADR-0046 §0/§5); one
      atomic commit.

### Flagged (not fabricated)

- **No dedicated LLM-error-ratio SLO/alert exists in §6** — the §6 table has no
  LLM-availability row, and `netops_llm_requests_total` carries no error/status
  label, so a provider failure is detected via its breach of the existing §6
  first-token-latency SLO (`NetopsAgentFirstTokenExternalFastBurn`), not a
  fabricated `netops_llm_*` alert. A dedicated LLM-error-ratio SLO would be a NEW
  §6 row + NEW W3-T3 alert (out of W3-T5 scope). FLAGGED to the §6/W3-T3 owners.
- **Basis = synthetic, simulated budget.** The in-CI proof is `promtool` over
  synthetic series at compressed timestamps. The live-cluster MTTD (real injected
  fault on the W4-T1 kind cluster + 30-day soak) is the W4/W5 drill proof,
  named-deferred — never silently claimed as a live observation.

## Workflow

`wf-observability` → combined sonnet review → fixer if findings → verifier → one atomic commit.

## Risks

- **A harness that asserts an alert fires but never checks the window** → MTTD
  unproven. The < 5-min bound is the assertion.
- **No negative control** → can't distinguish "fires correctly" from "fires always".
