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

- [ ] Harness drives DB-down / queue-stall / LLM-failure synthetic series.
- [ ] Each fires its alert within **MTTD < 5 min**; healthy series does not fire (negative control).
- [ ] Runs deterministically in CI; live-cluster MTTD named-deferred; one atomic commit.

## Workflow

`wf-observability` → combined sonnet review → fixer if findings → verifier → one atomic commit.

## Risks

- **A harness that asserts an alert fires but never checks the window** → MTTD
  unproven. The < 5-min bound is the assertion.
- **No negative control** → can't distinguish "fires correctly" from "fires always".
