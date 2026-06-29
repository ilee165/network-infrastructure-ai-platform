# W3-T3 — Multi-window burn-rate alert rules + runbook links + `promtool` firing tests

| | |
|---|---|
| **Wave** | P3 W3 — SIEM export + SLO enforcement |
| **Owner** | `wf-observability` |
| **Review tier** | sonnet |
| **Depends on** | **W3-T2** (recording rules) |
| **ADRs** | ADR-0046 (the contract), ADR-0015 (alerting), ADR-0019 (Documentation Agent runbooks) |
| **PRODUCTION.md** | §6, §11 G-OBS |
| **Status** | Proposed |

## Objective

Implement the alerting layer of ADR-0046: a **multi-window multi-burn-rate alert
per SLO** (fast + slow window pair) over the W3-T2 recording rules, each linking a
**runbook**, each backed by a **`promtool test rules` case that proves it FIRES** on
a perturbed series — the alert-as-test discipline that prevents a green-at-setup
alert that never fires (the P1-W4 trap, the defining risk of this phase).

## Scope

**In** — a burn-rate alert per §6 SLO with the error budget + window pair stated in
the rule comment; a `runbook_url`/annotation per alert (runbook freshness ≤ 90
days); `promtool test rules` cases — **both** a not-firing (healthy) series and a
**firing** (perturbed) series per alert.

**Out** — recording rules (W3-T2); dashboards (W3-T4); the live fault-injection
MTTD run (W3-T5); authoring the runbook *content* (Documentation Agent / ADR-0019 —
link to it; create stubs if absent).

## Requirements (grounded in ADR-0046, PRODUCTION.md §6/§11 G-OBS §336)

1. **Multi-window burn-rate** per SLO (fast + slow), not a single threshold; budget
   + window pair in the comment.
2. **Runbook link mandatory** — every alert annotates a runbook path; an alert
   without one is incomplete (§336).
3. **Alert-as-test BITE proof** — each alert has a `promtool` *firing* case over a
   perturbed series **and** a not-firing healthy case; the firing case fails before
   the rule exists, passes after. No alert ships without its firing test.
4. **`promtool check rules` + `test rules` clean** and run in CI as a gate (prove
   the gate bites: a deliberately-broken rule fails CI, then revert).

## Contracts / artifacts

- `PrometheusRule` (alerting group) with burn-rate alerts + runbook annotations;
  `promtool` test files (firing + healthy per alert); CI wiring of `promtool test rules`.

## Test & gate plan

- `promtool check rules` + `promtool test rules` clean (locally first — L1; if
  absent locally, say so + lean on CI).
- **Prove the gate bites:** a broken/never-firing rule fails CI → revert.
- helm render + kubeconform on the rule manifest.

## Exit criteria

- [ ] A multi-window burn-rate alert per §6 SLO, budget + windows documented.
- [ ] Every alert links a runbook (stubs created if absent).
- [ ] Each alert has a `promtool` **firing** test that bites + a healthy not-firing test; `promtool test rules` wired in CI and **proven to bite**.
- [ ] Rules render + kubeconform-valid; one atomic commit.

## Workflow

`wf-observability` → combined sonnet review → fixer if findings → verifier → one atomic commit.

## Risks

- **Green-at-setup alert that never fires** — THE phase risk. The firing `promtool`
  case is the guard; no alert without it.
- **Single-threshold trip** → alert noise / slow detection. Multi-window burn-rate
  is required by ADR-0046.
- **Dead runbook link** → an alert points nowhere mid-incident.
