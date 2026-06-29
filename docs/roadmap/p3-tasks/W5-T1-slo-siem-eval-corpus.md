# W5-T1 — SLO/alert eval corpus + SIEM-export conformance eval

| | |
|---|---|
| **Wave** | P3 W5 — Evals + phase-exit gate |
| **Owner** | `wf-eval-designer` (strong) |
| **Review tier** | **strong** quality |
| **Depends on** | **W3** (SIEM + SLO) |
| **ADRs** | ADR-0046 (SLO), ADR-0045 (SIEM export), ADR-0016 (testing) |
| **PRODUCTION.md** | §6, §11 G-OBS |
| **Status** | Proposed |

## Objective

Build the **proof corpus** the W5-T3 gate cites for G-OBS: a labelled
**alert-correctness corpus** (each §6 alert: a firing case + a healthy case, with
expected MTTD) and a **SIEM-export conformance eval** (format validity across
syslog/CEF/HTTPS, at-least-once + no-gap under fault injection, export-lag within
SLO). Deterministic, byte-stable, CI-runnable.

## Scope

**In** — a labelled corpus of synthetic metric series per §6 alert (firing/healthy +
expected fire-window) consolidating the W3-T3/T5 `promtool` cases into a coverage
matrix; a SIEM-export conformance suite (RFC5424/CEF/JSON schema validity,
ordering, cursor-resume-no-gap, lag-within-SLO, sentinel-secret-absent); coverage
+ threshold assertions; corpus-shape guards (every alert class has a positive +
a negative, so a fire-always or never-fire analyzer can't pass).

**Out** — building the rules/alerts/exporter (W3); the routing re-run (W5-T2); the
gate doc (W5-T3); live-cluster MTTD (named-deferred).

## Requirements (grounded in ADR-0046/0045, PRODUCTION.md §6/§11 G-OBS)

1. **Every §6 alert covered** — firing + healthy case each; the matrix asserts no
   alert is uncovered.
2. **MTTD thresholds met + bite** — each firing case fires within its window; a
   perturbation that delays firing past the window **fails** (the floor bites, not
   vacuous — the P2 firewall-floor pattern).
3. **SIEM conformance** — format valid, ordered, no-gap on resume, lag within SLO,
   no secret leak; under a fault-injected sink outage.
4. **Deterministic + byte-stable** — runs in CI repeatably (synthetic series, no
   wall-clock flakiness; compressed timestamps).

## Contracts / artifacts

- Alert-correctness corpus + coverage matrix; SIEM-export conformance suite; CI wiring.

## Test & gate plan

- Corpus runs in CI deterministically; coverage matrix asserts every alert covered;
  threshold-bite + corpus-shape guards present.
- SIEM conformance suite green under fault injection.

## Exit criteria

- [ ] Every §6 alert has a firing + healthy case; coverage matrix asserts completeness.
- [ ] MTTD/threshold floors **bite** under perturbation; corpus-shape guards present.
- [ ] SIEM-export conformance (format/order/no-gap/lag/no-leak) green under fault injection.
- [ ] Deterministic + byte-stable in CI; one atomic commit.

## Workflow

`wf-eval-designer` (strong) → **`wf-quality-reviewer` (strong)** + `wf-spec-reviewer` → `wf-fixer` if findings → `wf-verifier` → one atomic commit.

## Risks

- **A vacuous floor** (passes regardless) → false G-OBS confidence. The
  perturbation-bite + corpus-shape guards are mandatory (P2 lesson).
- **Wall-clock flakiness** → non-deterministic CI. Use compressed synthetic timestamps.
