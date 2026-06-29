# W3-T2 — Prometheus recording rules for every §6 SLI

| | |
|---|---|
| **Wave** | P3 W3 — SIEM export + SLO enforcement |
| **Owner** | `wf-observability` |
| **Review tier** | sonnet |
| **Depends on** | W0-T5 (ADR-0046) |
| **ADRs** | ADR-0046 (the contract), ADR-0015 (Prometheus `/metrics`) |
| **PRODUCTION.md** | §6 (SLI table), §11 G-OBS |
| **Status** | Proposed |

## Objective

Implement the recording-rule layer of ADR-0046: **one Prometheus recording rule per
§6 SLI** (all 9 rows), naming the SLI and computing it from the metrics ADR-0015
already exposes. These are the inputs the burn-rate alerts (W3-T3) and dashboards
(W3-T4) consume.

## Scope

**In** — a recording rule per §6 SLI: API availability (non-5xx ratio), API read
latency (p95/p99 histograms), agent first-token latency, discovery success rate,
config-backup completeness, CR→audit completeness, topology-projection freshness,
**audit→SIEM export lag** (from W3-T1's metric), reasoning-trace persistence; rules
grouped + named per the ADR-0046 convention; rendered as a chart-managed rule
ConfigMap/PrometheusRule.

**Out** — the alerts (W3-T3); dashboards (W3-T4); the fault-injection harness
(W3-T5); any new app instrumentation (reuse existing metrics; flag a gap to the
relevant owner rather than inventing a metric here).

## Requirements (grounded in ADR-0046, PRODUCTION.md §6/§11 G-OBS)

1. **One rule per SLI row** — all 9 §6 rows have a recording rule; each names its
   SLI per the ADR-0046 convention.
2. **Computed from existing metrics** — built on ADR-0015's exposed metrics + the
   W3-T1 export-lag metric; no SLI left without a backing series (a missing series
   is a flagged gap, not a fabricated rule).
3. **`promtool check rules` clean** — the rules parse and the expressions are valid.
4. **Rendered + schema-valid** — the PrometheusRule/ConfigMap renders through the
   chart and passes kubeconform.

## Contracts / artifacts

- A `PrometheusRule` (recording group) per the §6 table; chart wiring.

## Test & gate plan

- `promtool check rules` clean (locally first — L1; if promtool absent locally, say
  so and lean on CI/rendered validation).
- helm render + kubeconform on the rule manifest.
- The *firing* proof is W3-T3 (alerts); this task delivers the inputs.

## Exit criteria

- [ ] A recording rule for each of the 9 §6 SLIs, named per ADR-0046; built on existing metrics + the export-lag metric.
- [ ] `promtool check rules` clean; PrometheusRule renders + kubeconform-valid.
- [ ] Any missing backing series flagged (not fabricated); one atomic commit.

## Workflow

`wf-observability` → combined sonnet review → fixer if findings → verifier → one atomic commit.

## Risks

- **An SLI with no backing metric** → a rule that silently evaluates to nothing.
  Flag the gap; don't fabricate.
- **Rule-naming drift** from ADR-0046 → W3-T3/T4 can't reference them cleanly.
