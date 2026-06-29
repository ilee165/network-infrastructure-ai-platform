# W3-T4 — Golden-signal Grafana dashboards-as-code

| | |
|---|---|
| **Wave** | P3 W3 — SIEM export + SLO enforcement |
| **Owner** | `wf-observability` |
| **Review tier** | sonnet |
| **Depends on** | **W3-T2** (recording rules) |
| **ADRs** | ADR-0046 (the contract), ADR-0015 (Grafana/metrics) |
| **PRODUCTION.md** | §6, §11 G-OBS §335 |
| **Status** | Proposed |

## Objective

Implement the dashboard layer of ADR-0046: **golden-signal (latency, traffic,
errors, saturation) Grafana dashboards as code** for `api`, each worker queue
(discovery/config/packet/docs), Postgres, Neo4j, Redis, and the LLM providers —
in-repo, linted, provisioned via the chart (G-OBS §335).

## Scope

**In** — one dashboard (or panel set) per component built on the W3-T2 recording
rules + ADR-0015 metrics; the four golden signals per component; dashboards as
code (jsonnet or JSON) in-repo; Grafana provisioning ConfigMap/sidecar wiring;
a dashboard lint/validate step.

**Out** — the alerts (W3-T3); the fault-injection harness (W3-T5); bespoke
business dashboards beyond the golden signals; new instrumentation (reuse metrics).

## Requirements (grounded in ADR-0046, PRODUCTION.md §11 G-OBS §335)

1. **Golden signals per component** — latency, traffic, errors, saturation for api,
   each queue, PG, Neo4j, Redis, LLM (the §335 inventory).
2. **As code, in-repo** — no click-ops dashboards; jsonnet/JSON committed +
   provisioned via the chart.
3. **Built on recording rules** — reuse W3-T2 rules where they exist (consistent
   SLI definitions across dashboard + alert).
4. **Lint/validate** — dashboards pass a JSON/jsonnet lint + the provisioning
   manifest passes kubeconform.

## Contracts / artifacts

- Dashboard files (jsonnet/JSON) per component; Grafana provisioning manifest;
  a lint/validate step.

## Test & gate plan

- Dashboard lint/validate clean; provisioning manifest renders + kubeconform-valid.
- Visual rendering is named-deferred (no live Grafana on host); the as-code +
  lint + provisioning is the biting layer (say so — L1).

## Exit criteria

- [ ] Golden-signal dashboards-as-code for api, each queue, PG, Neo4j, Redis, LLM.
- [ ] Built on W3-T2 recording rules; committed in-repo + provisioned via chart.
- [ ] Dashboard lint + provisioning kubeconform green; one atomic commit.

## Workflow

`wf-observability` → combined sonnet review → fixer if findings → verifier → one atomic commit.

## Risks

- **Click-ops dashboards** not in git → lost on redeploy, not reviewable. As-code only.
- **Dashboard SLIs diverging from alert SLIs** → confusing on-call. Reuse the W3-T2
  recording rules.
