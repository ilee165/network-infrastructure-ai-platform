# W2-T1 — api HPA (CPU + request-rate) + PodDisruptionBudget

| | |
|---|---|
| **Wave** | P3 W2 — Compute scale-out |
| **Owner** | `wf-infra` |
| **Review tier** | sonnet |
| **Depends on** | W0-T2 (ADR-0043) |
| **ADRs** | ADR-0043 (the contract), ADR-0029 (Helm GA), ADR-0013 (deploy), ADR-0010 (stateless JWT auth) |
| **PRODUCTION.md** | §3.2, §11 G-SCA |
| **Status** | Proposed |

## Objective

Implement ADR-0043's api half: a **HorizontalPodAutoscaler** on the `api`
Deployment (CPU + request-rate, min 2 / max N) and a **PodDisruptionBudget**
(minAvailable 1), rendered into the chart. Statelessness is a precondition (the
WebSocket fan-out, W2-T2) — cross-checked, not re-implemented here.

## Scope

**In** — the api HPA (`autoscaling/v2`, CPU + a request-rate custom/external
metric per ADR-0043), min/max replicas, scale-up/down behaviour (stabilization
windows), the PDB; chart values; resource requests/limits so HPA has a basis.

**Out** — the request-rate metric *source* if it needs new instrumentation
(coordinate with W3 observability); the WebSocket fan-out (W2-T2); KEDA workers
(W2-T3); the load drill (W4-T6).

## Requirements (grounded in ADR-0043, PRODUCTION.md §3.2/§11 G-SCA)

1. **min ≥ 2** always (HA); max + behaviour per ADR-0043; PDB minAvailable 1 so a
   drain never takes api to zero.
2. **CPU + request-rate** signals (not CPU alone) per ADR-0043; the request-rate
   metric must exist (reuse the §6/G-OBS api request metrics — coordinate, don't
   duplicate).
3. **Resource requests set** — HPA CPU% is meaningless without requests.
4. **Policy-as-test** — kubeconform/conftest/kube-linter green; render-twice stable.

## Contracts / artifacts

- api HPA + PDB manifests; chart values; resource requests/limits.

## Test & gate plan

- Infra gates green (helm lint, kubeconform, kube-linter, conftest).
- Scale-out/in observed for real in **W4-T6** (kind load drill); here render +
  policy only.

## Exit criteria

- [ ] api HPA (CPU + request-rate, min ≥ 2) + PDB (minAvailable 1) render + pass infra gates.
- [ ] Resource requests present; request-rate metric source confirmed (no duplicate instrumentation).
- [ ] Render-twice stable; one atomic commit.

## Workflow

`wf-infra` → combined sonnet review → fixer if findings → verifier → one atomic commit.

## Risks

- **HPA on CPU with no requests** → never scales. Requests are mandatory.
- **No PDB** → a node drain can take api to zero replicas mid-rollout.
- **Duplicate request-rate metric** diverging from the G-OBS one — reuse the §6 metric.
