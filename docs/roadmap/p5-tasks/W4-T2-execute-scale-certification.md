# W4-T2 — Execute reduced-scale certification

| Field | Contract |
|---|---|
| Owner | `wf-reliability` |
| Depends on | W4-T1, W1 complete, W3-T1, W3-T2 |
| Review | strong reliability review |
| Status | Proposed |

## Objective and scope

Run ADR-0060 scenarios on the kind host to the highest feasible passing point,
with hardened dispatch and hybrid topology present, and publish immutable raw
and summarized evidence. Out: describing the achieved point as full-scale
certification.

## Requirements and contracts

1. Preflight records host/cluster resources, image digests, release SHA,
   configuration, telemetry readiness, and abort thresholds.
2. Ascend declared scale points; record highest pass and first fail/not-run with
   resource/SLO reason. Do not tune thresholds after seeing results.
3. Observe autoscale out/in, per-queue isolation, PgBouncer budget, API SLOs,
   dispatch backlog/recovery, projection completion, and UI query usability.
4. Run each negative control in the same environment and retain its red result;
   incomplete telemetry invalidates the scenario.

## Test and gate plan

Run harness validators before and after. Verify artifact hashes and manifest
schema, independently recompute summaries from raw metrics, and rerun any
flaky/incomplete point rather than averaging it away. Re-run P3 drill-bite
proofs and Neo4j rebuild with the hybrid dataset.

## Exit criteria

- [ ] Every G-SCA dimension has achieved-vs-target evidence at release SHA.
- [ ] Positive run passes at the recorded point and negative control fails.
- [ ] P3 `drill-bite-proofs` stays green with the hybrid dataset.
- [ ] First unsupported point/reason and all telemetry gaps are explicit.
- [ ] Evidence review passes; one atomic commit.
