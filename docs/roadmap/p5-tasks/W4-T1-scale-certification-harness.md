# W4-T1 — Parameterized scale-certification harness

| Field | Contract |
|---|---|
| Owner | `wf-reliability` |
| Depends on | ADR-0060; W1 and W3 contracts |
| Review | strong reliability review |
| Status | Proposed |

## Objective and scope

Build reproducible manifests/tools for the five G-SCA dimensions, renderable at
full target and runnable at smaller declared points. Out: claiming a capacity
result or requiring production secrets.

## Requirements and contracts

1. Seeded estate generates 500-device discovery input deterministically;
   projection fixture represents 5,000 devices/100,000 interfaces including
   cloud/hybrid layers without loading all data in controller memory.
2. k6 profile models 100 concurrent authenticated synthetic users and records
   endpoint mix, latency/errors, request IDs, and ramp/steady/cooldown phases.
3. Queue profiles generate 10× per-queue bursts and observe KEDA isolation;
   DB collector asserts PgBouncer/reserved-admin connection budgets.
4. Scenario manifest records seed, scale, SHA/digests, config and assertion
   thresholds; artifacts are secret-free. Every scenario has a failing control.

## Test and gate plan

Unit-test deterministic generation and manifest validation. Render full-target
manifests in CI without executing them. Execute a smoke point and, for each
assertion, plant the ADR-0060 regression and prove non-zero before restoring.
Run shell/yaml/k6 validation, kind harness smoke, and artifact schema checks.

## Exit criteria

- [ ] All five target workloads render exactly at §11 values.
- [ ] Reduced smoke run works and each negative control bites.
- [ ] Evidence manifest is reproducible, complete, and secret-free.
- [ ] Harness docs and commands are runnable; one atomic commit.
