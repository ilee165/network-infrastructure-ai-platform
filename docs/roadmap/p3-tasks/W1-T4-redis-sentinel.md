# W1-T4 — Redis Sentinel ×3 + AOF persistence

| | |
|---|---|
| **Wave** | P3 W1 — Data-tier HA |
| **Owner** | `wf-infra` |
| **Review tier** | sonnet |
| **Depends on** | W0-T3 (ADR-0044) |
| **ADRs** | ADR-0044 (the contract), ADR-0008 (Redis broker/result/cache), ADR-0029 (Helm GA) |
| **PRODUCTION.md** | §3.2 |
| **Status** | Proposed |

## Objective

Implement ADR-0044's Redis HA half: **Redis Sentinel (3 nodes) + AOF persistence**
for the broker/result/cache, rendered into the chart with hardened defaults. This
backs the KEDA queue-length signal (W2-T3) and the WebSocket pub/sub fan-out
(W2-T2); broker loss must be tolerable because tasks are idempotent + re-enqueueable.

## Scope

**In** — Sentinel topology (3 sentinels + Redis primary/replica) manifests; AOF
persistence config; client connection config pointed at Sentinel for failover-aware
discovery (app + workers + KEDA); secure-by-default (auth, non-root, resource
limits); `lookup` for any dev secret (**L4**).

**Out** — Redis Cluster sharding (single-shard Sentinel only per ADR-0044); the
WebSocket fan-out logic (W2-T2); the KEDA ScaledObjects (W2-T3); a Redis failover
drill (broker loss tolerated by design — covered indirectly by W4 idempotency).

## Requirements (grounded in ADR-0044, ADR-0008, PRODUCTION.md §3.2)

1. **Sentinel ×3 + AOF** — automatic primary failover; AOF so recent state survives
   restart.
2. **Failover-aware clients** — app/worker/KEDA connect via Sentinel so a primary
   change is transparent.
3. **Broker-loss tolerance** — document that tasks are idempotent + re-enqueueable
   and scheduled jobs re-fire on next beat (the design rationale; W4-T5 asserts the
   idempotency).
4. **Secure-by-default + L4** — auth required, non-root, limits; dev secret via
   `lookup` reuse-or-generate.

## Contracts / artifacts

- Sentinel + Redis manifests; AOF config; Sentinel-aware client config; chart values.

## Test & gate plan

- Infra gates: helm lint, kubeconform, kube-linter, conftest — green.
- Sentinel failover exercised in **W4-T1** kind bring-up (or rendered emulation if
  absent locally — say which; L1).
- L4 render-twice stable.

## Exit criteria

- [ ] Sentinel ×3 + AOF render + pass infra gates; clients are Sentinel-aware.
- [ ] Broker-loss-tolerance rationale documented (ties to W4-T5 idempotency).
- [ ] Secure-by-default; L4 render-twice stable; one atomic commit.

## Workflow

`wf-infra` → combined sonnet review → fixer if findings → verifier → one atomic commit.

## Risks

- **Clients pinned to a static Redis host** (not Sentinel) → failover invisible to
  the app, broker effectively single-point. Use Sentinel discovery.
- **AOF disabled** → cache/broker state lost on restart beyond what idempotency
  covers.
