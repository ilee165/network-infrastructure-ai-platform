# W2-T3 — KEDA ScaledObjects per queue (discovery/config/packet/docs) on Redis queue length

| | |
|---|---|
| **Wave** | P3 W2 — Compute scale-out |
| **Owner** | `wf-infra` |
| **Review tier** | sonnet |
| **Depends on** | W0-T2 (ADR-0043), **W1-T4** (Sentinel) |
| **ADRs** | ADR-0043 (the contract), ADR-0008 (Celery per-queue Deployments), ADR-0031 (packet sandbox node pool), ADR-0029 (Helm GA) |
| **PRODUCTION.md** | §3.2, §11 G-SCA |
| **Status** | Proposed |

## Objective

Implement ADR-0043's worker half: a **KEDA ScaledObject per Celery queue**
(`discovery`, `config`, `packet`, `docs`) scaling on **Redis queue length**, with
**per-queue isolation** (one queue's burst must not starve another) and the
**packet-worker dedicated-node-pool exception** (D14/ADR-0031). HPA-on-celery-
exporter is the named fallback.

## Scope

**In** — four ScaledObjects (one per queue) targeting the per-queue worker
Deployments (ADR-0008); the Redis-list-length trigger via Sentinel; min/max +
cooldown per ADR-0043; the packet ScaledObject bounded to the sandbox node pool
(ADR-0031), no NET_RAW pods on general nodes; chart values.

**Out** — the worker idempotency code (W2-T4); the api HPA (W2-T1); the queue-burst
*drill* (W4-T6); the celery-exporter HPA fallback (named in ADR-0043, not built).

## Requirements (grounded in ADR-0043, ADR-0008/0031, PRODUCTION.md §3.2/§11 G-SCA)

1. **One ScaledObject per queue** on Redis queue length; independent min/max so the
   queues scale separately (per-queue isolation, G-SCA §329) — W4-T6 asserts a
   `discovery` burst doesn't starve `config`/`packet`/`docs`.
2. **Sentinel-aware trigger** — the KEDA Redis scaler discovers the primary via
   Sentinel (W1-T4) so failover doesn't break scaling.
3. **Packet-pool exception** — packet workers scale only within the D14 sandbox node
   pool; no privileged/NET_RAW pods scheduled onto general nodes.
4. **Policy-as-test** — kubeconform/conftest/kube-linter green; render-twice stable.

## Contracts / artifacts

- Four KEDA `ScaledObject` manifests; chart values; node-pool affinity for packet.

## Test & gate plan

- Infra gates green; KEDA CRD schema validated (kubeconform with the KEDA schema or
  a documented skip).
- Real scale-out/in + isolation exercised in **W4-T6** (kind); here render + policy.

## Exit criteria

- [ ] Four per-queue ScaledObjects render + pass infra gates; independent min/max (isolation).
- [ ] Redis trigger is Sentinel-aware; packet bounded to the sandbox node pool.
- [ ] Render-twice stable; one atomic commit.

## Workflow

`wf-infra` → combined sonnet review → fixer if findings → verifier → one atomic commit.

## Risks

- **Shared scaling across queues** → a `discovery` burst starves `config`/`packet`.
  Independent ScaledObjects are the isolation guarantee W4-T6 checks.
- **Packet worker on a general node** → NET_RAW outside the sandbox (security
  regression). Node-pool affinity mandatory.
