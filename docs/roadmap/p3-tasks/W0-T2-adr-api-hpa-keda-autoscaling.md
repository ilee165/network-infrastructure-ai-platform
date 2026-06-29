# W0-T2 — ADR-0043 api HPA + KEDA per-queue worker autoscaling

| | |
|---|---|
| **Wave** | P3 W0 — ADRs / design gate |
| **Owner** | `wf-implementer` |
| **Review tier** | sonnet |
| **Depends on** | — |
| **Builds on** | ADR-0008 (Celery/Redis async jobs), ADR-0013 (Docker/K8s deploy), ADR-0029 (Helm GA + hardening), ADR-0031 (packet sandbox node pool) |
| **PRODUCTION.md** | §3.2, §11 G-SCA |
| **Status** | Proposed |

## Objective

Ratify the compute scale-out design: **api Horizontal Pod Autoscaler** (CPU +
request-rate, ≥2 replicas always, PodDisruptionBudget) and **KEDA ScaledObjects
per Celery queue** (discovery/config/packet/docs) scaling on **Redis queue
length**, with the HPA-on-celery-exporter fallback named. Fix scale targets,
min/max replicas, and the per-queue isolation requirement.

## Scope

**In** — autoscaler choice (KEDA primary, celery-exporter HPA fallback), the
scaling signal (Redis list length per queue), min/max replicas + PDB minAvailable,
the packet-worker dedicated-node-pool exception (D14/ADR-0031), and the
per-queue-isolation requirement (a `discovery` burst must not starve
`config`/`packet`/`docs`) that W4-T6 asserts.

**Out** — implementation (W2-T1/T3); the queue-burst *drill* (W4-T6);
certified-scale numbers (named-deferred).

## Requirements (grounded in PRODUCTION.md §3.2, §11 G-SCA)

1. **api stateless + ≥2 replicas:** HPA on CPU + request rate; PDB minAvailable 1.
   Statelessness depends on ADR-0044 (WebSocket fan-out) — cross-reference it.
2. **KEDA per queue:** one ScaledObject per queue on Redis queue length;
   `acks_late` + idempotent tasks (ADR cross-ref to W2-T4) so scale-in/node loss
   only re-runs work.
3. **Per-queue isolation:** independent ScaledObjects so one queue's burst does not
   consume another's capacity — the G-SCA §329 requirement.
4. **Packet-worker exception:** pinned to the D14 sandbox node pool; its scaling
   bounded separately (no NET_RAW pods on general nodes).
5. **Fallback named:** HPA-on-celery-exporter if KEDA unavailable (no silent default).

## Contracts / artifacts

- `docs/adr/0043-api-hpa-keda-worker-autoscaling.md` (Proposed), ADR index updated.

## Test & gate plan

- D16 docs gates only. The ADR names the assertions W2-T1/T3 (render/policy) and
  W4-T6 (queue-burst + load drill) must satisfy.

## Exit criteria

- [ ] ADR-0043 written: HPA signals + min/max + PDB; KEDA per-queue signal; isolation; packet-pool exception; fallback.
- [ ] Certified-scale-deferred named; ADR index updated; one atomic commit.

## Workflow

`wf-implementer` drafts → combined sonnet review → fixer if findings → verifier → one atomic commit.

## Risks

- **KEDA scaling signal lag** → bursts drain slowly. The ADR must state the polling
  interval and cooldown so the drill target is realistic.
- **Stateless-api assumption** silently broken if WS fan-out (ADR-0044) slips —
  keep the two ADRs cross-referenced.
