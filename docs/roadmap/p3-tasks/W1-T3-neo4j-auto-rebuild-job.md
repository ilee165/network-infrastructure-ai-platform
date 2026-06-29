# W1-T3 — Neo4j automated-rebuild Job (liveness-fail → recreate + rebuild)

| | |
|---|---|
| **Wave** | P3 W1 — Data-tier HA |
| **Owner** | `wf-infra` |
| **Review tier** | sonnet |
| **Depends on** | W0-T1 (ADR-0042 context) |
| **ADRs** | ADR-0005 (Neo4j topology projection — "fully rebuildable from Postgres"), ADR-0030 (backup/DR), ADR-0029 (Helm GA) |
| **PRODUCTION.md** | §3.2 (Neo4j single + automated rebuild), §8, §11 G-REL |
| **Status** | Proposed |

## Objective

Harden the Neo4j recovery path that D5/ADR-0005 designed: a **single Neo4j instance
with an automated-rebuild Job** so a liveness failure triggers **recreate +
projection rebuild from Postgres**, and the **measured rebuild time becomes the
topology-RTO** that the W4-T4 drill asserts. Neo4j Community has no clustering;
this is the designed HA mitigation.

## Scope

**In** — the rebuild Job/CronJob (or operator hook) that re-projects the topology
from Postgres; the liveness→recreate wiring (probe + restart policy); the
post-rebuild readiness signal; a `--% sh -c` wrapper on any exec argv (**L3**);
emitting the rebuild-duration metric (so the topology-RTO is observable and the
W4-T4 drill + G-OBS freshness SLO can read it).

**Out** — the destroy-and-rebuild *drill* (W4-T4); Neo4j Enterprise causal cluster
(ADR-0005/§3.2 opt-in, not built); the projection logic itself (exists from M-series
— this orchestrates it).

## Requirements (grounded in ADR-0005, PRODUCTION.md §3.2/§8)

1. **Rebuild-from-Postgres** — the Job re-projects topology from the system of
   record; Neo4j holds no un-rebuildable state (D5).
2. **Automatic on liveness failure** — probe failure → recreate → rebuild → ready;
   no manual step.
3. **Rebuild duration measured** — emitted as a metric; this value is the
   topology-RTO the W4-T4 drill compares against (< 30 min at the certified scale,
   reduced-scale proof here).
4. **L3 exec argv** — any `$(VAR)` in a Job exec command wrapped in `sh -c` (K8s
   does not substitute it).

## Contracts / artifacts

- Rebuild Job/CronJob manifest + liveness/recreate wiring + rebuild-duration metric;
  chart values.

## Test & gate plan

- Infra gates: helm lint, kubeconform, kube-linter, conftest — green.
- The rebuild path is exercised for real in **W4-T4** (kind); here, render + a local
  dry-run of the rebuild command (or a rendered emulation if Neo4j/kind absent
  locally — say which; L1).

## Exit criteria

- [ ] Automated-rebuild Job renders + passes infra gates; liveness-fail → recreate + rebuild wired.
- [ ] Rebuild-duration metric emitted (feeds the W4-T4 topology-RTO assertion + G-OBS freshness).
- [ ] L3 `sh -c` on exec argv; one atomic commit.

## Workflow

`wf-infra` → combined sonnet review → fixer if findings → verifier → one atomic commit.

## Risks

- **Rebuild not actually triggered** by liveness failure → silent stale topology.
  The recreate→rebuild chain must be wired, not assumed.
- **L3 `$(VAR)` in exec argv** → the Job runs with a literal `$(VAR)` and silently
  mis-targets. Wrap in `sh -c`.
