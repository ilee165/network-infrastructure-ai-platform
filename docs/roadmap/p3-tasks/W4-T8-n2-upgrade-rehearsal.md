# W4-T8 — N-2 → N upgrade rehearsal on seeded data (expand/contract + rolling order + Neo4j rebuild)

| | |
|---|---|
| **Wave** | P3 W4 — kind HA + drills + gate promotion + upgrade |
| **Owner** | `wf-infra` + `wf-implementer` (migration) |
| **Review tier** | sonnet (strong if a migration touches audit/credentials) |
| **Depends on** | **W1**, **W2**, **W4-T1** (kind) |
| **ADRs** | ADR-0047 (drill harness), ADR-0029 (Helm GA), ADR-0002 (Alembic expand/contract), ADR-0005 (Neo4j rebuild) |
| **PRODUCTION.md** | §10 (upgrade), §11 G-MNT §346 |
| **Status** | DONE — merged pending (drill + probe + bite + Helm pre-upgrade migrate Job + CI wiring). Bite GREEN on the authoring host (POSITIVE green; contract-too-early + force-unavail negative controls both RED); validate-harness W4-T8 block 30/30; conftest hardening.rego 251/251, kubeconform strict + kube-linter clean on the rendered Job. Live kind run stays opt-in/signal-only (ADR-0048 Rejected) — the cluster-free bite is the blocking gate. |

## Objective

Implement the G-MNT §346 upgrade rehearsal: on the W4-T1 kind cluster, seed an
**N-2** dataset and rehearse the **N-2 → N upgrade** — Alembic **expand/contract**
migration as a Helm pre-upgrade Job, the **rolling order** (migrate → workers with
Celery warm shutdown → api → frontend), and the **post-upgrade Neo4j rebuild** —
asserting **no downtime and no data loss**. Closes the P2-deferred §11 G-MNT item.

## Scope

**In** — seed an N-2-shaped dataset; run the upgrade through the rolling order;
assert the expand migration lets N-1/N-2 pods run against the expanded schema (no
break), api stays available (≥2 replicas) through the roll, workers warm-shut
without losing in-flight tasks, and the Neo4j projection rebuilds post-upgrade;
the migration Job uses `sh -c` for any exec argv (**L3**).

**Out** — the HA manifests (W1/W2); the kind topology (W4-T1); the contract
(down-revision) migration timing (only shipped after the prior release is out of
support — PRODUCTION.md §10, named); certified-scale seeded dataset (reduced-scale
here; full prod-shaped dataset named-deferred → GA).

## Requirements (grounded in ADR-0047/0002, PRODUCTION.md §10, §11 G-MNT §346)

1. **Expand/contract** — release N adds (expand); N-1/N-2 pods run correctly against
   the expanded schema (the rolling-upgrade-without-downtime property).
2. **Rolling order** — migrate (expand) → roll workers per queue with Celery warm
   shutdown → roll api (≥2 replicas keep availability) → frontend; Neo4j rebuild if
   the projection schema changed.
3. **No data loss / no downtime** — asserted across the roll on real PG; audit chain
   intact through the migration.
4. **Seeded N-2 dataset** — reduced-scale; the prod-shaped dataset is
   named-deferred → GA.
5. **L3 `sh -c`** on the migration Job exec argv; **L5 pipefail** on the rehearsal
   pipeline.

## Contracts / artifacts

- Seed fixture (N-2 dataset); the upgrade-rehearsal harness (Helm pre-upgrade Job +
  rolling-order driver + assertions); CI wiring on the W4-T1 topology.

## Test & gate plan

- Rehearsal on kind: N-2 → N upgrade, expand migration, rolling order, Neo4j
  rebuild; assert availability + no data loss on real PG; audit chain intact.
- **L3** `sh -c`; **L5** pipefail; local/kind-runner first (**L1**).

## Exit criteria

- [x] N-2 → N upgrade rehearsed on kind: expand migration (`alembic upgrade head` + additive `ADD COLUMN`), rolling order (migrate → workers → api → post-upgrade Neo4j rebuild), post-upgrade Neo4j re-projection. Rehearsal harness: `ci/kind/assertions/checks/n2-upgrade-rehearsal.sh` + `-drill-probe.yaml`; Helm pre-upgrade migrate Job `deploy/kubernetes/netops/templates/db-migrate-job.yaml` (hook-weight −5, `migrationJob.preUpgrade`, default OFF, enabled in `values-kind-ha.yaml`).
- [x] N-1/N-2 pods run on the expanded schema (N-1 reader `SELECT n1_col` survives the additive expand); api held ≥2 ready through the roll (no downtime); workers rolled (warm shutdown); **no committed-row loss** + audit spine intact (count + max seq), all on real PG. Two negative controls bite: contract-too-early column drop → N-1 reader RED; force-unavail → no-downtime RED (`ci/kind/selftest/n2-upgrade-rehearsal-bite.sh`, GREEN on host).
- [x] Prod-shaped dataset + contract-migration timing named-deferred → GA (§10 / ADR-0047 §4); L3 `sh -c` positional args; L5 `set -euo pipefail`; one atomic commit. Static gate: `validate-harness.sh` W4-T8 block; CI bite step in `drill-bite-proofs` (blocking) + `kind-harness-ha` (static).

## Workflow

`wf-infra` (rehearsal) + `wf-implementer` (migration) → combined sonnet review (strong if migration touches audit/credentials) → fixer if findings → verifier → one atomic commit.

## Risks

- **Contract shipped too early** (drops a column N-1 still reads) → breaks rollback.
  Expand only this release; contract after the prior release leaves support (§10).
- **L3 `$(VAR)` in the migration Job** → migration runs with literal `$(VAR)`,
  silently wrong. Wrap in `sh -c`.
- **Asserting on SQLite** → migration/rolling semantics differ on PG. Real PG.
