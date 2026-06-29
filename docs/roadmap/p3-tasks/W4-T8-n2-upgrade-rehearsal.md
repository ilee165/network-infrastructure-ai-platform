# W4-T8 — N-2 → N upgrade rehearsal on seeded data (expand/contract + rolling order + Neo4j rebuild)

| | |
|---|---|
| **Wave** | P3 W4 — kind HA + drills + gate promotion + upgrade |
| **Owner** | `wf-infra` + `wf-implementer` (migration) |
| **Review tier** | sonnet (strong if a migration touches audit/credentials) |
| **Depends on** | **W1**, **W2**, **W4-T1** (kind) |
| **ADRs** | ADR-0047 (drill harness), ADR-0029 (Helm GA), ADR-0002 (Alembic expand/contract), ADR-0005 (Neo4j rebuild) |
| **PRODUCTION.md** | §10 (upgrade), §11 G-MNT §346 |
| **Status** | Proposed |

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

- [ ] N-2 → N upgrade rehearsed on kind: expand migration, rolling order, post-upgrade Neo4j rebuild.
- [ ] N-1/N-2 pods run on the expanded schema; api available through the roll; workers warm-shut; **no data loss** (real PG, audit intact).
- [ ] Prod-shaped dataset named-deferred → GA; L3 `sh -c`; L5 pipefail; one atomic commit.

## Workflow

`wf-infra` (rehearsal) + `wf-implementer` (migration) → combined sonnet review (strong if migration touches audit/credentials) → fixer if findings → verifier → one atomic commit.

## Risks

- **Contract shipped too early** (drops a column N-1 still reads) → breaks rollback.
  Expand only this release; contract after the prior release leaves support (§10).
- **L3 `$(VAR)` in the migration Job** → migration runs with literal `$(VAR)`,
  silently wrong. Wrap in `sh -c`.
- **Asserting on SQLite** → migration/rolling semantics differ on PG. Real PG.
