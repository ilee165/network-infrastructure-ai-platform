# W4-T4 — Neo4j destroy-and-rebuild drill (topology restored ≤ topology-RTO)

| | |
|---|---|
| **Wave** | P3 W4 — kind HA + drills + gate promotion + upgrade |
| **Owner** | `wf-reliability` |
| **Review tier** | sonnet |
| **Depends on** | **W1-T3** (auto-rebuild Job), **W4-T1** (kind) |
| **ADRs** | ADR-0047 (drill harness), ADR-0005 (Neo4j projection rebuildable from PG), ADR-0030 (DR) |
| **PRODUCTION.md** | §8, §11 G-REL §317 |
| **Status** | Proposed |

## Objective

Implement the G-REL §317 drill: on the W4-T1 kind cluster, **destroy Neo4j** and
assert the **full topology is rebuilt from Postgres within the topology-RTO** (the
W1-T3 measured rebuild time; < 30 min at certified scale, reduced-scale proof here).
Ships with a **negative control** proving the assertion bites.

## Scope

**In** — the drill: seed a topology, destroy Neo4j, trigger/await the W1-T3
auto-rebuild, assert the topology matches the Postgres source of record and rebuild
completes within the RTO; the negative control (rebuild disabled / projection
incomplete → topology mismatch → red); records the measured reduced-scale rebuild
time.

**Out** — the rebuild Job itself (W1-T3); the kind topology (W4-T1); certified-scale
(5,000-device) rebuild timing (named-deferred → GA).

## Requirements (grounded in ADR-0047/0005, PRODUCTION.md §11 G-REL §317)

1. **Destroy → rebuild-from-PG** — after destroying Neo4j, the topology is fully
   restored from the system of record (D5), not from a Neo4j backup.
2. **Within topology-RTO** — rebuild completes within the W1-T3 measured RTO at
   reduced scale; the measured value is recorded (feeds the named-ceiling note).
3. **Completeness asserted** — restored node/edge counts match the Postgres source
   (a partial rebuild fails).
4. **Negative control bites** — rebuild disabled / projection truncated → topology
   mismatch → assertion red.
5. **Reduced-scale, stated**; **L5 pipefail**.

## Contracts / artifacts

- Neo4j rebuild drill harness (seed → destroy → rebuild → compare); negative-control
  variant; CI wiring on the W4-T1 topology.

## Test & gate plan

- Drill on kind: destroy → rebuild within RTO; restored topology matches PG.
- **Negative control:** disabled rebuild → mismatch → red; revert.
- L5 pipefail; local/kind-runner first (L1).

## Exit criteria

- [ ] Neo4j destroyed → topology fully rebuilt from Postgres within the topology-RTO (reduced scale).
- [ ] Restored node/edge counts match the PG source (completeness asserted).
- [ ] Negative control **bites** (mismatch → red), then reverted; rebuild time recorded.
- [ ] Scale stated; L5 pipefail; one atomic commit.

## Workflow

`wf-reliability` → combined sonnet review → fixer if findings → verifier → one atomic commit.

## Risks

- **"Rebuild" that reads a Neo4j dump** instead of Postgres → not the D5 guarantee.
  Rebuild from the system of record.
- **Partial rebuild reported as success** → silent topology gaps. Assert completeness
  against PG counts.
