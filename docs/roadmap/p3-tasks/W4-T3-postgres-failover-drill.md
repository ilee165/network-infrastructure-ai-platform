# W4-T3 — Postgres failover drill (primary kill → promote ≤ 60 s, zero committed-audit loss)

| | |
|---|---|
| **Wave** | P3 W4 — kind HA + drills + gate promotion + upgrade |
| **Owner** | `wf-reliability` (escalated — audit path) |
| **Review tier** | **strong** spec + quality (audit durability) |
| **Depends on** | **W1-T1** (CNPG + sync-audit), **W1-T2** (sync session), **W4-T1** (kind) |
| **ADRs** | ADR-0047 (drill harness), ADR-0042 (PG HA + sync audit), ADR-0038 (audit hash-chain) |
| **PRODUCTION.md** | §8, §11 G-REL §316 |
| **Status** | Proposed |

## Objective

Implement the G-REL §316 failover drill: on the W4-T1 kind cluster, **kill the
Postgres primary**, assert **automated promotion with write service restored ≤ 60 s**
and **zero committed-audit-entry loss** (the synchronous audit path from
ADR-0042/W1-T2). Ships with a **negative control** proving the assertion bites.

## Scope

**In** — the drill harness: seed audit rows, kill the CNPG primary, measure
promotion + write-restore time, verify **every committed audit row** (hash-chain
intact, no `seq` gap) survives on the promoted primary; the negative control (async
commit / non-quorum config → a committed row is lost → assertion red); runs against
**real PG** on kind.

**Out** — the CNPG manifests (W1-T1); the sync-session app wiring (W1-T2); the kind
topology (W4-T1); certified-scale failover (named-deferred → GA).

## Requirements (grounded in ADR-0047/0042, PRODUCTION.md §11 G-REL §316)

1. **Primary kill → auto-promote ≤ 60 s** — write service restored within the RTO;
   no manual step.
2. **Zero committed-audit loss** — every audit row committed before the kill is
   present + hash-chain-valid after promotion (the sync-quorum guarantee). Asserted
   on real PG, never SQLite.
3. **Negative control bites** — with async/non-quorum commit, a committed row is
   lost and the assertion goes **red** (proves the drill measures what it claims).
4. **Reduced-scale, stated**; **L5 pipefail + `test -s`** on the drill pipeline.

## Contracts / artifacts

- Failover drill harness (seed → kill → measure → verify); negative-control variant;
  CI wiring on the W4-T1 topology.

## Test & gate plan

- Drill on kind: kill primary → promotion ≤ 60 s; zero committed-audit loss
  (hash-chain intact, no gap), real PG.
- **Negative control:** async commit → row lost → red; revert.
- L5 pipefail; local/kind-runner first (L1).

## Exit criteria

- [ ] Primary kill → automated promotion, write service ≤ 60 s.
- [ ] **Zero committed-audit-entry loss** verified on real PG (hash-chain intact, no `seq` gap).
- [ ] Negative control (async commit) **bites** (loses a row → red), then reverted.
- [ ] Scale stated; L5 pipefail; one atomic commit.

## Workflow

`wf-reliability` (escalated) → **`wf-spec-reviewer` (strong) + `wf-quality-reviewer` (strong)** → `wf-fixer` (strong) if findings → `wf-verifier` → one atomic commit.

## Risks

- **A drill that doesn't actually kill the primary** or asserts nothing → false
  green. The negative control is the proof it bites.
- **Asserting audit survival on SQLite** → hides the sync-replication semantics.
  Real PG only.
- **RTO measured wrong** (from kill vs. from detection) → define the start point.
