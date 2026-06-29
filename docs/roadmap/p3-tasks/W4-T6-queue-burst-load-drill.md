# W4-T6 — Queue-burst KEDA + reduced-scale API load + PgBouncer budget

| | |
|---|---|
| **Wave** | P3 W4 — kind HA + drills + gate promotion + upgrade |
| **Owner** | `wf-reliability` |
| **Review tier** | sonnet |
| **Depends on** | **W2-T1** (api HPA), **W2-T3** (KEDA), **W4-T1** (kind) |
| **ADRs** | ADR-0047 (drill harness), ADR-0043 (HPA/KEDA), ADR-0042 (PgBouncer) |
| **PRODUCTION.md** | §11 G-SCA §326–§330 |
| **Status** | Proposed |

## Objective

Implement the G-SCA mechanism drills at **reduced scale** on the W4-T1 kind cluster:
**(a)** a 10× `discovery` queue-burst triggers **KEDA scale-out then scale-in** and
drains within SLO **without starving** `config`/`packet`/`docs` (per-queue
isolation, §329); **(b)** an API load test shows **p95 held** and a **1→2-replica
improvement** (§327); **(c)** **PgBouncer shows no connection exhaustion** (§330).
The certified-scale numbers (5,000-device / 100-user) are **named-deferred → GA**.

## Scope

**In** — a queue-burst generator (10× normal `discovery` depth) + assertions on
KEDA scale-out/in and per-queue isolation; a k6/locust API load run at reduced
concurrency asserting p95 + the 1→2-replica delta; a PgBouncer connection-budget
assertion under the load; each with the scale it ran at stated.

**Out** — the HPA/KEDA manifests (W2-T1/T3); the kind topology (W4-T1); the
certified-scale targets (named-deferred); the soak (W4-T7).

## Requirements (grounded in ADR-0047/0043, PRODUCTION.md §11 G-SCA)

1. **Queue-burst isolation (§329)** — 10× `discovery` → KEDA scale-out, drain within
   SLO, scale-in after; `config`/`packet`/`docs` **not starved** (independent
   ScaledObjects). Negative control: shared scaling → starvation → red.
2. **API load p95 + replica delta (§327)** — reduced-concurrency load holds p95;
   2 replicas beat 1 (mechanism of linear improvement); zero 5xx.
3. **PgBouncer budget (§330)** — no connection-exhaustion errors under the load.
4. **Named ceiling** — 100-user / 5,000-device / 500-device-in-60-min are
   **deferred-accepted → GA** with the promotion path; the drill states its reduced
   scale and does **not** claim the certified numbers.
5. **L5 pipefail**; **L1** local/kind-runner first.

## Contracts / artifacts

- Queue-burst generator + isolation assertions; k6/locust load script + p95/replica
  assertions; PgBouncer budget assertion; CI wiring; the named-ceiling note.

## Test & gate plan

- Drill on kind: burst → scale-out/in within SLO, isolation holds; load → p95 held,
  2>1 replica, zero 5xx; PgBouncer no exhaustion.
- **Negative control:** shared scaling → starvation → red; revert.
- L5 pipefail; local/kind-runner first (L1).

## Exit criteria

- [ ] 10× `discovery` burst → KEDA scale-out/in within SLO; `config`/`packet`/`docs` not starved (isolation).
- [ ] Reduced-scale API load: p95 held, 2-replica > 1-replica, zero 5xx; PgBouncer no exhaustion.
- [ ] Certified-scale numbers **named-deferred → GA** (not claimed); scale stated; negative control bites.
- [ ] L5 pipefail; one atomic commit.

## Workflow

`wf-reliability` → combined sonnet review → fixer if findings → verifier → one atomic commit.

## Risks

- **Over-claiming certified scale** from a kind run → dishonest gate. State reduced
  scale; defer the numbers.
- **A "burst" that doesn't trigger scale-out** → false green. Assert the replica
  count actually changed.
- **Per-queue starvation undetected** → the isolation guarantee unproven; the
  negative control is the check.
